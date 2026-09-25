"""离线回放：用新策略版本重评估历史访问记录，生成差异报告。

- 只生成差异报告，绝不改写原始审计决策；
- 重评估不消耗租约额度，只检查租约当前是否仍然有效；
- 每批处理后把游标与累积差异持久化，进程重启后可从断点续跑。
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import ALLOW, DENY, REPLAY_FINISHED, EvaluationContext, ReplayJob
from .namespace import Resolver
from .policy import evaluate_rules
from .leases import LeaseManager
from .store import Store


@dataclass
class _ReEval:
    outcome: str
    rule: str | None
    reason: str | None
    lease_covers: bool


class Replayer:
    def __init__(self, store: Store, leases: LeaseManager, clock, batch_size: int = 100, after_batch=None):
        self._store = store
        self._leases = leases
        self._clock = clock
        self._batch_size = batch_size
        self._after_batch = after_batch  # 测试钩子：每批提交后调用，用于模拟中断

    def run(self, job_id: str) -> ReplayJob:
        job = self._store.get_replay_job(job_id)
        if job is None:
            raise KeyError(job_id)
        if job.status == REPLAY_FINISHED:
            return job
        policy = self._store.get_policy(job.tenant_id, job.policy_version)
        view = self._store.get_namespace(job.tenant_id)
        while True:
            batch = self._store.decisions_after(job.tenant_id, job.cursor_seq, self._batch_size)
            if not batch:
                break
            for decision in batch:
                new = self._reevaluate(decision, policy, view)
                old = (decision.outcome, decision.matched_rule, decision.reason)
                if (new.outcome, new.rule, new.reason) != old:
                    job.diffs.append(
                        {
                            "decision_id": decision.decision_id,
                            "seq": decision.seq,
                            "canonical_path": decision.context.canonical_path if decision.context else None,
                            "old": {"outcome": decision.outcome, "rule": decision.matched_rule, "reason": decision.reason},
                            "new": {"outcome": new.outcome, "rule": new.rule, "reason": new.reason},
                            "lease_still_covers": new.lease_covers,
                        }
                    )
                job.cursor_seq = decision.seq
                job.scanned += 1
            self._store.update_replay_job(job)  # 每批提交一次游标
            if self._after_batch is not None:
                self._after_batch()
        job.status = REPLAY_FINISHED
        job.finished_at = self._clock().isoformat()
        self._store.update_replay_job(job)
        return job

    def _reevaluate(self, decision, policy, view) -> _ReEval:
        """完整重评估：重新解析 + 规则评估 + 租约有效性检查（不消耗、不写审计）。"""
        request = decision.request
        capabilities = tuple(request.get("capabilities", ()))
        if view is None or policy is None:
            return _ReEval(DENY, None, decision.reason, False)
        resolution = Resolver(view).resolve(request["path"])
        if not resolution.ok:
            return _ReEval(DENY, None, resolution.reason, False)
        ctx = EvaluationContext(
            canonical_path=resolution.canonical_path,
            source=resolution.mount.source,
            owner=resolution.node.owner,
            labels=resolution.node.labels,
            operation=request["operation"],
            caller_id=request["caller_id"],
            capabilities=capabilities,
        )
        outcome, rule, reason = evaluate_rules(policy, ctx)
        lease_covers = False
        if outcome == DENY:
            lease = self._leases.find_active(decision.tenant_id, ctx.canonical_path, ctx.operation)
            if lease is not None:
                outcome, reason, lease_covers = ALLOW, None, True
        return _ReEval(outcome, rule, reason, lease_covers)
