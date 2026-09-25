"""策略服务门面：登记命名空间、发布策略、签发例外、执行访问判定与策略回放。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import replace

from .clock import Clock, SystemClock, to_utc_iso
from .engine import PolicyEngine
from .models import (
    AccessRequest,
    Decision,
    ExceptionLease,
    PolicyVersion,
    ReplayDiff,
    ReplayJob,
    Resource,
    Rule,
)
from .reasons import AllowReason, DenyReason, MESSAGES
from .repository import Repository
from .resolver import NamespaceResolver

#: 有权签发例外租约的审批人
DEFAULT_APPROVERS = frozenset({"reviewer-02", "sec-approver"})


class PathPolicyService:
    def __init__(
        self,
        db_path: str = ":memory:",
        clock: Clock | None = None,
        approvers: frozenset[str] | None = None,
        tenant_roots: dict[str, str] | None = None,
    ) -> None:
        self.repo = Repository(db_path)
        self.clock = clock or SystemClock()
        self.approvers = approvers if approvers is not None else DEFAULT_APPROVERS
        # 缺省每个租户根是 /tenants/<tenant_id>，可用 tenant_roots 覆盖
        self._tenant_roots = dict(tenant_roots or {})

    def close(self) -> None:
        self.repo.close()

    def _now_iso(self) -> str:
        return to_utc_iso(self.clock.now())

    def tenant_root(self, tenant_id: str) -> str:
        return self._tenant_roots.setdefault(tenant_id, f"/tenants/{tenant_id}")

    # ------------------------------------------------------------------
    # 命名空间登记
    # ------------------------------------------------------------------
    def register_resource(
        self,
        tenant_id: str,
        resource_id: str,
        source: str,
        owner_id: str,
        labels: frozenset[str] | set[str] | tuple[str, ...] = frozenset(),
    ) -> Resource:
        root = self.tenant_root(tenant_id)
        canonical = resource_id if resource_id.startswith("/") else f"{root}/{resource_id}"
        import posixpath

        canonical = posixpath.normpath(canonical)
        if canonical != root and not canonical.startswith(root.rstrip("/") + "/"):
            raise ValueError(f"资源路径越过租户根：{canonical}")
        if source not in ("system_template", "runtime_record", "tenant_file", "archive_member"):
            raise ValueError(f"未知文件来源：{source}")
        resource = Resource(
            resource_id=canonical,
            tenant_id=tenant_id,
            source=source,  # type: ignore[arg-type]
            owner_id=owner_id,
            labels=frozenset(labels),
        )
        self.repo.upsert_resource(resource)
        self.repo.append_event(
            f"evt-{uuid.uuid4().hex[:12]}", "resource.registered",
            canonical, tenant_id, {"resource_id": canonical, "source": source}, self._now_iso(),
        )
        return resource

    def register_symlink(self, tenant_id: str, link_path: str, target: str) -> None:
        self.repo.upsert_symlink(tenant_id, link_path, target)

    def add_mount(self, tenant_id: str, alias: str, target: str) -> None:
        self.repo.add_mount(tenant_id, alias, target)

    def _build_resolver(self, tenant_id: str) -> NamespaceResolver:
        return NamespaceResolver(
            tenant_id=tenant_id,
            tenant_root=self.tenant_root(tenant_id),
            resources=self.repo.list_resources(tenant_id),
            symlinks=self.repo.list_symlinks(tenant_id),
            mounts=self.repo.list_mounts(tenant_id),
        )

    # ------------------------------------------------------------------
    # 策略发布（只追加，版本不可覆盖）
    # ------------------------------------------------------------------
    def publish_policy(
        self,
        tenant_id: str,
        version: str,
        rules: list[Rule] | tuple[Rule, ...],
        published_by: str,
    ) -> PolicyVersion:
        rule_ids = [rule.rule_id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("同一策略版本内规则 ID 必须唯一")
        base = self.repo.active_version(tenant_id)
        policy = PolicyVersion(
            version=version,
            tenant_id=tenant_id,
            rules=tuple(rules),
            published_at=self._now_iso(),
            published_by=published_by,
            base_version=base,
        )
        self.repo.publish_policy(policy)
        self.repo.append_event(
            f"evt-{uuid.uuid4().hex[:12]}", "policy.published",
            f"policy:{tenant_id}", tenant_id,
            {"version": version, "rule_count": len(rules), "base_version": base},
            self._now_iso(),
        )
        return policy

    def active_version(self, tenant_id: str) -> str | None:
        return self.repo.active_version(tenant_id)

    # ------------------------------------------------------------------
    # 例外租约
    # ------------------------------------------------------------------
    def grant_lease(
        self,
        lease_id: str,
        tenant_id: str,
        resource_ids: frozenset[str] | set[str] | tuple[str, ...],
        operations: frozenset[str] | set[str] | tuple[str, ...],
        quota: int,
        granted_by: str,
        ttl_seconds: int | None = None,
        expires_at: str | None = None,
        note: str = "",
    ) -> ExceptionLease:
        if granted_by not in self.approvers:
            raise PermissionError(f"{granted_by} 不是指定审批人，无权签发例外租约")
        if quota <= 0:
            raise ValueError("租约额度必须为正整数")
        known = self.repo.list_resources(tenant_id)
        exact = frozenset(resource_ids)
        unknown = sorted(rid for rid in exact if rid not in known)
        if unknown:
            raise ValueError(f"租约只能签发给已登记的精确资源集合，未知资源：{unknown}")
        if not exact or not operations:
            raise ValueError("租约必须绑定至少一个资源与一种操作")

        now = self.clock.now()
        if expires_at is not None:
            from .clock import parse_iso

            expiry = parse_iso(expires_at)
        elif ttl_seconds is not None:
            from datetime import timedelta

            expiry = now + timedelta(seconds=ttl_seconds)
        else:
            raise ValueError("必须提供 ttl_seconds 或 expires_at")
        if expiry <= now:
            raise ValueError("租约到期时间必须晚于当前时间")

        lease = ExceptionLease(
            lease_id=lease_id,
            tenant_id=tenant_id,
            resource_ids=exact,
            operations=frozenset(operations),
            quota=quota,
            used=0,
            granted_by=granted_by,
            granted_at=to_utc_iso(now),
            expires_at=to_utc_iso(expiry),
            state="active",
            note=note,
        )
        self.repo.insert_lease(lease)
        self.repo.append_event(
            f"evt-{uuid.uuid4().hex[:12]}", "lease.granted",
            lease_id, tenant_id,
            {"quota": quota, "resources": sorted(exact),
             "operations": sorted(lease.operations), "expires_at": lease.expires_at},
            self._now_iso(),
        )
        return lease

    def get_lease(self, lease_id: str) -> ExceptionLease | None:
        return self.repo.get_lease(lease_id)

    def revoke_lease(self, lease_id: str) -> None:
        self.repo.mark_lease_state(lease_id, "revoked")

    def _matching_leases(self, tenant_id: str, resource_id: str, operation: str):
        """返回范围精确匹配的租约（含已耗尽/到期），活动租约排在前面。

        try_consume_lease 只认 active 租约，但耗尽/到期的租约仍需保留在
        列表里，以便拒绝时返回稳定原因码。
        """
        leases = self.repo.list_leases(tenant_id)
        matches = [
            lease for lease in leases
            if lease.state != "revoked"
            and resource_id in lease.resource_ids and operation in lease.operations
        ]
        return sorted(matches, key=lambda item: (item.state != "active", item.expires_at))

    # ------------------------------------------------------------------
    # 访问判定
    # ------------------------------------------------------------------
    def evaluate(self, request: AccessRequest) -> Decision:
        # 幂等：同一 request_id 直接返回既有决定
        if request.request_id:
            existing = self.repo.find_decision_by_request(request.request_id)
            if existing is not None:
                return existing

        now_iso = self._now_iso()
        # 到期即回收
        expired_ids = self.repo.expire_due_leases(now_iso)
        for lease_id in expired_ids:
            lease = self.repo.get_lease(lease_id)
            if lease is not None:
                self.repo.append_event(
                    f"evt-{uuid.uuid4().hex[:12]}", "lease.expired",
                    lease_id, lease.tenant_id,
                    {"expires_at": lease.expires_at, "used": lease.used,
                     "quota": lease.quota},
                    now_iso,
                )

        resolver = self._build_resolver(request.tenant_id)
        resolution = resolver.resolve(request.requested_path, request.archive_member)

        decision_id = f"dec-{uuid.uuid4().hex[:16]}"
        if resolution.denied:
            decision = self._build_decision(
                decision_id, request, resolution,
                outcome="deny",
                reason_code=resolution.deny_reason or DenyReason.INVALID_PATH,
                reason_message=resolution.deny_detail
                or MESSAGES.get(resolution.deny_reason or "", "路径解析失败"),
                rule_id=None, lease_id=None, policy_version=None,
                rule_trace=(),
            )
            return self._commit_decision(decision, request, None)

        resource = resolution.resource
        assert resource is not None

        version = request.policy_version or self.repo.active_version(request.tenant_id)
        policy = self.repo.get_policy(request.tenant_id, version) if version else None
        if policy is None:
            decision = self._build_decision(
                decision_id, request, resolution,
                outcome="deny",
                reason_code=DenyReason.POLICY_VERSION_MISSING,
                reason_message=MESSAGES[DenyReason.POLICY_VERSION_MISSING]
                + f"（请求版本：{request.policy_version or '当前版本'}）",
                rule_id=None, lease_id=None, policy_version=version,
                rule_trace=(),
            )
            return self._commit_decision(decision, request, resource)

        engine = PolicyEngine(policy.rules)
        evaluation = engine.evaluate(request, resource)
        trace = tuple(
            {"rule_id": detail.rule_id, "effect": detail.effect,
             "matched": detail.matched, "reasons": list(detail.reasons)}
            for detail in evaluation.details
        )

        if evaluation.effect == "allow":
            decision = self._build_decision(
                decision_id, request, resolution,
                outcome="allow",
                reason_code=AllowReason.BY_POLICY,
                reason_message=MESSAGES[AllowReason.BY_POLICY],
                rule_id=evaluation.rule.rule_id if evaluation.rule else None,
                lease_id=None, policy_version=version, rule_trace=trace,
            )
            return self._commit_decision(decision, request, resource)

        # 策略拒绝：例外租约只能按精确资源+操作覆盖，且必须抢到一次额度
        leases = self._matching_leases(request.tenant_id, resource.resource_id, request.operation)
        for lease in leases:
            if not self.repo.try_consume_lease(lease.lease_id, now_iso):
                continue
            fresh = self.repo.get_lease(lease.lease_id)
            decision = self._build_decision(
                decision_id, request, resolution,
                outcome="allow",
                reason_code=AllowReason.BY_EXCEPTION_LEASE,
                reason_message=f"命中拒绝规则但由租约 {lease.lease_id} 放行"
                f"（剩余 {fresh.remaining if fresh else lease.remaining} 次）",
                rule_id=evaluation.rule.rule_id if evaluation.rule else None,
                lease_id=lease.lease_id, policy_version=version, rule_trace=trace,
            )
            committed = self._commit_decision(
                decision, request, resource, consumed_lease_id=lease.lease_id
            )
            if committed is decision:
                self.repo.record_consumption(lease.lease_id, decision_id, now_iso)
                self.repo.append_event(
                    f"evt-{uuid.uuid4().hex[:12]}", "lease.consumed",
                    lease.lease_id, request.tenant_id,
                    {"decision_id": decision_id, "resource_id": resource.resource_id,
                     "operation": request.operation},
                    now_iso,
                )
            return committed

        # 没有可用租约：若存在范围匹配但已耗尽/到期的租约，给出稳定原因
        reason = DenyReason.BY_POLICY
        message = MESSAGES[DenyReason.BY_POLICY]
        fresh = [self.repo.get_lease(item.lease_id) for item in leases]
        fresh = [item for item in fresh if item is not None]
        exhausted = next((item for item in fresh if item.state == "exhausted"), None)
        expired = next((item for item in fresh if item.state == "expired"), None)
        if exhausted is not None:
            reason = DenyReason.LEASE_EXHAUSTED
            message = f"匹配租约 {exhausted.lease_id} 额度已耗尽（{exhausted.used}/{exhausted.quota}）"
        elif expired is not None:
            reason = DenyReason.LEASE_EXPIRED
            message = f"匹配租约 {expired.lease_id} 已到期"
        decision = self._build_decision(
            decision_id, request, resolution,
            outcome="deny", reason_code=reason, reason_message=message,
            rule_id=evaluation.rule.rule_id if evaluation.rule else None,
            lease_id=None, policy_version=version, rule_trace=trace,
        )
        return self._commit_decision(decision, request, resource)

    def _build_decision(
        self, decision_id: str, request: AccessRequest, resolution,
        outcome: str, reason_code: str, reason_message: str,
        rule_id: str | None, lease_id: str | None,
        policy_version: str | None, rule_trace: tuple[dict, ...],
    ) -> Decision:
        return Decision(
            decision_id=decision_id,
            tenant_id=request.tenant_id,
            request_id=request.request_id,
            requested_path=request.requested_path,
            canonical_path=resolution.canonical_path,
            resource_id=resolution.resource.resource_id if resolution.resource else None,
            operation=request.operation,
            caller_id=request.caller_id,
            outcome=outcome,
            reason_code=reason_code,
            reason_message=reason_message,
            policy_version=policy_version,
            rule_id=rule_id,
            lease_id=lease_id,
            resolution_chain=tuple(resolution.chain()),
            rule_trace=rule_trace,
            evaluated_at=self._now_iso(),
        )

    def _commit_decision(
        self, decision: Decision, request: AccessRequest, resource,
        consumed_lease_id: str | None = None,
    ) -> Decision:
        """落库决定；若撞上并发的同 request_id 决定，归还预扣租约并返回既有决定。"""
        request_payload = {
            "tenant_id": request.tenant_id,
            "requested_path": request.requested_path,
            "operation": request.operation,
            "caller_id": request.caller_id,
            "capabilities": sorted(request.capabilities),
            "archive_member": request.archive_member,
            "policy_version": request.policy_version,
        }
        resource_payload = resource.to_row() if resource is not None else None
        if resource is not None:
            resource_payload["labels"] = sorted(resource.labels)
        try:
            self.repo.insert_decision(
                decision, json.dumps(request_payload, ensure_ascii=False),
                json.dumps(resource_payload, ensure_ascii=False) if resource_payload else None,
            )
        except sqlite3.IntegrityError:
            if consumed_lease_id is not None:
                self.repo.refund_lease(consumed_lease_id)
            existing = self.repo.find_decision_by_request(request.request_id) if request.request_id else None
            if existing is not None:
                return existing
            raise
        self.repo.append_event(
            f"evt-{uuid.uuid4().hex[:12]}", "access.evaluated",
            decision.decision_id, decision.tenant_id,
            {"decision_id": decision.decision_id, "outcome": decision.outcome,
             "reason_code": decision.reason_code},
            decision.evaluated_at,
        )
        return decision

    def get_decision(self, decision_id: str) -> Decision | None:
        return self.repo.get_decision(decision_id)

    # ------------------------------------------------------------------
    # 策略回放：同一事实在旧版本与目标版本下重跑引擎，只产出差异报告
    # ------------------------------------------------------------------
    def start_replay(self, tenant_id: str, target_version: str) -> ReplayJob:
        target = self.repo.get_policy(tenant_id, target_version)
        if target is None:
            raise ValueError(f"目标策略版本不存在：{target_version}")
        job = ReplayJob(
            job_id=f"replay-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            target_version=target_version,
            state="running",
            cursor="",
            started_at=self._now_iso(),
            finished_at=None,
            scanned=0,
            changed=0,
        )
        self.repo.insert_replay_job(job)
        self.repo.append_event(
            f"evt-{uuid.uuid4().hex[:12]}", "replay.started",
            job.job_id, tenant_id, {"target_version": target_version}, job.started_at,
        )
        return job

    def run_replay(self, job_id: str, batch_size: int = 200) -> ReplayJob:
        """推进回放作业，可重复调用直到 state=finished；进度落盘可跨重启恢复。"""
        while True:
            job = self.repo.get_replay_job(job_id)
            if job is None:
                raise ValueError(f"回放作业不存在：{job_id}")
            if job.state != "running":
                return job

            after_iso, after_id = self._split_cursor(job.cursor)
            rows = self.repo.iter_decisions(job.tenant_id, after_iso, after_id, batch_size)
            if not rows:
                finished = replace(job, state="finished", finished_at=self._now_iso())
                self.repo.save_replay_progress(
                    job_id, job.cursor, job.scanned, job.changed,
                    "finished", finished.finished_at,
                )
                self.repo.append_event(
                    f"evt-{uuid.uuid4().hex[:12]}", "replay.finished",
                    job_id, job.tenant_id,
                    {"scanned": job.scanned, "changed": job.changed},
                    finished.finished_at,
                )
                return finished

            target_policy = self.repo.get_policy(job.tenant_id, job.target_version)
            assert target_policy is not None
            target_engine = PolicyEngine(target_policy.rules)

            scanned = job.scanned
            changed = job.changed
            cursor = job.cursor
            for row in rows:
                cursor = f"{row['evaluated_at']}\x1f{row['decision_id']}"
                scanned += 1
                if row["resource_json"] is None:
                    # 解析期拒绝与策略内容无关，换版不会改变这类决定
                    continue
                facts = json.loads(row["resource_json"])
                resource = Resource(
                    resource_id=facts["resource_id"],
                    tenant_id=facts["tenant_id"],
                    source=facts["source"],
                    owner_id=facts["owner_id"],
                    labels=frozenset(facts.get("labels") or []),
                )
                request_facts = json.loads(row["request_json"])
                request = AccessRequest(
                    tenant_id=row["tenant_id"],
                    requested_path=row["requested_path"],
                    operation=row["operation"],
                    caller_id=row["caller_id"],
                    capabilities=frozenset(request_facts.get("capabilities") or []),
                    archive_member=bool(request_facts.get("archive_member")),
                    policy_version=job.target_version,
                )
                # 旧侧：当时落库的真实决定（可能包含租约改写）；
                # 新侧：同一事实在目标策略版本下的引擎结论（不重新消耗租约）。
                old_outcome = row["outcome"]
                old_rule_id = row["rule_id"]
                new_eval = target_engine.evaluate(request, resource)
                new_outcome = new_eval.effect
                new_rule_id = new_eval.rule.rule_id if new_eval.rule else None
                if old_outcome != new_outcome or old_rule_id != new_rule_id:
                    diff = ReplayDiff(
                        job_id=job_id,
                        decision_id=row["decision_id"],
                        evaluated_at=row["evaluated_at"],
                        requested_path=row["requested_path"],
                        operation=row["operation"],
                        old_outcome=old_outcome,
                        new_outcome=new_outcome,
                        old_rule_id=old_rule_id,
                        new_rule_id=new_rule_id,
                        old_reason=row["reason_code"],
                        new_reason=new_rule_id or DenyReason.NO_MATCHING_RULE,
                    )
                    self.repo.insert_replay_diff(diff)
                    changed += 1

            self.repo.save_replay_progress(job_id, cursor, scanned, changed, "running")

    @staticmethod
    def _split_cursor(cursor: str) -> tuple[str, str]:
        if not cursor:
            return "", ""
        iso, _, decision_id = cursor.partition("\x1f")
        return iso, decision_id

    def get_replay_job(self, job_id: str) -> ReplayJob | None:
        return self.repo.get_replay_job(job_id)

    def replay_diffs(self, job_id: str) -> list[dict]:
        return self.repo.list_replay_diffs(job_id)
