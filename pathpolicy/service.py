"""判定服务门面：组合命名空间解析、策略评估、例外租约与离线回放。

所有判定在单把可重入锁内完成，租约消耗与决策落库构成一个临界区，
保证并发请求不能穿透租约次数限制。
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from . import errors
from .leases import LeaseError, LeaseManager
from .models import (
    ALLOW,
    DENY,
    REPLAY_RUNNING,
    Decision,
    EvaluationContext,
    NamespaceView,
    PolicyVersion,
    ReplayJob,
    Rule,
)
from .namespace import Resolver
from .policy import evaluate_rules
from .replay import Replayer
from .store import Store


class ServiceError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DecisionService:
    def __init__(
        self,
        db_path: str,
        approvers: set[str] | frozenset[str],
        clock=_utc_now,
        replay_batch_size: int = 100,
        replay_after_batch=None,
    ):
        if not approvers:
            raise ValueError("必须配置至少一名指定审批人")
        self._store = Store(db_path)
        self._clock = clock
        self._lock = threading.RLock()
        self._leases = LeaseManager(self._store, frozenset(approvers), clock)
        self._replay_batch_size = replay_batch_size
        self._replay_after_batch = replay_after_batch

    def close(self) -> None:
        self._store.close()

    # ------------------------------------------------------------------
    # 配置：命名空间视图与策略版本
    # ------------------------------------------------------------------

    def put_namespace(self, view_data: dict) -> dict:
        view = NamespaceView.from_dict(view_data)
        with self._lock:
            self._store.save_namespace(view, self._clock().isoformat())
        return {"tenant_id": view.tenant_id, "mounts": len(view.mounts)}

    def publish_policy(self, tenant_id: str, version_id: str, rules: list[dict], published_by: str) -> dict:
        if not version_id:
            raise ServiceError(errors.INVALID_REQUEST, "版本号不能为空")
        if not rules:
            raise ServiceError(errors.INVALID_REQUEST, "规则列表不能为空")
        policy = PolicyVersion(
            tenant_id=tenant_id,
            version_id=version_id,
            rules=[Rule.from_dict(r) for r in rules],
            published_by=published_by,
            published_at=self._clock().isoformat(),
        )
        with self._lock:
            if not self._store.save_policy(policy):
                raise ServiceError(errors.INVALID_REQUEST, f"策略版本 {version_id} 已存在，版本不可覆盖", 409)
        return {"tenant_id": tenant_id, "version_id": version_id, "rules": len(policy.rules)}

    # ------------------------------------------------------------------
    # 访问判定
    # ------------------------------------------------------------------

    def evaluate(
        self,
        tenant_id: str,
        path: str,
        operation: str,
        caller_id: str,
        capabilities: tuple[str, ...] = (),
        policy_version: str | None = None,
    ) -> Decision:
        if not path or not operation or not caller_id:
            raise ServiceError(errors.INVALID_REQUEST, "path、operation、caller_id 均为必填")
        request = {
            "path": path,
            "operation": operation,
            "caller_id": caller_id,
            "capabilities": list(capabilities),
            "policy_version": policy_version,
        }
        with self._lock:
            now = self._clock()
            view = self._store.get_namespace(tenant_id)
            if view is None:
                return self._record(tenant_id, request, None, DENY, errors.NAMESPACE_MISSING, None, None, [], None, now)

            resolution = Resolver(view).resolve(path)
            if not resolution.ok:
                return self._record(
                    tenant_id, request, None, DENY, resolution.reason, None, None, resolution.chain, None, now
                )

            context = EvaluationContext(
                canonical_path=resolution.canonical_path,
                source=resolution.mount.source,
                owner=resolution.node.owner,
                labels=resolution.node.labels,
                operation=operation,
                caller_id=caller_id,
                capabilities=tuple(capabilities),
            )
            policy = (
                self._store.get_policy(tenant_id, policy_version)
                if policy_version
                else self._store.get_latest_policy(tenant_id)
            )
            if policy is None:
                return self._record(
                    tenant_id, request, context, DENY, errors.POLICY_VERSION_MISSING, None, policy_version,
                    resolution.chain, None, now,
                )

            outcome, rule_id, reason = evaluate_rules(policy, context)
            lease_id = None
            if outcome == DENY:
                lease = self._leases.find_active(tenant_id, context.canonical_path, operation)
                if lease is not None and self._leases.consume(lease.lease_id):
                    outcome, reason, lease_id = ALLOW, None, lease.lease_id
            return self._record(
                tenant_id, request, context, outcome, reason, rule_id, policy.version_id,
                resolution.chain, lease_id, now,
            )

    def _record(self, tenant_id, request, context, outcome, reason, rule_id, version, chain, lease_id, now) -> Decision:
        decision = Decision(
            decision_id=f"dec-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            request=request,
            context=context,
            outcome=outcome,
            reason=reason,
            matched_rule=rule_id,
            policy_version=version,
            chain=chain,
            lease_id=lease_id,
            evaluated_at=now.isoformat(),
        )
        return self._store.append_decision(decision)

    def get_decision(self, decision_id: str) -> Decision:
        decision = self._store.get_decision(decision_id)
        if decision is None:
            raise ServiceError(errors.INVALID_REQUEST, f"决策 {decision_id} 不存在", 404)
        return decision

    # ------------------------------------------------------------------
    # 例外租约
    # ------------------------------------------------------------------

    def grant_lease(
        self,
        tenant_id: str,
        approved_by: str,
        paths: list[str],
        operations: list[str],
        max_uses: int,
        ttl_seconds: int,
    ):
        """签发租约。给定路径先解析为规范化路径，保证资源集合精确。"""
        with self._lock:
            try:
                self._leases.ensure_approver(approved_by)
            except LeaseError as exc:
                raise ServiceError(exc.code, str(exc), 403) from exc
            view = self._store.get_namespace(tenant_id)
            if view is None:
                raise ServiceError(errors.NAMESPACE_MISSING, f"租户 {tenant_id} 尚未注册命名空间视图", 409)
            resolver = Resolver(view)
            canonical = []
            for raw in paths:
                resolution = resolver.resolve(raw)
                if not resolution.ok:
                    raise ServiceError(resolution.reason, f"路径 {raw} 无法规范化：{resolution.reason}")
                canonical.append(resolution.canonical_path)
            try:
                return self._leases.grant(
                    tenant_id, approved_by, tuple(canonical), tuple(operations), max_uses, ttl_seconds
                )
            except LeaseError as exc:
                raise ServiceError(exc.code, str(exc), 403) from exc

    def get_lease(self, lease_id: str):
        lease = self._leases.get(lease_id)
        if lease is None:
            raise ServiceError(errors.LEASE_NOT_FOUND, f"租约 {lease_id} 不存在", 404)
        return lease

    def revoke_lease(self, lease_id: str):
        try:
            return self._leases.revoke(lease_id)
        except LeaseError as exc:
            raise ServiceError(exc.code, str(exc), 404) from exc

    # ------------------------------------------------------------------
    # 离线回放
    # ------------------------------------------------------------------

    def start_replay(self, tenant_id: str, policy_version: str) -> ReplayJob:
        with self._lock:
            if self._store.get_policy(tenant_id, policy_version) is None:
                raise ServiceError(errors.POLICY_VERSION_MISSING, f"策略版本 {policy_version} 不存在", 404)
            job = ReplayJob(
                job_id=f"rp-{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                policy_version=policy_version,
                cursor_seq=0,
                status=REPLAY_RUNNING,
                diffs=[],
                scanned=0,
                created_at=self._clock().isoformat(),
            )
            self._store.save_replay_job(job)
        return self._run_replay(job.job_id)

    def resume_replay(self, job_id: str) -> ReplayJob:
        return self._run_replay(job_id)

    def _run_replay(self, job_id: str) -> ReplayJob:
        replayer = Replayer(
            self._store, self._leases, self._clock,
            batch_size=self._replay_batch_size, after_batch=self._replay_after_batch,
        )
        try:
            return replayer.run(job_id)
        except KeyError:
            raise ServiceError(errors.INVALID_REQUEST, f"回放任务 {job_id} 不存在", 404) from None

    def get_replay(self, job_id: str) -> ReplayJob:
        job = self._store.get_replay_job(job_id)
        if job is None:
            raise ServiceError(errors.INVALID_REQUEST, f"回放任务 {job_id} 不存在", 404)
        return job
