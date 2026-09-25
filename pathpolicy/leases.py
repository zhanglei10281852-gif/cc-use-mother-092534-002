"""例外租约：短期放行的签发、匹配与回收。

- 只能由服务配置的指定审批人签发；
- 资源集合为精确规范化路径，不做前缀匹配；
- 额度用完或到期即回收（状态派生，匹配条件自然失效）；
- 消耗走条件更新，配合服务层锁，并发请求不能穿透次数限制。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from . import errors
from .models import LEASE_ACTIVE, Lease
from .store import Store


class LeaseError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class LeaseManager:
    def __init__(self, store: Store, approvers: frozenset[str], clock):
        self._store = store
        self._approvers = approvers
        self._clock = clock

    def ensure_approver(self, approved_by: str) -> None:
        if approved_by not in self._approvers:
            raise LeaseError(errors.APPROVER_NOT_ALLOWED, f"签发人 {approved_by} 不在指定审批人名单")

    def grant(
        self,
        tenant_id: str,
        approved_by: str,
        resources: tuple[str, ...],
        operations: tuple[str, ...],
        max_uses: int,
        ttl_seconds: int,
    ) -> Lease:
        self.ensure_approver(approved_by)
        if not resources:
            raise LeaseError(errors.INVALID_REQUEST, "资源集合不能为空")
        if not operations:
            raise LeaseError(errors.INVALID_REQUEST, "操作列表不能为空")
        if max_uses < 1:
            raise LeaseError(errors.INVALID_REQUEST, "额度必须为正整数")
        if ttl_seconds < 1:
            raise LeaseError(errors.INVALID_REQUEST, "有效期必须为正数秒")
        now = self._clock()
        lease = Lease(
            lease_id=f"ls-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            approved_by=approved_by,
            resources=resources,
            operations=operations,
            max_uses=max_uses,
            used_count=0,
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
            created_at=now.isoformat(),
        )
        self._store.save_lease(lease)
        return lease

    def find_active(self, tenant_id: str, canonical_path: str, operation: str) -> Lease | None:
        """找出一个精确覆盖 (路径, 操作) 的有效租约；临近到期者优先消耗。"""
        now = self._clock()
        candidates = [
            lease
            for lease in self._store.leases_for_tenant(tenant_id)
            if lease.status(now) == LEASE_ACTIVE and lease.covers(canonical_path, operation)
        ]
        candidates.sort(key=lambda lease: lease.expires_at)
        return candidates[0] if candidates else None

    def consume(self, lease_id: str) -> bool:
        return self._store.consume_lease(lease_id)

    def get(self, lease_id: str) -> Lease | None:
        return self._store.get_lease(lease_id)

    def revoke(self, lease_id: str) -> Lease:
        if not self._store.revoke_lease(lease_id):
            raise LeaseError(errors.LEASE_NOT_FOUND, f"租约 {lease_id} 不存在")
        return self._store.get_lease(lease_id)
