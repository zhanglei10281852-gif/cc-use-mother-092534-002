"""判定服务端到端测试：判定、决策查询、例外租约、并发与重启恢复。"""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from pathpolicy import errors
from pathpolicy.models import ALLOW, DENY
from pathpolicy.service import DecisionService, ServiceError

from fixtures import APPROVER, NAMESPACE_VIEW, POLICY_V1, TENANT

T0 = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start: datetime = T0):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "svc.db")
        self.clock = FakeClock()
        self.service = self.make_service()
        self.service.put_namespace(NAMESPACE_VIEW)
        self.service.publish_policy(TENANT, "v1", POLICY_V1, APPROVER)

    def make_service(self, **kwargs) -> DecisionService:
        kwargs.setdefault("clock", self.clock)
        return DecisionService(self.db, approvers={APPROVER}, **kwargs)

    def tearDown(self) -> None:
        self.service.close()
        self.tmp.cleanup()

    def evaluate(self, path: str, operation: str = "read", **kwargs):
        kwargs.setdefault("caller_id", "svc-backup")
        return self.service.evaluate(TENANT, path, operation, **kwargs)


class EvaluateTest(ServiceTestBase):
    def test_allow_records_matched_rule_and_chain(self) -> None:
        decision = self.evaluate("/templates/base.conf")
        self.assertEqual(decision.outcome, ALLOW)
        self.assertEqual(decision.matched_rule, "r-template-read")
        self.assertEqual(decision.policy_version, "v1")
        self.assertGreater(len(decision.chain), 0)

    def test_symlink_and_alias_forms_share_policy_outcome(self) -> None:
        """同一文档经不同路径形态访问，规范化后命中同一条规则。"""
        for path in ("/docs/report.txt", "/link-to-report", "/abs-link"):
            decision = self.evaluate(path)
            self.assertEqual(decision.outcome, ALLOW, path)
            self.assertEqual(decision.matched_rule, "r-docs-read")
            self.assertEqual(decision.context.canonical_path, "/docs/report.txt")

    def test_deny_by_explicit_rule(self) -> None:
        decision = self.evaluate("/docs/secret.txt")
        self.assertEqual((decision.outcome, decision.reason, decision.matched_rule),
                         (DENY, errors.RULE_DENIED, "r-pii-deny"))

    def test_deny_when_no_rule_matches(self) -> None:
        decision = self.evaluate("/docs/report.txt", "write")
        self.assertEqual((decision.outcome, decision.reason, decision.matched_rule),
                         (DENY, errors.NO_MATCHING_RULE, None))

    def test_missing_policy_version_rejected_with_stable_reason(self) -> None:
        decision = self.evaluate("/docs/report.txt", policy_version="v-does-not-exist")
        self.assertEqual((decision.outcome, decision.reason), (DENY, errors.POLICY_VERSION_MISSING))

    def test_resolution_failure_is_audited(self) -> None:
        decision = self.evaluate("/loop-a")
        self.assertEqual((decision.outcome, decision.reason), (DENY, errors.LINK_LOOP))
        stored = self.service.get_decision(decision.decision_id)
        self.assertEqual(stored.reason, errors.LINK_LOOP)
        self.assertGreater(len(stored.chain), 0)

    def test_get_decision_returns_chain_and_matched_rule(self) -> None:
        decision = self.evaluate("/abs-link")
        fetched = self.service.get_decision(decision.decision_id)
        steps = [entry["step"] for entry in fetched.chain]
        self.assertIn("symlink", steps)
        self.assertEqual(fetched.matched_rule, "r-docs-read")

    def test_duplicate_policy_version_rejected(self) -> None:
        with self.assertRaises(ServiceError) as ctx:
            self.service.publish_policy(TENANT, "v1", POLICY_V1, APPROVER)
        self.assertEqual(ctx.exception.http_status, 409)


class LeaseTest(ServiceTestBase):
    def grant(self, paths, operations=("read",), max_uses=2, ttl=3600, approved_by=APPROVER):
        return self.service.grant_lease(TENANT, approved_by, paths, list(operations), max_uses, ttl)

    def test_non_approver_cannot_grant(self) -> None:
        with self.assertRaises(ServiceError) as ctx:
            self.grant(["/docs/secret.txt"], approved_by="random-user")
        self.assertEqual(ctx.exception.code, errors.APPROVER_NOT_ALLOWED)

    def test_lease_allows_denied_resource_within_quota(self) -> None:
        lease = self.grant(["/docs/secret.txt"], max_uses=2)
        for _ in range(2):
            decision = self.evaluate("/docs/secret.txt")
            self.assertEqual(decision.outcome, ALLOW)
            self.assertEqual(decision.lease_id, lease.lease_id)
            self.assertEqual(decision.matched_rule, "r-pii-deny")  # 记录被拒绝的规则，经例外放行
        # 额度用完即回收
        self.assertEqual(self.service.get_lease(lease.lease_id).status(self.clock()), "exhausted")
        decision = self.evaluate("/docs/secret.txt")
        self.assertEqual((decision.outcome, decision.lease_id), (DENY, None))

    def test_lease_matches_exact_resource_and_operation_only(self) -> None:
        self.grant(["/docs/secret.txt"], operations=("read",), max_uses=5)
        # 同资源不同操作不放行
        self.assertEqual(self.evaluate("/docs/secret.txt", "write").outcome, DENY)
        # 不同资源（即便同目录）不放行
        self.assertEqual(self.evaluate("/docs/../docs/secret.txt", "write").outcome, DENY)

    def test_lease_expires_and_is_reclaimed(self) -> None:
        lease = self.grant(["/docs/secret.txt"], max_uses=5, ttl=60)
        self.clock.advance(seconds=61)
        self.assertEqual(self.service.get_lease(lease.lease_id).status(self.clock()), "expired")
        self.assertEqual(self.evaluate("/docs/secret.txt").outcome, DENY)

    def test_lease_paths_are_normalized_at_grant_time(self) -> None:
        """签发时给定任意访问形态，租约保存的是规范化路径。"""
        lease = self.grant(["/link-to-report"], operations=("read",), max_uses=1)
        self.assertEqual(lease.resources, ("/docs/report.txt",))

    def test_concurrent_requests_cannot_exceed_quota(self) -> None:
        self.grant(["/docs/secret.txt"], max_uses=3)
        outcomes = []
        lock = threading.Lock()

        def worker():
            decision = self.evaluate("/docs/secret.txt")
            with lock:
                outcomes.append(decision.outcome)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count(ALLOW), 3)
        self.assertEqual(outcomes.count(DENY), 9)

    def test_lease_consumption_survives_restart(self) -> None:
        lease = self.grant(["/docs/secret.txt"], max_uses=2)
        self.assertEqual(self.evaluate("/docs/secret.txt").outcome, ALLOW)
        self.service.close()
        # 模拟重启：同一数据库新建服务实例
        self.service = self.make_service()
        restored = self.service.get_lease(lease.lease_id)
        self.assertEqual(restored.used_count, 1)
        self.assertEqual(self.evaluate("/docs/secret.txt").outcome, ALLOW)
        self.assertEqual(self.evaluate("/docs/secret.txt").outcome, DENY)

    def test_revoke_reclaims_immediately(self) -> None:
        lease = self.grant(["/docs/secret.txt"], max_uses=5)
        self.service.revoke_lease(lease.lease_id)
        self.assertEqual(self.service.get_lease(lease.lease_id).status(self.clock()), "revoked")
        self.assertEqual(self.evaluate("/docs/secret.txt").outcome, DENY)


if __name__ == "__main__":
    unittest.main()
