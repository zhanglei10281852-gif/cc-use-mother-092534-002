"""服务端到端：压缩包成员名、挂载别名与后挂载覆盖。"""
from __future__ import annotations

import unittest

from pathpolicy.models import AccessRequest, Rule
from pathpolicy.reasons import DenyReason
from pathpolicy.service import PathPolicyService


class NamespaceE2ETest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PathPolicyService(":memory:")
        self.service.register_resource(
            "t1", "/tenants/t1/bundle/app.conf", "archive_member", "deploy", frozenset()
        )
        self.service.register_resource(
            "t1", "/tenants/t1/run/audit.log", "runtime_record", "svc", frozenset()
        )
        self.service.publish_policy("t1", "v1", [
            Rule("allow-archive", "allow", sources=frozenset({"archive_member"})),
            Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
            Rule("deny-default", "deny"),
        ], published_by="reviewer-02")

    def tearDown(self) -> None:
        self.service.close()

    def test_safe_archive_member_allowed(self) -> None:
        decision = self.service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="bundle/app.conf",
            operation="read", caller_id="svc-1", archive_member=True,
        ))
        self.assertEqual(decision.outcome, "allow")
        self.assertEqual(decision.resource_id, "/tenants/t1/bundle/app.conf")

    def test_traversal_member_denied_before_policy(self) -> None:
        decision = self.service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="bundle/../../etc/passwd",
            operation="read", caller_id="svc-1", archive_member=True,
        ))
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason_code, DenyReason.UNSAFE_ARCHIVE_MEMBER)

    def test_mount_alias_allowed(self) -> None:
        self.service.add_mount("t1", "/mnt/audit", "/tenants/t1/run")
        decision = self.service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/mnt/audit/audit.log",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.outcome, "allow")
        self.assertEqual(decision.resource_id, "/tenants/t1/run/audit.log")

    def test_later_parent_mount_shadows_earlier_child(self) -> None:
        self.service.add_mount("t1", "/mnt/data", "/tenants/t1/run")
        self.service.add_mount("t1", "/mnt", "/tenants/t1")
        decision = self.service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/mnt/data/audit.log",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason_code, DenyReason.MOUNT_SHADOWED)

    def test_remount_same_alias_is_ambiguous(self) -> None:
        self.service.add_mount("t1", "/mnt/logs", "/tenants/t1/run")
        self.service.add_mount("t1", "/mnt/logs", "/tenants/t1/other")
        decision = self.service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/mnt/logs/audit.log",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.reason_code, DenyReason.MOUNT_SHADOWED)


if __name__ == "__main__":
    unittest.main()
