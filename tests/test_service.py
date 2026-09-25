"""服务级测试：版本化判定、例外租约、并发配额、重启持久化与策略回放。"""
from __future__ import annotations

import threading
import tempfile
import unittest
from pathlib import Path

from pathpolicy.clock import FakeClock
from pathpolicy.models import AccessRequest, Rule
from pathpolicy.reasons import AllowReason, DenyReason
from pathpolicy.service import PathPolicyService

APPROVER = "reviewer-02"


def build_service(db: str = ":memory:") -> PathPolicyService:
    service = PathPolicyService(db, clock=FakeClock())
    service.register_resource("t1", "/tenants/t1/secret/key.pem",
                              "tenant_file", "owner-a", frozenset({"secret"}))
    service.register_resource("t1", "/tenants/t1/run/log.txt",
                              "runtime_record", "owner-b")
    service.register_resource("t1", "/tenants/t1/template/base.img",
                              "system_template", "owner-c")
    service.publish_policy("t1", "v1", [
        Rule("allow-template", "allow", sources=frozenset({"system_template"})),
        Rule("deny-secret-read", "deny",
             operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
        Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
    ], published_by="reviewer-02")
    return service


def read_secret(request_id: str | None = None, caps=frozenset()) -> AccessRequest:
    return AccessRequest(
        tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
        operation="read", caller_id="svc-1", capabilities=caps,
        request_id=request_id,
    )


class DecisionTest(unittest.TestCase):
    def test_policy_allow_and_deny(self) -> None:
        service = build_service()
        denied = service.evaluate(read_secret())
        self.assertEqual(denied.outcome, "deny")
        self.assertEqual(denied.reason_code, DenyReason.BY_POLICY)
        self.assertEqual(denied.rule_id, "deny-secret-read")

        allowed = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/run/log.txt",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(allowed.outcome, "allow")
        self.assertEqual(allowed.rule_id, "allow-runtime")

    def test_decision_carries_chain_and_trace(self) -> None:
        service = build_service()
        decision = service.evaluate(read_secret())
        kinds = [step["kind"] for step in decision.resolution_chain]
        self.assertIn("normalize", kinds)
        self.assertIn("lookup", kinds)
        matched_rules = {item["rule_id"]: item["matched"] for item in decision.rule_trace}
        self.assertEqual(matched_rules["deny-secret-read"], True)

    def test_missing_policy_version_denies(self) -> None:
        service = build_service()
        decision = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/run/log.txt",
            operation="read", caller_id="svc-1", policy_version="v999",
        ))
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason_code, DenyReason.POLICY_VERSION_MISSING)

    def test_tenant_without_policy_denies(self) -> None:
        service = build_service()
        service.register_resource("t2", "data.txt", "tenant_file", "o")
        decision = service.evaluate(AccessRequest(
            tenant_id="t2", requested_path="/tenants/t2/data.txt",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.reason_code, DenyReason.POLICY_VERSION_MISSING)

    def test_resolution_failure_short_circuits(self) -> None:
        service = build_service()
        service.register_symlink("t1", "/tenants/t1/lp", "/tenants/t1/lp2")
        service.register_symlink("t1", "/tenants/t1/lp2", "/tenants/t1/lp")
        decision = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/lp",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.reason_code, DenyReason.LINK_CYCLE)
        self.assertIsNone(decision.policy_version)


class IdempotencyTest(unittest.TestCase):
    def test_same_request_id_returns_same_decision(self) -> None:
        service = build_service()
        first = service.evaluate(read_secret(request_id="req-1"))
        second = service.evaluate(read_secret(request_id="req-1"))
        self.assertEqual(first.decision_id, second.decision_id)


class LeaseTest(unittest.TestCase):
    def test_only_designated_approver_can_grant(self) -> None:
        service = build_service()
        with self.assertRaises(PermissionError):
            service.grant_lease(
                "lease-x", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
                frozenset({"read"}), quota=1, granted_by="operator-01", ttl_seconds=60,
            )

    def test_lease_requires_exact_registered_resource(self) -> None:
        service = build_service()
        with self.assertRaises(ValueError):
            service.grant_lease(
                "lease-x", "t1", frozenset({"/tenants/t1/secret/*"}),
                frozenset({"read"}), quota=1, granted_by=APPROVER, ttl_seconds=60,
            )

    def test_lease_allows_then_exhausts(self) -> None:
        service = build_service()
        service.grant_lease(
            "lease-1", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=2, granted_by=APPROVER, ttl_seconds=3600,
        )
        first = service.evaluate(read_secret())
        self.assertEqual(first.outcome, "allow")
        self.assertEqual(first.reason_code, AllowReason.BY_EXCEPTION_LEASE)
        self.assertEqual(first.lease_id, "lease-1")

        second = service.evaluate(read_secret())
        self.assertEqual(second.outcome, "allow")
        self.assertEqual(second.lease_id, "lease-1")

        third = service.evaluate(read_secret())
        self.assertEqual(third.outcome, "deny")
        self.assertEqual(third.reason_code, DenyReason.LEASE_EXHAUSTED)

        lease = service.get_lease("lease-1")
        self.assertEqual(lease.used, 2)
        self.assertEqual(lease.state, "exhausted")

    def test_lease_does_not_cover_other_resource_or_operation(self) -> None:
        service = build_service()
        service.register_resource("t1", "/tenants/t1/secret/other.pem",
                                  "tenant_file", "owner-a", frozenset({"secret"}))
        service.grant_lease(
            "lease-1", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=5, granted_by=APPROVER, ttl_seconds=3600,
        )
        decision = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/secret/other.pem",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason_code, DenyReason.BY_POLICY)

    def test_expired_lease_is_reclaimed(self) -> None:
        service = build_service()
        service.grant_lease(
            "lease-1", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=5, granted_by=APPROVER, ttl_seconds=60,
        )
        service.clock.advance(61)
        decision = service.evaluate(read_secret())
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason_code, DenyReason.LEASE_EXPIRED)
        self.assertEqual(service.get_lease("lease-1").state, "expired")

    def test_concurrent_requests_cannot_pierce_quota(self) -> None:
        service = build_service()
        service.grant_lease(
            "lease-1", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=20, granted_by=APPROVER, ttl_seconds=3600,
        )
        outcomes: list[str] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            for _ in range(5):
                decision = service.evaluate(read_secret())
                outcomes.append(decision.outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(outcomes), 40)
        self.assertEqual(outcomes.count("allow"), 20)
        self.assertEqual(outcomes.count("deny"), 20)
        self.assertEqual(service.get_lease("lease-1").used, 20)


class PersistenceTest(unittest.TestCase):
    def test_lease_consumption_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "policy.db")
            service = build_service(db_path)
            service.grant_lease(
                "lease-1", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
                frozenset({"read"}), quota=3, granted_by=APPROVER, ttl_seconds=3600,
            )
            decisions = [service.evaluate(read_secret()) for _ in range(2)]
            decision_id = decisions[1].decision_id
            service.close()

            restarted = PathPolicyService(db_path, clock=FakeClock())
            lease = restarted.get_lease("lease-1")
            self.assertEqual(lease.used, 2)
            self.assertEqual(lease.state, "active")
            stored = restarted.get_decision(decision_id)
            self.assertIsNotNone(stored)
            self.assertEqual(stored.requested_path, "/tenants/t1/secret/key.pem")
            # 只剩一次额度
            self.assertEqual(restarted.evaluate(read_secret()).outcome, "allow")
            self.assertEqual(restarted.evaluate(read_secret()).reason_code,
                             DenyReason.LEASE_EXHAUSTED)
            restarted.close()


class ReplayTest(unittest.TestCase):
    def _history_under_v1(self, service: PathPolicyService) -> tuple[str, str, str]:
        # 三条历史：模板放行、密钥读取拒绝（一条租约放行）、运行记录放行
        template = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/template/base.img",
            operation="read", caller_id="svc-1",
        ))
        denied = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
            operation="read", caller_id="svc-1",
        ))
        service.grant_lease(
            "lease-r", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=1, granted_by=APPROVER, ttl_seconds=3600,
        )
        leased = service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
            operation="read", caller_id="svc-1",
        ))
        self.assertEqual(template.outcome, "allow")
        self.assertEqual(denied.outcome, "deny")
        self.assertEqual(leased.outcome, "allow")
        return template.decision_id, denied.decision_id, leased.decision_id

    def test_replay_reports_flips_without_rewriting_audit(self) -> None:
        service = build_service()
        template_id, denied_id, leased_id = self._history_under_v1(service)

        # v2：模板改为拒绝；带 secret 标签的读取改为允许
        service.publish_policy("t1", "v2", [
            Rule("deny-template", "deny", sources=frozenset({"system_template"})),
            Rule("allow-secret-read", "allow",
                 operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
            Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
        ], published_by=APPROVER)

        job = service.start_replay("t1", "v2")
        finished = service.run_replay(job.job_id, batch_size=1)
        self.assertEqual(finished.state, "finished")
        self.assertEqual(finished.scanned, 3)
        self.assertEqual(finished.changed, 3)

        diffs = {item["decision_id"]: item for item in service.replay_diffs(job.job_id)}
        self.assertEqual(diffs[template_id]["old_outcome"], "allow")
        self.assertEqual(diffs[template_id]["new_outcome"], "deny")
        self.assertEqual(diffs[denied_id]["new_rule_id"], "allow-secret-read")
        self.assertEqual(diffs[leased_id]["old_outcome"], "allow")
        self.assertEqual(diffs[leased_id]["new_outcome"], "allow")
        # 规则也发生了变化（租约放行 -> 策略放行），应被报告
        self.assertEqual(diffs[leased_id]["new_rule_id"], "allow-secret-read")

        # 原审计一行未改
        self.assertEqual(service.get_decision(template_id).outcome, "allow")
        self.assertEqual(service.get_decision(denied_id).outcome, "deny")
        self.assertEqual(service.get_decision(leased_id).lease_id, "lease-r")

    def test_replay_cursor_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "policy.db")
            service = build_service(db_path)
            self._history_under_v1(service)
            service.publish_policy("t1", "v2", [
                Rule("deny-template", "deny", sources=frozenset({"system_template"})),
                Rule("allow-secret-read", "allow",
                     operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
                Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
            ], published_by=APPROVER)
            job = service.start_replay("t1", "v2")
            service.run_replay(job.job_id, batch_size=2)  # 只跑 2/3
            service.close()

            restarted = PathPolicyService(db_path, clock=FakeClock())
            resumed = restarted.run_replay(job.job_id, batch_size=2)
            self.assertEqual(resumed.state, "finished")
            self.assertEqual(resumed.scanned, 3)
            self.assertEqual(resumed.changed, 3)
            diffs = restarted.replay_diffs(job.job_id)
            self.assertEqual(len(diffs), 3)
            restarted.close()

    def test_replay_unknown_version_rejected(self) -> None:
        service = build_service()
        with self.assertRaises(ValueError):
            service.start_replay("t1", "v404")


if __name__ == "__main__":
    unittest.main()
