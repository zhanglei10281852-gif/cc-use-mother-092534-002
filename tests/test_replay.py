"""离线回放测试：差异报告、不改写审计、游标断点续跑、不消耗租约。"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from pathpolicy import errors
from pathpolicy.models import ALLOW, DENY
from pathpolicy.service import DecisionService, ServiceError

from fixtures import APPROVER, NAMESPACE_VIEW, POLICY_V1, POLICY_V2, TENANT


class Crash(Exception):
    pass


class ReplayTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "svc.db")
        self.service = self.make_service()
        self.service.put_namespace(NAMESPACE_VIEW)
        self.service.publish_policy(TENANT, "v1", POLICY_V1, APPROVER)

    def make_service(self, **kwargs) -> DecisionService:
        return DecisionService(self.db, approvers={APPROVER}, **kwargs)

    def tearDown(self) -> None:
        self.service.close()
        self.tmp.cleanup()

    def record_three_decisions(self) -> None:
        self.service.evaluate(TENANT, "/docs/report.txt", "read", "svc-backup")    # allow r-docs-read
        self.service.evaluate(TENANT, "/templates/base.conf", "read", "svc-backup")  # allow r-template-read
        self.service.evaluate(TENANT, "/docs/secret.txt", "read", "svc-backup")    # deny r-pii-deny


class ReplayTest(ReplayTestBase):
    def test_replay_lists_changed_decisions_without_rewriting_audit(self) -> None:
        self.record_three_decisions()
        self.service.publish_policy(TENANT, "v2", POLICY_V2, APPROVER)
        job = self.service.start_replay(TENANT, "v2")

        self.assertEqual(job.status, "finished")
        self.assertEqual(job.scanned, 3)
        by_decision = {d["decision_id"]: d for d in job.diffs}
        self.assertEqual(len(by_decision), 2)

        # 报告：v1 放行 -> v2 封锁；模板访问不受影响；secret 命中规则变化
        report_diff = next(d for d in job.diffs if d["canonical_path"] == "/docs/report.txt")
        self.assertEqual(report_diff["old"], {"outcome": ALLOW, "rule": "r-docs-read", "reason": None})
        self.assertEqual(report_diff["new"]["outcome"], DENY)
        self.assertEqual(report_diff["new"]["rule"], "r-docs-lockdown")

        secret_diff = next(d for d in job.diffs if d["canonical_path"] == "/docs/secret.txt")
        self.assertEqual(secret_diff["old"]["rule"], "r-pii-deny")
        self.assertEqual(secret_diff["new"]["rule"], "r-docs-lockdown")  # 封锁规则优先级更高

        # 原审计记录不被改写
        for decision_id in by_decision:
            stored = self.service.get_decision(decision_id)
            self.assertEqual(stored.policy_version, "v1")

    def test_replay_cursor_survives_restart_and_resumes(self) -> None:
        self.record_three_decisions()
        self.service.publish_policy(TENANT, "v2", POLICY_V2, APPROVER)
        self.service.close()

        calls = {"n": 0}

        def crash_on_second_batch() -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise Crash()

        fragile = self.make_service(replay_batch_size=1, replay_after_batch=crash_on_second_batch)
        with self.assertRaises(Crash):
            fragile.start_replay(TENANT, "v2")
        job_id = sqlite3.connect(self.db).execute("SELECT job_id FROM replay_jobs").fetchone()[0]
        interrupted = fragile.get_replay(job_id)
        self.assertEqual(interrupted.status, "replaying")
        self.assertEqual(interrupted.cursor_seq, 2)  # 两批已提交，游标不丢
        fragile.close()

        # 模拟重启后续跑：从游标继续，不重复扫描、不重复记录差异
        recovered = self.make_service()
        job = recovered.resume_replay(job_id)
        self.assertEqual(job.status, "finished")
        self.assertEqual(job.scanned, 3)
        self.assertEqual(len(job.diffs), 2)
        self.assertEqual(len({d["decision_id"] for d in job.diffs}), 2)
        self.service = recovered

    def test_replay_never_consumes_lease(self) -> None:
        lease = self.service.grant_lease(TENANT, APPROVER, ["/docs/secret.txt"], ["read"], 1, 3600)
        decision = self.service.evaluate(TENANT, "/docs/secret.txt", "read", "svc-backup")
        self.assertEqual((decision.outcome, decision.lease_id), (ALLOW, lease.lease_id))

        self.service.publish_policy(TENANT, "v2", POLICY_V1, APPROVER)  # 规则不变，仅验证租约语义
        job = self.service.start_replay(TENANT, "v2")
        # 租约已耗尽：重评估不再放行，差异报告如实标注 lease_still_covers
        self.assertEqual(len(job.diffs), 1)
        self.assertFalse(job.diffs[0]["lease_still_covers"])
        # 回放本身不消耗额度
        self.assertEqual(self.service.get_lease(lease.lease_id).used_count, 1)

    def test_replay_requires_existing_policy_version(self) -> None:
        with self.assertRaises(ServiceError) as ctx:
            self.service.start_replay(TENANT, "v-missing")
        self.assertEqual(ctx.exception.code, errors.POLICY_VERSION_MISSING)


if __name__ == "__main__":
    unittest.main()
