"""HTTP 接口冒烟测试：判定、决策查询、租约、回放、错误码。"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from pathpolicy.server import make_server
from pathpolicy.service import DecisionService

from fixtures import APPROVER, NAMESPACE_VIEW, POLICY_V1, POLICY_V2, TENANT


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        service = DecisionService(os.path.join(cls.tmp.name, "svc.db"), approvers={APPROVER})
        cls.server = make_server(service, port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.service = service

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.service.close()
        cls.tmp.cleanup()

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_01_full_flow(self) -> None:
        status, _ = self.call("PUT", f"/v1/tenants/{TENANT}/namespace", NAMESPACE_VIEW)
        self.assertEqual(status, 200)
        status, _ = self.call("POST", f"/v1/tenants/{TENANT}/policies",
                              {"version_id": "v1", "rules": POLICY_V1, "published_by": APPROVER})
        self.assertEqual(status, 200)

        # 判定：符号链接 -> 规范化路径 -> 命中规则
        status, decision = self.call("POST", f"/v1/tenants/{TENANT}/evaluate",
                                     {"path": "/abs-link", "operation": "read", "caller_id": "svc-a"})
        self.assertEqual(status, 200)
        self.assertEqual(decision["outcome"], "allow")
        self.assertEqual(decision["canonical_path"], "/docs/report.txt")
        self.assertEqual(decision["matched_rule"], "r-docs-read")

        # 查询接口：逐步解析链 + 最终命中规则
        status, fetched = self.call("GET", f"/v1/decisions/{decision['decision_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["matched_rule"], "r-docs-read")
        self.assertIn("symlink", [entry["step"] for entry in fetched["chain"]])

        # 拒绝：稳定原因码
        status, denied = self.call("POST", f"/v1/tenants/{TENANT}/evaluate",
                                   {"path": "/loop-a", "operation": "read", "caller_id": "svc-a"})
        self.assertEqual(status, 200)
        self.assertEqual(denied["reason"], "LINK_LOOP")

        # 例外租约：签发 -> 放行 -> 额度耗尽回收
        status, lease = self.call("POST", f"/v1/tenants/{TENANT}/leases",
                                  {"approved_by": APPROVER, "paths": ["/docs/secret.txt"],
                                   "operations": ["read"], "max_uses": 1, "ttl_seconds": 3600})
        self.assertEqual(status, 200)
        self.assertEqual(lease["resources"], ["/docs/secret.txt"])
        status, via_lease = self.call("POST", f"/v1/tenants/{TENANT}/evaluate",
                                      {"path": "/docs/secret.txt", "operation": "read", "caller_id": "svc-a"})
        self.assertEqual((via_lease["outcome"], via_lease["lease_id"]), ("allow", lease["lease_id"]))
        status, lease_now = self.call("GET", f"/v1/leases/{lease['lease_id']}")
        self.assertEqual(lease_now["status"], "exhausted")
        status, blocked = self.call("POST", f"/v1/tenants/{TENANT}/evaluate",
                                    {"path": "/docs/secret.txt", "operation": "read", "caller_id": "svc-a"})
        self.assertEqual(blocked["outcome"], "deny")

        # 回放：发布 v2 后对历史记录出差异报告
        status, _ = self.call("POST", f"/v1/tenants/{TENANT}/policies",
                              {"version_id": "v2", "rules": POLICY_V2, "published_by": APPROVER})
        self.assertEqual(status, 200)
        status, job = self.call("POST", f"/v1/tenants/{TENANT}/replays", {"policy_version": "v2"})
        self.assertEqual(status, 200)
        self.assertEqual(job["status"], "finished")
        self.assertGreater(job["changed_count"], 0)
        status, report = self.call("GET", f"/v1/replays/{job['job_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(report["changed_count"], len(report["diffs"]))

    def test_02_error_responses(self) -> None:
        status, body = self.call("POST", f"/v1/tenants/{TENANT}/leases",
                                 {"approved_by": "intruder", "paths": ["/docs/secret.txt"],
                                  "operations": ["read"], "max_uses": 1, "ttl_seconds": 60})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "APPROVER_NOT_ALLOWED")

        status, body = self.call("POST", f"/v1/tenants/{TENANT}/evaluate",
                                 {"path": "/docs/report.txt", "operation": "read",
                                  "caller_id": "svc-a", "policy_version": "v-nope"})
        self.assertEqual(body["reason"], "POLICY_VERSION_MISSING")

        status, _ = self.call("GET", "/v1/decisions/dec-nope")
        self.assertEqual(status, 404)
        status, _ = self.call("GET", "/v1/unknown-route")
        self.assertEqual(status, 404)
        status, _ = self.call("GET", "/v1/healthz")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
