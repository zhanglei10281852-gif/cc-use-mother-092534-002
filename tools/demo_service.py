"""端到端演示：解析链、版本化决定、例外租约与策略回放。

运行：python3 tools/demo_service.py
使用临时文件数据库，结束后自动清理。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pathpolicy.clock import FakeClock
from pathpolicy.models import AccessRequest, Rule
from pathpolicy.service import PathPolicyService


def show(title: str, decision) -> None:
    print(f"\n== {title} ==")
    print(f"请求: {decision.requested_path} 操作={decision.operation}")
    print(f"结论: {decision.outcome.upper()}  原因={decision.reason_code}")
    print(f"说明: {decision.reason_message}")
    print(f"策略版本: {decision.policy_version}  命中规则: {decision.rule_id}"
          f"  租约: {decision.lease_id}")
    print("解析链:")
    for step in decision.resolution_chain:
        note = f"  # {step['note']}" if step["note"] else ""
        print(f"  {step['index']}. {step['kind']}: {step['input']} -> {step['output']}{note}")
    if decision.rule_trace:
        print("规则轨迹:")
        for item in decision.rule_trace:
            flag = "命中" if item["matched"] else "跳过"
            print(f"  [{flag}] {item['rule_id']} ({item['effect']})")
            for reason in item["reasons"]:
                print(f"        - {reason}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "demo.db")
        service = PathPolicyService(db_path, clock=FakeClock())

        # 1. 登记命名空间
        service.register_resource(
            "t1", "/tenants/t1/secret/key.pem", "tenant_file", "app-svc",
            frozenset({"secret", "pii"}),
        )
        service.register_resource(
            "t1", "/tenants/t1/run/audit.log", "runtime_record", "app-svc",
        )
        service.register_resource(
            "t1", "/tenants/t1/template/base.img", "system_template", "platform",
        )
        service.register_symlink("t1", "/tenants/t1/k", "/tenants/t1/secret/key.pem")

        # 2. 发布策略 v1：模板与运行记录可读，密钥读取拒绝
        service.publish_policy("t1", "v1", [
            Rule("allow-template", "allow", sources=frozenset({"system_template"})),
            Rule("deny-secret-read", "deny",
                 operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
            Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
        ], published_by="reviewer-02")

        show("符号链接访问密钥（拒绝）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/k",
            operation="read", caller_id="job-7",
        )))

        show("越过租户根（拒绝）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/../../etc/shadow",
            operation="read", caller_id="job-7",
        )))

        show("运行记录读取（允许）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/run/audit.log",
            operation="read", caller_id="job-7",
        )))

        show("系统模板读取（允许）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/template/base.img",
            operation="read", caller_id="job-7",
        )))

        # 3. 指定审批人签发一次性例外
        service.grant_lease(
            "lease-demo", "t1", frozenset({"/tenants/t1/secret/key.pem"}),
            frozenset({"read"}), quota=1, granted_by="reviewer-02", ttl_seconds=600,
            note="故障排查一次性放行",
        )
        show("租约放行密钥读取（允许）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
            operation="read", caller_id="job-7",
        )))
        show("额度耗尽后再次访问（拒绝）", service.evaluate(AccessRequest(
            tenant_id="t1", requested_path="/tenants/t1/secret/key.pem",
            operation="read", caller_id="job-7",
        )))

        # 4. 发布 v2 并回放历史
        service.publish_policy("t1", "v2", [
            Rule("deny-template", "deny", sources=frozenset({"system_template"})),
            Rule("allow-secret", "allow",
                 operations=frozenset({"read"}), labels_any=frozenset({"secret"})),
            Rule("allow-runtime", "allow", sources=frozenset({"runtime_record"})),
        ], published_by="reviewer-02")

        job = service.start_replay("t1", "v2")
        result = service.run_replay(job.job_id)
        print("\n== 策略回放 v1 -> v2 ==")
        print(f"扫描 {result.scanned} 条历史决定，{result.changed} 条结论或命中规则会改变")
        for diff in service.replay_diffs(job.job_id):
            print(f"  {diff['decision_id']}: {diff['old_outcome']}"
                  f"({diff['old_rule_id'] or diff['old_reason']}) -> "
                  f"{diff['new_outcome']}({diff['new_rule_id'] or diff['new_reason']})"
                  f"  [{diff['requested_path']}]")

        service.close()
        print("\n演示完成（临时数据库已清理）。")


if __name__ == "__main__":
    main()
