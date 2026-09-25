"""测试共享的命名空间视图与策略 fixtures。"""
from __future__ import annotations

TENANT = "tenant-a"
APPROVER = "reviewer-01"

# 命名空间视图：
#   /                 -> tenant-volume (seq 1)：文档、符号链接、压缩包
#   /templates        -> system-template (seq 2)：系统模板
#   /shared           -> shared-volume (seq 5)：后挂载，用于遮蔽检查
NAMESPACE_VIEW = {
    "tenant_id": TENANT,
    "mounts": [
        {
            "prefix": "/",
            "source": "tenant-volume",
            "seq": 1,
            "tree": {
                "kind": "dir",
                "owner": "root",
                "children": {
                    "docs": {
                        "kind": "dir",
                        "owner": "alice",
                        "children": {
                            "report.txt": {"kind": "file", "owner": "alice", "labels": ["internal"]},
                            "secret.txt": {"kind": "file", "owner": "alice", "labels": ["pii", "restricted"]},
                        },
                    },
                    "link-to-report": {"kind": "symlink", "target": "docs/report.txt", "owner": "alice"},
                    "abs-link": {"kind": "symlink", "target": "/docs/report.txt", "owner": "alice"},
                    "loop-a": {"kind": "symlink", "target": "loop-b", "owner": "alice"},
                    "loop-b": {"kind": "symlink", "target": "loop-a", "owner": "alice"},
                    "old-link": {"kind": "symlink", "target": "/shared/data.txt", "owner": "alice"},
                    "bundle.tar": {
                        "kind": "archive",
                        "owner": "ops",
                        "labels": ["run-record"],
                        "members": {
                            "logs": {
                                "kind": "dir",
                                "owner": "ops",
                                "children": {
                                    "run.log": {"kind": "file", "owner": "ops", "labels": ["run-record"]}
                                },
                            },
                            "inner-link": {"kind": "symlink", "target": "logs/run.log", "owner": "ops"},
                            "escape-link": {"kind": "symlink", "target": "../../outside.txt", "owner": "ops"},
                        },
                    },
                },
            },
        },
        {
            "prefix": "/templates",
            "source": "system-template",
            "seq": 2,
            "tree": {
                "kind": "dir",
                "owner": "root",
                "children": {
                    "base.conf": {"kind": "file", "owner": "root", "labels": ["template"]}
                },
            },
        },
        {
            "prefix": "/shared",
            "source": "shared-volume",
            "seq": 5,
            "tree": {
                "kind": "dir",
                "owner": "root",
                "children": {
                    "data.txt": {"kind": "file", "owner": "bob", "labels": ["internal"]}
                },
            },
        },
    ],
}

# 策略 v1：模板只读放行；含 pii 标签拒绝；/docs 读取放行
POLICY_V1 = [
    {"rule_id": "r-template-read", "priority": 10, "effect": "allow",
     "source": "system-template", "operations": ["read"], "note": "系统模板只读"},
    {"rule_id": "r-pii-deny", "priority": 20, "effect": "deny",
     "labels_any": ["pii"], "note": "含个人信息的文件默认拒绝"},
    {"rule_id": "r-docs-read", "priority": 30, "effect": "allow",
     "path_prefix": "/docs", "operations": ["read"], "note": "普通文档可读"},
]

# 策略 v2：在 v1 基础上把 /docs 读取也收紧为拒绝（用于回放差异）
POLICY_V2 = [
    {"rule_id": "r-docs-lockdown", "priority": 5, "effect": "deny",
     "path_prefix": "/docs", "operations": ["read"], "note": "事件响应：文档区临时封锁"},
    *POLICY_V1,
]
