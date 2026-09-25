"""领域实体与值对象。

对应 domain/contract.json 中的实体：namespace、resource、policy_version、
access_decision、exception_lease、replay_job。所有时间一律 ISO 8601 带时区。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# 节点类型
DIR = "dir"
FILE = "file"
SYMLINK = "symlink"
ARCHIVE = "archive"

# 决策结果
ALLOW = "allow"
DENY = "deny"

# 租约状态（派生，不单独落库）
LEASE_ACTIVE = "active"
LEASE_EXHAUSTED = "exhausted"
LEASE_EXPIRED = "expired"
LEASE_REVOKED = "revoked"

# 回放任务状态
REPLAY_RUNNING = "replaying"
REPLAY_FINISHED = "finished"


@dataclass
class Node:
    """命名空间视图中的节点：目录、文件、符号链接或压缩包（成员作为子节点）。"""

    node_id: str
    name: str
    kind: str
    owner: str
    labels: tuple[str, ...]
    mount_seq: int  # 所属挂载的序号，即节点注册时的视图版本
    canonical_rel: str  # 相对挂载根的路径，压缩包边界以 "!/" 分隔
    link_target: str | None = None
    children: dict[str, "Node"] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = {
            "kind": self.kind,
            "owner": self.owner,
            "labels": list(self.labels),
        }
        if self.link_target is not None:
            data["target"] = self.link_target
        if self.children:
            data["children"] = {name: child.to_dict() for name, child in self.children.items()}
        return data


@dataclass
class Mount:
    """一条挂载：命名空间前缀 -> 后端树。同前缀时序号大者（后挂载）生效。"""

    prefix: str  # 规范化后的命名空间前缀，如 "/" 或 "/shared"
    source: str  # 文件来源标签，如 system-template / tenant-volume / run-record
    seq: int  # 挂载序号，单调递增
    root: Node

    def to_dict(self) -> dict:
        return {"prefix": self.prefix, "source": self.source, "seq": self.seq, "tree": self.root.to_dict()}


@dataclass
class NamespaceView:
    """租户的文件命名空间视图：有序挂载表 + 各后端节点树。"""

    tenant_id: str
    mounts: list[Mount]

    @classmethod
    def from_dict(cls, data: dict) -> "NamespaceView":
        mounts = []
        for entry in data.get("mounts", []):
            prefix = _normalize_prefix(entry["prefix"])
            seq = int(entry["seq"])
            root = _build_node(entry["tree"], name="", mount_seq=seq, canonical_rel="", id_prefix=f"m{seq}:")
            mounts.append(Mount(prefix=prefix, source=entry["source"], seq=seq, root=root))
        return cls(tenant_id=data["tenant_id"], mounts=mounts)

    def to_dict(self) -> dict:
        return {"tenant_id": self.tenant_id, "mounts": [m.to_dict() for m in self.mounts]}


def _normalize_prefix(prefix: str) -> str:
    parts = [p for p in prefix.split("/") if p not in ("", ".")]
    return "/" + "/".join(parts)


def _build_node(tree: dict, name: str, mount_seq: int, canonical_rel: str, id_prefix: str) -> Node:
    kind = tree.get("kind", DIR)
    node = Node(
        node_id=f"{id_prefix}{canonical_rel or '/'}",
        name=name,
        kind=kind,
        owner=tree.get("owner", "unknown"),
        labels=tuple(tree.get("labels", ())),
        mount_seq=mount_seq,
        canonical_rel=canonical_rel,
        link_target=tree.get("target"),
    )
    children = tree.get("children") or tree.get("members") or {}
    boundary = "/" if kind != ARCHIVE else "!/"
    for child_name, child_tree in children.items():
        child_rel = f"{canonical_rel}{boundary}{child_name}" if canonical_rel else child_name
        node.children[child_name] = _build_node(
            child_tree, name=child_name, mount_seq=mount_seq, canonical_rel=child_rel, id_prefix=id_prefix
        )
    return node


@dataclass
class Resolution:
    """一次命名空间解析的结果。失败时 reason 为稳定原因码，chain 保留已走步骤。"""

    ok: bool
    reason: str | None
    chain: list[dict]
    node: Node | None = None
    mount: Mount | None = None
    canonical_path: str | None = None


@dataclass
class EvaluationContext:
    """规则评估上下文：规范化路径、来源、所有者、敏感标签、调用能力与操作。"""

    canonical_path: str
    source: str
    owner: str
    labels: tuple[str, ...]
    operation: str
    caller_id: str
    capabilities: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "canonical_path": self.canonical_path,
            "source": self.source,
            "owner": self.owner,
            "labels": list(self.labels),
            "operation": self.operation,
            "caller_id": self.caller_id,
            "capabilities": list(self.capabilities),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvaluationContext":
        return cls(
            canonical_path=data["canonical_path"],
            source=data["source"],
            owner=data["owner"],
            labels=tuple(data["labels"]),
            operation=data["operation"],
            caller_id=data["caller_id"],
            capabilities=tuple(data["capabilities"]),
        )


@dataclass
class Rule:
    """一条策略规则。所有条件字段为与关系；空字段表示不限制。"""

    rule_id: str
    priority: int  # 数值小者优先
    effect: str  # "allow" 或 "deny"
    path_prefix: str | None = None
    source: str | None = None
    owner: str | None = None
    labels_any: tuple[str, ...] = ()
    capability: str | None = None
    operations: tuple[str, ...] = ()
    note: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        return cls(
            rule_id=data["rule_id"],
            priority=int(data.get("priority", 100)),
            effect=data["effect"],
            path_prefix=data.get("path_prefix"),
            source=data.get("source"),
            owner=data.get("owner"),
            labels_any=tuple(data.get("labels_any", ())),
            capability=data.get("capability"),
            operations=tuple(data.get("operations", ())),
            note=data.get("note", ""),
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "priority": self.priority,
            "effect": self.effect,
            "path_prefix": self.path_prefix,
            "source": self.source,
            "owner": self.owner,
            "labels_any": list(self.labels_any),
            "capability": self.capability,
            "operations": list(self.operations),
            "note": self.note,
        }


@dataclass
class PolicyVersion:
    """一个不可变的策略版本。发布后不得修改，只能追加新版本。"""

    tenant_id: str
    version_id: str
    rules: list[Rule]
    published_by: str
    published_at: str

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyVersion":
        return cls(
            tenant_id=data["tenant_id"],
            version_id=data["version_id"],
            rules=[Rule.from_dict(r) for r in data["rules"]],
            published_by=data["published_by"],
            published_at=data["published_at"],
        )

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "version_id": self.version_id,
            "rules": [r.to_dict() for r in self.rules],
            "published_by": self.published_by,
            "published_at": self.published_at,
        }


@dataclass
class Decision:
    """一次访问判定。append-only：一旦写入不得修改，回放只生成差异报告。"""

    decision_id: str
    tenant_id: str
    request: dict  # 原始请求（路径、操作、调用者、能力、指定版本）
    context: EvaluationContext | None  # 解析成功时的评估上下文
    outcome: str  # allow / deny
    reason: str | None  # 拒绝原因码；放行时为 None
    matched_rule: str | None  # 最终命中规则；经租约放行时记录被拒绝的规则
    policy_version: str | None
    chain: list[dict]  # 逐步解析链
    lease_id: str | None  # 经例外租约放行时的租约 id
    evaluated_at: str
    seq: int = 0  # 审计序号，由存储层分配

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "tenant_id": self.tenant_id,
            "seq": self.seq,
            "outcome": self.outcome,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "policy_version": self.policy_version,
            "lease_id": self.lease_id,
            "canonical_path": self.context.canonical_path if self.context else None,
            "evaluated_at": self.evaluated_at,
            "request": self.request,
            "chain": self.chain,
        }


@dataclass
class Lease:
    """例外租约：指定审批人签发给精确资源集合的短期放行额度。"""

    lease_id: str
    tenant_id: str
    approved_by: str
    resources: tuple[str, ...]  # 精确规范化路径，不做前缀匹配
    operations: tuple[str, ...]
    max_uses: int
    used_count: int
    expires_at: str
    created_at: str
    revoked: bool = False

    def status(self, now: datetime) -> str:
        if self.revoked:
            return LEASE_REVOKED
        if self.used_count >= self.max_uses:
            return LEASE_EXHAUSTED
        if now >= datetime.fromisoformat(self.expires_at):
            return LEASE_EXPIRED
        return LEASE_ACTIVE

    def covers(self, canonical_path: str, operation: str) -> bool:
        return canonical_path in self.resources and operation in self.operations

    def to_dict(self, now: datetime) -> dict:
        return {
            "lease_id": self.lease_id,
            "tenant_id": self.tenant_id,
            "approved_by": self.approved_by,
            "resources": list(self.resources),
            "operations": list(self.operations),
            "max_uses": self.max_uses,
            "used_count": self.used_count,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "status": self.status(now),
        }


@dataclass
class ReplayJob:
    """一次离线回放。游标 cursor_seq 持久化，重启后可从断点续跑。"""

    job_id: str
    tenant_id: str
    policy_version: str
    cursor_seq: int
    status: str
    diffs: list[dict]
    scanned: int
    created_at: str
    finished_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "status": self.status,
            "cursor_seq": self.cursor_seq,
            "scanned": self.scanned,
            "changed_count": len(self.diffs),
            "diffs": self.diffs,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }
