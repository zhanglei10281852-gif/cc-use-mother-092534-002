"""领域模型：不可变值对象与持久化结构。

所有路径在系统内部一律使用 POSIX 风格、绝对路径、以 "/" 连接的规范形式。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal

Source = Literal["system_template", "runtime_record", "tenant_file", "archive_member"]
Effect = Literal["allow", "deny"]
DecisionOutcome = Literal["allow", "deny"]
LeaseState = Literal["active", "exhausted", "expired", "revoked"]
JobState = Literal["running", "finished", "failed"]


@dataclass(frozen=True)
class Resource:
    """已登记的文件实体。

    resource_id 是规范化后的绝对路径，租户内全局唯一；
    source 描述文件来源；labels 为敏感标签集合。
    """

    resource_id: str
    tenant_id: str
    source: Source
    owner_id: str
    labels: frozenset[str] = field(default_factory=frozenset)

    def to_row(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "tenant_id": self.tenant_id,
            "source": self.source,
            "owner_id": self.owner_id,
            "labels": "\n".join(sorted(self.labels)),
        }

    @classmethod
    def from_row(cls, row: dict) -> "Resource":
        labels = row["labels"] or ""
        return cls(
            resource_id=row["resource_id"],
            tenant_id=row["tenant_id"],
            source=row["source"],
            owner_id=row["owner_id"],
            labels=frozenset(p for p in labels.split("\n") if p),
        )


@dataclass(frozen=True)
class ResolutionStep:
    """解析链中的一步，面向查询接口的逐步解释。"""

    index: int
    kind: str  # normalize | symlink | mount | boundary | lookup
    input: str
    output: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Resolution:
    requested_path: str
    canonical_path: str
    tenant_id: str
    steps: tuple[ResolutionStep, ...]
    resource: Resource | None = None
    deny_reason: str | None = None
    deny_detail: str = ""

    @property
    def denied(self) -> bool:
        return self.deny_reason is not None

    def chain(self) -> list[dict]:
        return [step.to_dict() for step in self.steps]


@dataclass(frozen=True)
class Rule:
    """一条匹配规则。

    matchers 全部命中才算匹配（AND 语义），空集合表示不约束该维度。
    path_pattern 支持 glob：* 不跨目录，** 跨目录。
    """

    rule_id: str
    effect: Effect
    operations: frozenset[str] = field(default_factory=frozenset)
    sources: frozenset[str] = field(default_factory=frozenset)
    labels_any: frozenset[str] = field(default_factory=frozenset)
    owners: frozenset[str] = field(default_factory=frozenset)
    path_pattern: str | None = None
    capabilities: frozenset[str] = field(default_factory=frozenset)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "effect": self.effect,
            "operations": sorted(self.operations),
            "sources": sorted(self.sources),
            "labels_any": sorted(self.labels_any),
            "owners": sorted(self.owners),
            "path_pattern": self.path_pattern,
            "capabilities": sorted(self.capabilities),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if data["effect"] not in ("allow", "deny"):
            raise ValueError(f"规则效果非法：{data['effect']}")
        return cls(
            rule_id=data["rule_id"],
            effect=data["effect"],
            operations=frozenset(data.get("operations") or []),
            sources=frozenset(data.get("sources") or []),
            labels_any=frozenset(data.get("labels_any") or []),
            owners=frozenset(data.get("owners") or []),
            path_pattern=(data.get("path_pattern") or None),
            capabilities=frozenset(data.get("capabilities") or []),
            description=data.get("description", ""),
        )


@dataclass(frozen=True)
class PolicyVersion:
    """一次不可变的策略发布。"""

    version: str
    tenant_id: str
    rules: tuple[Rule, ...]
    published_at: str
    published_by: str
    base_version: str | None = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "tenant_id": self.tenant_id,
            "rules": [rule.to_dict() for rule in self.rules],
            "published_at": self.published_at,
            "published_by": self.published_by,
            "base_version": self.base_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyVersion":
        return cls(
            version=data["version"],
            tenant_id=data["tenant_id"],
            rules=tuple(Rule.from_dict(item) for item in data["rules"]),
            published_at=data["published_at"],
            published_by=data["published_by"],
            base_version=data.get("base_version"),
        )


@dataclass(frozen=True)
class AccessRequest:
    """一次访问判定的输入。

    requested_path 可以是绝对路径、含 "."/".."、符号链接路径或压缩包成员名；
    archive_member=True 时按压缩包成员名规则校验，不做挂载/链接展开。
    """

    tenant_id: str
    requested_path: str
    operation: str
    caller_id: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    archive_member: bool = False
    policy_version: str | None = None  # None 表示使用当前生效版本
    request_id: str | None = None  # 幂等键


@dataclass(frozen=True)
class DecisionDetail:
    """规则匹配的解释项。"""

    rule_id: str
    effect: Effect
    matched: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    decision_id: str
    tenant_id: str
    request_id: str | None
    requested_path: str
    canonical_path: str | None
    resource_id: str | None
    operation: str
    caller_id: str
    outcome: DecisionOutcome
    reason_code: str
    reason_message: str
    policy_version: str | None
    rule_id: str | None
    lease_id: str | None
    resolution_chain: tuple[dict, ...]
    rule_trace: tuple[dict, ...]
    evaluated_at: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ExceptionLease:
    """短期例外：只能由指定审批人签发，绑定精确资源集合与操作集合。"""

    lease_id: str
    tenant_id: str
    resource_ids: frozenset[str]
    operations: frozenset[str]
    quota: int
    used: int
    granted_by: str
    granted_at: str
    expires_at: str
    state: LeaseState
    note: str = ""

    @property
    def remaining(self) -> int:
        return max(0, self.quota - self.used)

    def to_row(self) -> dict:
        return {
            "lease_id": self.lease_id,
            "tenant_id": self.tenant_id,
            "resource_ids": "\n".join(sorted(self.resource_ids)),
            "operations": "\n".join(sorted(self.operations)),
            "quota": self.quota,
            "used": self.used,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "state": self.state,
            "note": self.note,
        }

    @classmethod
    def from_row(cls, row: dict) -> "ExceptionLease":
        return cls(
            lease_id=row["lease_id"],
            tenant_id=row["tenant_id"],
            resource_ids=frozenset(p for p in (row["resource_ids"] or "").split("\n") if p),
            operations=frozenset(p for p in (row["operations"] or "").split("\n") if p),
            quota=int(row["quota"]),
            used=int(row["used"]),
            granted_by=row["granted_by"],
            granted_at=row["granted_at"],
            expires_at=row["expires_at"],
            state=row["state"],
            note=row.get("note", ""),
        )


@dataclass(frozen=True)
class ReplayDiff:
    job_id: str
    decision_id: str
    evaluated_at: str
    requested_path: str
    operation: str
    old_outcome: str
    new_outcome: str
    old_rule_id: str | None
    new_rule_id: str | None
    old_reason: str
    new_reason: str


@dataclass(frozen=True)
class ReplayJob:
    job_id: str
    tenant_id: str
    target_version: str
    state: JobState
    cursor: str
    started_at: str
    finished_at: str | None
    scanned: int
    changed: int
