"""虚拟机敏感路径策略服务。

合并规范化路径、文件来源、所有者、敏感标签、调用能力与操作类型，
产出可版本化的允许/拒绝决定；支持审批例外租约、只增审计与策略回放。
"""
from __future__ import annotations

from .clock import Clock, FakeClock
from .models import (
    AccessRequest,
    Decision,
    DecisionDetail,
    ExceptionLease,
    PolicyVersion,
    ReplayDiff,
    ReplayJob,
    Resolution,
    ResolutionStep,
    Resource,
    Rule,
)
from .reasons import DenyReason
from .service import PathPolicyService

SOURCES = ("system_template", "runtime_record", "tenant_file", "archive_member")

__all__ = [
    "PathPolicyService",
    "AccessRequest",
    "Decision",
    "DecisionDetail",
    "ExceptionLease",
    "PolicyVersion",
    "ReplayDiff",
    "ReplayJob",
    "Resolution",
    "ResolutionStep",
    "Resource",
    "Rule",
    "DenyReason",
    "Clock",
    "FakeClock",
    "SOURCES",
]
