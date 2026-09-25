"""稳定的决定原因代码。

代码一经发布即成为对外合同：审计、回放报告与调用方都按这些字符串
排查原因，只能新增、不得改名或复用。
"""
from __future__ import annotations


class DenyReason:
    #: 组件展开中检测到符号链接环（或展开深度超限）
    LINK_CYCLE = "DENY_LINK_CYCLE"
    #: 规范化结果越过租户根目录
    TENANT_ROOT_ESCAPE = "DENY_TENANT_ROOT_ESCAPE"
    #: 命中的挂载条目已被后挂载覆盖，文件身份不可确定
    MOUNT_SHADOWED = "DENY_MOUNT_SHADOWED"
    #: 压缩包成员名不安全（绝对路径、盘符、.. 逃逸、反斜杠等）
    UNSAFE_ARCHIVE_MEMBER = "DENY_UNSAFE_ARCHIVE_MEMBER"
    #: 请求绑定的策略版本不存在，或命名空间从未发布策略
    POLICY_VERSION_MISSING = "DENY_POLICY_VERSION_MISSING"
    #: 任何显式拒绝规则命中
    BY_POLICY = "DENY_BY_POLICY"
    #: 无规则命中，默认拒绝
    NO_MATCHING_RULE = "DENY_NO_MATCHING_RULE"
    #: 规范化后找不到已登记资源
    UNKNOWN_RESOURCE = "DENY_UNKNOWN_RESOURCE"
    #: 路径本身非法（空路径、NUL 字节）
    INVALID_PATH = "DENY_INVALID_PATH"
    #: 存在范围匹配的例外租约，但额度已耗尽
    LEASE_EXHAUSTED = "DENY_LEASE_EXHAUSTED"
    #: 存在范围匹配的例外租约，但已到期
    LEASE_EXPIRED = "DENY_LEASE_EXPIRED"


class AllowReason:
    BY_POLICY = "ALLOW_BY_POLICY"
    BY_EXCEPTION_LEASE = "ALLOW_BY_EXCEPTION_LEASE"


MESSAGES = {
    DenyReason.LINK_CYCLE: "符号链接展开成环或超过最大展开深度",
    DenyReason.TENANT_ROOT_ESCAPE: "规范化路径越过租户根目录",
    DenyReason.MOUNT_SHADOWED: "挂载条目已被后挂载覆盖，无法确定文件身份",
    DenyReason.UNSAFE_ARCHIVE_MEMBER: "压缩包成员名不安全",
    DenyReason.POLICY_VERSION_MISSING: "策略版本缺失",
    DenyReason.BY_POLICY: "命中显式拒绝规则",
    DenyReason.NO_MATCHING_RULE: "无规则命中，默认拒绝",
    DenyReason.UNKNOWN_RESOURCE: "规范化路径不存在已登记资源",
    DenyReason.INVALID_PATH: "路径非法",
    DenyReason.LEASE_EXHAUSTED: "例外租约额度已耗尽",
    DenyReason.LEASE_EXPIRED: "例外租约已到期",
    AllowReason.BY_POLICY: "命中允许规则",
    AllowReason.BY_EXCEPTION_LEASE: "命中允许规则且由有效例外租约放行",
}
