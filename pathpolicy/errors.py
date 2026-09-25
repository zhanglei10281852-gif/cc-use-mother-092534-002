"""稳定的拒绝原因码。

原因码属于对外契约：可以新增，但既有码的语义不得改变，
调用方与审计系统可以依赖这些码做长期统计与告警。
"""

# ---- 命名空间解析阶段 ----
LINK_LOOP = "LINK_LOOP"  # 符号链接成环，或展开次数超过安全上限
TENANT_ROOT_ESCAPE = "TENANT_ROOT_ESCAPE"  # 规范化后越过租户根（含压缩包成员越界）
MOUNT_SHADOWED = "MOUNT_SHADOWED"  # 链接目标被更晚的挂载覆盖，无法确定真实对象
RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"  # 路径组件、成员或挂载不存在

# ---- 策略评估阶段 ----
POLICY_VERSION_MISSING = "POLICY_VERSION_MISSING"  # 请求的策略版本不存在或尚未发布
NO_MATCHING_RULE = "NO_MATCHING_RULE"  # 没有任何规则命中，默认拒绝
RULE_DENIED = "RULE_DENIED"  # 显式命中拒绝规则

# ---- 配置与请求 ----
NAMESPACE_MISSING = "NAMESPACE_MISSING"  # 租户尚未注册命名空间视图
INVALID_REQUEST = "INVALID_REQUEST"  # 请求参数不合法

# ---- 例外租约 ----
APPROVER_NOT_ALLOWED = "APPROVER_NOT_ALLOWED"  # 签发人不在指定审批人名单
LEASE_NOT_FOUND = "LEASE_NOT_FOUND"  # 租约不存在

ALL = frozenset(
    {
        LINK_LOOP,
        TENANT_ROOT_ESCAPE,
        MOUNT_SHADOWED,
        RESOURCE_NOT_FOUND,
        POLICY_VERSION_MISSING,
        NO_MATCHING_RULE,
        RULE_DENIED,
        NAMESPACE_MISSING,
        INVALID_REQUEST,
        APPROVER_NOT_ALLOWED,
        LEASE_NOT_FOUND,
    }
)
