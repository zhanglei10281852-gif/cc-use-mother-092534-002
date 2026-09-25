"""策略规则评估。

规则按 (priority, rule_id) 升序排列，首个命中的规则生效；
所有条件字段为与关系，空字段不限制。无命中时默认拒绝。
"""
from __future__ import annotations

from . import errors
from .models import ALLOW, DENY, EvaluationContext, PolicyVersion, Rule


def rule_matches(rule: Rule, ctx: EvaluationContext) -> bool:
    if rule.path_prefix is not None and not ctx.canonical_path.startswith(rule.path_prefix):
        return False
    if rule.source is not None and ctx.source != rule.source:
        return False
    if rule.owner is not None and ctx.owner != rule.owner:
        return False
    if rule.labels_any and not set(rule.labels_any).intersection(ctx.labels):
        return False
    if rule.capability is not None and rule.capability not in ctx.capabilities:
        return False
    if rule.operations and ctx.operation not in rule.operations:
        return False
    return True


def evaluate_rules(policy: PolicyVersion, ctx: EvaluationContext) -> tuple[str, str | None, str | None]:
    """返回 (结果, 命中规则 id, 拒绝原因码)。命中拒绝规则时原因码为 RULE_DENIED。"""
    for rule in sorted(policy.rules, key=lambda r: (r.priority, r.rule_id)):
        if rule_matches(rule, ctx):
            if rule.effect == ALLOW:
                return ALLOW, rule.rule_id, None
            return DENY, rule.rule_id, errors.RULE_DENIED
    return DENY, None, errors.NO_MATCHING_RULE
