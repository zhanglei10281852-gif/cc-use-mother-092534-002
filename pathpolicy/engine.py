"""版本化策略引擎。

规则按 PolicyVersion.rules 的声明顺序求值：第一条匹配的规则直接决定
结果（deny 优先由策略作者通过排序表达）；没有任何规则匹配则默认拒绝。
每条规则无论是否匹配都产生一条 DecisionDetail，供查询接口解释最终命中
的是哪条规则、其余规则为何未命中。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import AccessRequest, DecisionDetail, Resource, Rule


@dataclass(frozen=True)
class Evaluation:
    effect: str  # allow | deny
    rule: Rule | None
    details: tuple[DecisionDetail, ...]


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """把 glob 翻译成完整匹配正则：* 不跨 /，** 跨 /，? 匹配单字符。"""
    out = ["^"]
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # 吞掉连续的 * 以及紧随的一个 /
                i += 2
                if i < len(pattern) and pattern[i] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    out.append("$")
    return re.compile("".join(out))


class PolicyEngine:
    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self.rules = rules
        self._compiled = {
            rule.rule_id: _glob_to_regex(rule.path_pattern)
            for rule in rules
            if rule.path_pattern
        }

    def explain_match(
        self, rule: Rule, request: AccessRequest, resource: Resource
    ) -> tuple[bool, list[str]]:
        """返回 (是否匹配, 各维度命中说明)；未命中时说明里给出第一个失败维度。"""
        reasons: list[str] = []
        matched = True

        if rule.operations and request.operation not in rule.operations:
            matched = False
            reasons.append(f"操作 {request.operation} 不在 {sorted(rule.operations)}")
        else:
            reasons.append(f"操作 {request.operation} 命中")

        if rule.sources and resource.source not in rule.sources:
            matched = False
            reasons.append(f"来源 {resource.source} 不在 {sorted(rule.sources)}")
        elif rule.sources:
            reasons.append(f"来源 {resource.source} 命中")

        if rule.labels_any and not (rule.labels_any & resource.labels):
            matched = False
            reasons.append(
                f"敏感标签 {sorted(resource.labels)} 与 {sorted(rule.labels_any)} 无交集"
            )
        elif rule.labels_any:
            reasons.append(
                f"敏感标签命中 {sorted(rule.labels_any & resource.labels)}"
            )

        if rule.owners and resource.owner_id not in rule.owners:
            matched = False
            reasons.append(f"所有者 {resource.owner_id} 不在 {sorted(rule.owners)}")
        elif rule.owners:
            reasons.append(f"所有者 {resource.owner_id} 命中")

        if rule.path_pattern:
            regex = self._compiled[rule.rule_id]
            if not regex.match(resource.resource_id):
                matched = False
                reasons.append(f"路径 {resource.resource_id} 不匹配 {rule.path_pattern}")
            else:
                reasons.append(f"路径匹配 {rule.path_pattern}")

        if rule.capabilities and not (rule.capabilities <= request.capabilities):
            missing = sorted(rule.capabilities - request.capabilities)
            matched = False
            reasons.append(f"调用能力缺失 {missing}")
        elif rule.capabilities:
            reasons.append(f"调用能力 {sorted(rule.capabilities)} 全部具备")

        return matched, reasons

    def evaluate(self, request: AccessRequest, resource: Resource) -> Evaluation:
        details: list[DecisionDetail] = []
        for index, rule in enumerate(self.rules):
            matched, reasons = self.explain_match(rule, request, resource)
            details.append(
                DecisionDetail(
                    rule_id=rule.rule_id,
                    effect=rule.effect,
                    matched=matched,
                    reasons=tuple(reasons),
                )
            )
            if matched:
                return Evaluation(rule.effect, rule, tuple(details))
        return Evaluation("deny", None, tuple(details))
