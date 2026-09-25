"""策略规则评估测试：优先级、字段匹配、默认拒绝。"""
from __future__ import annotations

import unittest

from pathpolicy import errors
from pathpolicy.models import ALLOW, DENY, EvaluationContext, PolicyVersion, Rule
from pathpolicy.policy import evaluate_rules

CTX = EvaluationContext(
    canonical_path="/docs/secret.txt",
    source="tenant-volume",
    owner="alice",
    labels=("pii",),
    operation="read",
    caller_id="svc-backup",
    capabilities=("cap:read-sensitive",),
)


def make_policy(rules: list[dict]) -> PolicyVersion:
    return PolicyVersion(
        tenant_id="tenant-a",
        version_id="v1",
        rules=[Rule.from_dict(r) for r in rules],
        published_by="reviewer-01",
        published_at="2026-09-25T00:00:00+00:00",
    )


class PolicyTest(unittest.TestCase):
    def test_first_match_by_priority_wins(self) -> None:
        policy = make_policy([
            {"rule_id": "r-allow", "priority": 30, "effect": "allow", "path_prefix": "/docs"},
            {"rule_id": "r-deny", "priority": 10, "effect": "deny", "labels_any": ["pii"]},
        ])
        outcome, rule_id, reason = evaluate_rules(policy, CTX)
        self.assertEqual((outcome, rule_id, reason), (DENY, "r-deny", errors.RULE_DENIED))

    def test_capability_required_for_rule_match(self) -> None:
        policy = make_policy([
            {"rule_id": "r-sensitive", "priority": 10, "effect": "allow", "capability": "cap:read-sensitive"},
        ])
        outcome, rule_id, _ = evaluate_rules(policy, CTX)
        self.assertEqual((outcome, rule_id), (ALLOW, "r-sensitive"))
        no_cap = EvaluationContext(**{**CTX.__dict__, "capabilities": ()})
        outcome, rule_id, reason = evaluate_rules(policy, no_cap)
        self.assertEqual((outcome, rule_id, reason), (DENY, None, errors.NO_MATCHING_RULE))

    def test_all_condition_fields_are_anded(self) -> None:
        policy = make_policy([
            {"rule_id": "r1", "priority": 10, "effect": "allow",
             "path_prefix": "/docs", "source": "tenant-volume", "owner": "alice",
             "labels_any": ["pii"], "operations": ["read"]},
        ])
        outcome, rule_id, _ = evaluate_rules(policy, CTX)
        self.assertEqual((outcome, rule_id), (ALLOW, "r1"))
        write_ctx = EvaluationContext(**{**CTX.__dict__, "operation": "write"})
        outcome, _, reason = evaluate_rules(policy, write_ctx)
        self.assertEqual((outcome, reason), (DENY, errors.NO_MATCHING_RULE))

    def test_no_matching_rule_defaults_to_deny(self) -> None:
        policy = make_policy([
            {"rule_id": "r1", "priority": 10, "effect": "allow", "path_prefix": "/elsewhere"},
        ])
        outcome, rule_id, reason = evaluate_rules(policy, CTX)
        self.assertEqual((outcome, rule_id, reason), (DENY, None, errors.NO_MATCHING_RULE))

    def test_same_priority_falls_back_to_rule_id_order(self) -> None:
        policy = make_policy([
            {"rule_id": "b-rule", "priority": 10, "effect": "allow"},
            {"rule_id": "a-rule", "priority": 10, "effect": "deny"},
        ])
        _, rule_id, _ = evaluate_rules(policy, CTX)
        self.assertEqual(rule_id, "a-rule")


if __name__ == "__main__":
    unittest.main()
