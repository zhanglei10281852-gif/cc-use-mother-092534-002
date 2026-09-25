"""策略引擎：规则维度匹配、glob、能力与匹配轨迹。"""
from __future__ import annotations

import unittest

from pathpolicy.engine import PolicyEngine
from pathpolicy.models import AccessRequest, Resource, Rule


SECRET = Resource(
    "/tenants/t1/secret/key.pem", "t1", "tenant_file", "owner-a", frozenset({"pii", "secret"})
)
LOG = Resource(
    "/tenants/t1/run/log.txt", "t1", "runtime_record", "owner-b", frozenset()
)


def req(operation: str = "read", caps: frozenset[str] = frozenset()) -> AccessRequest:
    return AccessRequest(
        tenant_id="t1", requested_path=SECRET.resource_id,
        operation=operation, caller_id="caller-1", capabilities=caps,
    )


class RuleMatchTest(unittest.TestCase):
    def test_first_match_wins_allow(self) -> None:
        engine = PolicyEngine((
            Rule("r-deny-secret", "deny", operations=frozenset({"read"}),
                 labels_any=frozenset({"secret"})),
            Rule("r-allow-all", "allow", operations=frozenset({"read"})),
        ))
        result = engine.evaluate(req(), SECRET)
        self.assertEqual(result.effect, "deny")
        self.assertEqual(result.rule.rule_id, "r-deny-secret")

    def test_skip_to_next_rule(self) -> None:
        engine = PolicyEngine((
            Rule("r-deny-secret", "deny", labels_any=frozenset({"secret"})),
            Rule("r-allow-all", "allow"),
        ))
        result = engine.evaluate(req(), LOG)
        self.assertEqual(result.effect, "allow")
        self.assertEqual(result.rule.rule_id, "r-allow-all")
        self.assertFalse(result.details[0].matched)
        self.assertTrue(result.details[1].matched)

    def test_default_deny_when_nothing_matches(self) -> None:
        engine = PolicyEngine((
            Rule("r-allow-write", "allow", operations=frozenset({"write"})),
        ))
        result = engine.evaluate(req("read"), LOG)
        self.assertEqual(result.effect, "deny")
        self.assertIsNone(result.rule)

    def test_source_and_owner(self) -> None:
        engine = PolicyEngine((
            Rule("r-template", "allow", sources=frozenset({"system_template"})),
            Rule("r-owner", "allow", owners=frozenset({"owner-b"})),
        ))
        self.assertEqual(engine.evaluate(req(), LOG).rule.rule_id, "r-owner")
        template = Resource(
            "/tenants/t1/template/base.img", "t1", "system_template",
            "owner-a", frozenset(),
        )
        self.assertEqual(engine.evaluate(req(), template).rule.rule_id, "r-template")

    def test_capabilities_required(self) -> None:
        engine = PolicyEngine((
            Rule("r-caps", "allow", capabilities=frozenset({"debug"})),
            Rule("r-fallback", "allow"),
        ))
        self.assertEqual(
            engine.evaluate(req(caps=frozenset()), SECRET).rule.rule_id, "r-fallback"
        )
        self.assertEqual(
            engine.evaluate(req(caps=frozenset({"debug"})), SECRET).rule.rule_id, "r-caps"
        )

    def test_trace_records_every_rule(self) -> None:
        engine = PolicyEngine((
            Rule("r1", "deny", operations=frozenset({"write"})),
            Rule("r2", "allow"),
        ))
        result = engine.evaluate(req("read"), SECRET)
        self.assertEqual(len(result.details), 2)
        self.assertFalse(result.details[0].matched)
        self.assertTrue(any("操作 read" in note for note in result.details[0].reasons))


class GlobTest(unittest.TestCase):
    def test_star_does_not_cross_slash(self) -> None:
        engine = PolicyEngine((Rule("r", "allow", path_pattern="/tenants/t1/secret/*"),))
        self.assertEqual(
            engine.evaluate(req(), Resource(
                "/tenants/t1/secret/key.pem", "t1", "tenant_file", "o", frozenset()
            )).effect,
            "allow",
        )
        self.assertEqual(
            engine.evaluate(req(), Resource(
                "/tenants/t1/secret/sub/key.pem", "t1", "tenant_file", "o", frozenset()
            )).effect,
            "deny",
        )

    def test_double_star_crosses_slash(self) -> None:
        engine = PolicyEngine((Rule("r", "allow", path_pattern="/tenants/t1/**/*.pem"),))
        self.assertEqual(
            engine.evaluate(req(), Resource(
                "/tenants/t1/secret/a/b/key.pem", "t1", "tenant_file", "o", frozenset()
            )).effect,
            "allow",
        )

    def test_literal_glob(self) -> None:
        engine = PolicyEngine((Rule("r", "allow", path_pattern="/tenants/t1/run/log.txt"),))
        self.assertEqual(engine.evaluate(req(), LOG).effect, "allow")
        self.assertEqual(
            engine.evaluate(req(), Resource(
                "/tenants/t1/run/other.txt", "t1", "runtime_record", "o", frozenset()
            )).effect,
            "deny",
        )


if __name__ == "__main__":
    unittest.main()
