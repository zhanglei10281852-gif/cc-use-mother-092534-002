"""命名空间解析器测试：多形态路径统一、稳定拒绝原因码、解析链。"""
from __future__ import annotations

import unittest

from pathpolicy import errors
from pathpolicy.models import NamespaceView
from pathpolicy.namespace import Resolver

from fixtures import NAMESPACE_VIEW


def make_resolver() -> Resolver:
    return Resolver(NamespaceView.from_dict(NAMESPACE_VIEW))


class ResolveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = make_resolver()

    def test_absolute_path_resolves_to_canonical(self) -> None:
        result = self.resolver.resolve("/docs/report.txt")
        self.assertTrue(result.ok)
        self.assertEqual(result.canonical_path, "/docs/report.txt")
        self.assertEqual(result.mount.source, "tenant-volume")
        self.assertEqual(result.node.owner, "alice")

    def test_all_access_forms_unify_to_same_canonical_path(self) -> None:
        """绝对路径、符号链接、词法变体必须收敛到同一规范化路径。"""
        forms = ["/docs/report.txt", "/link-to-report", "/abs-link", "/docs/./report.txt", "//docs//report.txt"]
        canonical = {self.resolver.resolve(form).canonical_path for form in forms}
        self.assertEqual(canonical, {"/docs/report.txt"})

    def test_mount_alias_carries_source(self) -> None:
        result = self.resolver.resolve("/templates/base.conf")
        self.assertTrue(result.ok)
        self.assertEqual(result.canonical_path, "/templates/base.conf")
        self.assertEqual(result.mount.source, "system-template")

    def test_archive_member_resolves_with_boundary(self) -> None:
        result = self.resolver.resolve("/bundle.tar/logs/run.log")
        self.assertTrue(result.ok)
        self.assertEqual(result.canonical_path, "/bundle.tar!/logs/run.log")
        self.assertEqual(result.node.labels, ("run-record",))

    def test_archive_member_symlink_inside_archive(self) -> None:
        result = self.resolver.resolve("/bundle.tar/inner-link")
        self.assertTrue(result.ok)
        self.assertEqual(result.canonical_path, "/bundle.tar!/logs/run.log")

    def test_lexical_escape_beyond_tenant_root_rejected(self) -> None:
        for path in ("/../etc/passwd", "/docs/../../outside"):
            result = self.resolver.resolve(path)
            self.assertFalse(result.ok, path)
            self.assertEqual(result.reason, errors.TENANT_ROOT_ESCAPE)

    def test_archive_member_escape_rejected(self) -> None:
        result = self.resolver.resolve("/bundle.tar/escape-link")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, errors.TENANT_ROOT_ESCAPE)

    def test_link_loop_rejected(self) -> None:
        result = self.resolver.resolve("/loop-a")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, errors.LINK_LOOP)

    def test_late_mount_shadowing_rejected(self) -> None:
        """链接注册(seq 1)之后，目标路径被 seq 5 的挂载覆盖 -> 无法确定真实对象。"""
        result = self.resolver.resolve("/old-link")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, errors.MOUNT_SHADOWED)

    def test_direct_path_to_late_mount_is_fine(self) -> None:
        """直接访问后挂载下的路径不触发遮蔽（遮蔽只约束旧视图注册的链接）。"""
        result = self.resolver.resolve("/shared/data.txt")
        self.assertTrue(result.ok)
        self.assertEqual(result.canonical_path, "/shared/data.txt")

    def test_missing_component_rejected(self) -> None:
        result = self.resolver.resolve("/docs/no-such-file.txt")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, errors.RESOURCE_NOT_FOUND)

    def test_resolution_chain_records_steps(self) -> None:
        result = self.resolver.resolve("/abs-link")
        steps = [entry["step"] for entry in result.chain]
        self.assertEqual(steps[0], "normalize")
        self.assertIn("mount", steps)
        self.assertIn("symlink", steps)
        self.assertIn("component", steps)

    def test_failed_resolution_keeps_partial_chain(self) -> None:
        result = self.resolver.resolve("/loop-a")
        self.assertFalse(result.ok)
        self.assertGreater(len(result.chain), 0)

    def test_namespace_view_roundtrip(self) -> None:
        view = NamespaceView.from_dict(NAMESPACE_VIEW)
        restored = NamespaceView.from_dict(view.to_dict())
        self.assertEqual(
            Resolver(restored).resolve("/bundle.tar/logs/run.log").canonical_path,
            "/bundle.tar!/logs/run.log",
        )


if __name__ == "__main__":
    unittest.main()
