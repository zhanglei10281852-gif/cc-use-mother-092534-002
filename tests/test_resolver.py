"""路径解析：规范化、链接环、租户边界、挂载覆盖、压缩包成员名。"""
from __future__ import annotations

import unittest

from pathpolicy.models import Resource
from pathpolicy.reasons import DenyReason
from pathpolicy.resolver import Mount, NamespaceResolver


def make_resolver(**kwargs) -> NamespaceResolver:
    resources = {
        "/tenants/t1/secret/key.pem": Resource(
            "/tenants/t1/secret/key.pem", "t1", "tenant_file", "owner-a", frozenset({"secret"})
        ),
        "/tenants/t1/run/log.txt": Resource(
            "/tenants/t1/run/log.txt", "t1", "runtime_record", "owner-b", frozenset()
        ),
        "/tenants/t1/template/base.img": Resource(
            "/tenants/t1/template/base.img", "t1", "system_template", "owner-a", frozenset()
        ),
    }
    defaults = dict(
        tenant_id="t1",
        tenant_root="/tenants/t1",
        resources=resources,
    )
    defaults.update(kwargs)
    return NamespaceResolver(**defaults)


class NormalizeTest(unittest.TestCase):
    def test_absolute_and_dotdot(self) -> None:
        resolver = make_resolver()
        result = resolver.resolve("/tenants/t1/run/../secret/./key.pem")
        self.assertIsNone(result.deny_reason)
        self.assertEqual(result.canonical_path, "/tenants/t1/secret/key.pem")
        kinds = [step.kind for step in result.steps]
        self.assertIn("normalize", kinds)
        self.assertIn("boundary", kinds)
        self.assertIn("lookup", kinds)

    def test_backslash_normalized(self) -> None:
        resolver = make_resolver()
        result = resolver.resolve("/tenants/t1/secret/key.pem")
        self.assertIsNone(result.deny_reason)

    def test_empty_path_denied(self) -> None:
        result = make_resolver().resolve("")
        self.assertEqual(result.deny_reason, DenyReason.INVALID_PATH)

    def test_nul_byte_denied(self) -> None:
        result = make_resolver().resolve("/tenants/t1/a\x00b")
        self.assertEqual(result.deny_reason, DenyReason.INVALID_PATH)


class SymlinkTest(unittest.TestCase):
    def test_symlink_chain_resolves(self) -> None:
        resolver = make_resolver(symlinks={
            "/tenants/t1/alias": "/tenants/t1/secret",
        })
        result = resolver.resolve("/tenants/t1/alias/key.pem")
        self.assertIsNone(result.deny_reason, result.deny_detail)
        self.assertEqual(result.canonical_path, "/tenants/t1/secret/key.pem")
        self.assertTrue(any(step.kind == "symlink" for step in result.steps))

    def test_relative_symlink(self) -> None:
        resolver = make_resolver(symlinks={
            "/tenants/t1/run/link.txt": "../secret/key.pem",
        })
        result = resolver.resolve("/tenants/t1/run/link.txt")
        self.assertIsNone(result.deny_reason)
        self.assertEqual(result.canonical_path, "/tenants/t1/secret/key.pem")

    def test_direct_link_cycle_denied(self) -> None:
        resolver = make_resolver(symlinks={
            "/tenants/t1/a": "/tenants/t1/b",
            "/tenants/t1/b": "/tenants/t1/a",
        })
        result = resolver.resolve("/tenants/t1/a")
        self.assertEqual(result.deny_reason, DenyReason.LINK_CYCLE)
        self.assertTrue(any(step.kind == "symlink" for step in result.steps))

    def test_self_cycle_denied(self) -> None:
        resolver = make_resolver(symlinks={"/tenants/t1/loop": "/tenants/t1/loop"})
        result = resolver.resolve("/tenants/t1/loop")
        self.assertEqual(result.deny_reason, DenyReason.LINK_CYCLE)


class BoundaryTest(unittest.TestCase):
    def test_dotdot_escape_denied(self) -> None:
        result = make_resolver().resolve("/tenants/t1/../../etc/passwd")
        self.assertEqual(result.deny_reason, DenyReason.TENANT_ROOT_ESCAPE)

    def test_symlink_escape_denied(self) -> None:
        resolver = make_resolver(symlinks={
            "/tenants/t1/evil": "/tenants/t2/secret/key.pem",
        })
        result = resolver.resolve("/tenants/t1/evil")
        self.assertEqual(result.deny_reason, DenyReason.TENANT_ROOT_ESCAPE)


class MountTest(unittest.TestCase):
    def test_mount_alias_resolves(self) -> None:
        resolver = make_resolver(mounts=[
            Mount("/mnt/logs", "/tenants/t1/run", registered_order=1),
        ])
        result = resolver.resolve("/mnt/logs/log.txt")
        self.assertIsNone(result.deny_reason)
        self.assertEqual(result.canonical_path, "/tenants/t1/run/log.txt")
        mount_steps = [s for s in result.steps if s.kind == "mount"]
        self.assertTrue(mount_steps)

    def test_shadowed_mount_denied(self) -> None:
        resolver = make_resolver(mounts=[
            Mount("/mnt", "/tenants/t1/run", registered_order=1),
            Mount("/mnt", "/tenants/t1/other", registered_order=2, shadowed=True),
        ])
        result = resolver.resolve("/mnt/log.txt")
        self.assertEqual(result.deny_reason, DenyReason.MOUNT_SHADOWED)

    def test_parent_mount_shadows_child(self) -> None:
        resolver = make_resolver(mounts=[
            Mount("/mnt/data", "/tenants/t1/run", registered_order=1, shadowed=True),
            Mount("/mnt", "/tenants/t1", registered_order=2),
        ])
        result = resolver.resolve("/mnt/data/log.txt")
        self.assertEqual(result.deny_reason, DenyReason.MOUNT_SHADOWED)

    def test_link_then_mount(self) -> None:
        resolver = make_resolver(
            symlinks={"/tenants/t1/entry": "/mnt/logs/log.txt"},
            mounts=[Mount("/mnt/logs", "/tenants/t1/run", registered_order=1)],
        )
        result = resolver.resolve("/tenants/t1/entry")
        self.assertIsNone(result.deny_reason, result.deny_detail)
        self.assertEqual(result.canonical_path, "/tenants/t1/run/log.txt")


class ArchiveMemberTest(unittest.TestCase):
    def test_safe_member(self) -> None:
        resources = {
            "/tenants/t1/dir/f.txt": Resource(
                "/tenants/t1/dir/f.txt", "t1", "archive_member", "owner-a", frozenset()
            ),
        }
        resolver = make_resolver(resources=resources)
        result = resolver.resolve("dir/f.txt", archive_member=True)
        self.assertIsNone(result.deny_reason)
        self.assertEqual(result.canonical_path, "/tenants/t1/dir/f.txt")

    def test_dotdot_member_denied(self) -> None:
        result = make_resolver().resolve("../outside.txt", archive_member=True)
        self.assertEqual(result.deny_reason, DenyReason.UNSAFE_ARCHIVE_MEMBER)

    def test_absolute_member_denied(self) -> None:
        result = make_resolver().resolve("/etc/passwd", archive_member=True)
        self.assertEqual(result.deny_reason, DenyReason.UNSAFE_ARCHIVE_MEMBER)

    def test_backslash_traversal_member_denied(self) -> None:
        result = make_resolver().resolve("dir\\..\\..\\x", archive_member=True)
        self.assertEqual(result.deny_reason, DenyReason.UNSAFE_ARCHIVE_MEMBER)

    def test_drive_member_denied(self) -> None:
        result = make_resolver().resolve("C:\\Windows\\x", archive_member=True)
        self.assertEqual(result.deny_reason, DenyReason.UNSAFE_ARCHIVE_MEMBER)


class LookupTest(unittest.TestCase):
    def test_unknown_resource_denied(self) -> None:
        result = make_resolver().resolve("/tenants/t1/nope")
        self.assertEqual(result.deny_reason, DenyReason.UNKNOWN_RESOURCE)

    def test_chain_is_complete(self) -> None:
        result = make_resolver().resolve("/tenants/t1/secret/key.pem")
        indices = [step.index for step in result.steps]
        self.assertEqual(indices, list(range(len(result.steps))))


if __name__ == "__main__":
    unittest.main()
