"""路径解析：把任意访问名解析为租户命名空间内的规范资源标识。

解析顺序（每一步都写入 ResolutionStep，供查询接口逐步回放）：

1. 词法规范化：POSIX 化（反斜杠转换）、处理 "."/".."、压斜杠。
2. 压缩包成员模式：只做成员名安全校验，禁止绝对路径、盘符、".." 逃逸。
3. 挂载别名：前缀匹配最长的已登记挂载点；若该挂载点处于
   shadowed（被后挂载覆盖）状态且解析目标落入覆盖窗口，拒绝。
4. 符号链接展开：逐组件展开，已访问的 (路径, 链接目标) 成环即拒绝，
   展开深度受限。
5. 租户根边界：规范结果必须位于租户根之下，越界拒绝。
6. 资源查找：命中已登记资源，否则拒绝。
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from .models import Resolution, ResolutionStep, Resource
from .reasons import DenyReason

MAX_SYMLINK_DEPTH = 40
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class Mount:
    """挂载条目。

    alias 是租户可见的访问前缀（如 /mnt/data），target 是租户命名空间内
    的真实前缀。registered_order 小的先挂载；order 更大、前缀更具体的后挂载
    会把先挂载的同前缀区域标记为 shadowed。
    """

    alias: str
    target: str
    registered_order: int
    shadowed: bool = False


def _lex_normalize(raw: str) -> str:
    # 统一反斜杠为分隔符：同时用于压缩包成员名穿越防护
    value = raw.replace("\\", "/")
    if not value.startswith("/"):
        value = "/" + value
    return posixpath.normpath(value)


def _is_unsafe_archive_member(name: str) -> str | None:
    """返回非空字符串表示不安全原因；None 表示安全。"""
    if "\x00" in name:
        return "成员名含 NUL 字节"
    if name.startswith("/") or name.startswith("\\"):
        return "成员名不允许绝对路径"
    if _DRIVE_RE.match(name):
        return "成员名不允许盘符"
    normalized = name.replace("\\", "/")
    parts: list[str] = []
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return "成员名包含越出根目录的 .."
            parts.pop()
            continue
        parts.append(part)
    return None


class NamespaceResolver:
    """租户内的挂载表、符号链接表与资源登记表。"""

    def __init__(
        self,
        tenant_id: str,
        tenant_root: str,
        resources: dict[str, Resource],
        symlinks: dict[str, str] | None = None,
        mounts: list[Mount] | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.tenant_root = posixpath.normpath(tenant_root)
        if not self.tenant_root.startswith("/"):
            raise ValueError("tenant_root 必须是绝对路径")
        self.resources = dict(resources)
        self.symlinks = {_lex_normalize(k): v for k, v in (symlinks or {}).items()}
        raw_mounts = list(mounts or [])
        for mount in raw_mounts:
            if not mount.alias.startswith("/") or not mount.target.startswith("/"):
                raise ValueError("挂载别名与目标都必须是绝对路径")
        # 同一别名出现多次：后挂载覆盖先前挂载，文件身份不可确定，全部拒绝
        seen_aliases: set[str] = set()
        shadowed_aliases: set[str] = set()
        for mount in sorted(raw_mounts, key=lambda m: m.registered_order):
            if mount.alias in seen_aliases:
                shadowed_aliases.add(mount.alias)
            seen_aliases.add(mount.alias)
        self.mounts = sorted(
            [
                Mount(mount.alias, mount.target, mount.registered_order,
                      shadowed=mount.shadowed or mount.alias in shadowed_aliases)
                for mount in raw_mounts
            ],
            key=lambda m: (-len(m.alias), m.registered_order),
        )

    # ------------------------------------------------------------------
    # 挂载解析
    # ------------------------------------------------------------------
    def _apply_mount(self, path: str) -> tuple[str, Mount | None]:
        for mount in self.mounts:
            alias = posixpath.normpath(mount.alias)
            if path == alias or path.startswith(alias.rstrip("/") + "/"):
                suffix = path[len(alias):]
                # suffix 以 "/" 开头，不能用 posixpath.join（会把它当绝对路径）
                merged = mount.target.rstrip("/") + suffix if suffix else mount.target
                return posixpath.normpath(merged), mount
        return path, None

    # ------------------------------------------------------------------
    # 符号链接逐组件展开
    # ------------------------------------------------------------------
    def _find_link(self, path: str) -> tuple[str, str] | None:
        """返回命中的 (链接路径, 目标)，精确匹配优先，否则取最长前缀。"""
        exact = self.symlinks.get(path)
        if exact is not None:
            return path, exact
        best: tuple[int, str, str] | None = None
        for link, target in self.symlinks.items():
            if path.startswith(link.rstrip("/") + "/"):
                if best is None or len(link) > best[0]:
                    best = (len(link), link, target)
        return (best[1], best[2]) if best else None

    def _expand_symlinks(
        self, path: str, steps: list[ResolutionStep]
    ) -> tuple[str | None, str | None, str]:
        """返回 (最终路径, 拒绝原因, 细节)。

        环检测：记录本次展开链上已经展开过的链接节点；同一个链接节点
        第二次被展开必然成环（a -> b -> a 也能捕获）。
        """
        index = len(steps)
        expanded_links: set[str] = set()
        current = _lex_normalize(path)
        for depth in range(MAX_SYMLINK_DEPTH):
            found = self._find_link(current)
            if found is None:
                return current, None, ""
            link_path, link_target = found
            if link_path in expanded_links:
                return (
                    None,
                    DenyReason.LINK_CYCLE,
                    f"链接节点 {link_path} 在展开链中重复出现，检测到链接环",
                )
            expanded_links.add(link_path)

            suffix = current[len(link_path):] if current != link_path else ""
            resolved = link_target
            if not resolved.startswith("/"):
                # 相对链接相对于链接所在目录，而不是当前路径所在目录
                resolved = posixpath.join(posixpath.dirname(link_path), resolved)
            if suffix:
                # 直接字符串拼接：suffix 以 "/" 开头，posixpath.join 会把它当绝对路径
                resolved = resolved.rstrip("/") + suffix
            resolved = _lex_normalize(resolved)
            steps.append(
                ResolutionStep(
                    index=index,
                    kind="symlink",
                    input=current,
                    output=resolved,
                    note=f"展开符号链接 {link_path} -> {link_target}",
                )
            )
            index += 1
            current = resolved
        return None, DenyReason.LINK_CYCLE, f"符号链接展开超过最大深度 {MAX_SYMLINK_DEPTH}"

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def resolve(self, requested: str, archive_member: bool = False) -> Resolution:
        steps: list[ResolutionStep] = []
        index = 0

        if not requested or "\x00" in requested:
            return self._deny(
                requested, None, steps, DenyReason.INVALID_PATH, "路径为空或含 NUL 字节"
            )

        if archive_member:
            unsafe = _is_unsafe_archive_member(requested)
            steps.append(
                ResolutionStep(index, "normalize", requested, requested, "压缩包成员名校验")
            )
            if unsafe:
                return self._deny(requested, None, steps, DenyReason.UNSAFE_ARCHIVE_MEMBER, unsafe)
            canonical = posixpath.normpath(
                self.tenant_root + "/" + requested.replace("\\", "/")
            )
            steps.append(
                ResolutionStep(
                    index + 1, "boundary", requested, canonical, "成员名安全校验通过，映射到租户根内"
                )
            )
            return self._finish(requested, canonical, steps)

        try:
            canonical = _lex_normalize(requested)
        except (ValueError, TypeError):
            return self._deny(requested, None, steps, DenyReason.INVALID_PATH, "词法规范化失败")
        steps.append(
            ResolutionStep(index, "normalize", requested, canonical, "词法规范化（处理 . 与 ..）")
        )
        index += 1

        mounted, mount = self._apply_mount(canonical)
        if mount is not None:
            note = f"挂载别名 {mount.alias} -> {mount.target}"
            if mount.shadowed:
                note += "；该挂载已被后挂载覆盖"
            steps.append(
                ResolutionStep(index, "mount", canonical, mounted, note)
            )
            index += 1
            if mount.shadowed:
                return self._deny(requested, None, steps, DenyReason.MOUNT_SHADOWED, note)
        canonical = mounted

        expanded, reason, detail = self._expand_symlinks(canonical, steps)
        if reason is not None or expanded is None:
            return self._deny(requested, None, steps, reason or DenyReason.LINK_CYCLE, detail)
        canonical = expanded

        # 符号链接展开后可能落到另一个挂载目标上，需要再应用一次挂载，
        # 但最多两轮（挂载 -> 链接 -> 挂载），第二轮结果若仍是 shadowed 即拒绝。
        remounted, remount = self._apply_mount(canonical)
        if remount is not None and remounted != canonical:
            steps.append(
                ResolutionStep(
                    len(steps),
                    "mount",
                    canonical,
                    remounted,
                    f"链接目标落入挂载 {remount.alias} -> {remount.target}"
                    + ("；该挂载已被后挂载覆盖" if remount.shadowed else ""),
                )
            )
            if remount.shadowed:
                return self._deny(
                    requested, None, steps, DenyReason.MOUNT_SHADOWED,
                    "链接展开后命中被覆盖挂载",
                )
            canonical = remounted

        root = self.tenant_root
        if canonical != root and not canonical.startswith(root.rstrip("/") + "/"):
            steps.append(
                ResolutionStep(
                    len(steps), "boundary", canonical, canonical,
                    f"租户根边界检查失败：{canonical} 不在 {root} 之内",
                )
            )
            return self._deny(
                requested, None, steps, DenyReason.TENANT_ROOT_ESCAPE,
                f"{canonical} 越过租户根 {root}",
            )
        steps.append(
            ResolutionStep(len(steps), "boundary", canonical, canonical, f"位于租户根 {root} 之内")
        )

        return self._finish(requested, canonical, steps)

    def _finish(
        self, requested: str, canonical: str, steps: list[ResolutionStep]
    ) -> Resolution:
        resource = self.resources.get(canonical)
        if resource is None:
            steps.append(
                ResolutionStep(
                    len(steps), "lookup", canonical, canonical, "未找到已登记资源"
                )
            )
            return Resolution(
                requested_path=requested,
                canonical_path=canonical,
                tenant_id=self.tenant_id,
                steps=tuple(steps),
                resource=None,
                deny_reason=DenyReason.UNKNOWN_RESOURCE,
                deny_detail=f"{canonical} 未登记",
            )
        steps.append(
            ResolutionStep(
                len(steps), "lookup", canonical, resource.resource_id,
                f"命中资源 owner={resource.owner_id} source={resource.source} "
                f"labels={sorted(resource.labels)}",
            )
        )
        return Resolution(
            requested_path=requested,
            canonical_path=canonical,
            tenant_id=self.tenant_id,
            steps=tuple(steps),
            resource=resource,
        )

    @staticmethod
    def _deny(
        requested: str,
        canonical: str | None,
        steps: list[ResolutionStep],
        reason: str,
        detail: str,
    ) -> Resolution:
        return Resolution(
            requested_path=requested,
            canonical_path=canonical,
            tenant_id="",
            steps=tuple(steps),
            resource=None,
            deny_reason=reason,
            deny_detail=detail,
        )
