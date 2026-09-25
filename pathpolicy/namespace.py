"""文件命名空间解析器。

把同一份文档的各种访问形态——绝对路径、符号链接、挂载别名、压缩包成员名——
统一解析为规范化路径，并记录逐步解析链。解析失败时抛出带稳定原因码的拒绝：

- LINK_LOOP：符号链接成环，或展开次数超过安全上限；
- TENANT_ROOT_ESCAPE：词法规范化越出租户根，或压缩包成员路径越出压缩包根；
- MOUNT_SHADOWED：符号链接目标被更晚的挂载覆盖，无法确定链接注册时指向的对象；
- RESOURCE_NOT_FOUND：组件、成员或挂载不存在。

遮蔽检查的语义：节点（含符号链接）注册于所属挂载的视图版本 mount_seq；
当链接展开后的目标路径命中 mount_seq 更大的挂载时，说明该目标在链接注册
之后被后挂载覆盖，链接创建者意图指向的对象已不可确定，默认拒绝。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import errors
from .models import ARCHIVE, SYMLINK, Mount, NamespaceView, Node, Resolution

MAX_LINK_EXPANSIONS = 40  # 安全上限：防止链接链无限展开


class _Reject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class _State:
    """一次解析过程中的可变状态：链接展开计数与展开中的链接栈（环检测）。"""

    expansions: int = 0
    link_stack: set[str] = field(default_factory=set)


class Resolver:
    """对单个租户的命名空间视图做路径解析。视图在解析期间不可变。"""

    def __init__(self, view: NamespaceView):
        self._view = view
        # 最长前缀优先；同前缀时后挂载（序号大者）生效
        self._mounts = sorted(view.mounts, key=lambda m: (-len(m.prefix), -m.seq))

    def resolve(self, raw_path: str) -> Resolution:
        chain: list[dict] = []
        try:
            mount, node = self._resolve_path(raw_path, chain, _State(), via_seq=None)
        except _Reject as exc:
            return Resolution(ok=False, reason=exc.reason, chain=chain)
        canonical = _join(mount.prefix, node.canonical_rel)
        return Resolution(ok=True, reason=None, chain=chain, node=node, mount=mount, canonical_path=canonical)

    # ------------------------------------------------------------------
    # 命名空间层：词法规范化 -> 挂载匹配 -> 树内行走
    # ------------------------------------------------------------------

    def _resolve_path(self, path: str, chain: list[dict], state: _State, via_seq: int | None) -> tuple[Mount, Node]:
        components = _lexical(path, chain)
        mount = self._match_mount(components)
        if mount is None:
            raise _Reject(errors.RESOURCE_NOT_FOUND)
        if via_seq is not None and mount.seq > via_seq:
            chain.append({"step": "mount-shadowed", "prefix": mount.prefix, "mount_seq": mount.seq, "registered_seq": via_seq})
            raise _Reject(errors.MOUNT_SHADOWED)
        chain.append({"step": "mount", "prefix": mount.prefix, "source": mount.source, "mount_seq": mount.seq})
        inner = components[len(_split(mount.prefix)):]
        return mount, self._walk(mount, mount.root, [], inner, chain, state, in_archive=False)

    def _match_mount(self, components: list[str]) -> Mount | None:
        for mount in self._mounts:
            prefix_parts = _split(mount.prefix)
            if components[: len(prefix_parts)] == prefix_parts:
                return mount
        return None

    # ------------------------------------------------------------------
    # 树内行走：目录、符号链接、压缩包成员
    # ------------------------------------------------------------------

    def _walk(
        self,
        mount: Mount,
        root: Node,
        base: list[str],
        components: list[str],
        chain: list[dict],
        state: _State,
        in_archive: bool,
    ) -> Node:
        """从 root 出发解析 components。base 是当前节点相对 root 的组件路径。"""
        node = root
        node_comps = list(base)
        i = 0
        while i < len(components):
            name = components[i]
            child = node.children.get(name)
            if child is None:
                raise _Reject(errors.RESOURCE_NOT_FOUND)
            chain.append({"step": "component", "name": name, "node": child.node_id, "kind": child.kind})
            rest = components[i + 1 :]

            if child.kind == SYMLINK:
                target = child.link_target or ""
                chain.append({"step": "symlink", "node": child.node_id, "target": target})
                self._enter_link(child, state)
                try:
                    if target.startswith("/") and not in_archive:
                        # 绝对路径：回到命名空间根重新解析，并做后挂载遮蔽检查
                        jumped = target if not rest else target.rstrip("/") + "/" + "/".join(rest)
                        _, resolved = self._resolve_path(jumped, chain, state, via_seq=child.mount_seq)
                        return resolved
                    # 相对路径相对链接所在目录展开；压缩包内的绝对路径相对压缩包根展开
                    origin = [] if target.startswith("/") else node_comps
                    merged = _merge(origin, _split(target) + rest)
                    return self._walk(mount, root, [], merged, chain, state, in_archive)
                finally:
                    state.link_stack.discard(child.node_id)

            if child.kind == ARCHIVE and rest:
                chain.append({"step": "archive", "node": child.node_id, "member": "/".join(rest)})
                # 压缩包成员路径不允许越出压缩包根；成员树作为子树继续行走
                return self._walk(mount, child, [], rest, chain, state, in_archive=True)

            node = child
            node_comps.append(name)
            i += 1
        return node

    @staticmethod
    def _enter_link(node: Node, state: _State) -> None:
        state.expansions += 1
        if state.expansions > MAX_LINK_EXPANSIONS or node.node_id in state.link_stack:
            raise _Reject(errors.LINK_LOOP)
        state.link_stack.add(node.node_id)


# ----------------------------------------------------------------------
# 词法工具
# ----------------------------------------------------------------------


def _split(path: str) -> list[str]:
    return [p for p in path.split("/") if p not in ("", ".")]


def _join(prefix: str, rel: str) -> str:
    if not rel:
        return prefix
    return prefix.rstrip("/") + "/" + rel if prefix != "/" else "/" + rel


def _lexical(path: str, chain: list[dict]) -> list[str]:
    """词法规范化：折叠 "." 与重复分隔符，弹出 ".."；弹出租户根即拒绝。"""
    if not path.startswith("/"):
        raise _Reject(errors.INVALID_REQUEST)
    stack: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                chain.append({"step": "escape", "input": path})
                raise _Reject(errors.TENANT_ROOT_ESCAPE)
            stack.pop()
        else:
            stack.append(part)
    chain.append({"step": "normalize", "input": path, "output": "/" + "/".join(stack)})
    return stack


def _merge(base: list[str], parts: list[str]) -> list[str]:
    """把链接目标组件合并到基准目录上，处理 ".."；越出基准根即拒绝。"""
    stack = list(base)
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise _Reject(errors.TENANT_ROOT_ESCAPE)
            stack.pop()
        else:
            stack.append(part)
    return stack
