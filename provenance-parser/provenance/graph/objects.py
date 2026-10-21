"""客体解析：fd/路径 -> 节点键。

只回答“这个客体是哪个节点”；边方向由 graph/flow.py 负责。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core import args as A
from ..core import paths as P
from ..core.events import Call
from ..core.kinds import Bucket, FileKey, NetKey
from .state import State
from .state.fds import FdEntry


@dataclass(frozen=True, slots=True)
class ResolvedObject:
    kind: str  # file / network / none
    key: FileKey | NetKey | None = None
    node_kind: str = ""
    proto: str = ""
    bucket: Bucket = Bucket.OTHER
    reason: str = ""


AT_FDCWD = -100


class ObjectResolver:
    def __init__(self, state: State) -> None:
        self.st = state
        self.counts = {"path_unresolved": 0, "fd_from_token": 0}

    # -- 路径 ----------------------------------------------------------
    def _seg(self, call: Call):
        return self.st.proc.observe(call.head_row)

    def _cwd(self, call: Call) -> str:
        seg = self._seg(call)
        return seg.cwd or call.head_row.cwd or ""

    def _root(self, call: Call) -> str:
        return self._seg(call).root or "/"

    @staticmethod
    def _apply_root(value: str, root: str) -> str:
        if not value.startswith("/") or not root or root == "/":
            return value
        prefix = root.rstrip("/")
        if value == prefix or value.startswith(prefix + "/"):
            return value
        return P.normalize(prefix + value)

    def _base_dir(self, call: Call, dirfd_key: str | None) -> str | None:
        """返回相对路径的基目录。

        ``None`` 表示调用了 dirfd 但无法解析（表里没有、token 里也没有路径）：
        调用方必须放弃该路径，不能回退 cwd 去猜。
        """
        if not dirfd_key:
            return self._cwd(call)
        raw = call.args.get(dirfd_key)
        if not raw:
            return self._cwd(call)
        fd = A.int_of(raw)
        if fd is None:
            self.st.fds.counts["dirfd_miss"] += 1
            return None
        if fd == AT_FDCWD:
            return self._cwd(call)
        path = self.st.fds.dir_path(call.container_id, call.pid, fd)
        if path:
            return path
        # 表里没有，但 dirfd token 本身可能带 <d>/path：用它兜底。
        token = A.fd_of(raw)
        if (token is not None and token.kind == "directory"
                and not A.is_unknown_name(token.name)):
            self.st.fds.counts["dirfd_from_token"] += 1
            return token.name
        self.st.fds.counts["dirfd_miss"] += 1
        return None

    def norm_path(self, raw: str, call: Call, dirfd_key: str | None = None) -> str:
        if not raw:
            return ""
        value = P.path_value(raw)
        if not value or A.is_unknown_name(value):
            return ""
        root = self._root(call)
        if value.startswith("/"):
            return self._apply_root(P.normalize(value), root)
        base = self._base_dir(call, dirfd_key)
        if base is None:
            # dirfd 不可解析：不建节点，不拿 cwd 猜。
            self.counts["path_unresolved"] += 1
            return ""
        if not base:
            self.counts["path_unresolved"] += 1
            return "?" + value
        return self._apply_root(P.normalize(value, base), root)

    def path_arg(self, call: Call, *keys: str,
                 dirfd_key: str | None = None) -> str:
        for key in keys:
            raw = call.args.get(key, "")
            if raw:
                path = self.norm_path(raw, call, dirfd_key)
                if path:
                    return path
        return ""

    def by_path(self, call: Call, *keys: str,
                dirfd_key: str | None = None) -> ResolvedObject:
        path = self.path_arg(call, *keys, dirfd_key=dirfd_key)
        if not path:
            return ResolvedObject("none", bucket=Bucket.OTHER, reason="path_unresolved")
        return ResolvedObject(
            "file", FileKey(self.st.host_id, call.container_id, path)
        )

    # -- fd ------------------------------------------------------------
    def fd_entry_value(
        self, call: Call, value: str
    ) -> tuple[A.Fd | None, FdEntry | None]:
        fd = A.fd_of(value)
        if fd is None:
            return None, None
        entry = self.st.fds.get(call.container_id, call.pid, fd.num)
        if entry is not None:
            self.st.fds.counts["fd_table_hit"] += 1
        elif fd.name and not A.is_unknown_name(fd.name):
            entry = FdEntry(kind=fd.kind, name=fd.name, proto=fd.proto)
            self.counts["fd_from_token"] += 1
            self.st.fds.counts["fd_from_token"] += 1
        return fd, entry

    def fd_entry(self, call: Call, key: str = "fd") -> tuple[A.Fd | None, FdEntry | None]:
        return self.fd_entry_value(call, call.args.get(key, ""))

    def from_entry(
        self,
        call: Call,
        fd: A.Fd,
        entry: FdEntry,
        *,
        unix_bucket: Bucket = Bucket.OTHER,
    ) -> ResolvedObject:
        proto = entry.proto or fd.proto
        if entry.kind in ("ipv4", "ipv6"):
            if not A.tuple_usable(entry.name, session=True):
                return ResolvedObject("none", bucket=Bucket.OTHER, reason="tuple_unusable")
            return ResolvedObject(
                "network",
                NetKey(self.st.host_id, entry.name),
                proto=proto,
            )
        if entry.kind == "unix":
            path = A.unix_path(entry.name)
            if not path:
                return ResolvedObject("none", bucket=unix_bucket, reason="unix_unusable")
            path = self._apply_root(P.normalize(path), self._root(call))
            return ResolvedObject(
                "file",
                FileKey(self.st.host_id, call.container_id, path),
                node_kind="unix",
            )
        if entry.kind == "memfd":
            if A.is_unknown_name(entry.name):
                return ResolvedObject("none", bucket=Bucket.OTHER, reason="unknown_name")
            path = (entry.name if entry.name.startswith("memfd:")
                    else f"memfd:{entry.name}")
            return ResolvedObject(
                "file",
                FileKey(self.st.host_id, call.container_id, path),
                node_kind="memfd",
            )
        if A.is_unknown_name(entry.name):
            return ResolvedObject("none", bucket=Bucket.OTHER, reason="unknown_name")
        return ResolvedObject(
            "file",
            FileKey(self.st.host_id, call.container_id, entry.name),
            node_kind=entry.kind,
        )

    def by_fd_value(self, call: Call, value: str) -> ResolvedObject:
        fd, entry = self.fd_entry_value(call, value)
        if fd is None or entry is None:
            return ResolvedObject("none", bucket=Bucket.UNKNOWN_FD, reason="fd_unknown")
        return self.from_entry(call, fd, entry)

