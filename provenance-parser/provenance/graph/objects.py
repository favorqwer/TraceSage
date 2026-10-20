"""客体解析与统一流向：fd/路径 -> 节点键 -> 边。

这是“fd 是文件还是套接字、应该建 p2f 还是 p2n”的唯一入口。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core import args as A
from ..core import paths as P
from ..core.events import Call
from ..core.graph import Outcome
from ..core.kinds import Bucket, EdgeClass, FileKey, NetKey
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


class ObjectResolver:
    def __init__(self, state: State) -> None:
        self.st = state
        self.counts = {"path_unresolved": 0, "fd_from_token": 0}

    # -- 路径 ----------------------------------------------------------
    def norm_path(self, raw: str, call: Call) -> str:
        if not raw:
            return ""
        value = P.path_value(raw)
        if not value or A.is_unknown_name(value):
            return ""
        cwd = call.head_row.cwd or ""
        if not value.startswith("/") and not cwd:
            self.counts["path_unresolved"] += 1
            return ""
        return P.normalize(value, cwd)

    def path_arg(self, call: Call, *keys: str) -> str:
        for key in keys:
            raw = call.args.get(key, "")
            if raw:
                path = self.norm_path(raw, call)
                if path:
                    return path
        return ""

    def by_path(self, call: Call, *keys: str) -> ResolvedObject:
        path = self.path_arg(call, *keys)
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
        if entry is None and fd.name and not A.is_unknown_name(fd.name):
            entry = FdEntry(kind=fd.kind, name=fd.name, proto=fd.proto)
            self.counts["fd_from_token"] += 1
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
            return ResolvedObject(
                "file",
                FileKey(self.st.host_id, call.container_id, path),
                node_kind="unix",
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

    # -- 统一流向 ------------------------------------------------------
    def flow(self, ctx, out: Outcome, call: Call, obj: ResolvedObject,
             action: str, head: bool, res: int | None) -> Bucket:
        if obj.kind == "none":
            return obj.bucket

        if obj.kind == "network":
            node = ctx.graph.net_node(obj.key.tuple, obj.proto)
            if node is None:
                return Bucket.OTHER
            ctx.graph.attach(out, node)
            if action in ("read", "recv"):
                ctx.graph.add(out, ctx.graph.edge(
                    EdgeClass.N2P, "recv", node.key, ctx.key(call),
                    call, res=res, head=head,
                ))
            else:
                ctx.graph.add(out, ctx.graph.edge(
                    EdgeClass.P2N, "send", ctx.key(call), node.key,
                    call, res=res, head=head,
                ))
            return Bucket.COVERED

        node = ctx.graph.file_node(
            call.container_id, obj.key.path, obj.node_kind
        )
        if node is None:
            return Bucket.OTHER
        ctx.graph.attach(out, node)
        if action in ("read", "probe", "mmap", "load_image", "recv"):
            ctx.graph.add(out, ctx.graph.edge(
                EdgeClass.F2P, action, node.key, ctx.key(call),
                call, res=res, head=head,
            ))
        else:
            ctx.graph.add(out, ctx.graph.edge(
                EdgeClass.P2F, action, ctx.key(call), node.key,
                call, res=res, head=head,
            ))
        if action in ("read", "write"):
            ctx.derive_proc(out, call, node.key, action, ctx.key(call))
        return Bucket.COVERED
