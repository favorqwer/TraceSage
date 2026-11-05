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
from .state.fds import FdEntry, FileTarget, NetTarget, SyntheticTarget, FdTarget


@dataclass(frozen=True, slots=True)
class ResolvedObject:
    kind: str  # file / network / none
    key: FileKey | NetKey | None = None
    node_kind: str = ""
    proto: str = ""
    bucket: Bucket = Bucket.OTHER
    reason: str = ""


AT_FDCWD = -100

# 合成键前缀：这些名字不是文件系统路径，绝不交给路径规整（normpath 会把它们改写）
_SYNTHETIC_PREFIXES = ("pipe:[", "socket:[", "netlink:[", "unix:[", "memfd:")
# 未建模成 :File 节点的 fd 类型（由上层的 file_kind_of 拒建，这里只保证名字不被规整）
_UNMODELED_KINDS = frozenset({
    "socket", "netlink", "event", "timerfd", "signalfd", "inotify",
    "eventpoll", "bpf", "other",
})


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
        shown, resolved = P.parse_path_arg(raw)
        value = resolved or shown
        if not value or A.is_unknown_name(value):
            return ""
        root = self._root(call)
        if value.startswith("/"):
            # 注记里的解析路径是“进程根内绝对路径”，统一映射到宿主视图
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

    # -- 进程文件系统状态 ------------------------------------------------
    def observe_fs(self, call: Call) -> None:
        """维护 cwd / chroot 根；必须在 handler 解析完本次路径之后调用。

        chroot/pivot_root 的目标由 handler 解析一次并落到 `ProcState.note_root_target`，
        本方法只消费该结果，不再自己重算（单一来源）。chdir 不建节点，走同一个
        `norm_path` 解析（含注记剥离、相对拼接、chroot 映射）。
        """
        name = call.call
        if name not in ("chdir", "fchdir", "chroot", "pivot_root"):
            return
        result = call.result
        if result is None or result < 0:
            return
        proc = self.st.proc
        seg = proc.live(call.container_id, call.pid) or proc.observe(call.head_row)

        if name == "fchdir":
            fd = A.fd_of(call.args.get("fd"))
            path = ""
            if fd is not None:
                path = self.st.fds.dir_path(call.container_id, call.pid, fd.num)
                if not path and (fd.kind == "directory"
                                 and not A.is_unknown_name(fd.name)):
                    # 表里没有，但事件 token 带 <d>/path：用同一解析器兜底。
                    path = self.norm_path(fd.name, call)
                    self.st.fds.counts["fchdir_from_token"] += 1
            if path:
                seg.cwd = path
                proc.counts["fs_state_updates"] += 1
            else:
                self.st.fds.counts["fchdir_miss"] += 1
            return

        if name in ("chroot", "pivot_root"):
            value = proc.take_root_target(call.head_row.num)
            if not value:
                value = self.path_arg(call, "path", "filename", "name",
                                      "newroot", "new_root")
            if value:
                seg.root = value
                proc.counts["fs_state_updates"] += 1
            return

        value = self.path_arg(call, "path", "filename", "name",
                              "newroot", "new_root")
        if value:
            seg.cwd = value
            proc.counts["fs_state_updates"] += 1

    def by_path(self, call: Call, *keys: str,
                dirfd_key: str | None = None) -> ResolvedObject:
        path = self.path_arg(call, *keys, dirfd_key=dirfd_key)
        if not path:
            return ResolvedObject("none", bucket=Bucket.OTHER, reason="path_unresolved")
        return ResolvedObject(
            "file", FileKey(self.st.host_id, call.container_id, path)
        )

    # -- fd ------------------------------------------------------------
    def target_from_token(
        self, call: Call, fd: A.Fd, *, kind: str = "", name: str = ""
    ) -> FdTarget | None:
        """fd token / 已解析路径 -> 句柄客体（句柄表唯一的构造入口）。

        - `ipv4/ipv6` -> `NetTarget`；`unix` -> 解析并套 chroot 根的 `FileTarget`；
        - 合成键（`pipe:[…]`、`socket:[…]`、`netlink:[…]`、`memfd:…`）原样保留，不进路径规整；
        - 其余（file / directory / 未知）走 `norm_path`：剥注记 + 相对拼接 + chroot 映射。

        `_apply_root` 自带前缀幂等判断，所以传入已解析路径也不会重复套根。
        """
        k = (kind or fd.kind or "").strip()
        raw = name or fd.name or ""

        if k in ("ipv4", "ipv6"):
            return NetTarget(raw, k, fd.proto) if raw else None

        if k == "unix":
            path = A.unix_path(raw)
            if not path:
                return None
            return FileTarget(
                self._apply_root(P.normalize(path), self._root(call)), "unix"
            )

        if any(raw.startswith(prefix) for prefix in _SYNTHETIC_PREFIXES):
            synth = "memfd" if raw.startswith("memfd:") else (k or "other")
            return SyntheticTarget(raw, synth)

        if k == "memfd":
            if A.is_unknown_name(raw):
                return None
            text = raw if raw.startswith("memfd:") else f"memfd:{raw}"
            return SyntheticTarget(text, "memfd")

        if k in _UNMODELED_KINDS:
            # socket / netlink / event 等匿名 IPC：保留名字，由上层的 file_kind_of
            # 决定不建节点（与既有行为一致），但绝不把它当文件系统路径规整。
            return SyntheticTarget(raw, k) if raw else None

        if not raw or A.is_unknown_name(raw):
            return None
        path = self.norm_path(raw, call)
        if not path:
            return None
        return FileTarget(path, k or "unknown")

    def fd_entry_value(
        self, call: Call, value: str
    ) -> tuple[A.Fd | None, FdEntry | None]:
        fd = A.fd_of(value)
        if fd is None:
            return None, None
        entry = self.st.fds.get(call.container_id, call.pid, fd.num)
        if entry is not None:
            self.st.fds.counts["fd_table_hit"] += 1
            return fd, entry
        if fd.name and not A.is_unknown_name(fd.name):
            target = self.target_from_token(call, fd)
            if target is not None:
                self.counts["fd_from_token"] += 1
                self.st.fds.counts["fd_from_token"] += 1
                return fd, FdEntry(target, fd.proto)
        return fd, None

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
        """句柄客体 -> 节点键。`target` 已解析，这里不做任何路径判断。"""
        target = entry.target
        if target is None:
            bucket = unix_bucket if fd.kind == "unix" else Bucket.UNKNOWN_FD
            reason = "unix_unusable" if fd.kind == "unix" else "fd_unknown"
            return ResolvedObject("none", bucket=bucket, reason=reason)
        if isinstance(target, NetTarget):
            if not A.tuple_usable(target.endpoints, session=True):
                return ResolvedObject("none", bucket=Bucket.OTHER, reason="tuple_unusable")
            return ResolvedObject(
                "network",
                NetKey(self.st.host_id, target.endpoints),
                proto=target.proto or entry.proto or fd.proto,
            )
        if isinstance(target, FileTarget):
            return ResolvedObject(
                "file",
                FileKey(self.st.host_id, call.container_id, target.path),
                node_kind=target.kind,
            )
        return ResolvedObject(
            "file",
            FileKey(self.st.host_id, call.container_id, target.name),
            node_kind=target.kind,
        )

    def by_fd_value(self, call: Call, value: str) -> ResolvedObject:
        fd, entry = self.fd_entry_value(call, value)
        if fd is None or entry is None:
            return ResolvedObject("none", bucket=Bucket.UNKNOWN_FD, reason="fd_unknown")
        return self.from_entry(call, fd, entry)

