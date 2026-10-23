"""进程身份：start_ns / born_src / exec 分裂 / 退出 / §5.7 的唯一 pid 解析。

全项目只有 `resolve()` 回答“这个 pid 在 T 时刻是哪个节点”，任何动词
都不得自己实现一套（设计文档 §5.7）。

身份规则（§2.1/§5.8）：
  clone 成功 -> 子进程 start_ns = 该事件进入行时刻，born_src=clone
  exec 成功  -> 旧段在 exec 时刻结束；同 pid 新段 start_ns = exec 时刻，born_src=exec
  首次观测且无 clone/exec 记录 -> start_ns=0（未知），born_src=unknown
  同 pid 两个 unknown 段会撞主键 -> 第二段改用事件时刻，born_src=collision，并计数
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...core import args as A
from ...core import paths as P
from ...core.events import EventRow
from ...core.kinds import ProcKey


@dataclass(slots=True)
class Seg:
    key: ProcKey
    born_src: str
    order: int
    parent: ProcKey | None = None
    exited_ns: int | None = None
    exe_path: str = ""
    cmdline: str = ""
    ppid: int | None = None
    # uid = 日志列 %user.uid 的原始观测值；euid = 从 geteuid/setuid 跟踪的有效用户 id。
    uid: str = ""
    euid: int | None = None
    cwd: str = ""
    root: str = "/"
    threads: set[int] = field(default_factory=set)

    @property
    def start_ns(self) -> int:
        return self.key.start_ns


def _remember_cmdline(seg: Seg, value: str) -> None:
    """统一 cmdline 写入：只丢空值和单独一个 '-'，保留 -f/-n/-c/--wait 等真实参数。"""
    text = (value or "").strip()
    if text and text != "-":
        seg.cmdline = text


class ProcState:
    def __init__(self, host_id: str) -> None:
        self.host_id = host_id
        self._segs: dict[tuple[str, int], list[Seg]] = {}
        self._by_key: dict[ProcKey, Seg] = {}
        self._cid_by_pid: dict[int, set[str]] = {}
        self._order = 0
        self.exec_destinations: set[ProcKey] = set()
        self.clone_destinations: set[ProcKey] = set()
        self._root_targets: dict[int, str] = {}
        self.counts = {
            "born_clone": 0,
            "born_exec": 0,
            "born_unknown": 0,
            "born_collision": 0,
            "late_clone_upgrade": 0,
            "pid_resolve_tie": 0,
            "target_unresolved": 0,
            "target_pid_other_ns": 0,
            "uid_observed": 0,
            "fs_state_updates": 0,
            "fchdir_miss": 0,
            "thread_clone": 0,
            "thread_exit": 0,
            "thread_untracked": 0,
            "exit_no_segment": 0,
            "exit_tid_missing": 0,
            "late_event_after_exit": 0,
        }

    # -- 建段 ----------------------------------------------------------
    def _new(self, cid: str, pid: int, start_ns: int, src: str,
             parent: ProcKey | None = None) -> Seg:
        self._order += 1
        seg = Seg(key=ProcKey(self.host_id, cid, pid, start_ns), born_src=src, order=self._order,
                  parent=parent)
        seg.threads.add(pid)
        self._segs.setdefault((cid, pid), []).append(seg)
        self._by_key[seg.key] = seg
        self._cid_by_pid.setdefault(pid, set()).add(cid)
        self.counts["born_" + src] = self.counts.get("born_" + src, 0) + 1
        return seg

    def _live(self, cid: str, pid: int) -> Seg | None:
        for seg in reversed(self._segs.get((cid, pid), ())):
            if seg.exited_ns is None:
                return seg
        return None

    def live(self, cid: str, pid: int) -> Seg | None:
        """只读查询活段；退出路径不得借它创建新段。"""
        return self._live(cid, pid)

    def is_dead(self, cid: str, pid: int) -> bool:
        """最后一个段已退出且没有活段：后续普通事件视为迟到事件。"""
        if self._live(cid, pid) is not None:
            return False
        segs = self._segs.get((cid, pid), ())
        return bool(segs and segs[-1].exited_ns is not None)

    def observe(self, row: EventRow) -> Seg:
        """保证该行所属进程有一个活段，并刷新最后观测到的身份属性。"""
        seg = self._live(row.container_id, row.pid)
        if seg is None:
            segs = self._segs.get((row.container_id, row.pid), [])
            start_ns = 0
            src = "unknown"
            # 主键碰撞：前一个 unknown 段也占着 start_ns=0
            if segs and segs[-1].key.start_ns == 0:
                start_ns = row.ns
                src = "collision"
            seg = self._new(row.container_id, row.pid, start_ns, src)
        if row.exe:
            seg.exe_path = row.exe
        _remember_cmdline(seg, row.proc_args)
        if row.ruid:
            seg.uid = row.ruid
        if seg.ppid is None and row.ppid > 0:
            seg.ppid = row.ppid
        if not seg.cwd and row.cwd:
            # %proc.cwd 可能带内核注记（`shown(resolved)`）：先取真实路径再规整。
            # 这里不套 chroot 根：%proc.cwd 的视图层级未定，套根会重复映射。
            seg.cwd = P.normalize(P.path_value(row.cwd)) or row.cwd
        return seg

    # -- 身份事件 ------------------------------------------------------
    def on_clone(self, parent: Seg, child_pid: int, start_ns: int,
                 exe_path: str, cmdline: str) -> Seg:
        cid = parent.key.container_id
        live = self._live(cid, child_pid)
        if live is not None and live.born_src == "unknown":
            # 子进程的事件早于 clone 退出行到达：把已建的 unknown 段升级成 clone 段。
            # 旧键已经产出过的边会留下一个 start_ns=0 的节点；计入 late_clone_upgrade。
            self._by_key.pop(live.key, None)
            live.key = ProcKey(self.host_id, cid, child_pid, start_ns)
            self._by_key[live.key] = live
            live.born_src = "clone"
            live.parent = parent.key
            live.cwd = live.cwd or parent.cwd
            live.root = parent.root
            live.threads.add(child_pid)
            _remember_cmdline(live, cmdline)
            if live.euid is None:
                live.euid = parent.euid
            self.counts["born_clone"] += 1
            self.counts["born_unknown"] = max(0, self.counts["born_unknown"] - 1)
            self.counts["late_clone_upgrade"] += 1
            self.clone_destinations.add(live.key)
            return live
        seg = self._new(cid, child_pid, start_ns, "clone", parent=parent.key)
        self.clone_destinations.add(seg.key)
        seg.ppid = parent.key.pid
        seg.exe_path = exe_path
        _remember_cmdline(seg, cmdline)
        seg.cwd = parent.cwd
        seg.root = parent.root
        seg.euid = parent.euid
        return seg

    def on_exec(self, seg: Seg, start_ns: int, exe_path: str, cmdline: str) -> Seg:
        self.on_exit(seg, start_ns)
        new = self._new(seg.key.container_id, seg.key.pid, start_ns, "exec", parent=seg.parent)
        self.exec_destinations.add(new.key)
        new.ppid = seg.ppid
        new.uid = seg.uid
        new.euid = seg.euid
        new.cwd = seg.cwd
        new.root = seg.root
        new.exe_path = exe_path
        _remember_cmdline(new, cmdline)
        return new

    # -- 线程身份 ------------------------------------------------------
    def on_thread_clone(self, parent: Seg, tid: int) -> None:
        parent.threads.add(tid)
        self.counts["thread_clone"] += 1

    def on_thread_exit(self, seg: Seg, tid: int, start_ns: int) -> bool:
        """返回 True 表示最后一个线程退出，进程应结束。"""
        if tid in seg.threads:
            seg.threads.discard(tid)
        else:
            self.counts["thread_untracked"] += 1
        if seg.threads:
            self.counts["thread_exit"] += 1
            return False
        self.on_exit(seg, start_ns)
        return True

    # -- 身份属性（uid/euid）与路径状态 ---------------------------------
    def observe_uid(self, call) -> None:
        """从 geteuid/setuid/setresuid/setreuid 成功事件更新 euid。"""
        name = call.call
        if name not in ("geteuid", "setuid", "setresuid", "setreuid", "setfsuid"):
            return
        seg = self._live(call.container_id, call.pid) or self.observe(call.head_row)
        if name == "geteuid":
            row = call.exit or call.head_row
            value = A.int_of(row.args.get("euid"))
            if value is not None and value >= 0:
                seg.euid = value
                self.counts["uid_observed"] += 1
            return

        result = call.result
        if result is not None and result < 0:
            return
        keys = {
            "setuid": ("uid",),
            "setresuid": ("euid",),
            "setreuid": ("euid", "uid"),
            "setfsuid": ("fsuid",),
        }.get(name, ())
        for key in keys:
            value = A.int_of(call.args.get(key))
            if value is not None and value >= 0:
                seg.euid = value
                self.counts["uid_observed"] += 1
                return

    def note_root_target(self, event_num: int, path: str) -> None:
        """handler 已解析出的 chroot/pivot_root 目标（宿主视图），交由状态更新消费。

        单一来源：路径只解析一次（`ObjectResolver.resolve_path`），状态不再自己重算，
        从结构上消除“建点用一条路径、进程状态用另一条路径”的分裂。
        """
        if len(self._root_targets) > 4096:
            self._root_targets.clear()
        self._root_targets[event_num] = path

    def take_root_target(self, event_num: int) -> str:
        return self._root_targets.pop(event_num, "")

    def on_exit(self, seg: Seg, start_ns: int) -> None:
        if seg.exited_ns is None:
            seg.exited_ns = start_ns
        seg.threads.clear()

    # -- 解析（§5.7）---------------------------------------------------
    def resolve(self, cid: str, pid: int, at_ns: int) -> Seg | None:
        best: Seg | None = None
        ties = 0
        for seg in self._segs.get((cid, pid), ()):
            if seg.key.start_ns > at_ns:
                continue
            if seg.exited_ns is not None and seg.exited_ns <= at_ns:
                continue
            if best is None or (seg.key.start_ns, seg.order) > (best.key.start_ns, best.order):
                if best is not None and seg.key.start_ns == best.key.start_ns:
                    ties += 1
                best = seg
        if best is None:
            self.counts["target_unresolved"] += 1
            if pid in self._cid_by_pid and cid not in self._cid_by_pid[pid]:
                # 该 pid 在别的容器里存在：PID 命名空间错配的强信号
                self.counts["target_pid_other_ns"] += 1
            return None
        if ties:
            self.counts["pid_resolve_tie"] += 1
        return best

    def resolve_or_none(self, cid: str, pid: int, at_ns: int) -> ProcKey | None:
        seg = self.resolve(cid, pid, at_ns)
        return seg.key if seg is not None else None

    def get(self, key: ProcKey) -> Seg | None:
        return self._by_key.get(key)

    def parent_of(self, seg: Seg, at_ns: int | None = None) -> ProcKey | None:
        if seg.parent is not None:
            return seg.parent
        if seg.ppid and seg.ppid > 0:
            # 解析时刻取调用时刻：born_src=unknown 的段 start_ns=0，
            # 若拿 0 去解析，会把"捕获内出生、实际更晚"的父进程排除掉。
            at = at_ns if at_ns is not None else (seg.exited_ns or seg.key.start_ns)
            parent = self.resolve(seg.key.container_id, seg.ppid, at)
            return parent.key if parent else None
        return None

    # -- 报告 ----------------------------------------------------------
    def segments(self):
        for group in self._segs.values():
            for seg in group:
                yield seg

    def identity_stats(self) -> dict[str, int]:
        """按 (container, pid) 聚合身份段，区分合法 exec 与无 exec 的重复段。"""
        groups: dict[tuple[str, int], list[Seg]] = {}
        for (cid, pid), segs in self._segs.items():
            groups[(cid, pid)] = list(segs)

        extra = extra_exec = extra_clone = 0
        placeholders = unexplained = 0
        multi = 0
        for segs in groups.values():
            if len(segs) <= 1:
                continue
            multi += 1
            has_clone = any(s.key in self.clone_destinations for s in segs)
            for seg in segs:
                if (seg.key.start_ns == 0
                        and seg.key not in self.clone_destinations
                        and seg.key not in self.exec_destinations
                        and has_clone):
                    placeholders += 1
            for seg in sorted(segs, key=lambda s: s.key.start_ns)[1:]:
                extra += 1
                if seg.key in self.exec_destinations:
                    extra_exec += 1
                elif seg.key in self.clone_destinations:
                    extra_clone += 1
                elif seg.key.start_ns != 0 or not has_clone:
                    unexplained += 1

        return {
            "unique_pids": len(groups),
            "segments": sum(len(v) for v in groups.values()),
            "multi_node_groups": multi,
            "extra_segments": extra,
            "extra_with_exec": extra_exec,
            "extra_with_clone": extra_clone,
            "late_clone_placeholders": placeholders,
            "unexplained_segments": unexplained,
        }

    def stats(self) -> dict[str, int]:
        out = dict(self.counts)
        out.update(self.identity_stats())
        return out
