"""进程身份：born_ns / born_src / exec 分裂 / 退出 / §5.7 的唯一 pid 解析。

全项目只有 `resolve()` 回答"这个 pid 在 T 时刻是哪个节点"，任何动词
都不得自己实现一套（设计文档 §5.7）。

身份规则（§2.1/§5.8）：
  clone 成功 -> 子进程 born_ns = 该事件进入行时刻，born_src=clone
  exec 成功  -> 旧段在 exec 时刻结束；同 pid 新段 born_ns = exec 时刻，born_src=exec
  首次观测且无 clone/exec 记录 -> born_ns=0（未知），born_src=unknown
  同 pid 两个 unknown 段会撞主键 -> 第二段改用事件时刻，born_src=collision，并计数
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.events import EventRow
from ...core.kinds import ProcKey


@dataclass(slots=True)
class Seg:
    key: ProcKey
    born_src: str
    seq: int
    parent: ProcKey | None = None
    exited_ns: int | None = None
    exe: str = ""
    cmdline: str = ""
    ppid: int | None = None
    ruid: str = ""

    @property
    def born_ns(self) -> int:
        return self.key.born_ns


class ProcState:
    def __init__(self, host_id: str) -> None:
        self.host_id = host_id
        self._segs: dict[tuple[str, int], list[Seg]] = {}
        self._by_key: dict[ProcKey, Seg] = {}
        self._cid_by_pid: dict[int, set[str]] = {}
        self._seq = 0
        self.counts = {
            "born_clone": 0,
            "born_exec": 0,
            "born_unknown": 0,
            "born_collision": 0,
            "late_clone_upgrade": 0,
            "pid_resolve_tie": 0,
            "target_unresolved": 0,
            "target_pid_other_ns": 0,
        }

    # -- 建段 ----------------------------------------------------------
    def _new(self, cid: str, pid: int, born_ns: int, src: str,
             parent: ProcKey | None = None) -> Seg:
        self._seq += 1
        seg = Seg(key=ProcKey(self.host_id, cid, pid, born_ns), born_src=src, seq=self._seq,
                  parent=parent)
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

    def observe(self, row: EventRow) -> Seg:
        """保证该行所属进程有一个活段，并刷新最后观测到的身份属性。"""
        seg = self._live(row.container_id, row.pid)
        if seg is None:
            segs = self._segs.get((row.container_id, row.pid), [])
            born = 0
            src = "unknown"
            # 主键碰撞：前一个 unknown 段也占着 born_ns=0
            if segs and segs[-1].key.born_ns == 0:
                born = row.ns
                src = "collision"
            seg = self._new(row.container_id, row.pid, born, src)
        if row.exe:
            seg.exe = row.exe
        if row.cmdline and not row.cmdline.startswith("-"):
            seg.cmdline = row.cmdline
        if row.ruid:
            seg.ruid = row.ruid
        if seg.ppid is None and row.ppid > 0:
            seg.ppid = row.ppid
        return seg

    # -- 身份事件 ------------------------------------------------------
    def on_clone(self, parent: Seg, child_pid: int, ts_ns: int,
                 exe: str, cmdline: str) -> Seg:
        cid = parent.key.container_id
        live = self._live(cid, child_pid)
        if live is not None and live.born_src == "unknown":
            # 子进程的事件早于 clone 退出行到达：把已建的 unknown 段升级成 clone 段。
            # 旧键已经产出过的边会留下一个 born_ns=0 的节点；计入 late_clone_upgrade。
            self._by_key.pop(live.key, None)
            live.key = ProcKey(self.host_id, cid, child_pid, ts_ns)
            self._by_key[live.key] = live
            live.born_src = "clone"
            live.parent = parent.key
            self.counts["born_clone"] += 1
            self.counts["born_unknown"] = max(0, self.counts["born_unknown"] - 1)
            self.counts["late_clone_upgrade"] += 1
            return live
        seg = self._new(cid, child_pid, ts_ns, "clone", parent=parent.key)
        seg.ppid = parent.key.pid
        seg.exe = exe
        seg.cmdline = cmdline
        return seg

    def on_exec(self, seg: Seg, ts_ns: int, exe: str, cmdline: str) -> Seg:
        seg.exited_ns = seg.exited_ns if seg.exited_ns is not None else ts_ns
        new = self._new(seg.key.container_id, seg.key.pid, ts_ns, "exec", parent=seg.parent)
        new.ppid = seg.ppid
        new.ruid = seg.ruid
        new.exe = exe
        new.cmdline = cmdline
        return new

    def on_exit(self, seg: Seg, ts_ns: int) -> None:
        if seg.exited_ns is None:
            seg.exited_ns = ts_ns

    # -- 解析（§5.7）---------------------------------------------------
    def resolve(self, cid: str, pid: int, at_ns: int) -> Seg | None:
        best: Seg | None = None
        ties = 0
        for seg in self._segs.get((cid, pid), ()):
            if seg.key.born_ns > at_ns:
                continue
            if seg.exited_ns is not None and seg.exited_ns <= at_ns:
                continue
            if best is None or (seg.key.born_ns, seg.seq) > (best.key.born_ns, best.seq):
                if best is not None and seg.key.born_ns == best.key.born_ns:
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
            # 解析时刻取调用时刻：born_src=unknown 的段 born_ns=0，
            # 若拿 0 去解析，会把"捕获内出生、实际更晚"的父进程排除掉。
            at = at_ns if at_ns is not None else (seg.exited_ns or seg.key.born_ns)
            parent = self.resolve(seg.key.container_id, seg.ppid, at)
            return parent.key if parent else None
        return None

    # -- 报告 ----------------------------------------------------------
    def segments(self):
        for group in self._segs.values():
            for seg in group:
                yield seg

    def stats(self) -> dict[str, int]:
        out = dict(self.counts)
        out["segments"] = sum(len(v) for v in self._segs.values())
        return out
