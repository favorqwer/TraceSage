"""事件读取模型：一行 sysdig 输出，以及一次逻辑调用。"""

from __future__ import annotations

from dataclasses import dataclass

from . import args as A


@dataclass(slots=True)
class EventRow:
    """一行 sysdig 输出。

    只保留无条件字段与 evt.args —— 条件字段（fd.name / fd.type / rawres）
    一律从 args 解，原因见 README 的实测注释。
    """

    num: int
    ns: int
    direction: str  # ">" 进入行 / "<" 退出行
    call: str
    pid: int
    tid: int
    container_id: str
    exe: str
    cwd: str
    ppid: int
    ruid: str
    proc_args: str
    args: dict[str, str]
    rawres: int | None = None
    buffer_b64: str = ""
    # 退出行的 evt.latency（纳秒）；缺失为 None。配对用 end_ns - latency 反推开始时刻。
    latency_ns: int | None = None
    na_fields: frozenset[str] = frozenset()

    @property
    def is_enter(self) -> bool:
        return self.direction == ">"


@dataclass(slots=True)
class Call:
    """一次逻辑调用：进入行 + 退出行（孤儿行只有一侧）。"""

    call: str
    enter: EventRow | None
    exit: EventRow | None
    args: dict[str, str]
    rawres: int | None = None
    buffer_b64: str = ""

    @classmethod
    def build(cls, enter: EventRow | None, exit: EventRow | None) -> "Call":
        merged: dict[str, str] = {}
        for row in (enter, exit):
            if row is None:
                continue
            for key, value in row.args.items():
                if value != "":
                    merged[key] = value
        name = (enter or exit).call  # type: ignore[union-attr]
        # 结果只取退出行：进入行在内核 ABI 里没有返回值，若回退到进入行
        # 的 %evt.rawres，会把"未观测"写成"实测零"（§3.2 三态语义）。
        rawres = exit.rawres if exit is not None else None
        buffer_b64 = ""
        for row in (exit, enter):
            if row is not None and row.buffer_b64:
                buffer_b64 = row.buffer_b64
                break
        return cls(
            call=name,
            enter=enter,
            exit=exit,
            args=merged,
            rawres=rawres,
            buffer_b64=buffer_b64,
        )

    @property
    def head_row(self) -> EventRow:
        return self.enter or self.exit  # type: ignore[return-value]

    @property
    def tail_row(self) -> EventRow | None:
        return self.exit

    @property
    def pid(self) -> int:
        return self.head_row.pid

    @property
    def tid(self) -> int:
        return self.head_row.tid

    @property
    def container_id(self) -> str:
        return self.head_row.container_id

    @property
    def start_ns(self) -> int:
        return self.head_row.ns

    @property
    def end_ns(self) -> int:
        return self.exit.ns if self.exit is not None else self.head_row.ns

    @property
    def event_id(self) -> int:
        return self.head_row.num

    @property
    def rows(self) -> list[int]:
        return [row.num for row in (self.enter, self.exit) if row is not None]

    def text(self, key: str) -> str:
        return self.args.get(key, "")

    def has(self, key: str) -> bool:
        return bool(self.args.get(key))

    def number(self, key: str) -> int | None:
        value = self.args.get(key)
        return A.int_of(value) if value else None

    @property
    def result_source(self) -> str | None:
        """结果取自哪个字段：rawres（%evt.rawres）/ args（evt.args 的 res=）/ 无。"""
        if self.rawres is not None:
            return "rawres"
        if self.number("res") is not None:
            return "args"
        return None

    @property
    def result(self) -> int | None:
        """统一结果：优先退出行 %evt.rawres，缺失时回退 evt.args 的 res=。"""
        if self.rawres is not None:
            return self.rawres
        return self.number("res")


@dataclass(slots=True)
class BadRow:
    line_no: int
    reason: str
    sample: str
