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
    cmdline: str
    args: dict[str, str]

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
        return cls(call=name, enter=enter, exit=exit, args=merged)

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
    def ts_ns(self) -> int:
        return self.head_row.ns

    @property
    def te_ns(self) -> int:
        return self.exit.ns if self.exit is not None else self.head_row.ns

    @property
    def evt(self) -> int:
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


@dataclass(slots=True)
class BadRow:
    line_no: int
    reason: str
    sample: str
