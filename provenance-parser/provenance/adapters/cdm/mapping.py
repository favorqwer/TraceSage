"""事件映射表的加载与校验。

表在 ``data/cdm_events.toml``（CDM 数据源的唯一转录点，与 sysdig 侧的
``data/verbs.toml`` + ``data/calls.toml`` 对应）。本模块只做三件事：

1. 把 TOML 解析成不可变的 ``EventTable``；
2. 在加载时校验关系类型与动作名，写错立即抛错（不允许运行期静默丢事件）；
3. 对未登记的事件名返回 None，由调用方落 UNMAPPED 桶并逐类型计数。
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from ...core.kinds import Bucket, EdgeClass

#: 允许的边属性动作名。取自项目既有动词表（data/verbs.toml）里的动作集合，
#: 加上 mmap 三态。表里出现集合外的名字说明映射写错了，加载时直接失败。
ALLOWED_ACTIONS = frozenset(
    {
        "clone", "exec", "exit", "signal", "wait", "ptrace",
        "mem_read", "mem_write", "pidfd_getfd",
        "create", "link", "rename", "unlink", "truncate", "write", "chmod",
        "mount", "umount", "chroot", "setns", "ioctl",
        "read", "stat", "mmap_read", "mmap_write", "mmap_exec",
        "connect", "bind", "listen", "send", "recv", "accept",
    }
)

#: 允许的 special 处理函数名（实现在 emit.py）。
ALLOWED_SPECIALS = frozenset(
    {
        "open_attr", "handle", "drop_kernel", "unmapped", "attr", "blind",
        "no_owner", "exec", "exit", "mmap", "chmod", "rename", "link",
        "signal", "wait",
    }
)

#: TOML 里 skip 字段的取值 -> 账本桶。skip 表示「不建边，落这个桶」。
SKIP_BUCKETS: dict[str, Bucket] = {
    "handle": Bucket.HANDLE,
    "attr": Bucket.ATTR,
    "no_object": Bucket.NO_OBJECT,
    "drop": Bucket.DROP,
    "unmapped": Bucket.UNMAPPED,
}

#: TOML 里 skip 字段允许的取值。
ALLOWED_SKIPS = frozenset(SKIP_BUCKETS)

OBJECT_CLASSES = ("file", "net", "subject")

#: 需要进程身份才能处理的 special（要建边，或要按主体刷新属性）。
#: 其余 special（drop_kernel / handle / unmapped / blind / open_attr）不依赖主体，
#: 主体缺失时不能把它们改判成「无进程归属」——那会把「内核对象无名」的真实原因
#: 掩盖成「进程没找到」（THEIA 实测被吃 615 万条 MPROTECT）。
SUBJECT_SPECIALS = frozenset(
    {"exec", "exit", "mmap", "chmod", "rename", "link", "signal", "wait"}
)


@dataclass(frozen=True, slots=True)
class Branch:
    """一个客体类别的处理方式：建边，或落某个账本桶。"""

    edge: EdgeClass | None = None
    action: str = ""
    syscall: str = ""
    skip: str = ""


@dataclass(frozen=True, slots=True)
class EventRule:
    name: str
    gate: str          # "always" | "success"
    result: str        # "data" | "errno" | "none"
    branches: dict[str, Branch]
    special: str = ""
    note: str = ""
    needs_subject: bool = True


class EventTable:
    def __init__(self, rules: dict[str, EventRule]) -> None:
        self.rules = rules

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self.rules)

    def get(self, name: str) -> EventRule | None:
        return self.rules.get(name)

    @staticmethod
    def load(path: str | Path) -> "EventTable":
        with open(path, "rb") as handle:
            payload = tomllib.load(handle)
        rules: dict[str, EventRule] = {}
        for entry in payload.get("event", []):
            name = str(entry.get("name", ""))
            if not name:
                raise ValueError(f"映射表条目缺 name：{entry!r}")
            if name in rules:
                raise ValueError(f"映射表条目重复：{name}")
            gate = str(entry.get("gate", "always"))
            if gate not in ("always", "success"):
                raise ValueError(f"{name} 的 gate 非法：{gate}")
            result = str(entry.get("result", "none"))
            if result not in ("data", "errno", "none"):
                raise ValueError(f"{name} 的 result 非法：{result}")
            special = str(entry.get("special", ""))
            if special and special not in ALLOWED_SPECIALS:
                raise ValueError(f"{name} 的 special 未实现：{special}")
            branches: dict[str, Branch] = {}
            # TOML 里子表写作 [event.file] / [event.net] / [event.subject]，
            # 归属到最近一个 [[event]] 元素，因此类名直接挂在 entry 上。
            for cls in OBJECT_CLASSES:
                spec = entry.get(cls)
                if spec is None:
                    continue
                branch = EventTable._branch(name, cls, spec)
                branches[cls] = branch
            rules[name] = EventRule(
                name=name,
                gate=gate,
                result=result,
                branches=branches,
                special=special,
                note=str(entry.get("note", "")),
                needs_subject=bool(branches) or special in SUBJECT_SPECIALS,
            )
        return EventTable(rules)

    @staticmethod
    def _branch(event_name: str, cls: str, spec: dict) -> Branch:
        skip = str(spec.get("skip", ""))
        edge_text = str(spec.get("edge", ""))
        action = str(spec.get("action", ""))
        syscall = str(spec.get("syscall", "")) or action
        if skip:
            if skip not in ALLOWED_SKIPS:
                raise ValueError(f"{event_name}.{cls} 的 skip 非法：{skip}")
            return Branch(skip=skip)
        if not edge_text or not action:
            raise ValueError(f"{event_name}.{cls} 必须同时给 edge 与 action，或给 skip")
        try:
            edge = EdgeClass(edge_text)
        except ValueError as exc:
            raise ValueError(f"{event_name}.{cls} 的 edge 非法：{edge_text}") from exc
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"{event_name}.{cls} 的 action 非法：{action}")
        return Branch(edge=edge, action=action, syscall=syscall)
