"""系统调用分类：调用名(+flags) -> Decision。

唯一真源是 data/verbs.toml 与 data/calls.toml。本模块只做查表与两条特判：
open 家族按 O_CREAT/O_TRUNC/O_TMPFILE 分流；creat 天然等于 O_CREAT。

纯逻辑：不碰图、不碰状态、不碰 IO。``Tables`` 由调用方注入，不使用全局缓存。
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import args as A
from .events import Call
from .kinds import EdgeClass, ObjSource, Verdict

OPEN_FAMILY = {"open", "openat", "openat2", "open64", "openat64"}
CREATE_ALWAYS = {"creat"}

# 本版按约定延后的内核对象动词（客体无稳定名字，R3）。
DEFERRED_VERBS = ("module", "bpf", "io_uring", "shm")


@dataclass(frozen=True, slots=True)
class VerbSpec:
    name: str
    edge: EdgeClass
    source: ObjSource
    gate: str
    calls: tuple[str, ...]
    note: str


@dataclass(frozen=True, slots=True)
class Decision:
    """分类结论。纯函数产物，不含任何图状态。"""

    verdict: Verdict
    verb: str = ""
    reason: str = ""


class Tables:
    def __init__(self, data_dir: str | Path) -> None:
        data = Path(data_dir)
        verbs_doc = tomllib.loads((data / "verbs.toml").read_text(encoding="utf-8"))
        calls_doc = tomllib.loads((data / "calls.toml").read_text(encoding="utf-8"))

        self.verbs: dict[str, VerbSpec] = {}
        self.by_call: dict[str, VerbSpec] = {}
        for item in verbs_doc.get("verb", []):
            spec = VerbSpec(
                name=item["name"],
                edge=EdgeClass(item["edge"]),
                source=ObjSource(item["source"]),
                gate=item.get("gate", "always"),
                calls=tuple(item.get("calls", [])),
                note=item.get("note", ""),
            )
            if spec.name in self.verbs:
                raise ValueError(f"动词重复：{spec.name}")
            self.verbs[spec.name] = spec
            for call in spec.calls:
                if call in self.by_call:
                    raise ValueError(f"调用名重复归属：{call}")
                self.by_call[call] = spec

        self.ledger: dict[str, tuple[Verdict, str, str]] = {}
        for item in calls_doc.get("group", []):
            group = item["name"]
            verdict = Verdict(item["verdict"])
            reason = item.get("reason", "")
            for call in item.get("calls", []):
                if call in self.ledger or call in self.by_call:
                    raise ValueError(f"调用名重复归属：{call}")
                self.ledger[call] = (verdict, reason, group)

        overlap = (set(self.ledger) | set(self.by_call)) & OPEN_FAMILY
        if overlap:
            raise ValueError(f"open 家族必须走分流规则，不应出现在表里：{sorted(overlap)}")

    def decide(self, call: Call) -> Decision:
        name = call.call
        entry = self.ledger.get(name)
        if entry is not None:
            verdict, reason, _group = entry
            if verdict is Verdict.HANDLE:
                return Decision(Verdict.HANDLE, reason=reason)
            if verdict is Verdict.ATTR:
                return Decision(Verdict.ATTR, reason=reason)
            if verdict is Verdict.DROP:
                return Decision(Verdict.DROP, reason=reason)
            return Decision(Verdict.OPS, reason=reason)

        if name in CREATE_ALWAYS:
            return Decision(Verdict.EMIT, verb="create")
        if name in OPEN_FAMILY:
            flags = A.flags_of(call.args.get("flags"))
            if "O_TMPFILE" in flags:
                return Decision(Verdict.DROP, reason="open_tmpfile")
            if "O_CREAT" in flags or "O_TRUNC" in flags:
                return Decision(Verdict.EMIT, verb="create")
            return Decision(Verdict.DROP, reason="open_readonly")

        spec = self.by_call.get(name)
        if spec is not None:
            return Decision(Verdict.EMIT, verb=spec.name)
        return Decision(Verdict.UNMAPPED, reason="unmapped")

    # -- 供测试与报告 --------------------------------------------------
    def verb_count(self) -> int:
        return len(self.verbs)

    def coverage(self) -> dict[str, int]:
        return {
            "verbs": len(self.verbs),
            "deferred_verbs": len(DEFERRED_VERBS),
            "calls_to_verbs": len(self.by_call),
            "calls_to_ledger": len(self.ledger),
        }
