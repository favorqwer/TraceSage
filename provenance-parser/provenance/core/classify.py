"""系统调用分类：调用名(+flags) -> Decision。

本模块是纯逻辑：不读 TOML、不碰图、不碰状态、不碰 IO。
分类表由装配层加载后注入 ``Classifier``。
"""

from __future__ import annotations

from dataclasses import dataclass

from . import args as A
from .events import Call
from .kinds import EdgeClass, ObjSource, Verdict
from .syscalls import CREATE_ALWAYS, OPEN_FAMILY

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
    """分类结论。纯函数产物，不含任何图状态。

    ``value`` 是该调用在设计上的溯源等级（L1 主干 / L2 增强 / L3 记账 /
    L4 丢弃），只用于报告「哪些 L1 因数据源拿不到客体而降级为记账」；
    不参与任何图的产出。门控为空的 ``EMIT`` 一律视为 L1。
    """

    verdict: Verdict
    verb: str = ""
    reason: str = ""
    value: str = ""


class Classifier:
    """已加载好的分类表；构造时只接收内存字典，不做 IO。"""

    def __init__(
        self,
        verbs: dict[str, VerbSpec],
        by_call: dict[str, VerbSpec],
        ledger: dict[str, tuple[Verdict, str, str]],
        ledger_value: dict[str, str],
    ) -> None:
        self.verbs = verbs
        self.by_call = by_call
        self.ledger = ledger
        self.ledger_value = ledger_value

    def decide(self, call: Call) -> Decision:
        name = call.call
        # 采集端不认识的调用会渲染成 <unknown>，参数全空：连名字都没有，
        # 无法归属。它和「账本表没登记」是两件事，所以单独一个 verdict。
        if name == "<unknown>":
            return Decision(Verdict.BLIND, reason="collector_unknown", value="L0")
        entry = self.ledger.get(name)
        if entry is not None:
            verdict, reason, _group = entry
            value = self.ledger_value.get(name, "L3")
            if verdict is Verdict.HANDLE:
                return Decision(Verdict.HANDLE, reason=reason, value=value)
            if verdict is Verdict.ATTR:
                return Decision(Verdict.ATTR, reason=reason, value=value)
            if verdict is Verdict.DROP:
                return Decision(Verdict.DROP, reason=reason, value=value)
            return Decision(Verdict.OPS, reason=reason, value=value)

        if name in CREATE_ALWAYS:
            return Decision(Verdict.EMIT, verb="create", value="L1")
        if name in OPEN_FAMILY:
            flags = A.flags_of(call.args.get("flags"))
            if "O_TMPFILE" in flags:
                # 匿名临时文件：不建 File 节点，但 fd 必须进句柄表。
                return Decision(Verdict.HANDLE, reason="open_tmpfile", value="L3")
            if "O_CREAT" in flags or "O_TRUNC" in flags:
                return Decision(Verdict.EMIT, verb="create", value="L1")
            # 只读/只写/只打开：不建边，但 fd 必须进句柄表。
            return Decision(Verdict.HANDLE, reason="open_readonly", value="L3")

        spec = self.by_call.get(name)
        if spec is not None:
            return Decision(Verdict.EMIT, verb=spec.name, value="L1")
        return Decision(Verdict.UNMAPPED, reason="unmapped", value="L2")

    def is_known_syscall(self, name: str) -> bool:
        """未归类项是否为已知系统调用（用于报告区分「漏登记」与「真的没登记」）。"""
        return name in self.by_call or name in self.ledger or name in OPEN_FAMILY

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
