"""单个调用可用的协作对象集合：状态、图、客体解析、策略。

它只是把四个小部件组合起来，不承载具体业务分支。
"""

from __future__ import annotations

from ..core.events import Call
from ..core.graph import Outcome
from ..core.kinds import Bucket
from ..core.options import EmitOptions
from .emitter import GraphEmitter
from .objects import ObjectResolver
from .policies import Policies
from .state import State


class EmitContext:
    def __init__(self, state: State, options: EmitOptions) -> None:
        self.st = state
        self.graph = GraphEmitter(state, options)
        self.objects = ObjectResolver(state)
        self.policy = Policies(state, self.graph)

    # -- 身份与图 ------------------------------------------------------
    def key(self, call: Call):
        return self.graph.key(call)

    def seg(self, call: Call):
        return self.graph.seg(call)

    def res(self, call: Call) -> int | None:
        return call.number("res")

    def proc_node(self, seg):
        return self.graph.proc_node(seg)

    def file_node(self, cid: str, path: str, kind: str = ""):
        return self.graph.file_node(cid, path, kind)

    def net_node(self, name: str, proto: str = ""):
        return self.graph.net_node(name, proto)

    def edge(self, *args, **kwargs):
        return self.graph.edge(*args, **kwargs)

    def add(self, out: Outcome, edge) -> bool:
        return self.graph.add(out, edge)

    def attach(self, out: Outcome, node) -> None:
        self.graph.attach(out, node)

    # -- 客体 ----------------------------------------------------------
    def norm_path(self, raw: str, call: Call) -> str:
        return self.objects.norm_path(raw, call)

    def path_arg(self, call: Call, *keys: str) -> str:
        return self.objects.path_arg(call, *keys)

    def fd_entry(self, call: Call, key: str = "fd"):
        return self.objects.fd_entry(call, key)

    # -- 策略 ----------------------------------------------------------
    def gate(self, call: Call, gate: str):
        return self.policy.gate(self, call, gate)

    def no_object(self, out: Outcome, call: Call, fd) -> Outcome:
        return self.policy.no_object(self, out, call, fd)

    def derive_proc(self, out, call, file_key, action, subject) -> None:
        self.policy.derive_proc(self, out, call, file_key, action, subject)

    # -- 账本/证据 ------------------------------------------------------
    def covered(self, out: Outcome, call: Call) -> Outcome:
        return out.cover(call)

    def give_up(self, out: Outcome, call: Call, bucket: Bucket, reason: str) -> Outcome:
        return out.settle(call, bucket, reason)

    def note_attempt(self, out, call, verb, target, res) -> None:
        self.policy.note_attempt(self, out, call, verb, target, res)

    def attempt(self, out, call, verb, target, res) -> Outcome:
        self.note_attempt(out, call, verb, target, res)
        return out.settle(call, Bucket.ATTEMPT, verb)

    def ops(self, out, call, name: str) -> None:
        out.ops.append((self.key(call), name, call.ts_ns))
