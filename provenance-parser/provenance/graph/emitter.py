"""图产出：只负责节点、边、序号与端点登记。"""

from __future__ import annotations

from ..core import args as A
from ..core.events import Call
from ..core.graph import Edge, Node, Outcome
from ..core.kinds import EdgeClass, FileKey, NetKey, ProcKey, file_kind_of
from ..core.options import EmitOptions
from ..core.results import norm_res
from .state import State
from .state.proc import Seg


class GraphEmitter:
    def __init__(self, state: State, options: EmitOptions) -> None:
        self.st = state
        self.options = options
        self.host = state.host_id
        self._seq = 0
        self.counts = {"self_loop": 0}

    # -- 身份 ----------------------------------------------------------
    def seg(self, call: Call) -> Seg:
        return self.st.proc.observe(call.head_row)

    def key(self, call: Call) -> ProcKey:
        return self.seg(call).key

    def node_for(self, key) -> Node | None:
        if isinstance(key, ProcKey):
            seg = self.st.proc.get(key)
            return self.proc_node(seg) if seg is not None else None
        return None

    def proc_node(self, seg: Seg) -> Node:
        props: dict[str, object] = {
            "exe": seg.exe or None,
            "args": seg.args or None,
            "ppid": seg.ppid,
            "ruid": seg.ruid or None,
            "uid": seg.uid,
        }
        props.update(self.st.containers.props_for(seg.key.container_id))
        return Node(seg.key, props)

    def file_node(self, cid: str, path: str, kind: str = "") -> Node | None:
        if not path:
            return None
        normalized = file_kind_of(kind)
        if normalized is None:
            return None
        return Node(FileKey(self.host, cid, path), {"kind": normalized.value})

    def net_node(self, name: str, proto: str = "") -> Node | None:
        if not name:
            return None
        return Node(NetKey(self.host, name), {"proto": proto or None})

    # -- 边 ------------------------------------------------------------
    def reset_seq(self) -> None:
        self._seq = 0

    def edge(
        self,
        cls: EdgeClass,
        action: str,
        src: ProcKey | FileKey | NetKey,
        dst: ProcKey | FileKey | NetKey,
        call: Call,
        *,
        res: int | None = None,
        head: bool = False,
        old_path: str = "",
        target_path: str = "",
        mode: str = "",
    ) -> Edge | None:
        if src == dst:
            self.counts["self_loop"] += 1
            return None
        # 结果唯一出口：fd 号与内存地址不得当作 "字节数 / 错误码" 落图。
        res = norm_res(action, call.call, res)
        payload = None
        if head and self.options.keep_payload and (res is None or res >= 0):
            payload = A.payload_head_b64(call.buffer_b64, self.options.payload_max_bytes)
        edge = Edge(
            cls=cls,
            action=action,
            src=src,
            dst=dst,
            evt=call.evt,
            seq=self._seq,
            ts_ns=call.ts_ns,
            te_ns=call.te_ns,
            res=res,
            head=payload,
            old_path=old_path or None,
            target_path=target_path or None,
            mode=mode or None,
        )
        self._seq += 1
        return edge

    def add(self, out: Outcome, edge: Edge | None) -> bool:
        if edge is None:
            return False
        out.edges.append(edge)
        # 边端点必须都在节点登记表里，否则写库时 MATCH 不到端点。
        for key in (edge.src, edge.dst):
            if isinstance(key, ProcKey):
                node = self.node_for(key)
                if node is not None and not any(n.key == key for n in out.nodes):
                    out.nodes.append(node)
        return True

    def attach(self, out: Outcome, node: Node | None) -> None:
        if node is not None:
            out.nodes.append(node)
