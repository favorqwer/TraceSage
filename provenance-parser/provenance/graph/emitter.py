"""图产出：只负责节点、边、序号与端点登记。"""

from __future__ import annotations

from ..core import args as A
from ..core.events import Call
from ..core.graph import Edge, Node, Outcome
from ..core.kinds import EdgeClass, FileKey, NetKey, ProcKey, file_kind_of
from ..core.options import EmitOptions
from ..core.results import norm_result
from ..core.syscalls import canonical_syscall
from .state import State
from .state.proc import Seg

# 合成键：不是文件系统路径，不做路径规整检查
_SYNTHETIC_PREFIXES = ("pipe:[", "socket:[", "netlink:[", "unix:[", "memfd:")
# 路径审计：不合规的 File 路径计数（重建后必须为 0）。strict 模式下直接抛错。
PATH_AUDIT = {"dirty": 0, "samples": []}


def audit_file_path(path: str, strict: bool) -> None:
    if path.startswith(_SYNTHETIC_PREFIXES) or path.startswith("?"):
        return
    dirty = not path.startswith("/") or ".(" in path or "(/" in path
    if not dirty:
        return
    PATH_AUDIT["dirty"] += 1
    if len(PATH_AUDIT["samples"]) < 20:
        PATH_AUDIT["samples"].append(path)
    if strict:
        raise ValueError(f"未规整的文件路径进入图：{path!r}")


class GraphEmitter:
    def __init__(self, state: State, options: EmitOptions) -> None:
        self.st = state
        self.options = options
        self.host = state.host_id
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
        # 图上的名字：exe_path / cmdline / uid（日志观测值）/ euid（geteuid 跟踪的
        # 有效用户）。容器属性带 container_ 前缀，避免被读成“这个进程有特权”。
        props: dict[str, object] = {
            "exe_path": seg.exe_path or None,
            "cmdline": seg.cmdline or None,
            "ppid": seg.ppid,
            "uid": seg.uid or None,
            "euid": seg.euid,
        }
        props.update(self.st.containers.props_for(seg.key.container_id))
        return Node(seg.key, props)

    def file_node(self, cid: str, path: str, kind: str = "") -> Node | None:
        if not path:
            return None
        audit_file_path(path, getattr(self.options, "strict_paths", False))
        normalized = file_kind_of(kind)
        if normalized is None:
            return None
        return Node(FileKey(self.host, cid, path), {"file_type": normalized.value})

    def net_node(self, name: str, proto: str = "") -> Node | None:
        if not name:
            return None
        return Node(NetKey(self.host, name), {"proto": proto or None})

    # -- 边 ------------------------------------------------------------
    def edge(
        self,
        cls: EdgeClass,
        action: str,
        src: ProcKey | FileKey | NetKey,
        dst: ProcKey | FileKey | NetKey,
        call: Call,
        *,
        result: int | None = None,
        payload: bool = False,
        to_path: str = "",
        mode: str = "",
    ) -> Edge | None:
        if src == dst:
            self.counts["self_loop"] += 1
            return None
        # 结果唯一出口：fd 号与内存地址不得当作 "字节数 / 错误码" 落图。
        result = norm_result(action, call.call, result)
        payload_b64 = None
        if payload and self.options.keep_payload and (result is None or result >= 0):
            payload_b64 = A.payload_head_b64(call.buffer_b64, self.options.payload_max_bytes)
        edge = Edge(
            cls=cls,
            action=action,
            src=src,
            dst=dst,
            event_id=call.event_id,
            start_ns=call.start_ns,
            end_ns=call.end_ns,
            syscall=canonical_syscall(call.call),
            result=result,
            payload_b64=payload_b64,
            to_path=to_path or None,
            mode=mode or None,
        )
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
