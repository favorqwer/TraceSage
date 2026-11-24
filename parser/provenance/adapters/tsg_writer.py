"""TSG 单文件索引写入适配器：实现 parser 的 GraphWriter 协议，直接由 .scap 流式写出 .tsg。"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

from ..core.graph import Edge, Node
from ..core.kinds import FileKey, NetKey, NodeKey, ProcKey, label_of

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tsg.format import TSGWriter  # noqa: E402


def _vertex_key(key: NodeKey) -> str:
    if isinstance(key, ProcKey):
        return f"{key.host_id}|{key.container_id}|{key.pid}|{key.start_ns}"
    if isinstance(key, FileKey):
        if key.container_id and key.container_id != "host":
            return f"{key.container_id}|{key.path}"
        return key.path
    return key.endpoints


def _process_content(key: ProcKey, props: dict[str, Any]) -> str:
    for field in ("exe_path", "exepath", "name"):
        val = str(props.get(field) or "").strip()
        if val:
            return val
    cmd = str(props.get("cmdline") or props.get("args") or "").strip()
    if cmd.startswith("/"):
        return cmd.split(" ", 1)[0]
    return _vertex_key(key)


def _node_props(key: NodeKey, props: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(key, ProcKey):
        exepath = _process_content(key, props)
        out["content"] = exepath
        out["host_id"] = key.host_id
        out["container_id"] = key.container_id
        out["pid"] = key.pid
        out["exepath"] = exepath
        if props.get("name") is not None:
            out["name"] = str(props["name"])
        cmd = props.get("cmdline") if props.get("cmdline") is not None else props.get("args")
        if cmd is not None:
            out["args"] = str(cmd)
        if props.get("ppid") is not None:
            out["ppid"] = int(props["ppid"])
        for extra in ("uid", "euid", "container_privileged", "container_host_root_rw"):
            if props.get(extra) is not None:
                out[extra] = props[extra]
    elif isinstance(key, FileKey):
        out["content"] = key.path
        out["host_id"] = key.host_id
        out["container_id"] = key.container_id
        if props.get("file_type") is not None:
            out["file_type"] = str(props["file_type"])
    else:
        assert isinstance(key, NetKey)
        out["content"] = key.endpoints
        out["host_id"] = key.host_id
        proto = props.get("proto") if props.get("proto") is not None else props.get("protocol")
        if proto is not None:
            out["protocol"] = str(proto)
    return out


class TSGGraphWriter:
    """将 parser 流式产出的 Node/Edge 直接写入单文件 graphs/<scenario>.tsg。"""

    def __init__(
        self,
        out_path: str | Path,
        *,
        scenario: str = "",
        database: str = "",
        source_scap: str = "",
        log: Any = print,
    ) -> None:
        scap_size = 0
        scap_mtime = 0
        if source_scap:
            p = Path(source_scap)
            if p.is_file():
                st = p.stat()
                scap_size = int(st.st_size)
                scap_mtime = int(st.st_mtime)
        self._writer = TSGWriter(
            out_path,
            scenario=scenario,
            database=database,
            source_scap=str(source_scap),
            source_scap_size=scap_size,
            source_scap_mtime=scap_mtime,
            log=log,
        )
        self._failed = False
        self.meta: dict[str, Any] = {}

    def write_nodes(self, nodes: list[Node]) -> None:
        for node in nodes:
            self._writer.add_vertex(
                label_of(node.key),
                _vertex_key(node.key),
                _node_props(node.key, node.props),
            )

    def write_edges(self, edges: list[Edge]) -> None:
        for edge in edges:
            self._writer.add_edge(
                rel=edge.cls.value,
                src_kind=label_of(edge.src),
                src_key=_vertex_key(edge.src),
                dst_kind=label_of(edge.dst),
                dst_key=_vertex_key(edge.dst),
                event_id=edge.event_id,
                start_ns=edge.start_ns,
                end_ns=edge.end_ns,
                syscall=edge.syscall,
                action=edge.action,
                result=edge.result,
                payload_b64=edge.payload_b64,
                to_path=edge.to_path,
                mode=edge.mode,
            )

    def abort(self) -> None:
        self._failed = True
        self._writer.abort()

    def close(self) -> None:
        if self._failed:
            return
        self.meta = self._writer.finish()
