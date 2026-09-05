"""System call handler registration: the four special syscalls (execve /
accept / fcntl / rename) plus the MetaConfig-driven generic directions
(f2p / p2f / n2p / p2n).

Actions need to emit graph elements, so they take a ``ParserContext``
(the pipeline parser) that provides id generation, edge queueing, and the
entity registry.  Registration order is load-bearing: same-named syscalls
across direction tables overwrite each other in dict order (see the
generic-directions comment below), so keep the sequence unchanged.
"""

import re
from typing import Dict, List, Optional, Protocol

from ..jsonl.fields import extract_size
from ..jsonl.record import parse_timestamp_ns
from ..model.entities import Entity, FileEntity, NetworkEntity
from ..model.entity_node import EntityNode
from ..model.event_edge import EventEdge
from .meta_config import MetaConfig
from .system_call import Fingerprint, SystemCall, SystemCallFactory

_RENAME_PATHS = re.compile(
    r"oldpath=(?P<old>.+?) newpath=(?P<new>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)"
)
_PARENT_PATTERN = re.compile(r"ptid=(?P<parentPID>\d+)\((?P<parent>.+?)\)")


class ParserContext(Protocol):
    """Pipeline facilities the syscall actions need (implemented by
    SysdigLogParser)."""

    def next_event_id(self) -> int: ...

    def queue_edge(self, rel: str, edge: EventEdge) -> None: ...

    def get_or_create_process(
        self, process_key: str, pid: str, process_name: str, exe_path: str
    ) -> object: ...

    def get_or_create_file(self, file_key: str, path: str) -> object: ...

    def register_forward_flow(self, key: str, edge: EventEdge) -> None: ...

    def extend_forward_flow(self, key: str, end_ns: int) -> None: ...

    def note_incomplete_network(self) -> None: ...


def _normalize_rename_path(path: Optional[str]) -> str:
    if path is None:
        return ""
    normalized = path.strip()
    if normalized.endswith(")") and "(" in normalized:
        normalized = normalized[normalized.index("(") + 1:-1].strip()
    return normalized


# MetaConfig 驱动的四类通用方向：
#   rel -> (工厂实体类型, 系统调用名集合, start_entities 中作为边源/汇的下标)
# 这四类系统调用的两端实体都取自进入记录
# （start_entities[0]=Process，[1]=File/Network），方向由下标决定。
# 顺序须与旧版逐段注册一致（ftop -> ptof -> ntop -> pton），
# 保证同名系统调用（如 rename 同时在 ftop/ptof 中）的覆盖结果不变。
_GENERIC_SYSCALL_DIRECTIONS = (
    ("f2p", FileEntity, MetaConfig.ftop_system_calls, 1, 0),
    ("p2f", FileEntity, MetaConfig.ptof_system_calls, 0, 1),
    ("n2p", NetworkEntity, MetaConfig.ntop_system_calls, 1, 0),
    ("p2n", NetworkEntity, MetaConfig.pton_system_calls, 0, 1),
)


def _update_p2p_links(
    ctx: ParserContext,
    start_rec: Dict[str, str],
    end_rec: Dict[str, str],
    start_entities: List[Optional[Entity]],
    end_entities: List[Optional[Entity]],
) -> None:
    """Extend the end time of the execve p2p edge keyed by the acting process.

    execve registers its parent->child edge under the parent's key (ptid);
    this lookup by the acting process's pid+name therefore only ever matches
    when the acting process is that parent — the child's own events never
    extend the edge.
    """
    end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
    key = end_rec.get("pid", "") + end_rec.get("process", "")
    ctx.extend_forward_flow(key, end_ns)


def _make_edge_action(
    ctx: ParserContext, rel: str, src_idx: int, dst_idx: int
):
    """Build the edge action shared by the four MetaConfig-driven directions.

    两端实体都取自进入记录（start_entities[0]=Process，[1]=File/Network），
    (src_idx, dst_idx) 决定边方向；size 取自退出记录 args 的 res=，
    res 缺失或为负（size == -1）时不建边。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        first_node = EntityNode(start_entities[0])
        second_node = EntityNode(start_entities[1])
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        size = extract_size(end_rec.get("args", ""))
        if size != -1:
            edge = EventEdge(
                first_node if src_idx == 0 else second_node,
                first_node if dst_idx == 0 else second_node,
                ctx.next_event_id(),
                start_rec.get("event", ""),
                size,
                start_ns,
                end_ns,
            )
            ctx.queue_edge(rel, edge)

    return action


def build_handlers(ctx: ParserContext) -> Dict[Fingerprint, SystemCall]:
    """Build the full fingerprint -> SystemCall handler table."""
    handlers: Dict[Fingerprint, SystemCall] = {}

    # --- 通用方向（MetaConfig 驱动：f2p / p2f / n2p / p2n）---
    for rel, entity_cls, syscall_names, src_idx, dst_idx in _GENERIC_SYSCALL_DIRECTIONS:
        factory = SystemCallFactory(entity_cls, None)
        factory.add_action(_make_update_p2p_links_action(ctx))
        factory.add_action(_make_edge_action(ctx, rel, src_idx, dst_idx))
        for sc_name in syscall_names:
            sc = factory.get_system_call(sc_name)
            handlers[sc.fingerprint] = sc

    # --- execve (special: PtoP + file edge) ---
    def _execve_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        p_end = end_entities[0]  # Process
        p_end_node = EntityNode(p_end)
        f = start_entities[1]  # FileEntity (executable)
        file_node = EntityNode(f)
        exe_path = start_rec.get("exepath", "")
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        args = end_rec.get("args", "")

        if "res=0" in args:
            if f.path != "<NA>":
                edge = EventEdge(
                    file_node, p_end_node, ctx.next_event_id(),
                    "execve", 0, start_ns, end_ns,
                )
                ctx.queue_edge("f2p", edge)

            parent_match = _PARENT_PATTERN.search(args)
            if parent_match:
                pid_parent = parent_match.group("parentPID")
                name_parent = parent_match.group("parent")
                key_parent = pid_parent + name_parent
                parent = ctx.get_or_create_process(
                    key_parent, pid_parent, name_parent, exe_path
                )
                parent_node = EntityNode(parent)
                forward_edge = EventEdge(
                    parent_node, p_end_node, ctx.next_event_id(),
                    "execve", 0, start_ns, end_ns,
                )
                ctx.queue_edge("p2p", forward_edge)
                ctx.register_forward_flow(key_parent, forward_edge)

    execve_sc = SystemCall(
        Fingerprint("execve", FileEntity, None),
    ).add_action(_execve_action)
    handlers[execve_sc.fingerprint] = execve_sc

    # --- accept (special: NtoP) ---
    def _accept_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        p = end_entities[0]  # Process
        p_node = EntityNode(p)
        n = end_entities[1]  # NetworkEntity
        if n is None:
            # 无完整五元组的 accept（如内核 fd 地址）-> 不建边，可审计
            ctx.note_incomplete_network()
            return
        n_node = EntityNode(n)
        ts_end = end_rec.get("timestamp", "0.0")
        end_ns = parse_timestamp_ns(ts_end)

        edge = EventEdge(
            n_node, p_node, ctx.next_event_id(),
            "accept", 0, end_ns, end_ns,
        )
        ctx.queue_edge("n2p", edge)

    accept_sc = SystemCall(
        Fingerprint("accept", None, NetworkEntity),
    ).add_action(_accept_action)
    handlers[accept_sc.fingerprint] = accept_sc

    # --- fcntl (special: NtoP) ---
    def _fcntl_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        p = end_entities[0]  # Process
        p_node = EntityNode(p)
        n = end_entities[1]  # NetworkEntity
        if n is None:
            ctx.note_incomplete_network()
            return
        n_node = EntityNode(n)

        edge = EventEdge(
            n_node, p_node, ctx.next_event_id(),
            "fcntl", 0, start_ns, end_ns,
        )
        ctx.queue_edge("n2p", edge)

    fcntl_sc = SystemCall(
        Fingerprint("fcntl", None, NetworkEntity),
    ).add_action(_fcntl_action)
    handlers[fcntl_sc.fingerprint] = fcntl_sc

    # --- rename (special: PtoF + FtoP) ---
    def _rename_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        args = end_rec.get("args", "")
        rename_match = _RENAME_PATHS.search(args)
        if not rename_match:
            return

        old_path = _normalize_rename_path(rename_match.group("old"))
        new_path = _normalize_rename_path(rename_match.group("new"))

        p = start_entities[0]  # Process
        p_node = EntityNode(p)

        old_file = ctx.get_or_create_file(old_path, old_path)
        old_f_node = EntityNode(old_file)
        f2p_edge = EventEdge(
            old_f_node, p_node, ctx.next_event_id(),
            "rename", 0, start_ns, end_ns,
        )
        ctx.queue_edge("f2p", f2p_edge)

        new_file = ctx.get_or_create_file(new_path, new_path)
        new_f_node = EntityNode(new_file)
        p2f_edge = EventEdge(
            p_node, new_f_node, ctx.next_event_id(),
            "rename", 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2f", p2f_edge)

    rename_sc = SystemCall(
        Fingerprint("rename", None, None),
    ).add_action(_rename_action)
    handlers[rename_sc.fingerprint] = rename_sc

    return handlers


def _make_update_p2p_links_action(ctx: ParserContext):
    """Bind _update_p2p_links to the context so it fits the Action signature."""

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)

    return action
