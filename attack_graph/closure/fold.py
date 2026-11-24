"""折叠与展开编排：候选内容三元组、进程身份摘要、闭包展开流程。

本文件依赖 `domain`、`closure.traversal`、`closure.snapshot` 与 `closure.policy`；
不导入 `rules`、`llm`、`routing`。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from domain.edge import (
    PRODUCER_RELS,
    SCENARIO_KIND_LABELS,
    content_triple_of,
    is_derivation,
    labels_of,
    normalize_rel,
    owner_is_source,
    triple,
)
from closure.trace import trace_event
from closure.traversal import Event, run_causal_closure
from closure.policy import is_startup_dependency
from closure.snapshot import open_source
from closure.storage import effect_code, effect_name

# ==== 1. 折叠 ====


@dataclass
class CollapsedEdge:
    src: str
    syscall: str
    dst: str
    src_label: str = "Process"
    dst_label: str = "Process"
    instances: int = 0
    bytes: int = 0
    # 成败集合：同一内容三元组的多条实例可能既有成功又有失败（图上 result <0 / >=0）。
    # 报告按（三元组 × 成败）拆开输出，不去猜“哪一条代表它”。
    effects: set[str] = field(default_factory=set)
    event_ids: list[int] = field(default_factory=list)
    t0: int = 0
    t1: int = 0
    rels: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)   # 来源进程（同一个内容三元组可能由多个进程产生）
    # 入闭包通道（各实例按位或）：这条三元组是从哪几类顶点被收进闭包的（判定层用作束的细分键）
    channels: int = 0
    # 两端顶点的**身份**（判定层按身份找上层已判过的边用）：进程 → ("Process", 进程标识)、
    # 文件 → ("File", 路径)、网络 → ("Network", 四元组)。内容三元组与报告口径不受影响，
    # 只是多存一份身份，避免“同一个程序跑了 191 次”时把 191 个进程的判定历史混在一起。
    src_identities: set[tuple[str, str]] = field(default_factory=set)
    dst_identities: set[tuple[str, str]] = field(default_factory=set)
    # 结构上下文（判定时渲染给模型看，不进报告）：离终点事件最少几跳、从哪个顶点被回推出来。
    # `via_kind` / `via_key` 是原始标识（判定层的“上游交接明细”按它定位上一层顶点：进程侧是
    # 进程标识，对象侧是路径本身）；显示文本在 `to_dict` / `fold_records` 里渲染一次。
    dist: int = 0
    via_kind: str = ""
    via_key: str = ""

    def via_text(self) -> str:
        """这条边从哪个顶点被回推出来（空 = 终点事件本身）。"""
        return f"{self.via_kind} {self.via_key}" if self.via_kind else "终点事件"

    def to_dict(self, *, with_event_ids: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "syscall": self.syscall,
            "dst": self.dst,
            "src_label": self.src_label,
            "dst_label": self.dst_label,
            "instances": self.instances,
            "bytes": self.bytes,
            "effects": sorted(self.effects),
            "t0": self.t0,
            "t1": self.t1,
            "rels": sorted(self.rels),
            "member_processes": sorted(self.members),
            "src_identities": sorted([list(x) for x in self.src_identities]),
            "dst_identities": sorted([list(x) for x in self.dst_identities]),
            "dist": self.dist,
            "via": self.via_text(),
            "via_kind": self.via_kind,
            "via_key": self.via_key,
            "channels": self.channels,
        }
        if with_event_ids:
            out["event_ids"] = self.event_ids
        return out


@dataclass
class FoldResult:
    edges: list[CollapsedEdge]
    raw_instances: int
    dropped_startup_reads: int = 0


def _other_identity(row: dict[str, Any]) -> tuple[str, str]:
    """这条边“另一端”（非归属进程那一端）的身份。

    派生边（p2p）的另一端是父进程，取它的进程标识；文件与网络端点取路径 / 四元组。
    取不到标识时返回空串身份，折叠时会被丢弃（宁可这一端没有身份，也不要拿内容冒充身份）。
    """
    label = str(row.get("other_label") or "")
    if label == "Process":
        return label, str(row.get("other_process_id") or "")
    return label, str(row.get("other") or "")


def fold(rows: Iterable[dict[str, Any]]) -> FoldResult:
    """把事件实例折成内容三元组。

    只合并不删边；唯一的例外是 `is_startup_dependency` 命中的行（进程启动期读入、且全图未被
    写入的标准动态共享库），命中条数记在 `dropped_startup_reads` 里，由调用方写进日志。
    """
    rows_list = list(rows) if not isinstance(rows, list) else rows

    # 预扫描：收集本次反向展开中被写入/创建/修改的全部客体，以及各进程首次对外产生动作的时刻
    written_targets: set[str] = set()
    proc_first_action: dict[str, int] = {}
    for row in rows_list:
        rel = str(row.get("rel") or "")
        pid = str(row.get("process_id") or "")
        st = int(row.get("starttime") or 0)
        if rel in PRODUCER_RELS:
            other = str(row.get("other") or "")
            if other:
                written_targets.add(other)
            if pid and (pid not in proc_first_action or st < proc_first_action[pid]):
                proc_first_action[pid] = st
        elif is_derivation(rel):
            if pid and (pid not in proc_first_action or st < proc_first_action[pid]):
                proc_first_action[pid] = st

    table: dict[tuple[str, str, str], CollapsedEdge] = {}
    raw = 0
    dropped = 0
    for row in rows_list:
        raw += 1
        other_path = str(row.get("other") or "")
        rel = str(row.get("rel") or "")
        sc = str(row.get("syscall") or "")
        pid = str(row.get("process_id") or "")
        st = int(row.get("starttime") or 0)

        # 仅在进程启动期（首次对外动作之前）读入、且全图未曾被写入的标准动态共享库，方视为底层环境初始化依赖
        first_act = proc_first_action.get(pid, float("inf"))
        if is_startup_dependency(rel, sc, other_path, st, first_act, written_targets):
            dropped += 1
            continue

        src, syscall, dst, src_label = content_triple_of(
            row["rel"], row["syscall"], row["owner"], row["other"])
        # 两端标签用于消除 `/usr/bin/mv` 这类"既是进程又是文件"的内容歧义（与取边时的判定共用一份）
        _src_label, dst_label = labels_of(row["rel"])
        key = (src, syscall, dst)
        edge = table.get(key)
        if edge is None:
            edge = CollapsedEdge(
                src=src,
                syscall=syscall,
                dst=dst,
                src_label=src_label,
                dst_label=dst_label,
                t0=row["starttime"],
                t1=row["endtime"],
                dist=int(row.get("dist") or 0),
                via_kind=str(row.get("via_kind") or ""),
                via_key=str(row.get("via_key") or ""),
                channels=int(row.get("support") or 0),
            )
            table[key] = edge
        else:
            edge.channels |= int(row.get("support") or 0)
            if int(row.get("dist") or 0) < edge.dist:
                # 同一个三元组可能有多个实例：结构上下文取跳数最小的那一份（确定性：相同则保留先到的）
                edge.dist = int(row.get("dist") or 0)
                edge.via_kind = str(row.get("via_kind") or "")
                edge.via_key = str(row.get("via_key") or "")
        edge.instances += 1
        effect = str(row.get("effect") or "")
        if effect:
            edge.effects.add(effect)
        edge.bytes += max(0, int(row.get("bytes") or 0))
        edge.event_ids.append(int(row["event_id"]))
        edge.t0 = min(edge.t0, int(row["starttime"]))
        edge.t1 = max(edge.t1, int(row.get("endtime") or row["starttime"]))
        edge.rels.add(row["rel"])
        if row.get("process_id"):
            edge.members.add(str(row["process_id"]))
        # 两端身份：属主那一端一定是进程（归属规则），另一端按标签取；标识为空就丢这一端
        owner_ident = ("Process", str(row.get("process_id") or ""))
        other_ident = _other_identity(row)
        src_ident, dst_ident = ((owner_ident, other_ident) if owner_is_source(row["rel"])
                                else (other_ident, owner_ident))
        if src_ident[1]:
            edge.src_identities.add(src_ident)
        if dst_ident[1]:
            edge.dst_identities.add(dst_ident)
    edges = sorted(table.values(), key=lambda e: (e.t0, e.src, e.syscall, e.dst))
    return FoldResult(edges=edges, raw_instances=raw, dropped_startup_reads=dropped)


def fold_records(rows: Iterable[dict[str, Any]], *,
                 process_info_fn: Optional[Callable[[str], Any]] = None,
                 process_metas: Optional[dict[str, dict[str, Any]]] = None,
                 network_protocols: Optional[dict[str, str]] = None,
                 ) -> tuple[dict[tuple[str, str, str], dict[str, Any]], dict[str, Any]]:
    """一步直接折叠为带完整渲染上下文的候选三元组字典映射，消除上层二次循环包装。"""
    folded = fold(rows)
    metas = process_metas or {}
    protocols = network_protocols or {}
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in folded.edges:
        rec = edge.to_dict(with_event_ids=True)
        if edge.via_kind == "Process" and process_info_fn:
            info = process_info_fn(edge.via_key) or {}
            shown = str(info.get("exepath") or info.get("name") or "")
            rec["via"] = f"Process {shown or edge.via_key}"
        members = sorted(rec.get("member_processes") or [])
        if members:
            rec["process_id"] = min(members, key=lambda k: (int((metas.get(k) or {}).get("t0") or 0), k))
        # 网络端点协议
        src_label = str(rec.get("src_label") or "")
        dst_label = str(rec.get("dst_label") or "")
        if src_label == "Network":
            rec["network_protocol"] = protocols.get(str(rec.get("src") or ""), "")
        elif dst_label == "Network":
            rec["network_protocol"] = protocols.get(str(rec.get("dst") or ""), "")
        else:
            rec["network_protocol"] = ""
        records[triple(rec)] = rec
    return records, {"raw_instances": folded.raw_instances,
                     "collapsed_triples": len(records),
                     "dropped_startup_reads": folded.dropped_startup_reads}


# ==== 2. 进程身份摘要 ====


def _origins(by_process: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """进程标识 -> 来源（执行新程序 / 派生 / 无记录），取时间最早的那条派生边。

    派生边的另一端就是父进程：记下父进程标识与内容、派生条数，供渲染使用（不再查库）。
    """
    out: dict[str, dict[str, Any]] = {}
    for pid, rows in by_process.items():
        exec_t = spawn_t = None
        exec_p = spawn_p = exec_pc = spawn_pc = ""
        n = 0
        for row in rows:
            if not is_derivation(str(row.get("rel") or "")):
                continue
            t = int(row.get("starttime") or 0)
            other = str(row.get("other_process_id") or "")
            content = str(row.get("other") or "")
            n += 1
            if str(row.get("syscall") or "") == "execve":
                if exec_t is None or t < exec_t:
                    exec_t, exec_p, exec_pc = t, other, content
            elif spawn_t is None or t < spawn_t:
                spawn_t, spawn_p, spawn_pc = t, other, content
        if exec_t is not None:
            out[pid] = {"kind": "exec", "parent": exec_p, "parent_content": exec_pc, "t": exec_t, "n": n}
        elif spawn_t is not None:
            out[pid] = {"kind": "spawn", "parent": spawn_p, "parent_content": spawn_pc, "t": spawn_t, "n": n}
        else:
            out[pid] = {"kind": "none", "parent": "", "parent_content": "", "t": 0, "n": 0}
    return out


def summarize_process(source: Any, process_id: str, owner: str,
                      rows: list[dict[str, Any]]) -> dict[str, Any]:
    """一个进程的身份摘要（命令行、时间范围、边数）。"""
    info = source.process_info(process_id) or {}
    return {
        "process_id": process_id,
        "owner": owner,
        "owner_args": info.get("cmdline") or info.get("args") or "",
        "owner_pid": info.get("pid") or "",
        "t0": min(int(r["starttime"]) for r in rows),
        "t1": max(int(r.get("endtime") or r["starttime"]) for r in rows),
        "n_edges": len(rows),
    }


def build_process_context(source: Any, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """从闭包产出的事件行生成每个进程的身份摘要（按进程标识去重）。

    `rows` 已经按（开始时刻, 事件编号）排好序（闭包引擎排的），分组是顺序遍历，
    因此每个进程的边清单天然有序，这里不再逐个进程重排一遍。
    """
    by_process: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_process.setdefault(str(row["process_id"]), []).append(row)

    origins = _origins(by_process)
    metas: dict[str, dict[str, Any]] = {}
    for pid, process_rows in by_process.items():
        meta = summarize_process(source, pid, str(process_rows[0]["owner"]), process_rows)
        meta["origin"] = origins.get(pid) or {"kind": "none", "parent": "", "parent_content": "",
                                              "t": 0, "n": 0}
        metas[pid] = meta
    return metas


# ==== 3. 展开编排 ====


@dataclass
class Prepared:
    """一次展开的结果与它需要的活资源（来源保持打开，供判定中途重跑闭包）。"""

    source: Any
    seeds: list[Event]
    stats: dict[str, Any]
    rounds: int = 1


def seed_events(deps: "Deps") -> list[Event]:
    """把 intake 命中的终点事件转成闭包种子（终点事件本身永远收进闭包，不受规则影响）。"""
    seeds: list[Event] = []
    for row in deps.record.poi_rows:
        raw_start = row.get("starttime")
        raw_end = row.get("endtime")
        raw_res = row.get("res")
        has_start = raw_start is not None
        has_end = raw_end is not None
        start = int(raw_start) if has_start else 0
        end = int(raw_end) if has_end else start
        res_val = int(raw_res) if raw_res is not None else None
        seeds.append(Event(
            event_id=int(row["event_id"]), rel=str(row.get("rel") or deps.scenario.poi.rel),
            syscall=str(row.get("syscall") or ""), bytes=int(row.get("bytes") or 0), start=start,
            end=end, pid=str(row.get("process_id") or ""),
            owner=str(row.get("process_content") or ""), other=str(row.get("other") or ""),
            other_label=str(row.get("other_label")
                            or SCENARIO_KIND_LABELS.get(deps.scenario.poi.kind, "Network")),
            effect=effect_name(effect_code(raw_res)),
            action=str(row.get("action") or ""),
            result=res_val,
            has_start=has_start,
            has_end=has_end,
            src_host=str(row.get("src_host") or ""),
            dst_host=str(row.get("dst_host") or ""),
            dst_kind=row.get("dst_kind"),
        ))
    return seeds


def _collect_raw_events_and_vertices(
    rows: list[dict[str, Any]],
    source: Any,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """将阶段 1 闭包原始事件整理为规范单事件记录列表与按实体主键去重的属性表。"""
    has_vertex_attr = hasattr(source, "vertex_attr")
    vertex_attrs: dict[str, dict[str, Any]] = {}
    raw_events: list[dict[str, Any]] = []

    def ensure_vertex(kind: str, key: str) -> dict[str, Any]:
        vkey = f"{kind}:{key}"
        attr = vertex_attrs.get(vkey)
        if attr is None:
            attr = source.vertex_attr(kind, key) if has_vertex_attr else {"kind": kind, "key": key}
            vertex_attrs[vkey] = attr
        return attr

    for row in rows:
        rel_short = normalize_rel(str(row.get("rel") or ""))
        src_label, dst_label = labels_of(rel_short)
        rel_full = f"{src_label}To{dst_label}"
        owner_key = str(row.get("process_id") or "")
        other_label = str(row.get("other_label") or "")
        other_key = (
            str(row.get("other_process_id") or "")
            if other_label == "Process"
            else str(row.get("other") or "")
        )
        if owner_is_source(rel_short):
            src_kind, src_key = "Process", owner_key
            dst_kind, dst_key = other_label or dst_label, other_key
        else:
            src_kind, src_key = other_label or src_label, other_key
            dst_kind, dst_key = "Process", owner_key

        src_attr = ensure_vertex(src_kind, src_key)
        dst_attr = ensure_vertex(dst_kind, dst_key)
        src_host = str(row.get("src_host") or src_attr.get("host_id") or "")
        dst_host = str(row.get("dst_host") or dst_attr.get("host_id") or "")
        src_file_type = row.get("src_kind") if row.get("src_kind") is not None else src_attr.get("file_type")
        dst_file_type = row.get("dst_kind") if row.get("dst_kind") is not None else dst_attr.get("file_type")
        action = str(row.get("action") or "")
        eid = int(row["event_id"])
        start_ns = int(row["starttime"]) if row.get("has_start", True) else None
        end_ns = int(row["endtime"]) if row.get("has_end", True) else None

        raw_events.append({
            "id": f"{rel_full}:{eid}:{action}",
            "event_id": eid,
            "rel": rel_short,
            "rel_full": rel_full,
            "action": action,
            "syscall": str(row.get("syscall") or ""),
            "start_ns": start_ns,
            "end_ns": end_ns,
            "result": row.get("result"),
            "bytes": int(row.get("bytes") or 0),
            "effect": str(row.get("effect") or ""),
            "src_kind": src_kind,
            "src_key": src_key,
            "src_host": src_host,
            "src_file_type": src_file_type,
            "dst_kind": dst_kind,
            "dst_key": dst_key,
            "dst_host": dst_host,
            "dst_file_type": dst_file_type,
            "dist": int(row.get("dist") or 0),
            "via_kind": str(row.get("via_kind") or ""),
            "via_key": str(row.get("via_key") or ""),
            "support": int(row.get("support") or 0),
        })
    return raw_events, vertex_attrs


def event_to_raw_dict(ev: Event) -> dict[str, Any]:
    """按需将单条轻量 Event 对象转为规范原始事件字典（仅在阶段 6.5 / 阶段 7 对目标事件调用）。"""
    rel_short = normalize_rel(ev.rel)
    src_label, dst_label = labels_of(rel_short)
    rel_full = f"{src_label}To{dst_label}"
    other_label = ev.other_label
    other_key = ev.other_process_id if other_label == "Process" else ev.other
    if owner_is_source(rel_short):
        src_kind, src_key = "Process", ev.pid
        dst_kind, dst_key = other_label or dst_label, other_key
    else:
        src_kind, src_key = other_label or src_label, other_key
        dst_kind, dst_key = "Process", ev.pid
    action = ev.action or ""
    eid = ev.event_id
    return {
        "id": f"{rel_full}:{eid}:{action}",
        "event_id": eid,
        "rel": rel_short,
        "rel_full": rel_full,
        "action": action,
        "syscall": ev.syscall,
        "start_ns": ev.start if ev.has_start else None,
        "end_ns": ev.end if ev.has_end else None,
        "result": ev.result,
        "bytes": ev.bytes,
        "effect": ev.effect,
        "src_kind": src_kind,
        "src_key": src_key,
        "src_host": ev.src_host,
        "src_file_type": ev.src_kind,
        "dst_kind": dst_kind,
        "dst_key": dst_key,
        "dst_host": ev.dst_host,
        "dst_file_type": ev.dst_kind,
        "dist": ev.dist,
        "via_kind": ev.via_kind,
        "via_key": ev.via_key,
        "support": ev.support,
    }


def prepare(deps: "Deps") -> Prepared:
    """开来源、跑闭包（含受限前向补链）：因果闭包 → 进程摘要 → 折叠记录。失败时关掉来源再抛出。"""
    inv = deps.record
    source = getattr(deps, "source", None)
    if source is None:
        source = open_source(deps.graph, scenario=inv.scenario, log=deps.log)
    try:
        seeds = seed_events(deps)
        closure_res = run_causal_closure(source, seeds, poi_t0=int(inv.poi_t0 or 0),
                                         forward_chain=True, log=deps.log, with_events=True)
        rows = closure_res["rows"]
        stats = closure_res["stats"]
        seeds = closure_res["seeds"]
        stats["source"] = source.stats()

        # 直接保留轻量 Event 列表与 .tsg 路径，避免阶段 1 提前构造百万级全量字典副本
        inv.closure_events = closure_res.get("events") or []
        inv.tsg_path = str(getattr(source, "path", "") or "")

        metas = build_process_context(source, rows)
        inv.process_context.update(metas)
        if inv.poi_rows:
            poi_pid = str(inv.poi_rows[0].get("process_id") or "")
            if poi_pid in metas:
                inv.poi_process = poi_pid

        records, fold_stats = fold_records(
            rows,
            process_info_fn=source.process_info,
            process_metas=metas,
            network_protocols=source.network_protocols(),
        )
        inv.edges.update(records)
    except BaseException:
        source.close()
        raise

    deps.log(f"[expand] 闭包完成：{stats['rounds']} 轮 / 展开顶点 {stats['process_expands']} 个进程 + "
             f"{stats['object_expands']} 个文件或端点 / 收边 {stats['events_included']} 条 → "
             f"进程 {len(inv.process_context)} 个 / 折叠边 {len(inv.edges)} 条；"
             f"折叠跳过启动期动态库读取 {fold_stats['dropped_startup_reads']} 条；"
             f"来源 {stats['source']}")
    trace_event(deps.trace, "expand_closure", rounds=stats["rounds"], processes=len(inv.process_context),
                edges=len(inv.edges), events=stats["events_included"],
                rows_fetched=stats["rows_fetched"],
                dropped_startup_reads=fold_stats["dropped_startup_reads"],
                queries=stats["source"].get("queries"), source=stats["source"].get("source"))
    return Prepared(source=source, seeds=seeds, stats=stats)


def finish(prepared: Prepared) -> None:
    """关掉来源（判定结束或提前退出时调用）。"""
    prepared.source.close()
