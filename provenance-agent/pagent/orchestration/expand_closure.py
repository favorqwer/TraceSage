"""展开（编排，事件级闭包引擎）：终点事件 → 反向闭包 → 边行 → 折叠边 + 进程上下文。

第 1 层给出闭包的**事件集合**（每条边一条记录，带来源进程），本模块把它接给两个下游：

- `record.edges`：折叠边（内容三元组 → 记录），判定与报告的单位 —— 第 1 层尾部的折叠；
  网络端点的传输层协议在折叠后补进记录（只供判定时渲染，不属于三元组、不进报告）；
- `record.process_context`：进程身份摘要（命令行、来源、活动时间范围）—— 判定层的上下文准备，
  必须在事件行还在手上时调用，只用于判定时的渲染与报告的阶段划分。

判定上下文的分组单位就是**进程**（边的归属由图上的归属规则唯一决定：进程写文件/网络归源进程，
文件/网络被进程读写归目标进程，进程派生归子进程），没有“步骤 / 实例”这一层，不受展开顺序影响。

第 1 层会改变结果的判据全部来自判据表（`pagent/rules/l1_judgments.json`）：本模块只负责
按顺序调用——常驻服务进程（`l1.resident_processes`）→ 实例范围（`l1.filter_output_rows`）→
折叠（`l1.fold`）→ 条目剔除（`l1.apply_item_drops`）。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..contracts import triple
from ..core import settings
from ..core.trace import trace_event
from ..layers import l1_reach as l1
from ..layers import l2_judge as l2

if TYPE_CHECKING:
    from ..app import Deps

# 条目判据的编号：报告里的两个剔除计数按它们从剔除结果里取（表在 pagent/rules/l1_judgments.json）
_PROC_STATE_RULE = "item.proc_state_numeric_unlisted"
_EMPTY_READ_RULE = "item.all_instances_empty_read"


def seed_events(deps: "Deps") -> list[l1.Event]:
    """把 intake 命中的终点事件转成闭包种子（终点事件本身永远收进闭包，不受规则影响）。"""
    seeds: list[l1.Event] = []
    for row in deps.record.poi_rows:
        start = int(row.get("starttime") or 0)
        seeds.append(l1.Event(
            event_id=int(row["event_id"]), rel=str(row.get("rel") or deps.scenario.poi.rel),
            syscall=str(row.get("syscall") or ""), bytes=int(row.get("bytes") or 0), start=start,
            end=int(row.get("endtime") or start), pid=str(row.get("process_id") or ""),
            owner=str(row.get("process_content") or ""), other=str(row.get("other") or ""),
            other_label=str(row.get("other_label") or ("File" if deps.scenario.poi.kind == "file" else "Network")),
        ))
    return seeds


def expand_closure(deps: "Deps") -> dict[str, Any]:
    """跑一次闭包展开，把结果写进 `record`。

    只读本地顶点-时间索引（`source.stats()` 是本次的计数）。常驻服务进程在这里对整图算一次，
    当参数传给实例范围（不写全局状态）。
    """
    inv = deps.record
    protocol_by_network: dict[str, str] = {}
    source = l1.open_source(deps.graph, log=deps.log)
    try:
        result = l1.run_closure(source, seed_events(deps),
                                poi_t0=int(inv.poi_t0 or 0), log=deps.log, with_events=False)
        rows = result["rows"]
        # 进程静态属性：判定层的身份摘要要用（灌内存缓存；索引来源零查询）
        source.process_info_many(sorted({str(row.get("process_id") or "") for row in rows} - {""}))
        # 网络端点的传输层协议（顶点属性；索引顶点表里图着，只取一份）
        protocol_by_network = source.network_protocols()
        # 进程标识 -> 进程号：范围划分的「同进程号实例」要用（进程标识是拼接串，拆不得）
        process_numbers = source.process_numbers()
        # 常驻服务进程：收边之后、划范围之前对整图算一次
        residents = l1.resident_processes(deps.graph, log=deps.log)
        rows, scope_stats = l1.filter_output_rows(rows, inv.poi_rows,
                                                  enabled=settings.output_filter_enabled(),
                                                  log=deps.log, pids=process_numbers,
                                                  residents=residents)
        stats = dict(result["stats"])
        stats["source"] = source.stats()
        stats["scope"] = scope_stats
    finally:
        source.close()

    metas = l2.build_process_context(deps.graph, rows)
    inv.process_context.update(metas)
    if inv.poi_rows:
        poi_pid = str(inv.poi_rows[0].get("process_id") or "")
        if poi_pid in metas:
            inv.poi_process = poi_pid

    folded = l1.fold(rows)
    # 折叠之后的条目剔除（按判据表顺序执行；两份计数各记）
    folded_edges, drop_counts = l1.apply_item_drops(
        folded.edges, poi_event_ids=l1.poi_event_ids(inv.poi_rows),
        process_numbers=process_numbers, log=deps.log)
    proc_dropped = drop_counts.get(_PROC_STATE_RULE, 0)
    empty_dropped = drop_counts.get(_EMPTY_READ_RULE, 0)
    records: list[dict[str, Any]] = []
    for edge in folded_edges:
        record = edge.to_dict(with_event_ids=True)
        # 上游顶点统一成与边行同一口径的显示内容：进程用可执行路径（空则进程名），
        # 文件 / 网络端点用路径或标识串本身（两者本来就等于内容）。
        via = str(record.get("via") or "")
        if via.startswith("Process "):
            pid = via.split(" ", 1)[1]
            info = l1.process_info(deps.graph, pid)
            shown = str(info.get("exepath") or info.get("name") or "") if info else ""
            record["via"] = f"Process {shown or pid}"
        members = sorted(record.get("member_processes") or [])
        if members:
            record["process_id"] = min(members, key=lambda k: (int((metas.get(k) or {}).get("t0") or 0), k))
        # 网络端点协议（一条边最多一个网络端点）：给渲染用，不属于三元组、不进报告
        if str(record.get("src_label") or "") == "Network":
            record["network_protocol"] = protocol_by_network.get(str(record.get("src") or ""), "")
        elif str(record.get("dst_label") or "") == "Network":
            record["network_protocol"] = protocol_by_network.get(str(record.get("dst") or ""), "")
        else:
            record["network_protocol"] = ""
        records.append(record)

    for record in records:
        inv.edges[triple(record)] = record

    deps.log(f"[expand] 闭包完成：{stats['rounds']} 轮 / 展开顶点 {stats['process_expands']} 个进程 + "
             f"{stats['object_expands']} 个文件或端点 / 收边 {stats['events_included']} 条 → "
             f"进程 {len(inv.process_context)} 个 / 折叠边 {len(inv.edges)} 条；"
             f"实例范围 {scope_stats}；"
             f"来源 {stats['source']}")
    trace_event(deps.trace, "expand_closure", rounds=stats["rounds"], processes=len(inv.process_context),
                edges=len(inv.edges), events=stats["events_included"],
                rows_fetched=stats["rows_fetched"],
                queries=stats["source"].get("queries"), source=stats["source"].get("source"))
    return {"rounds": stats["rounds"], "stop_reason": "frontier_exhausted",
            "fold": {"raw_instances": folded.raw_instances, "collapsed_triples": len(inv.edges),
                     "empty_read_triples_dropped": empty_dropped,
                     "unrelated_proc_state_reads_dropped": proc_dropped},
            "scope": scope_stats,
            "closure": stats}
