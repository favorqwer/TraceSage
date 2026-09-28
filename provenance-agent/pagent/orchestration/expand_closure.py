"""展开（编排，事件级闭包引擎）：终点事件 → 反向闭包 → 边行 → 折叠边 + 进程上下文。

第 1 层给出闭包的**事件集合**（每条边一条记录，带来源进程），本模块把它接给两个下游：

- `record.edges`：折叠边（内容三元组 → 记录），判定与报告的单位 —— 第 1 层尾部的折叠；
- `record.process_context`：进程身份摘要（命令行、来源、活动时间范围）—— 判定层的上下文准备，
  必须在事件行还在手上时调用，只用于判定时的渲染与报告的阶段划分。

判定上下文的分组单位就是**进程**（边的归属由图上的归属规则唯一决定：进程写文件/网络归源进程，
文件/网络被进程读写归目标进程，进程派生归子进程），没有“步骤 / 实例”这一层，不受展开顺序影响。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..contracts import triple
from ..core import edge_rules, settings
from ..core.trace import trace_event
from ..layers import l1_reach as l1
from ..layers import l2_judge as l2

if TYPE_CHECKING:
    from ..app import Deps

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


def _rule_hit(edge: dict[str, Any]) -> bool:
    """候选边命中五条规则里的哪一条；未命中返回 False。"""
    if edge_rules.rule_of(edge["src"], edge["syscall"], edge["dst"],
                          str(edge.get("src_label") or ""))[0]:
        return True
    rel = str((edge.get("rels") or [""])[0])
    return bool(edge_rules.candidate_drop_code({**edge, "rel": rel}))


def _poi_triple(row: dict[str, Any]) -> tuple[str, str, str]:
    """终点事件的内容三元组（方向由 POI 的关系类型唯一决定）——不算「规则残留」的豁免名单。"""
    owner = str(row.get("process_content") or "")
    other = str(row.get("other") or "")
    syscall = str(row.get("syscall") or "")
    return (other, syscall, owner) if str(row.get("rel") or "") in ("f2p", "n2p") else (owner, syscall, other)


def expand_closure(deps: "Deps") -> dict[str, Any]:
    """跑一次闭包展开，把结果写进 `record`。

    展开分两遍（见 `l1_reach/siblings.py`）：第一遍定主干名单，第二遍带子进程把关。
    两遍都读同一个本地索引，中间没有任何东西会改它，所以两遍看到的是同一份数据。
    来源侧的计数按遍数分开：`source.stats()` 是第二遍的（第一遍的在把关统计的 `source_pass1` 里），
    两边不相加。
    """
    inv = deps.record
    source = l1.open_source(deps.graph, log=deps.log)
    try:
        result = l1.run_gated_closure(source, seed_events(deps),
                                      poi_t0=int(inv.poi_t0 or 0), log=deps.log)
        rows = result["rows"]
        stats = dict(result["stats"])
        stats["source"] = source.stats()
        stats["gate"] = result.get("gate")
    finally:
        source.close()

    metas = l2.build_process_context(deps.graph, rows)
    inv.process_context.update(metas)
    if settings.command_table_enabled():
        tally: dict[str, int] = {}
        for meta in metas.values():
            command = meta.get("command") or {}
            key = str(command.get("source") or "?")
            if key == "none":
                key = f"none:{command.get('reason')}"
            tally[key] = tally.get(key, 0) + 1
        deps.log(f"[commands] 命令表（开关打开）：{dict(sorted(tally.items()))}")
        trace_event(deps.trace, "commands", **{k: v for k, v in sorted(tally.items())})
    if inv.poi_rows:
        poi_pid = str(inv.poi_rows[0].get("process_id") or "")
        if poi_pid in metas:
            inv.poi_process = poi_pid

    folded = l1.fold(rows)
    for edge in folded.edges:
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
        inv.edges[triple(record)] = record

    # 五条规则都在取边时判完（命中就不收边）：这里数一遍候选表里有没有漏进来的命中
    # （**终点事件不受规则约束**，不计）。为 0 才说明那条口径成立。
    poi_triples = {_poi_triple(row) for row in inv.poi_rows}
    residue = sum(1 for key, edge in inv.edges.items() if key not in poi_triples and _rule_hit(edge))

    deps.log(f"[expand] 闭包完成：{stats['rounds']} 轮 / 展开顶点 {stats['process_expands']} 个进程 + "
             f"{stats['object_expands']} 个文件或端点 / 收边 {stats['events_included']} 条 → "
             f"进程 {len(inv.process_context)} 个 / 折叠边 {len(inv.edges)} 条；"
             f"规则残留 {residue} 条（终点事件除外，应为 0）；"
             f"规则剔除 {stats['dropped']} / 把关挡下 {stats.get('gate_blocked', 0)}；"
             f"来源（第二遍）{stats['source']}；主干（第一遍）{stats.get('gate')}")
    trace_event(deps.trace, "expand_closure", rounds=stats["rounds"], processes=len(inv.process_context),
                edges=len(inv.edges), events=stats["events_included"],
                rows_fetched=stats["rows_fetched"], dropped=stats["dropped"], gate=stats.get("gate"),
                queries=stats["source"].get("queries"), source=stats["source"].get("source"))
    return {"rounds": stats["rounds"], "stop_reason": "frontier_exhausted",
            "fold": {"raw_instances": folded.raw_instances, "collapsed_triples": len(inv.edges),
                     "rule_residue": residue},
            "dropped": dict(sorted(stats["dropped"].items())),
            "closure": stats}
