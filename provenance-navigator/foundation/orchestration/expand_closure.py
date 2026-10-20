"""展开（编排，事件级闭包引擎）：终点事件 → 反向闭包 → 边行 → 折叠边 + 进程上下文。

第 1 层给出闭包的**事件集合**（每条边一条记录，带来源进程），本模块把它接给两个下游：

- `record.edges`：折叠边（内容三元组 → 记录），判定与报告的单位——第 1 层尾部的折叠；
  网络端点的传输层协议在折叠后补进记录（只供判定时渲染，不属于三元组、不进报告）；
- `record.process_context`：进程身份摘要（命令行、来源、活动时间范围）——判定层的上下文准备，
  必须在事件行还在手上时调用，只用于判定时的渲染与报告的阶段划分。

判定上下文的分组单位就是**进程**（边的归属由图上的归属规则唯一决定：进程写文件/网络归源进程，
文件/网络被进程读写归目标进程，进程派生归子进程），没有“步骤 / 实例”这一层，不受展开顺序影响。

取数来源的生命周期**跨判定**：前向补链要在判定中途把新发现的事件当额外种子重跑一遍闭包，
所以来源由这里打开、判完（或出错）再关。对外三个入口：

- `prepare(deps)`：开来源 → 反向闭包 → 折叠 → 进程摘要，来源保持打开；
- `extend(deps, prepared, extra_seeds)`：把额外种子并进闭包重跑，返回**新增**的内容三元组；
- `finish(prepared)`：关来源。

本模块只负责按顺序编排：因果闭包（`l1.run_causal_closure`，内部执行反向闭包与受限前向补链）→
折叠（`l1.fold_records`）→ 进程身份摘要（`l2.build_process_context`）。**第 1 层不做任何尾部裁剪。**
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..core.trace import trace_event
from ..layers import l1_reach as l1
from ..layers import l2_judge as l2

if TYPE_CHECKING:
    from ..deps import Deps


@dataclass
class Prepared:
    """一次展开的结果与它需要的活资源（来源保持打开，供判定中途重跑闭包）。"""

    source: Any
    seeds: list[l1.Event]
    stats: dict[str, Any]
    fold: dict[str, Any]
    poi_t0: int = 0
    closed_processes: set[str] = field(default_factory=set)
    rounds: int = 1
    extra_seeds: int = 0
    new_triples: list[tuple[str, str, str]] = field(default_factory=list)


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


def prepare(deps: "Deps") -> Prepared:
    """开来源、跑闭包（含受限前向补链）：因果闭包 → 进程摘要 → 折叠记录。失败时关掉来源再抛出。"""
    inv = deps.record
    source = l1.open_source(deps.graph, log=deps.log)
    try:
        seeds = seed_events(deps)
        closure_res = l1.run_causal_closure(source, seeds, poi_t0=int(inv.poi_t0 or 0),
                                            forward_chain=True, log=deps.log)
        rows = closure_res["rows"]
        stats = closure_res["stats"]
        seeds = closure_res["seeds"]
        closed_processes = closure_res["closed_processes"]
        stats["source"] = source.stats()

        metas = l2.build_process_context(deps.graph, rows)
        inv.process_context.update(metas)
        if inv.poi_rows:
            poi_pid = str(inv.poi_rows[0].get("process_id") or "")
            if poi_pid in metas:
                inv.poi_process = poi_pid

        records, fold = l1.fold_records(
            rows,
            process_info_fn=lambda pid: l1.process_info(deps.graph, pid),
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
             f"来源 {stats['source']}")
    trace_event(deps.trace, "expand_closure", rounds=stats["rounds"], processes=len(inv.process_context),
                edges=len(inv.edges), events=stats["events_included"],
                rows_fetched=stats["rows_fetched"],
                queries=stats["source"].get("queries"), source=stats["source"].get("source"))
    return Prepared(source=source, seeds=seeds, stats=stats, fold=fold,
                    poi_t0=int(inv.poi_t0 or 0), closed_processes=closed_processes)


def extend(deps: "Deps", prepared: Prepared, extra_seeds: list[l1.Event],
           ) -> tuple[list[tuple[str, str, str]], dict[str, Any]]:
    """把额外种子并进闭包重跑，返回（新增的内容三元组, 本轮计数）。

    新增的三元组同时写进 `record.edges`；已经存在的三元组保持不变（闭包单调，重跑只会给出
    同一份或更多的边）。
    """
    inv = deps.record
    known = set(inv.edges)
    all_seeds = prepared.seeds + extra_seeds
    closure_res = l1.run_causal_closure(prepared.source, all_seeds, poi_t0=prepared.poi_t0,
                                        forward_chain=False, log=deps.log)
    rows = closure_res["rows"]
    stats = closure_res["stats"]
    prepared.closed_processes |= closure_res["closed_processes"]

    metas = l2.build_process_context(deps.graph, rows)
    inv.process_context.update(metas)
    records, _fold = l1.fold_records(
        rows,
        process_info_fn=lambda pid: l1.process_info(deps.graph, pid),
        process_metas=metas,
        network_protocols=prepared.source.network_protocols(),
    )
    new_triples = [key for key in records if key not in known]
    for key in new_triples:
        inv.edges[key] = records[key]
    prepared.rounds += 1
    prepared.extra_seeds = len(extra_seeds)
    prepared.new_triples = sorted(new_triples)
    deps.log(f"[expand] 前向补链重跑闭包：额外种子 {len(extra_seeds)} 条 / 收边 {stats['events_included']} 条 → "
             f"新增内容三元组 {len(new_triples)} 条（候选表合计 {len(inv.edges)} 条）")
    trace_event(deps.trace, "expand_forward", seeds=len(extra_seeds),
                events=stats["events_included"], new_triples=len(new_triples),
                edges=len(inv.edges))
    return new_triples, stats


def finish(prepared: Prepared) -> None:
    """关掉来源（判定结束或提前退出时调用）。"""
    prepared.source.close()
