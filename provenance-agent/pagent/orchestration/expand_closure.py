"""展开（编排，事件级闭包引擎）：终点事件 → 反向闭包 → 边行 → 步骤上下文 + 折叠边。

第 1 层给出闭包的**事件集合**（每条边一条记录，带来源进程），本模块负责把它变成下游要的两种东西：

- `record.steps`：步骤元信息（进程实例、摘要、同管道组的命令行）——只用于判定时的上下文渲染；
- `record.edges`：折叠边（内容三元组 → 记录），判定与报告的单位。

步骤键（`S:<进程>:<该进程最早一条被收进来的边的时刻>`）只用于分组与渲染，**不参与可达性计算**：
边的归属由图上的归属规则唯一决定（进程写文件/网络归源进程，文件/网络被进程读写归目标进程，
进程派生归子进程），不受展开顺序影响。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..contracts import triple
from ..core.trace import trace_event
from ..layers import l1_reach as l1
from ..layers import l2_prepare as l2

if TYPE_CHECKING:
    from ..app import Deps

_CHANNEL_PREFIXES = ("pipe:[", "unix:[")


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


def _steps_from_rows(rows: list[dict[str, Any]], graph: Any) -> tuple[dict[str, Any], dict[str, list[dict]]]:
    """按来源进程实例分组成步骤，并给每个步骤生成摘要与同管道组的命令行。

    `rows` 已经按（开始时刻, 事件编号）排好序（闭包引擎排的），分组是顺序遍历，
    因此每个步骤的边清单天然有序，这里不再逐个步骤重排一遍。
    """
    by_step: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_step.setdefault(str(row["step_key"]), []).append(row)

    metas: dict[str, dict[str, Any]] = {}
    for step_key, step_rows in by_step.items():
        step = l1.Step(key=step_key, process_id=_pid_of(step_key), owner=str(step_rows[0]["owner"]),
                       t0=int(step_rows[0]["starttime"]),
                       t1=max(int(r.get("endtime") or r["starttime"]) for r in step_rows), rows=step_rows)
        metas[step_key] = {"step_key": step_key, "owner": step.owner, "group": [step_key],
                           "summary": l2.summarize(graph, step), "group_cmds": []}

    # 同管道/unix 顶点上时间重叠的步骤并成一组（渲染上下文用；候选集不受影响）
    channels: dict[str, set[str]] = {}
    for step_key, step_rows in by_step.items():
        for row in step_rows:
            if row["rel"] in ("p2f", "f2p") and str(row["other"]).startswith(_CHANNEL_PREFIXES):
                channels.setdefault(str(row["other"]), set()).add(step_key)
    groups = _union_groups(channels)
    for members in groups:
        if len(members) < 2:
            continue
        cmds: list[str] = []
        for key in members:
            summary = (metas.get(key) or {}).get("summary") or {}
            cmd = f"{summary.get('owner') or ''} {summary.get('owner_args') or ''}".strip()
            if cmd and cmd not in cmds:
                cmds.append(cmd)
        for key in members:
            metas[key]["group"] = sorted(members)
            metas[key]["group_cmds"] = cmds
    return metas, by_step


def _pid_of(step_key: str) -> str:
    try:
        return l1.parse_step_key(step_key)[0]
    except Exception:  # noqa: BLE001 - 键格式异常不该让展开失败
        return ""


def _union_groups(channels: dict[str, set[str]]) -> list[set[str]]:
    """按共享顶点把步骤并成连通组（确定性：按步骤键排序后逐个合并）。"""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for members in channels.values():
        ordered = sorted(members)
        for member in ordered:
            parent.setdefault(member, member)
        for member in ordered[1:]:
            union(ordered[0], member)
    out: dict[str, set[str]] = {}
    for member in parent:
        out.setdefault(find(member), set()).add(member)
    return [out[key] for key in sorted(out)]


def expand_closure(deps: "Deps") -> dict[str, Any]:
    """跑一次闭包展开，把结果写进 `record`。"""
    inv = deps.record
    opts = l1.Options()
    source = l1.open_source(deps.graph, log=deps.log)
    try:
        result = l1.run_closure(source, seed_events(deps), options=opts,
                                poi_t0=int(inv.poi_t0 or 0), log=deps.log)
        rows = result["rows"]
        stats = dict(result["stats"])
        stats["source"] = source.stats()
        stats["options"] = opts.as_dict()
    finally:
        source.close()

    metas, by_step = _steps_from_rows(rows, deps.graph)
    inv.steps.update(metas)
    if inv.poi_rows:
        poi_pid = str(inv.poi_rows[0].get("process_id") or "")
        for key, meta in metas.items():
            if _pid_of(key) == poi_pid:
                inv.poi_step = key
                break

    folded = l2.fold(rows)
    for edge in folded.edges:
        record = edge.to_dict(with_event_ids=True)
        members = sorted(record.get("member_steps") or [])
        if members:
            record["step_key"] = min(members, key=lambda k: (int((metas.get(k) or {}).get("summary", {}).get("t0") or 0), k))
        inv.edges[triple(record)] = record

    deps.log(f"[expand] 闭包完成：{stats['rounds']} 轮 / 展开顶点 {stats['process_expands']} 个进程 + "
             f"{stats['object_expands']} 个文件或端点 / 收边 {stats['events_included']} 条 → "
             f"步骤 {len(inv.steps)} 个 / 折叠边 {len(inv.edges)} 条；"
             f"规则剔除 {stats['dropped']}；来源 {stats['source']}")
    trace_event(deps.trace, "expand_closure", rounds=stats["rounds"], steps=len(inv.steps),
                edges=len(inv.edges), events=stats["events_included"],
                rows_fetched=stats["rows_fetched"], dropped=stats["dropped"],
                queries=stats["source"].get("queries"), source=stats["source"].get("source"))
    return {"rounds": stats["rounds"], "stop_reason": "frontier_exhausted",
            "fold": {"raw_instances": folded.raw_instances, "collapsed_triples": len(inv.edges),
                     "dropped_r1": folded.dropped_r1, "dropped_r2": folded.dropped_r2},
            "failed": {}, "closure": stats}
