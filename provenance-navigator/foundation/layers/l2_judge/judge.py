"""判定引擎与渲染（判定层）：批头共享表装配、提示词渲染、模型调用与来路映射。

本模块高内聚融合：
1. 提示词渲染：任务说明头、同类规模表、上一级父束引用、跨束痕迹线索、成员样本行格式化；
2. 判定调用：整批 JSON 通信、四值结论（all/none/mixed/unknown）解析、失败重试与并发调度；
3. 结论归宿：四值结论映射至三段来路（confirmed/excluded/kept）。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ...contracts import parse_bundle_verdicts, rel_time, short
from ...core import graph_facts, prompts, settings
from ...core.llm import BudgetCallback, call_json
from .bundles import LEVEL_NAMES, scale_stats

# 判定文字说明字典
VERDICT_TEXT = {
    "all": "整束相关",
    "none": "整束无关",
    "mixed": "混杂（继续拆）",
    "unknown": "信息不足（继续拆）",
    "missing": "没给结论（继续拆）",
    "vacuous_kept": "空拆（与父束相同，按未排除留）",
    "fanout_kept": "扇出（拆分产生的单条边，按未排除留）",
    "leaf_kept": "单条边无可拆（按未排除留）",
    "cap_kept": "未判（达到调用上限）",
}

# 判定结论映射到三段来路的字典
TIERS = {"all": "confirmed", "none": "excluded"}

AGG_NOTE = """
本批开头可能有两张**共享表**，束行里用 C 编号 / P 编号引用它们：
- 「同类规模」表：本批涉及的每个对象类别下一共有多少个束、中位成员数；束行的「规模」行里给出本束
  在该类别里按成员数的排名与百分位。体量大本身不等于攻击（批量维护、包管理器、日志轮转都会很大）；
  但当"体量在同类里靠前 + 程序角色可疑 + 时间贴着攻击链"同时出现时，
  不要因为程序看着例行就整批判无关。
- 「上一级束」表：本批子束是从哪个更大的束拆出来的（程序、动作、成员数、总字节、对象个数、判定与理由）；
  束行的「上一级：P*」就是引用它。拆分不会让成员变多：上一级有上百条成员、命中同一个对端主机、
  字节量很大这类事实在本束仍然有效，不要因为本束只剩一两条成员就把上一级的事实丢掉。
"""

# 提示词系统模板
BUNDLE_SYSTEM = prompts.load("judge_bundle.md").replace(
    "{REASON_MAX_CHARS}", str(settings.reason_max_chars())
)


def tier_of(verdict: str) -> str:
    """四值判定结论 -> 边级三段来路（只有 all/none 改变来路，其余一律保留为 kept）。"""
    return TIERS.get(str(verdict), "kept")


def level_name(level: int) -> str:
    """获取当前层级的规范显示名称。"""
    return LEVEL_NAMES[level] if 0 <= level < len(LEVEL_NAMES) else f"第 {level + 1} 级"


def fmt_bytes(value: Any) -> str:
    """字节数字节格式化为人类可读字符串。"""
    n = int(value or 0)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"


def edge_line(mid: str, record: dict[str, Any], ref_t: int) -> str:
    """将一条样本边格式化为紧凑行。"""
    members = sorted(record.get("member_processes") or [])
    return (f"    {mid} [进程 {members[0] if members else '?'}]"
            f" [{record.get('src_label')}] {short(record.get('src'), 70)} --{record.get('syscall')}-->"
            f" [{record.get('dst_label')}] {short(record.get('dst'), 70)}"
            f"（折叠事件数 {record.get('instances')}，字节 {record.get('bytes')}，"
            f"时间 {rel_time(record.get('t0'), ref_t)}）")


def build_task_header(poi_rows: list[dict[str, Any]]) -> str:
    """生成本批任务说明头（阐明调查终点、时间原点与规则口径）。"""
    if not poi_rows:
        return ""
    row = poi_rows[0]
    rel = str(row.get("rel") or "")
    other_label = str(row.get("other_label") or "")
    src_label, dst_label = graph_facts.labels_of(rel)
    owner = str(row.get("process_content") or "")
    other = str(row.get("other") or "")
    if other_label == "Network":
        protocol = str(row.get("other_protocol") or "").strip()
        if protocol:
            other = f"{other}（{protocol}）"
    syscall = str(row.get("syscall") or "")
    src, _syscall, dst, _src_label = graph_facts.content_triple_of(rel, syscall, owner, other)
    t0 = min(int(r.get("starttime") or 0) for r in poi_rows)
    return "\n".join([
        "## 本次调查的任务",
        "- 目标事件（本次调查的终点，往回追的起点）：",
        f"  [{src_label}] {src} --{syscall}--> [{dst_label}] {dst}",
        f"- 目标事件发生次数：{len(poi_rows)} 次；时间原点（最早一次发生的时刻）＝ {t0} 纳秒"
        "（下面进程表与边行里的时间都是相对这个原点算出的秒数）",
        "- 调查方向：只找**可能属于攻击路径**的上游活动（判断标准见系统说明）；目标事件本身也在清单里。",
        "- 调查方式：从目标事件出发，一层一层往回走；这一轮给你的不是单条边，而是**束**"
        "（同一程序、同一动作、同一类对象上的一批边）。",
        "- 相对时间的正负号：负号表示早于目标事件，正号表示晚于它。",
        "- 清单口径：清单 = 从目标事件往回走收集到的边，再按（源内容、操作名、目标内容）折叠；"
        "一条边可能代表多个折叠事件；清单之外没有需要判断的边。",
    ])


def _parent_of(item: dict[str, Any]) -> dict[str, Any] | None:
    parent = item.get("parent")
    if parent and parent["size"] >= max(4, 2 * item["size"]):
        return parent
    return None


def _batch_tables(items: list[dict[str, Any]], scale_index: dict[str, dict[str, Any]],
                  ) -> tuple[list[str], dict[str, str], dict[str, str], dict[str, dict]]:
    class_ids: dict[str, str] = {}
    parent_ids: dict[str, str] = {}
    parents: dict[str, dict[str, Any]] = {}
    for item in items:
        classes = item.get("all_dirs") or []
        cls = classes[0] if classes else ""
        if cls and cls not in class_ids and scale_stats(scale_index, cls, item["size"]):
            class_ids[cls] = f"C{len(class_ids) + 1}"
        parent = _parent_of(item)
        if parent:
            bid = str(parent.get("bid") or "?")
            if bid not in parent_ids:
                parent_ids[bid] = f"P{len(parent_ids) + 1}"
                parents[bid] = parent
    lines: list[str] = []
    if class_ids:
        lines.append("### 同类规模（本批涉及的类别；束行「规模」行里的 C 编号引用这里）")
        for cls, cid in sorted(class_ids.items(), key=lambda kv: kv[1]):
            info = scale_index.get(cls) or {}
            lines.append(f"{cid} {short(cls, 46)}｜共 {info.get('n', 0)} 个束"
                         f"（中位 {info.get('median', 0)} 条）")
        lines.append("")
    if parent_ids:
        lines.append("### 上一级束（本批子束拆自这些束；束行「上一级：P*」引用这里）")
        for bid, pid in sorted(parent_ids.items(), key=lambda kv: kv[1]):
            parent = parents.get(bid) or {}
            lines.append(
                f"{pid} {short(' / '.join(parent.get('programs') or []) or '(无属主)', 40)}"
                f" {parent.get('syscall', '')}｜{parent.get('size', 0)} 条／{fmt_bytes(parent.get('bytes', 0))}"
                f"／{parent.get('objects_n', 0)} 个对象"
                f"｜判定 {VERDICT_TEXT.get(parent.get('verdict'), parent.get('verdict'))}"
                f"｜{short(parent.get('reason', ''), 50) or '(未给理由)'}")
        lines.append("")
    return lines, class_ids, parent_ids, parents


def _extra_lines(item: dict[str, Any], class_ids: dict[str, str], parent_ids: dict[str, str],
                 scale_index: dict[str, dict[str, Any]]) -> list[str]:
    classes = item.get("all_dirs") or []
    cls = classes[0] if classes else ""
    stats = scale_stats(scale_index, cls, item["size"]) if cls else None
    tail = ""
    if stats and cls in class_ids:
        tail = f"；同类 {class_ids[cls]} 第 {stats['rank']}（前 {stats['pct']}%）"
    lines = [f"    规模：成员 {item['size']} 条／{fmt_bytes(item['bytes'])}／"
             f"不同对象 {item['objects_n']} 个{tail}"]
    parent = _parent_of(item)
    if parent:
        pid = parent_ids.get(str(parent.get("bid") or "?"))
        if pid:
            lines.append(f"    上一级：{pid}")
    return lines


def render(items: list[dict[str, Any]], records: dict[Any, Any], ref_t: int, *,
           level_name: str = "", header: str = "", scale_index: dict[str, dict[str, Any]] | None = None,
           aggregate: bool = False, annotate: bool = False, state: Any = None) -> str:
    """渲染待投递给模型的完整提示词文本。"""
    scale_index = scale_index or {}
    parts: list[str] = []
    if header:
        parts.extend([header, ""])
    parts.append(f"## 本批要判的束（{len(items)} 个，来自层级「{level_name}」）")
    parts.append("")
    class_ids: dict[str, str] = {}
    parent_ids: dict[str, str] = {}
    if aggregate:
        tables, class_ids, parent_ids, _parents = _batch_tables(items, scale_index)
        parts.extend(tables)
    lines = parts
    for item in items:
        lines.append(f"{item['id']}｜程序 {short(' / '.join(item['programs']) or '(无属主)')}"
                     f"｜动作 {'+'.join(item['rels'])} {item['syscall']}"
                     f"｜对象目录 {short(' / '.join(item['dirs']) or '(无)')}｜成员 {item['size']} 条")
        if aggregate:
            lines.extend(_extra_lines(item, class_ids, parent_ids, scale_index))
        if annotate and state is not None:
            hot_dirs = [d for d in item.get("all_dirs", []) if state.mark_dirs.get(d)]
            hot_programs = [p for p in item["programs"] if state.mark_programs.get(p)]
            if hot_dirs or hot_programs:
                bits = []
                if hot_dirs:
                    bits.append("对象类别 " + "、".join(
                        f"{d}（已判相关的束里出现 {state.mark_dirs[d]} 次）" for d in hot_dirs[:3]))
                if hot_programs:
                    bits.append("本束程序 " + "、".join(
                        f"{p}（已判相关的束里出现 {state.mark_programs[p]} 次）" for p in hot_programs[:2]))
                lines.append("    线索：" + "；".join(bits) + "——这些痕迹与已判相关的活动重合，"
                             "若本束样本与它们同类，倾向相关；若明显是例行对象，仍可判无关。")
        for cmdline in item["cmdlines"]:
            lines.append(f"    命令行：{short(cmdline, 140)}")
        for index, triple in enumerate(item["sample"]):
            lines.append(edge_line(f"M{index + 1}", records[triple], ref_t))
        if item["size"] > len(item["sample"]):
            lines.append(f"    （还有 {item['size'] - len(item['sample'])} 条成员未列出，样本覆盖不同对象）")
        lines.append("")
    lines.append("请按系统说明对每个束给出四值判定；每个 id 原样回抄。")
    return chr(10).join(lines)


def judge_bundles(model: Any, items: list[dict[str, Any]], listing: str, *, budget: Any,
                  ) -> dict[str, Any]:
    """单批模型判定：发出 JSON 结构化请求并解析结论字典。"""
    config = {"callbacks": [BudgetCallback(budget, node="bundle")]}
    result = call_json(model, BUNDLE_SYSTEM, listing, config=config, role="bundle")
    if not result.get("_raw_ok", True):
        return {"ok": False, "error": result.get("_error") or "未知错误", "calls": 1}
    verdicts, invalid = parse_bundle_verdicts(result, {item["id"] for item in items})
    return {"ok": True, "verdicts": verdicts, "invalid": invalid, "calls": 1}


def run_batches(deps: Any, items: list[dict[str, Any]], batches: list[list[dict[str, Any]]],
                inv: Any, ref_t: int, *, level_name: str, scale_index: dict[str, Any],
                aggregate: bool, state: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """将当级的批次切片并发投递模型，处理重发重试并汇聚统计。"""
    verdicts: dict[str, dict[str, Any]] = {}
    out = {"calls": 0, "chars_max": 0, "invalid": 0, "missing": 0, "failed_batches": 0}
    if not batches:
        return verdicts, out
    header = build_task_header(inv.poi_rows)
    annotate = settings.annotate_marks_enabled()

    def run_single_batch(batch: list[dict[str, Any]]) -> dict[str, Any]:
        listing = render(batch, inv.edges, ref_t, level_name=level_name, header=header,
                         scale_index=scale_index, aggregate=aggregate, annotate=annotate,
                         state=state)
        result: dict[str, Any] = {}
        calls = 0
        for attempt in range(settings.batch_attempts()):
            result = judge_bundles(deps.model, batch, listing, budget=deps.budget)
            calls += 1
            if result.get("ok"):
                break
            deps.log(f"    [judge] 一批调用失败（第 {attempt + 1}/{settings.batch_attempts()} 次，"
                     f"{len(batch)} 个束 / {len(listing)} 字符）：{short(result.get('error'))}")
        ok = bool(result.get("ok"))
        return {
            "ok": ok, "verdicts": result.get("verdicts") or {}, "calls": calls,
            "invalid": int(result.get("invalid") or 0), "chars": len(listing),
            "missing": sum(1 for item in batch if item["id"] not in (result.get("verdicts") or {})),
        }

    with ThreadPoolExecutor(max_workers=min(settings.max_concurrency(), max(1, len(batches)))) as pool:
        results = list(pool.map(run_single_batch, batches))
    for result in results:
        out["calls"] += int(result.get("calls") or 0)
        out["chars_max"] = max(out["chars_max"], int(result.get("chars") or 0))
        out["invalid"] += int(result.get("invalid") or 0)
        out["missing"] += int(result.get("missing") or 0)
        if not result.get("ok"):
            out["failed_batches"] += 1
        verdicts.update(result.get("verdicts") or {})
    return verdicts, out
