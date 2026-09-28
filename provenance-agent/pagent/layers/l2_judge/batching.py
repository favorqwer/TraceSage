"""渲染（判定层内部）：把一批边与双层滚动上下文渲染成模型能读的文本。

**投递单位**：波内按 `PAGENT_JUDGE_BATCH`（默认 70）切批，同一波的所有批共用同一份冻结上下文；
本模块只负责把一批边写成文本，不负责分组与调度。

每次调用的文本顺序：
1. **任务说明**（`build_task_header`，所有波共用）：目标事件、时间原点、调查方向、清单口径；
2. **调查状态摘要**（第 2 层滚动上下文，`waves.JudgeState.build_summary`，逐波更新）；
3. **本波涉及的进程身份表**；
4. **本波全部边**：每条一行，下面可选跟两条局部信息——
   **上游交接明细**（第 1 层滚动上下文：这条边的上层顶点上已判过的边及其结论，
   `PAGENT_UPSTREAM_LIMIT` 控制条数）与**同一对象上的接触者**（已判过的会带结论）。

内容只来自图与日志：不含标准答案、`.query` 与场景特化判据。渲染确定性（同一输入逐字符相同）。
"""

from __future__ import annotations

from typing import Any

from ...contracts import conf, rel_time, short, triple
from ...core import settings
from ..l1_reach import labels_of

# 每条边前后各列几条邻居（同一对象上的接触者）
_NEIGHBOR_PER_SIDE = 2

# 命令表打开、且命令行确实拿不到时写给模型的原因（不写空串，让模型知道这是"没有记录"）
_COMMAND_NONE_TEXT = {
    "none_exec": "该进程执行过新程序，但日志与图都没有记下这条命令",
    "none_no_derivation": "进程在采集开始前就在运行，日志里没有它的启动记录",
    "none_chain_broken": "进程由父进程派生、未执行新程序，父进程的命令行也查不到",
    "none_no_parent": "进程由父进程派生、未执行新程序，父进程不在本次调查范围内",
    "none_too_deep": "进程由父进程派生，派生链超过设定层数仍未找到命令行",
}


def build_task_header(poi_rows: list[dict[str, Any]]) -> str:
    """把"这次调查在追什么"写成一段任务说明（所有波共用）。

    只有任务定义：目标事件（进程、方向、操作名、另一端）、实例数与时间原点、调查方向、清单口径，
    以及清单里两个字段的含义；不含任何场景特化的判据（哪些边算攻击仍然由模型判）。
    """
    if not poi_rows:
        return ""
    row = poi_rows[0]
    rel = str(row.get("rel") or "")
    src_label, dst_label = labels_of(rel, str(row.get("other_label") or ""))
    owner = str(row.get("process_content") or "")
    other = str(row.get("other") or "")
    src, dst = (owner, other) if rel in ("p2f", "p2n") else (other, owner)
    syscall = str(row.get("syscall") or "")
    t0 = min(int(r.get("starttime") or 0) for r in poi_rows)
    return "\n".join([
        "## 本次调查的任务",
        "- 目标事件（本次调查的终点，往回追的起点）：",
        f"  [{src_label}] {src} --{syscall}--> [{dst_label}] {dst}",
        f"- 实例数：{len(poi_rows)} 个；时间原点（最早一次发生的时刻）＝ {t0} 纳秒"
        "（下面进程表与边行里的时间都是相对这个原点算出的秒数）",
        "- 调查方向：只找**可能影响目标事件**的上游活动；目标事件本身也在清单里。",
        "- 调查方式：从目标事件出发，一层一层往回走；你已经判过的层会出现在「调查状态摘要」里，"
        "每条边下面还会列出它上一层顶点上已经判过的边。",
        "- 相对时间的正负号：负号表示早于目标事件，正号表示晚于它。",
        "- 清单口径：清单 = 从目标事件往回走收集到的边，再按（源内容、操作名、目标内容）折叠；"
        "一条边可能代表多个实例；清单之外没有需要判断的边。",
    ])


def _rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数（省字符、也更利于模型比较先后）。"""
    return rel_time(value, ref_t)


def object_of(edge: dict[str, Any]) -> str:
    """这条边的对象端点（文件 / 网络）；进程到进程的边没有对象，返回空串。"""
    if str(edge.get("src_label") or "") in ("File", "Network"):
        return str(edge.get("src") or "")
    if str(edge.get("dst_label") or "") in ("File", "Network"):
        return str(edge.get("dst") or "")
    return ""


def build_view_index(edges: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """按对象的时间索引（渲染"同一对象上的接触者"用）。确定性。"""
    by_object: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        obj = object_of(edge)
        if obj:
            by_object.setdefault(obj, []).append(edge)
    for group in by_object.values():
        group.sort(key=lambda e: (int(e.get("t0") or 0), str(e.get("src", "")),
                                  str(e.get("syscall", "")), str(e.get("dst", ""))))
    return {"by_object": by_object}


def _edge_brief(edge: dict[str, Any], ref_t: Any,
                verdicts: dict[tuple[str, str, str], dict[str, Any]] | None = None) -> str:
    """邻居边的一行摘要（时间 + 归属进程 + 两端 + 实例数与字节数 + 已判结论）。"""
    line = (f"{_rel_time(edge.get('t0'), ref_t)} [进程 {edge.get('process_id') or '?'}] "
            f"[{edge.get('src_label')}] {edge.get('src')} --{edge.get('syscall')}--> "
            f"[{edge.get('dst_label')}] {edge.get('dst')}"
            f"（实例 {edge.get('instances')}，字节 {edge.get('bytes')}）")
    record = (verdicts or {}).get(triple(edge))
    if record is not None:
        verdict = record.get("verdict") or {}
        direction = "相关" if record.get("relevant") else "无关"
        line += f"｜已判：{direction} {conf(verdict):.2f}（{short(verdict.get('reason'), 40)}）"
    return line


def _around(edges: list[dict[str, Any]], item: dict[str, Any],
            exclude: set[tuple[str, str, str]] = frozenset()) -> tuple[list[dict[str, Any]],
                                                                        list[dict[str, Any]]]:
    """这条边的邻居：全部结束在它开始之前的（取最近几条）+ 全部开始于它结束之后的（取最早几条）。"""
    key = triple(item)
    before = [e for e in edges
              if triple(e) != key and triple(e) not in exclude
              and int(e.get("t1") or 0) <= int(item.get("t0") or 0)]
    after = [e for e in edges
             if triple(e) != key and triple(e) not in exclude
             and int(e.get("t0") or 0) >= int(item.get("t1") or 0)]
    return before[-_NEIGHBOR_PER_SIDE:], after[:_NEIGHBOR_PER_SIDE]


def _context_lines(item: dict[str, Any], view: Any, ref_t: Any,
                   verdicts: dict[tuple[str, str, str], dict[str, Any]] | None = None) -> list[str]:
    """一条边旁的时间局部信息：同一对象上的接触者（默认开）；已判过的会带上结论。"""
    if not view:
        return []
    lines: list[str] = []
    shown: set[tuple[str, str, str]] = set()
    if settings.object_handoff_enabled():
        obj = object_of(item)
        if obj:
            near = (view.get("by_object") or {}).get(obj) or []
            before, after = _around(near, item, exclude=shown)
            if before or after:
                lines.append(f"  同一对象上的接触者（{obj}）：")
                lines.extend(f"    {_edge_brief(e, ref_t, verdicts)}" for e in before + after)
    return lines


def _upstream_lines(records: list[dict[str, Any]]) -> list[str]:
    """第 1 层：上层顶点上已判过的边（含结论），挂在每条待判边下面。"""
    if not records:
        return []
    lines = ["  上游交接明细（上一层顶点上已判过的边）："]
    for record in records:
        item = record.get("item") or {}
        verdict = record.get("verdict") or {}
        direction = "相关" if record.get("relevant") else "无关"
        lines.append(f"    [已判] [{item.get('src_label')}] {item.get('src')} --{item.get('syscall')}--> "
                     f"[{item.get('dst_label')}] {item.get('dst')}：{direction} {conf(verdict):.2f}"
                     f"（{short(verdict.get('reason'), 40)}）")
    return lines


def _render_process_table(process_ids: list[str], metas: dict[str, dict[str, Any]], ref_t: Any) -> str:
    """进程身份表：每行一个进程（程序、命令行、工作目录、来源、活动时间范围与边数）。"""
    lines = [f"## 本次涉及的进程（{len(process_ids)} 个）"]
    for pid in process_ids:
        meta = metas.get(pid) or {}
        owner = str(meta.get("owner") or "")
        head = f"进程 {pid}（{owner}）" if owner else f"进程 {pid}"
        command = meta.get("command") if settings.command_table_enabled() else None
        if isinstance(command, dict):
            if command.get("line"):
                note = ""
                if command.get("source") == "inherited":
                    chain = [str(x) for x in (command.get("via") or [])]
                    via = " → ".join(chain)
                    where = f"按父进程 {via}" if len(chain) <= 1 else f"按派生链 {via}"
                    note = (f"（{where} 推断：本窗口未记录这条命令，"
                            f"该进程由它派生且未执行新程序）")
                cmd_text = f"命令行：{command['line']!r}{note}"
            else:
                why = _COMMAND_NONE_TEXT.get(str(command.get("reason") or ""),
                                             "日志与图中都没有记录")
                cmd_text = f"命令行：（无记录：{why}）"
        else:
            args = str(meta.get("owner_args") or "")
            cmd_text = f"命令行：{args!r}" if args else "命令行：（无记录）"
        origin = meta.get("origin") or {}
        kind = str(origin.get("kind") or "none")
        parent = str(origin.get("parent_content") or origin.get("parent") or "")
        if kind == "exec":
            origin_text = f"由 {parent} 执行新程序启动（{_rel_time(origin.get('t'), ref_t)}）"
        elif kind == "spawn":
            origin_text = f"由 {parent} 派生、未执行新程序（{_rel_time(origin.get('t'), ref_t)}）"
        else:
            origin_text = "无派生记录（采集开始前就在运行，或派生边不在本次范围内）"
        lines.append(f"- {head}：{cmd_text}；工作目录 {meta.get('cwd')!r}；来源：{origin_text}；"
                     f"活动时间 {_rel_time(meta.get('t0'), ref_t)}~{_rel_time(meta.get('t1'), ref_t)}"
                     f"（边 {meta.get('n_edges')} 条）")
    return "\n".join(lines)


def _edge_line(item: dict[str, Any], ref_t: Any) -> str:
    line = (f"{item['id']}. [进程 {item.get('process_id') or '?'}] "
            f"[{item.get('src_label')}] {item['src']} --{item['syscall']}--> "
            f"[{item.get('dst_label')}] {item['dst']}"
            f" | 实例={item.get('instances')} 字节={item.get('bytes')}"
            f" 时间={_rel_time(item.get('t0'), ref_t)}~{_rel_time(item.get('t1'), ref_t)}")
    return line


def render(items: list[dict[str, Any]], metas: dict[str, dict[str, Any]], ref_t: Any,
           *, header: str = "", view: Any = None, state_summary: str = "",
           upstream: dict[str, list[dict[str, Any]]] | None = None,
           verdicts: dict[tuple[str, str, str], dict[str, Any]] | None = None,
           context_level: int = 2) -> str:
    """渲染一次投递的文本。

    `items` 必须**已经带编号**；`header` 是任务说明；`state_summary` 是第 2 层摘要；
    `upstream` 是「编号 -> 该边的上游交接明细」（第 1 层）；`verdicts` 用于给接触者行标已判结论。
    `context_level` 是超长时的逐级压缩开关（只压局部上下文，**边一条不少**）：
    2 = 上游明细 + 同对象接触者；1 = 只留上游明细；0 = 两者都不要。
    """
    parts: list[str] = []
    if header:
        parts.append(header)
    if state_summary:
        parts.append("## 调查状态摘要（你已经判过的层）\n" + state_summary)
    process_ids = list(dict.fromkeys(str(item.get("process_id") or "") for item in items))
    parts.append(_render_process_table(process_ids, metas, ref_t))
    parts.append(f"## 本次要判的边（{len(items)} 条）")
    parts.append("（每行的两端标签与内容就是这条边的两个端点；各字段含义见上面的任务说明）")
    for item in items:
        parts.append(_edge_line(item, ref_t))
        if context_level >= 1:
            parts.extend(_upstream_lines((upstream or {}).get(str(item.get("id"))) or []))
        if context_level >= 2 and settings.edge_context_enabled():
            parts.extend(_context_lines(item, view, ref_t, verdicts))
    parts.append("请逐条给出判定；每条必须带 id（原样回抄，不得省略、改写或重排）。")
    return "\n".join(parts)

