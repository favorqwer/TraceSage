"""渲染（判定层内部）：把一批边与双层滚动上下文渲染成模型能读的文本。

**投递单位**：波内按参数文件的 `judge.batch`（默认 70）切批，同一波的所有批共用同一份冻结上下文；
本模块只负责把一批边写成文本，不负责分组与调度。

每次调用的文本顺序：
1. **任务说明**（`build_task_header`，所有波共用）：目标事件、时间原点、调查方向、清单口径；
2. **调查状态摘要**（第 2 层滚动上下文，`waves.JudgeState.build_summary`，逐波更新）；
3. **本波涉及的进程身份表**；
4. **本波全部边**：每条一行，下面缩进列出它的**相关边**（合并成一块，同一条边只出现一次）——
   上层顶点上已经判过的边（参数文件的 `judge.upstream_limit` 控制条数）+ 同一对象上时间相邻的边
   （前后各 `judge.neighbor_per_side` 条、设为 0 就不列，优先与这条边方向相反的；
   前侧或后侧为空时补 1 条时间重叠的）。
   已判过的带结论；还没轮到判的标「尚未判到」（不等于排除）。

内容只来自图与日志：不含标准答案、`.query` 与场景特化判据。渲染确定性（同一输入逐字符相同）。
"""

from __future__ import annotations

from typing import Any

from ...contracts import rel_time, short, triple
from ...core import graph_facts, settings
# 同一对象邻居的位置标签（渲染用）
_POS_TEXT = {"before": "前", "after": "后", "overlap": "重叠"}


def build_task_header(poi_rows: list[dict[str, Any]]) -> str:
    """把"这次调查在追什么"写成一段任务说明（所有波共用）。

    只有任务定义：目标事件（进程、方向、操作名、另一端）、发生次数与时间原点、调查方向、清单口径；
    通用字段口径由系统提示词给出；不含任何场景特化的判据（哪些边算攻击仍然由模型判）。
    """
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
        "- 调查方式：从目标事件出发，一层一层往回走（一批判同一层，按波次由近到远推进）；"
        "你已经判过的层会出现在「调查状态摘要」里，每条边下面还会列出它的相关边。",
        "- 相对时间的正负号：负号表示早于目标事件，正号表示晚于它。",
        "- 清单口径：清单 = 从目标事件往回走收集到的边，再按（源内容、操作名、目标内容）折叠；"
        "一条边可能代表多个折叠事件；清单之外没有需要判断的边。",
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


def _endpoint_display(edge: dict[str, Any], label_key: str, content: Any) -> str:
    """端点的显示文字：网络端点在协议有记录时补「（协议）」后缀（顶点属性，非边属性）。"""
    if str(edge.get(label_key) or "") == "Network":
        protocol = str(edge.get("network_protocol") or "").strip()
        if protocol:
            return f"{content}（{protocol}）"
    return str(content)


def _related_line(edge: dict[str, Any], ref_t: Any, tag: str,
                  record: dict[str, Any] | None) -> str:
    """相关边的一行：时间 + 来源标签 + 两端 + 实例数与字节数 + 结论（没有结论就标明）。

    结论**只写"相关/无关"与理由，不写置信度数值**：数值不参与判断，写进模型读的文本里只会
    变成一个锚点（旧版实测：模型会读到"无关 0.80"这种自相矛盾的行）。
    """
    line = (f"{_rel_time(edge.get('t0'), ref_t)} [{tag}] [进程 {edge.get('process_id') or '?'}] "
            f"[{edge.get('src_label')}] {_endpoint_display(edge, 'src_label', edge.get('src'))} "
            f"--{edge.get('syscall')}--> "
            f"[{edge.get('dst_label')}] {_endpoint_display(edge, 'dst_label', edge.get('dst'))}"
            f"（折叠事件数 {edge.get('instances')}，字节 {edge.get('bytes')}）")
    if record is None:
        return line + "｜尚未判到"
    verdict = record.get("verdict") or {}
    direction = "相关" if record.get("relevant") else "无关"
    return line + f"｜已判：{direction}（{short(verdict.get('reason'), settings.reason_max_chars())}）"


def _direction_of(edge: dict[str, Any]) -> str:
    """这条边在它的对象端上是写（进程→对象）还是读（对象→进程）；没有对象返回空串。"""
    if str(edge.get("src_label") or "") in ("File", "Network"):
        return "read"
    if str(edge.get("dst_label") or "") in ("File", "Network"):
        return "write"
    return ""


def _pick(cands: list[dict[str, Any]], item_dir: str, limit: int, *, latest: bool,
          ) -> list[dict[str, Any]]:
    """候选里挑至多 limit 条：**优先与这条边方向相反的**（读边优先写它的、写边优先读它的），
    同方向补足；组内取时间最近的（前侧）或最早的（后侧）。返回时按时间顺序。
    """
    def rank(e: dict[str, Any]) -> tuple:
        t = int(e.get("t0") or 0)
        return (0 if _direction_of(e) != item_dir else 1,
                -t if latest else t,
                str(e.get("src", "")), str(e.get("syscall", "")), str(e.get("dst", "")))
    chosen = sorted(cands, key=rank)[:limit]
    chosen.sort(key=lambda e: (int(e.get("t0") or 0), str(e.get("src", "")),
                               str(e.get("syscall", "")), str(e.get("dst", ""))))
    return chosen


def _neighbors(edges: list[dict[str, Any]], item: dict[str, Any],
               exclude: frozenset = frozenset()) -> list[tuple[str, dict[str, Any]]]:
    """同一对象上的时间邻居：前侧、后侧各最多 `judge.neighbor_per_side` 条，**反方向优先**。

    前侧 = 结束时刻不晚于本边开始时刻的（组内取时间最近的）；
    后侧 = 开始时刻不早于本边结束时刻的（组内取时间最早的）。
    前侧或后侧为空时补 1 条与本边时间重叠的（标“重叠”，同样反方向优先）——
    管道、长会话这类边写边读的形状，靠它才能看到对面。
    条数设为 0 表示不列同一对象邻居（直接返回空）。
    """
    limit = settings.neighbor_per_side()
    if limit <= 0:
        return []
    overlap_count = settings.overlap_neighbor_count()
    key = triple(item)
    t0 = int(item.get("t0") or 0)
    t1 = int(item.get("t1") or 0)
    item_dir = _direction_of(item)
    before = [e for e in edges if triple(e) != key and triple(e) not in exclude
              and int(e.get("t1") or 0) <= t0]
    after = [e for e in edges if triple(e) != key and triple(e) not in exclude
             and int(e.get("t0") or 0) >= t1]
    out: list[tuple[str, dict[str, Any]]] = (
        [("before", e) for e in _pick(before, item_dir, limit, latest=True)]
        + [("after", e) for e in _pick(after, item_dir, limit, latest=False)])
    if overlap_count > 0 and (not before or not after):
        def overlap_rank(e: dict[str, Any]) -> tuple:
            t = int(e.get("t0") or 0)
            return (0 if _direction_of(e) != item_dir else 1, abs(t - t0), t,
                    str(e.get("src", "")), str(e.get("syscall", "")), str(e.get("dst", "")))
        overlap = [e for e in edges if triple(e) != key and triple(e) not in exclude
                   and int(e.get("t1") or 0) > t0 and int(e.get("t0") or 0) < t1]
        overlap.sort(key=overlap_rank)
        out.extend(("overlap", e) for e in overlap[:overlap_count])
    return out


def _related_lines(item: dict[str, Any], records: list[dict[str, Any]], view: Any, ref_t: Any,
                   verdicts: dict[tuple[str, str, str], dict[str, Any]] | None) -> list[str]:
    """本边的相关边（合并成一块，同一条边只出现一次）。

    顺序：先上层顶点上已判过的（不同时是同对象邻居的），再同对象邻居（前、后、重叠）。
    同一条边既在上层顶点又在同对象邻居里时，按邻居格式渲染（带时间），标签合并。
    同对象邻居列不列由条数决定（为 0 时 `_neighbors` 返回空）。
    """
    lines: list[str] = []
    contacts: list[tuple[str, dict[str, Any]]] = []
    pos_of: dict[tuple[str, str, str], str] = {}
    if view:
        obj = object_of(item)
        if obj:
            contacts = _neighbors((view.get("by_object") or {}).get(obj) or [], item)
            for pos, edge in contacts:
                pos_of.setdefault(triple(edge), pos)
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        up_item = record.get("item") or {}
        key = triple(up_item)
        if key in seen:
            continue
        seen.add(key)
        pos = pos_of.get(key)
        tag = f"同对象{_POS_TEXT[pos]}·上层顶点" if pos else "上层顶点"
        lines.append(_related_line(up_item, ref_t, tag, record))
    for pos, edge in contacts:
        key = triple(edge)
        if key in seen:
            continue
        seen.add(key)
        lines.append(_related_line(edge, ref_t, f"同对象{_POS_TEXT[pos]}",
                                   (verdicts or {}).get(key)))
    return [f"    {line}" for line in lines]


def _render_process_table(process_ids: list[str], metas: dict[str, dict[str, Any]], ref_t: Any) -> str:
    """进程身份表：每行一个进程（程序、命令行、工作目录、来源、活动时间范围与边数）。"""
    lines = [f"## 本次涉及的进程（{len(process_ids)} 个）"]
    for pid in process_ids:
        meta = metas.get(pid) or {}
        owner = str(meta.get("owner") or "")
        head = f"进程 {pid}（{owner}）" if owner else f"进程 {pid}"
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
            f"[{item.get('src_label')}] {_endpoint_display(item, 'src_label', item['src'])} "
            f"--{item['syscall']}--> "
            f"[{item.get('dst_label')}] {_endpoint_display(item, 'dst_label', item['dst'])}"
            f" | 折叠事件数={item.get('instances')} 字节={item.get('bytes')}"
            f" 时间={_rel_time(item.get('t0'), ref_t)}~{_rel_time(item.get('t1'), ref_t)}")
    return line


def render(items: list[dict[str, Any]], metas: dict[str, dict[str, Any]], ref_t: Any,
           *, header: str = "", view: Any = None, state_summary: str = "",
           upstream: dict[str, list[dict[str, Any]]] | None = None,
           verdicts: dict[tuple[str, str, str], dict[str, Any]] | None = None,
           wave: int | None = None, wave_total: int | None = None,
           wave_dist: int | None = None) -> str:
    """渲染一次投递的文本。

    `items` 必须**已经带编号**；`header` 是任务说明；`state_summary` 是第 2 层摘要；
    `upstream` 是「编号 -> 该边的上游交接明细」（第 1 层）；`verdicts` 用于给相关边标已判结论。
    `wave` / `wave_total` / `wave_dist` 是这批边在调查里的位置（第几波、共几波、离终点几跳），
    只写进本批标题。**没有上下文压缩**：每次投递都是完整上下文（边一条不少、相关边一条不少）。
    """
    parts: list[str] = []
    if header:
        parts.append(header)
    if state_summary:
        parts.append("## 调查状态摘要（你已经判过的层）\n" + state_summary)
    process_ids = list(dict.fromkeys(str(item.get("process_id") or "") for item in items))
    parts.append(_render_process_table(process_ids, metas, ref_t))
    where = ""
    if wave_dist is not None:
        where = f"，位于离终点第 {wave_dist} 跳"
        if wave is not None and wave_total is not None:
            where += f"，第 {wave}/{wave_total} 波"
    parts.append(f"## 本次要判的边（{len(items)} 条{where}）")
    parts.append("（每行的两端标签与内容就是这条边的两个端点；边下面的缩进行是它的相关边："
                 "「上层顶点」＝这条边是从哪个顶点回推出来的、在那个顶点上已经判过的边；"
                 "「同对象前/后/重叠」＝同一个文件或网络端点上时间相邻的边；"
                 "「｜已判：」后是结论，「｜尚未判到」＝还没轮到它所在的波）")
    for item in items:
        parts.append(_edge_line(item, ref_t))
        parts.extend(_related_lines(
            item, (upstream or {}).get(str(item.get("id"))) or [], view, ref_t, verdicts))
    parts.append("请逐条给出判定；每条必须带 id（原样回抄，不得省略、改写或重排）。")
    return "\n".join(parts)

