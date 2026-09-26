"""切批与提示词渲染（第 2 层内部）：按步骤分组、装填到批大小、渲染成模型能读的文本。

批大小只影响"重复发送的上下文总量"与并行度，不影响判定结果；步骤跨批时每批都带上自己的上下文。
"""

from __future__ import annotations

from typing import Any

# 每批最多渲染几个步骤的文件清单（上下文丰富度 vs 提示词大小的折中）
_MAX_LIST_IN_CONTEXT = 20


def _rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数（省 token、也更利于模型比较先后）。"""
    try:
        t = int(value or 0)
    except (TypeError, ValueError):
        return "?"
    if not ref_t or not t:
        return str(t)
    return f"{(t - int(ref_t)) / 1e9:+.1f}s"


def _render_step_context(index: int, total: int, step_key: str, meta: dict[str, Any]) -> str:
    summary = (meta or {}).get("summary") or {}
    lines = [f"### 步骤 {index}/{total}：{step_key or '(未知步骤)'}"]
    lines.append(f"进程：{summary.get('owner')}  命令行：{summary.get('owner_args')!r}  cwd={summary.get('cwd')!r}")
    lines.append(f"时间：{summary.get('t0')}..{summary.get('t1')}（{summary.get('duration_ms')} ms）")
    lines.append(f"规模：边 {summary.get('n_edges')} 条；写 {len(summary.get('wrote_files') or [])} 个文件 / "
                 f"读 {len(summary.get('read_files') or [])} 个文件 / 网络端点 {len(summary.get('networks') or [])} 个；"
                 f"出 {summary.get('bytes_out')} 字节 / 入 {summary.get('bytes_in')} 字节")
    wrote = list(summary.get("wrote_files") or [])[:_MAX_LIST_IN_CONTEXT]
    read = list(summary.get("read_files") or [])[:_MAX_LIST_IN_CONTEXT]
    nets = list(summary.get("networks") or [])[:_MAX_LIST_IN_CONTEXT]
    if wrote:
        lines.append(f"写过的文件：{wrote}")
    if read:
        lines.append(f"读过的文件：{read}")
    if nets:
        lines.append(f"网络端点：{nets}")
    top = list((summary.get("syscalls") or {}).items())[:10]
    if top:
        lines.append(f"syscall 分布（前 10）：{top}")
    group_cmds = [str(c) for c in ((meta or {}).get("group_cmds") or []) if c]
    if len(group_cmds) > 1:
        lines.append("同一管道组内各成员的命令行（本步骤的边属于其中一员，管道数据来自这里）：")
        lines.extend(f"  - {cmd[:200]}" for cmd in group_cmds[:8])
    return "\n".join(lines)


def render(items: list[dict[str, Any]], metas: dict[str, dict[str, Any]], ref_t: Any) -> str:
    """渲染一批：先按步骤列上下文，再按同样的分组列待判定的边（每条带编号与步骤号）。

    `items` 必须**已经带编号**（第一轮由 `index_items` 编号，第二轮沿用第一轮的编号）。
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        groups.setdefault(str(item.get("step_key") or ""), []).append(item)
    parts = [f"## 上下文（本批涉及 {len(groups)} 个步骤，共 {len(items)} 条边）"]
    for i, (step_key, _) in enumerate(groups.items(), start=1):
        parts.append(_render_step_context(i, len(groups), step_key, metas.get(step_key) or {}))
    parts.append("## 待判定的边")
    step_no = {step_key: i for i, step_key in enumerate(groups, start=1)}
    for item in items:
        parts.append(
            f"{item['id']}. [步骤{step_no[str(item.get('step_key') or '')]}] [{item.get('src_label')}] {item['src']}"
            f" --{item['syscall']}--> [{item.get('dst_label')}] {item['dst']}"
            f" | 实例={item.get('instances')} 字节={item.get('bytes')}"
            f" 时间={_rel_time(item.get('t0'), ref_t)}~{_rel_time(item.get('t1'), ref_t)}"
        )
    parts.append("请逐条给出判定；每条必须带 id（原样回抄，不得省略、改写或重排）。")
    return "\n".join(parts)


def index_items(batch: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """给批内每条边编号（`E001` 起，批内唯一）。"""
    items: list[dict[str, Any]] = []
    for step_key, edges in batch:
        for edge in edges:
            items.append({**edge, "step_key": step_key, "id": f"E{len(items) + 1:03d}"})
    return items


def make_batches(edges: list[dict[str, Any]], size: int) -> list[list[tuple[str, list[dict[str, Any]]]]]:
    """把边打包成批：**同一个步骤的边连在一起**，但一批可以装多个步骤（默认装到 size 条为止）。

    返回 `[[(step_key, edges), ...], ...]`。步骤内按 (t0, src, 操作名, dst) 排序；
    步骤按**首次出现顺序**依次装填，装到 size 条就封一批（步骤跨批时每批都带上自己的上下文）。
    确定性；不丢边（干跑测试断言）。
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for edge in edges:
        key = str(edge.get("step_key") or "")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(edge)

    batches: list[list[tuple[str, list[dict[str, Any]]]]] = []
    current: list[tuple[str, list[dict[str, Any]]]] = []
    current_n = 0
    for key in order:
        group = sorted(groups[key], key=lambda e: (int(e.get("t0") or 0), str(e.get("src", "")),
                                                   str(e.get("syscall", "")), str(e.get("dst", ""))))
        pos = 0
        while pos < len(group):
            room = size - current_n
            take = group[pos:pos + room]
            current.append((key, take))
            current_n += len(take)
            pos += len(take)
            if current_n >= size:
                batches.append(current)
                current, current_n = [], 0
    if current:
        batches.append(current)
    return batches
