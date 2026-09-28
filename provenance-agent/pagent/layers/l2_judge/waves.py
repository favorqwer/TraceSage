"""波次推进与调查状态（判定层内部，纯代码为主）。

**波**：把候选边按「离终点事件最少几跳」分层，一跳一波；判定逐波进行，波内按条数上限切批，
**同一波的所有批共用同一份冻结上下文**（整波判完才更新状态）。
波内按上层顶点（`via_kind` / `via_key`）聚拢、再按时间排，只影响行顺序。

**双层滚动上下文**（逐波更新，替代静态概览）：
- 第 1 层「上游交接明细」：这条边的上层顶点上**已经判过**的边及其结论（`JudgeState.upstream`）。
- 第 2 层「调查状态摘要」：已确认链片段、本波工作面、相关顶点状态、计数（`build_summary`）。

确定性：分组、排序、编号、摘要裁剪全部固定；模型只影响判定结论与折叠文本。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...contracts import conf, short, triple

# 摘要各小节最多渲染的行数（再按字符上限裁剪）
_WORKFACE_LIMIT = 30
_VERTEX_LIMIT = 40
_NARRATIVE_GAP = "\n\n"


def make_waves(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按离终点跳数分组：一跳一波，波内按上层顶点聚拢、再按时间排。确定性，不丢边。"""
    groups: dict[int, list[dict[str, Any]]] = {}
    for edge in edges:
        groups.setdefault(int(edge.get("dist") or 0), []).append(edge)
    waves: list[dict[str, Any]] = []
    for dist in sorted(groups):
        items = sorted(groups[dist], key=lambda e: (str(e.get("via_kind") or ""),
                                                    str(e.get("via_key") or ""),
                                                    int(e.get("t0") or 0),
                                                    str(e.get("src", "")),
                                                    str(e.get("syscall", "")),
                                                    str(e.get("dst", ""))))
        waves.append({"dist": dist, "items": items})
    return waves


def index_waves(waves: list[dict[str, Any]],
                ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """给全部波按发送顺序编**全局唯一**编号（E001 起、跨波连续）。

    返回（带编号与波号的波表, 扁平条目表, 编号到波号的对照）。编号是结论按边归位的键。
    """
    indexed: list[dict[str, Any]] = []
    flat: list[dict[str, Any]] = []
    wave_of: dict[str, int] = {}
    counter = 0
    for wave_index, wave in enumerate(waves):
        items: list[dict[str, Any]] = []
        for edge in wave["items"]:
            counter += 1
            item = {**edge, "id": f"E{counter:03d}"}
            items.append(item)
            flat.append(item)
            wave_of[item["id"]] = wave_index
        indexed.append({"dist": wave["dist"], "items": items, "wave": wave_index})
    return indexed, flat, wave_of


def via_content(item: dict[str, Any], metas: dict[str, dict[str, Any]]) -> str:
    """这条边的上层顶点在图上的内容（进程用可执行路径口径，对象用路径本身）。

    `via_kind` / `via_key` 是第 1 层折叠时留下的原始标识；进程侧要换成与边端点同一口径的内容，
    才能和已经判过的相邻边对上。
    """
    kind = str(item.get("via_kind") or "")
    key = str(item.get("via_key") or "")
    if not key:
        return ""
    if kind == "Process":
        return str((metas.get(key) or {}).get("owner") or key)
    return key


def _via_raw(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("via_kind") or ""), str(item.get("via_key") or ""))


def chunk_wave(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    """把一个波切成投递批次（每批不超过 `size` 条）：按上层顶点聚拢，再按条数装填。

    同一个上层顶点引出的边尽量待在同一批（因果上同一步）；一个上层顶点自身超过 `size` 时
    会跨批（拆的是投递，不是波）。确定性；不丢边（单测断言）。
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for item in items:
        key = _via_raw(item)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(item)
    chunks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for key in order:
        group = groups[key]
        pos = 0
        while pos < len(group):
            room = size - len(current)
            take = group[pos:pos + room]
            current.extend(take)
            pos += len(take)
            if len(current) >= size:
                chunks.append(current)
                current = []
    if current:
        chunks.append(current)
    return chunks


@dataclass
class JudgeState:
    """逐波累计的调查状态（纯内存、确定性更新）。"""

    by_triple: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    by_via: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    by_content: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    vertex: dict[str, list[int]] = field(default_factory=dict)   # 内容 -> [确认条数, 排除条数]
    chain: list[dict[str, Any]] = field(default_factory=list)    # 已确认边，按波顺序
    counts: dict[str, int] = field(default_factory=lambda: {"confirmed": 0, "excluded": 0,
                                                            "missing": 0})

    def register(self, items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                 wave_index: int) -> dict[str, int]:
        """把一波的结论登记进状态；没有结论的边只计缺失，不产生任何结论。"""
        out = {"confirmed": 0, "excluded": 0, "missing": 0}
        for item in items:
            verdict = verdicts.get(str(item.get("id")))
            if verdict is None:
                self.counts["missing"] += 1
                out["missing"] += 1
                continue
            relevant = bool(verdict.get("is_relevant"))
            record = {
                "id": item.get("id"), "wave": wave_index, "item": item,
                "triple": triple(item),
                "verdict": verdict, "relevant": relevant,
                "via_raw": _via_raw(item),
                "via": str(item.get("via") or ""),
            }
            self.by_triple[triple(item)] = record
            if record["via_raw"] != ("", ""):
                self.by_via.setdefault(record["via_raw"], []).append(record)
            # 源与目标内容相同时只登记一次（否则同一张记录会被记两遍、顶点计数翻倍）
            for content in dict.fromkeys((str(item.get("src") or ""), str(item.get("dst") or ""))):
                if content:
                    self.by_content.setdefault(content, []).append(record)
                    node = self.vertex.setdefault(content, [0, 0])
                    node[0 if relevant else 1] += 1
            self.counts["confirmed" if relevant else "excluded"] += 1
            out["confirmed" if relevant else "excluded"] += 1
            if relevant:
                self.chain.append(record)
        return out

    def upstream(self, item: dict[str, Any], metas: dict[str, dict[str, Any]],
                 limit: int) -> list[dict[str, Any]]:
        """第 1 层：这条边的上层顶点上已经判过的边（跳数最少在前、去重、最多 limit 条）。

        `limit` 为 0 时返回空（上限为 0 表示这一层明细不渲染）。
        """
        content = via_content(item, metas)
        if not content or limit <= 0:
            return []
        seen: set[str] = set()
        found: list[dict[str, Any]] = []
        for record in sorted(self.by_content.get(content) or [],
                             key=lambda r: (int(r.get("wave") or 0),
                                            int((r.get("item") or {}).get("t0") or 0))):
            rid = str(record.get("id") or "")
            if rid in seen:
                continue
            if len(found) >= limit:
                break
            seen.add(rid)
            found.append(record)
        return found

    # ------------------------------------------------------------------ #
    # 第 2 层：调查状态摘要
    # ------------------------------------------------------------------ #

    def _chain_lines(self, limit: int) -> list[str]:
        lines = []
        for record in self.chain[-limit:]:
            item = record.get("item") or {}
            verdict = record.get("verdict") or {}
            via = short(record.get("via") or "终点事件", 60)
            lines.append(f"- {item.get('src')} --{item.get('syscall')}--> {item.get('dst')}"
                         f"（置信度 {conf(verdict):.2f}；上层顶点 {via}）")
        return lines

    def _workface_lines(self, current_items: list[dict[str, Any]]) -> list[str]:
        order: list[str] = []
        counts: dict[str, list[int]] = {}
        for item in current_items:
            raw = _via_raw(item)
            key = f"{raw[0]} {raw[1]}".strip() or "终点事件"
            if key not in counts:
                counts[key] = [0, 0, 0]
                order.append(key)
            counts[key][2] += 1
            for record in self.by_via.get(raw) or []:
                counts[key][0 if record.get("relevant") else 1] += 1
        lines = []
        for key in order[:_WORKFACE_LIMIT]:
            confirmed, excluded, current = counts[key]
            lines.append(f"- {short(key, 80)}：已判确认 {confirmed} 条 / 排除 {excluded} 条；本次要判 {current} 条")
        if len(order) > _WORKFACE_LIMIT:
            lines.append(f"- 另有 {len(order) - _WORKFACE_LIMIT} 个上层顶点未列出。")
        return lines

    def _vertex_lines(self, remaining_items: list[dict[str, Any]],
                      metas: dict[str, dict[str, Any]]) -> list[str]:
        relevant: set[str] = set()
        for item in remaining_items:
            for content in (str(item.get("src") or ""), str(item.get("dst") or "")):
                if content:
                    relevant.add(content)
            via = via_content(item, metas)
            if via:
                relevant.add(via)
        rows = []
        for content in relevant:
            node = self.vertex.get(content)
            if not node or (node[0] == 0 and node[1] == 0):
                continue
            rows.append((node[0], node[1], content))
        rows.sort(key=lambda r: (-r[0], -r[1], r[2]))
        lines = [f"- {short(content, 80)}：确认 {c} 条 / 排除 {e} 条" for c, e, content in rows[:_VERTEX_LIMIT]]
        if len(rows) > _VERTEX_LIMIT:
            lines.append(f"- 另有 {len(rows) - _VERTEX_LIMIT} 个相关顶点未列出。")
        return lines

    def build_summary(self, current_items: list[dict[str, Any]], remaining_items: list[dict[str, Any]],
                      metas: dict[str, dict[str, Any]], *, max_chars: int, chain_limit: int) -> str:
        """组装第 2 层摘要；超长按「计数 → 顶点状态 → 工作面 → 链片段」从低到高丢弃。"""
        sections: list[str] = []
        chain = self._chain_lines(chain_limit)
        if chain:
            sections.append("### 已确认的上游活动（从终点往上，最近若干条）\n" + "\n".join(chain))
        workface = self._workface_lines(current_items)
        if workface:
            sections.append("### 本波工作面（上层顶点：已判数与本次条数）\n" + "\n".join(workface))
        vertices = self._vertex_lines(remaining_items, metas)
        if vertices:
            sections.append("### 相关顶点状态（只列后面还会出现的顶点）\n" + "\n".join(vertices))
        sections.append(f"### 计数\n- 到目前：已判 {len(self.by_triple)} 条"
                        f"（确认 {self.counts['confirmed']}，排除 {self.counts['excluded']}，"
                        f"缺失 {self.counts['missing']}）；本波 {len(current_items)} 条；"
                        f"剩余（含本波）{len(remaining_items)} 条。")
        while len(sections) > 1 and len(_NARRATIVE_GAP.join(sections)) > max_chars:
            sections.pop()
        text = _NARRATIVE_GAP.join(sections)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n（摘要已按长度上限截断）"
        return text

