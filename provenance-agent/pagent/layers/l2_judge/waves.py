"""波次推进与调查状态（判定层内部，纯代码为主）。

**波**：把候选边按「离终点事件最少几跳」分层，一跳一波；判定逐波进行，波内按条数上限切批，
**同一波的所有批共用同一份冻结上下文**（整波判完才更新状态）。
波内按上层顶点（`via_kind` / `via_key`）聚拢、再按时间排，只影响行顺序。

**双层滚动上下文**（逐波更新，替代静态概览）：
- 第 1 层「上游交接明细」：这条边的上层顶点上**已经判过**的边及其结论（`JudgeState.upstream`）。
- 第 2 层「调查状态摘要」：已确认链片段 + 服务会话一览（`build_summary`）。

确定性：分组、排序、编号、摘要裁剪全部固定；模型只影响判定结论与折叠文本。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...contracts import short, triple
from ...core import settings

# 摘要两节之间的间隔
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


def _via_raw(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("via_kind") or ""), str(item.get("via_key") or ""))


def _identities(item: dict[str, Any]) -> list[tuple[str, str]]:
    """这条边的两端身份（第 1 层折叠时存下）；同一身份只留一次。"""
    found: list[tuple[str, str]] = []
    for field_name in ("src_identities", "dst_identities"):
        for pair in item.get(field_name) or ():
            ident = (str(pair[0]), str(pair[1]))
            if ident[1]:
                found.append(ident)
    return list(dict.fromkeys(found))


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
    """逐波累计的调查状态（纯内存、确定性更新）。

    「上层已判过的边」按**顶点身份**索引（进程 → 进程标识、文件 → 路径、网络 → 四元组）：
    一个程序在一台机器上可能跑了很多次，按内容（可执行文件路径）找会把同名进程的历史混在一起
    （场景 3 实测：模型看到的 2,713 条“以前判过的记录”里只有 2.5% 真的关于那个进程）。
    身份由第 1 层的折叠给出（`src_identities` / `dst_identities`）。
    """

    by_triple: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    by_ident: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    session: dict[str, list[int]] = field(default_factory=dict)  # 连接端点 -> [确认条数, 排除条数]
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
                "via": str(item.get("via") or ""),
            }
            self.by_triple[triple(item)] = record
            for ident in _identities(item):
                self.by_ident.setdefault(ident, []).append(record)
            conn = str(item.get("session_conn") or "")
            if conn:
                node = self.session.setdefault(conn, [0, 0])
                node[0 if relevant else 1] += 1
            self.counts["confirmed" if relevant else "excluded"] += 1
            out["confirmed" if relevant else "excluded"] += 1
            if relevant:
                self.chain.append(record)
        return out

    def upstream(self, item: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        """第 1 层：这条边的上层顶点上已经判过的边（跳数最少在前、去重、最多 limit 条）。

        按上层顶点的**身份**（`via_kind` / `via_key`）查，只取确实以这个身份为一端的已判记录；
        优先给属主就是这个进程实例的记录。`limit` 为 0 表示这一层明细不渲染。
        """
        kind = str(item.get("via_kind") or "")
        key = str(item.get("via_key") or "")
        if limit <= 0 or not kind or not key:
            return []
        own: list[dict[str, Any]] = []
        others: list[dict[str, Any]] = []
        for record in self.by_ident.get((kind, key)) or []:
            owner = str((record.get("item") or {}).get("process_id") or "")
            (own if owner == key else others).append(record)
        order = lambda r: (int(r.get("wave") or 0),
                           int((r.get("item") or {}).get("t0") or 0),
                           str(r.get("id")))
        return (sorted(own, key=order) + sorted(others, key=order))[:limit]

    # ------------------------------------------------------------------ #
    # 第 2 层：调查状态摘要
    # ------------------------------------------------------------------ #

    def _chain_lines(self, limit: int) -> list[str]:
        """已确认链片段：只写边与上层顶点，**不写置信度数值**（数值不参与判断，写进去只会当锚点）。"""
        lines = []
        for record in self.chain[-limit:]:
            item = record.get("item") or {}
            via = short(record.get("via") or "终点事件", settings.via_max_chars())
            lines.append(f"- {item.get('src')} --{item.get('syscall')}--> {item.get('dst')}"
                         f"（上层顶点 {via}）")
        return lines

    def _session_lines(self, sessions: list[dict[str, Any]] | None) -> list[str]:
        """服务会话一览（第 2 层）：同一服务进程的多次连接放在一起比。

        数据全部来自第 1 层（`l1_reach/sessions.py`）；这里只做汇总与渲染，不参与判定。
        """
        if not sessions:
            return []
        limit = settings.session_overview_lines()
        active = [s for s in sessions if int(s.get("activity") or 0) > 0]
        zero = [s for s in sessions if int(s.get("activity") or 0) <= 0]
        lines = [f"- 本次清单里共 {len(sessions)} 次被服务进程接受过的连接："
                 f"命令活动大于 0 的 {len(active)} 次，等于 0 的 {len(zero)} 次。"]
        if active:
            lines.append("- 命令活动大于 0（有实际后续活动）：")
            for item in active[:limit]:
                lines.append("  " + self._session_line(item))
            if len(active) > limit:
                lines.append(f"  （另有 {len(active) - limit} 次未列出）")
        if zero:
            candidates = sum(int(s.get("candidates") or 0) for s in zero)
            counts = [self.session.get(str(s.get("conn")), [0, 0]) for s in zero]
            confirmed = sum(c[0] for c in counts)
            excluded = sum(c[1] for c in counts)
            lines.append(f"- 命令活动等于 0 的 {len(zero)} 次：本清单候选合计 {candidates} 条，"
                         f"已判 {confirmed + excluded} 条（确认 {confirmed} / 排除 {excluded}）；"
                         "这些会话除连接本身与自身的读写之外没有留下任何记录。")
        return lines

    def _session_line(self, item: dict[str, Any]) -> str:
        conn = str(item.get("conn") or "")
        counts = self.session.get(conn, [0, 0])
        service = str(item.get("service") or "")
        head = f"{conn}（{service}）" if service else conn
        return (f"{head}：命令活动 {item.get('activity')} 条，本清单候选 "
                f"{item.get('candidates')} 条，已判 {counts[0] + counts[1]} 条"
                f"（确认 {counts[0]} / 排除 {counts[1]}）")

    def build_summary(self, *, chain_limit: int,
                      sessions: list[dict[str, Any]] | None = None) -> str:
        """组装第 2 层摘要（已确认链片段 + 服务会话一览）。

        两节各自的条数由结构性上限管住（链片段 `chain_limit` 条、会话一览节内的 8 行），
        不另设字符上限。
        """
        sections: list[str] = []
        chain = self._chain_lines(chain_limit)
        if chain:
            sections.append("### 已确认的上游活动（从终点往上，最近若干条）\n" + "\n".join(chain))
        session_lines = self._session_lines(sessions)
        if session_lines:
            sections.append("### 服务会话一览（被服务进程接受过的连接，按命令活动从多到少）\n"
                            + "\n".join(session_lines))
        return _NARRATIVE_GAP.join(sections)

