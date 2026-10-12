"""调查记录（内存版，替代原 SQLite 状态图）。

旧实现把"实体 / 假设 / 缺口 + 支持·反驳·属于·由…推出"四类边写进 SQLite，为此需要连接、锁、
批量提交、失败重试、以及"登记必须排在预算熔断之前"这条顺序约束。架构精简后**结论本来就在内存里**
（主循环的已确认/已排除字典），所以记录改成普通字典，收尾时一次性落盘成 JSON 供审计。

保留的硬约束（与旧版一致，只是不再依赖数据库）：
- 缺口必须带 `next_action`（"下次该怎么查"），否则直接报错；
- 假设不得以 `tracing` 状态收场（`close_unclosed()` 在出报告前强制收尾）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

ENTITY_STATUSES = ("unexplored", "tracing", "confirmed", "excluded")
RELS = ("supports", "refutes", "derived-from")


def entity_key(etype: str, content: str) -> str:
    """确定性、可复用的实体键。"""
    e = (etype or "").lower()
    if e == "process":
        return f"proc:{content}"
    if e == "file":
        return f"file:{content}"
    if e == "network":
        return f"net:{content}"
    return f"{e}:{content}"


def _guess_type(content: str) -> str:
    """按内容猜实体类型（仅在调用方没给标签时的兜底）。"""
    if "->" in content and ":" in content:
        return "Network"
    if content.startswith(("pipe:[", "unix:[")):
        return "File"
    return "Process"


@dataclass
class Investigation:
    run_id: str
    scenario: str
    database: str = ""
    poi_process: str = ""
    poi_owner: str = ""
    poi_instances: int = 0
    poi_t0: int = 0
    poi_t1: int = 0
    # 终点事件的原文（闭包引擎的种子；每行含进程、另一端、操作名、字节数、起止时刻）
    poi_rows: list[dict[str, Any]] = field(default_factory=list)
    # 进程身份摘要：进程标识 -> {"owner": ..., "origin": {...}, "t0": ...}
    process_context: dict[str, dict[str, Any]] = field(default_factory=dict)
    # 折叠后的边（三元组 -> 记录），供判定与报告使用
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    confirmed: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    excluded: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    unjudged: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    # 记录表（内存）：节点 + 边
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    links: list[tuple[str, str, str, str]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)

    # --- 写 ---
    def add_entity(self, etype: str, content: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知实体状态 {status!r}")
        key = entity_key(etype, content)
        node = self.entities.get(key)
        if node is None:
            self.entities[key] = {"key": key, "kind": "entity", "etype": etype,
                                  "label": content, "status": status}
        elif node["status"] != "confirmed":
            # 已确认的不被后续的"排除"降级（同一实体可能同时是某条确认边的端点）
            node["status"] = status
        return key

    def add_hypothesis(self, key: str, label: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知假设状态 {status!r}")
        self.hypotheses = [h for h in self.hypotheses if h["key"] != key]
        self.hypotheses.append({"key": key, "kind": "hypothesis", "label": label, "status": status})
        return key

    def add_gap(self, label: str, next_action: str) -> None:
        """待证缺口：**必须**带一个具体的后继动作，不允许只记一句"图上没有"。"""
        if not next_action or not next_action.strip():
            raise ValueError("gap 必须带 next_action（哪个库、哪条查询/哪个工具）")
        if any(g["label"] == label for g in self.gaps):
            return
        self.gaps.append({"key": f"gap:{len(self.gaps) + 1}", "kind": "gap", "label": label,
                          "status": "open", "next_action": next_action.strip()})

    def link(self, src: str, rel: str, dst: str, *, note: str = "") -> None:
        if rel not in RELS:
            raise ValueError(f"未知关系 {rel!r}；允许 {RELS}")
        item = (src, rel, dst, note)
        if item not in self.links:
            self.links.append(item)

    def register_edges(self, records: list[dict[str, Any]], *, relevant: bool,
                       hypothesis_key: str = "") -> None:
        """把一批判定结论登记进记录表：实体 + supports / refutes。"""
        for edge in records:
            src_key = entity_key(edge.get("src_label") or _guess_type(edge["src"]), edge["src"])
            dst_key = entity_key(edge.get("dst_label") or _guess_type(edge["dst"]), edge["dst"])
            self.add_entity(edge.get("src_label") or _guess_type(edge["src"]), edge["src"],
                            status="confirmed" if relevant else "excluded")
            self.add_entity(edge.get("dst_label") or _guess_type(edge["dst"]), edge["dst"],
                            status="confirmed" if relevant else "excluded")
            if hypothesis_key:
                for key in (src_key, dst_key) if relevant else (src_key,):
                    self.link(key, "supports" if relevant else "refutes", hypothesis_key)

    # --- 收尾 ---
    def unclosed(self) -> list[dict[str, Any]]:
        return [h for h in self.hypotheses if h["status"] == "tracing"]

    def close_unclosed(self) -> int:
        """硬约束：假设不得以 tracing 状态离场。"""
        n = 0
        for h in self.hypotheses:
            if h["status"] == "tracing":
                h["status"] = "excluded"
                n += 1
        return n

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for node in list(self.entities.values()) + self.hypotheses + self.gaps:
            by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
            by_status[node["status"]] = by_status.get(node["status"], 0) + 1
        return {
            "nodes": len(self.entities) + len(self.hypotheses) + len(self.gaps),
            "by_kind": by_kind,
            "by_status": by_status,
            "edges": len(self.links),
            "unclosed_hypotheses": len(self.unclosed()),
            "open_gaps": sum(1 for g in self.gaps if g["status"] == "open"),
        }

    def dump(self, path: Optional[Path] = None) -> Optional[Path]:
        if path is None:
            return None
        payload = {
            "run_id": self.run_id, "scenario": self.scenario, "database": self.database,
            "poi_process": self.poi_process,
            "nodes": list(self.entities.values()) + self.hypotheses + self.gaps,
            "edges": [{"src": s, "rel": r, "dst": d, "note": n} for s, r, d, n in self.links],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        return Path(path)
