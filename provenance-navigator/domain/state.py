"""调查记录：闭包与判定阶段共用的可变状态（迁移期保留）。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

# ==== 4. 调查记录 ====

ENTITY_STATUSES = ("unexplored", "tracing", "confirmed", "excluded")
RELS = ("supports", "refutes", "derived-from")


def entity_key(etype: str, content: str) -> str:
    e = (etype or "").lower()
    if e == "process":
        return f"proc:{content}"
    if e == "file":
        return f"file:{content}"
    if e == "network":
        return f"net:{content}"
    return f"{e}:{content}"


def _guess_type(content: str) -> str:
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
    poi_rows: list[dict[str, Any]] = field(default_factory=list)
    process_context: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    origin: dict[tuple[str, str, str], str] = field(default_factory=dict)
    confirmed: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    kept: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    excluded: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    links: list[tuple[str, str, str, str]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)

    def mark(self, keys: Iterable[tuple[str, str, str]], origin: str) -> None:
        if origin not in ("confirmed", "kept", "excluded"):
            raise ValueError(f"未知来路 {origin!r}")
        for key in keys:
            self.origin[key] = origin

    def settle(self) -> None:
        self.confirmed = {}
        self.kept = {}
        self.excluded = {}
        for key, edge in self.edges.items():
            origin = self.origin.get(key, "kept")
            bucket = {"confirmed": self.confirmed, "excluded": self.excluded}.get(origin, self.kept)
            bucket[key] = edge

    def unexcluded(self) -> dict[tuple[str, str, str], dict[str, Any]]:
        return {**self.confirmed, **self.kept}

    def add_entity(self, etype: str, content: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知实体状态 {status!r}")
        key = entity_key(etype, content)
        node = self.entities.get(key)
        if node is None:
            self.entities[key] = {"key": key, "kind": "entity", "etype": etype,
                                  "label": content, "status": status}
        elif node["status"] != "confirmed":
            node["status"] = status
        return key

    def add_hypothesis(self, key: str, label: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知假设状态 {status!r}")
        self.hypotheses = [h for h in self.hypotheses if h["key"] != key]
        self.hypotheses.append({"key": key, "kind": "hypothesis", "label": label, "status": status})
        return key

    def add_gap(self, label: str, next_action: str) -> None:
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

    def unclosed(self) -> list[dict[str, Any]]:
        return [h for h in self.hypotheses if h["status"] == "tracing"]

    def close_unclosed(self) -> int:
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
        by_origin: dict[str, int] = {}
        for origin in self.origin.values():
            by_origin[origin] = by_origin.get(origin, 0) + 1
        return {
            "nodes": len(self.entities) + len(self.hypotheses) + len(self.gaps),
            "by_kind": by_kind,
            "by_status": by_status,
            "edges": len(self.links),
            "unclosed_hypotheses": len(self.unclosed()),
            "open_gaps": sum(1 for g in self.gaps if g["status"] == "open"),
            "origin": by_origin,
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

