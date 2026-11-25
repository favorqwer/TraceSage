"""边表读取、稳定排序、切块与提示词里的单行格式。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

KIND_NAME = {"P": "P", "F": "F", "N": "N", "?": "?"}


def triple_key(row):
    return (row["src_kind"], row["src"]), row["call"], (row["dst_kind"], row["dst"])


def load_triples(path: Path) -> list[dict[str, Any]]:
    triples: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                triples.append(json.loads(line))
    return triples


def ns_to_iso(ns: int | None, with_date: bool = True) -> str:
    if ns is None:
        return "-"
    dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    if with_date:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def order_triples(triples: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """按首次时间稳定排序；时间相同用内容排序，保证两次运行切块一致。"""
    return sorted(triples, key=lambda q: (
        q.get("first_ns") if q.get("first_ns") is not None else 0,
        q.get("src", ""), q.get("call", ""), q.get("dst", ""),
        q.get("id", ""),
    ))


def batches(items: list[Any], size: int) -> list[list[Any]]:
    if size <= 0:
        raise ValueError("批大小必须大于 0")
    return [items[i:i + size] for i in range(0, len(items), size)]


def format_edge(triple: dict[str, Any], max_line_chars: int = 320) -> str:
    """一条边一行：id + 源/动作/目标 + 次数 + 首末时间 + 成败 + 载荷预览。"""
    src = f"[{triple['src_kind']}|{triple['src']}]"
    dst = f"[{triple['dst_kind']}|{triple['dst']}]"
    first = ns_to_iso(triple.get("first_ns"))
    last = ns_to_iso(triple.get("last_ns"))
    span = first if first == last else f"{first}~{last}"
    line = f"{triple['id']} {src} --{triple['call']}--> {dst} n={triple['n']} t={span}"
    payload = triple.get("payload")
    if payload:
        line += f' pay="{payload}"'
    if len(line) > max_line_chars:
        line = line[: max_line_chars - 3] + "..."
    return line


def format_edge_block(triples: list[dict[str, Any]], max_line_chars: int = 320) -> str:
    return "\n".join(format_edge(q, max_line_chars) for q in triples)
