"""大模型逐批判定日志（.trace.jsonl）离线重放。

按 `(level, sorted(members))` 唯一定位每个束并恢复其模型判定结论，
在保持阶段 1~4 束划分不变的前提下跳过真实大模型接口调用。
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from llm.client import extract_json
from llm.verdict import parse_bundle_verdicts


def bundle_key(level: int, members: Iterable[Any]) -> tuple[int, tuple[tuple[Any, ...], ...]]:
    """生成与并发/批号无关的束唯一键：(层级, 排序后的成员三元组集合)。"""
    triples = sorted(tuple(member) for member in members)
    return int(level), tuple(triples)


@dataclass(frozen=True)
class _RecordedBundle:
    ok: bool
    row: Optional[dict[str, Any]]
    error: str = ""


def _extract_batch_verdicts(items: list[dict[str, Any]], result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """优先恢复已过引用守卫的最终 verdicts，缺失时回退从 _raw_text 解析。"""
    raw_verdicts = result.get("verdicts")
    if isinstance(raw_verdicts, dict):
        return {str(k): dict(v) for k, v in raw_verdicts.items() if isinstance(v, dict)}
    valid_ids = {str(item.get("id") or "") for item in items}
    raw_text = result.get("_raw_text")
    if isinstance(raw_text, str) and raw_text.strip():
        parsed = extract_json(raw_text)
        if parsed is not None:
            verdicts, _ = parse_bundle_verdicts(parsed, valid_ids)
            return verdicts
    return {}


class TraceReplay:
    """从 `.trace.jsonl` 加载束级大模型判定缓存并执行零调用重放。"""

    def __init__(
        self,
        trace_path: str | Path,
        entries: dict[tuple[int, tuple[tuple[Any, ...], ...]], _RecordedBundle],
        *,
        scenario: str = "",
        batches: int = 0,
    ) -> None:
        self.trace_path = str(Path(trace_path).resolve())
        self._entries = entries
        self.scenario = scenario
        self.recorded_batches = batches
        self._lock = threading.Lock()
        self.replayed_batches = 0
        self.replayed_items = 0

    @classmethod
    def from_file(cls, trace_path: str | Path, *, expected_scenario: Optional[str] = None) -> "TraceReplay":
        """解析 `.trace.jsonl` 文件并构建束键索引；场景不匹配或文件缺失时立即报错。"""
        path = Path(trace_path)
        if not path.is_file():
            raise FileNotFoundError(f"trace 重放文件不存在：{path}")

        entries: dict[tuple[int, tuple[tuple[Any, ...], ...]], _RecordedBundle] = {}
        trace_scenario = ""
        batches = 0

        with path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                line = raw_line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                rec_scenario = str(rec.get("scenario") or "")
                if rec_scenario:
                    if not trace_scenario:
                        trace_scenario = rec_scenario
                    elif rec_scenario != trace_scenario:
                        raise ValueError(f"trace 文件第 {line_no} 行场景名不一致：{rec_scenario} != {trace_scenario}")
                if expected_scenario and rec_scenario and rec_scenario != expected_scenario:
                    raise ValueError(f"trace 场景不匹配：{rec_scenario} != {expected_scenario}")

                if rec.get("kind") == "detail":
                    continue

                items = rec.get("items") or []
                result = rec.get("result") or {}
                batches += 1
                ok = bool(result.get("ok", True))
                error = str(result.get("error") or "")
                verdicts = _extract_batch_verdicts(items, result) if ok else {}

                for item in items:
                    key = bundle_key(int(item["level"]), item.get("members") or ())
                    bid = str(item.get("id") or "")
                    row = verdicts.get(bid)
                    entries[key] = _RecordedBundle(
                        ok=ok,
                        row=(dict(row) if isinstance(row, dict) else None),
                        error=error,
                    )

        if not entries:
            raise ValueError(f"trace 文件中未包含任何束级判定记录：{path}")
        return cls(path, entries, scenario=trace_scenario, batches=batches)

    def judge_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        """按当前批内每个束的 `(level, members)` 从缓存恢复结论，并将编号重映射为当前 `item['id']`。"""
        verdicts: dict[str, dict[str, Any]] = {}
        for item in items:
            key = bundle_key(int(item["level"]), item.get("members") or ())
            cached = self._entries.get(key)
            if cached is None:
                raise RuntimeError(
                    f"trace 重放未命中束：level={item['level']}, size={item.get('size')}, "
                    f"sample={list(item.get('members') or ())[:2]}"
                )
            if not cached.ok:
                with self._lock:
                    self.replayed_batches += 1
                return {"ok": False, "error": cached.error or "trace recorded failure", "calls": 1, "_replayed": True}
            if cached.row is not None:
                row = dict(cached.row)
                row["id"] = item["id"]
                verdicts[item["id"]] = row

        with self._lock:
            self.replayed_batches += 1
            self.replayed_items += len(items)
        return {"ok": True, "verdicts": verdicts, "invalid": 0, "calls": 1, "_replayed": True}
