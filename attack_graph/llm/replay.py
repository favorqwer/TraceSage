"""大模型逐批判定日志（.trace.jsonl）离线重放。

恢复首层的束与成员顺序，再按请求指纹及束成员定位已记录的模型判定。
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

INPUT_PROTOCOL = "triplet-v1"


def request_sha256(model: str, system: str, listing: str) -> str:
    request = json.dumps([model, system, listing], ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(request).hexdigest()


def bundle_key(level: int, members: Iterable[Any]) -> tuple[int, tuple[tuple[Any, ...], ...]]:
    """生成与并发/批号无关的束唯一键：(层级, 排序后的成员三元组集合)。"""
    triples = sorted(tuple(member) for member in members)
    if any(len(triple) != 3 for triple in triples):
        raise ValueError("判定成员必须是三元组")
    return int(level), tuple(triples)


@dataclass(frozen=True)
class _RecordedBundle:
    ok: bool
    row: Optional[dict[str, Any]]
    error: str = ""


def _extract_batch_verdicts(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """恢复经过引用校验的正式判定。"""
    raw_verdicts = result.get("verdicts")
    if isinstance(raw_verdicts, dict):
        return {str(k): dict(v) for k, v in raw_verdicts.items() if isinstance(v, dict)}
    return {}


class TraceReplay:
    """从 `.trace.jsonl` 加载束级大模型判定缓存并执行零调用重放。"""

    def __init__(
        self,
        trace_path: str | Path,
        entries: dict[tuple, _RecordedBundle],
        *,
        first_bundles: dict[tuple, int],
        member_positions: dict[tuple, int],
        scenario: str = "",
        batches: int = 0,
    ) -> None:
        self.trace_path = str(Path(trace_path).resolve())
        self._entries = entries
        self._first_bundles = first_bundles
        self._member_positions = member_positions
        self.scenario = scenario
        self.recorded_batches = batches
        self._lock = threading.Lock()
        self.replayed_batches = 0
        self.replayed_items = 0

    @classmethod
    def from_file(cls, trace_path: str | Path, *, expected_scenario: str,
                  expected_model: str) -> "TraceReplay":
        """解析 `.trace.jsonl` 文件并构建束键索引；场景不匹配或文件缺失时立即报错。"""
        path = Path(trace_path)
        if not path.is_file():
            raise FileNotFoundError(f"trace 重放文件不存在：{path}")

        entries = {}
        first_items = {}
        trace_scenario = ""
        batches = 0

        with path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                line = raw_line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("input_protocol") != INPUT_PROTOCOL:
                    raise ValueError(f"判定轨迹协议不兼容：{path}:{line_no}")
                if rec.get("model") != expected_model:
                    raise ValueError(f"判定轨迹模型不匹配：{path}:{line_no}")
                rec_scenario = str(rec.get("scenario") or "")
                if rec_scenario:
                    if not trace_scenario:
                        trace_scenario = rec_scenario
                    elif rec_scenario != trace_scenario:
                        raise ValueError(f"trace 文件第 {line_no} 行场景名不一致：{rec_scenario} != {trace_scenario}")
                if rec_scenario != expected_scenario:
                    raise ValueError(f"trace 场景不匹配：{rec_scenario} != {expected_scenario}")

                if rec.get("kind") == "detail":
                    continue

                items = rec.get("items") or []
                fingerprint = rec.get("request_sha256")
                if not isinstance(fingerprint, str) or len(fingerprint) != 64:
                    raise ValueError(f"判定轨迹缺少请求指纹：{path}:{line_no}")
                result = rec.get("result") or {}
                batches += 1
                ok = bool(result.get("ok", True))
                error = str(result.get("error") or "")
                verdicts = _extract_batch_verdicts(result) if ok else {}

                for item in items:
                    bid = str(item.get("id") or "")
                    level = int(item["level"])
                    members = tuple(tuple(member) for member in item.get("members") or ())
                    group = bundle_key(level, members)
                    key = (fingerprint, group)
                    if level == 0:
                        if not bid.startswith("B") or not bid[1:].isdigit() or bid in first_items:
                            raise ValueError(f"首层束编号无效或重复：{path}:{line_no} {bid}")
                        first_items[bid] = (group, members)
                    row = verdicts.get(bid)
                    entries[key] = _RecordedBundle(
                        ok=ok,
                        row=(dict(row) if isinstance(row, dict) else None),
                        error=error,
                    )

        if not entries:
            raise ValueError(f"trace 文件中未包含任何束级判定记录：{path}")
        first_bundles = {}
        member_positions = {}
        for bid in sorted(first_items, key=lambda bid: int(bid[1:])):
            group, members = first_items[bid]
            if group in first_bundles or not members:
                raise ValueError(f"首层束为空或重复：{path} {bid}")
            first_bundles[group] = len(first_bundles)
            for member in members:
                if member in member_positions:
                    raise ValueError(f"首层束成员重复：{path} {bid}")
                member_positions[member] = len(member_positions)
        return cls(path, entries, first_bundles=first_bundles, member_positions=member_positions,
                   scenario=trace_scenario, batches=batches)

    def order_members(self, triples: set[tuple]) -> list[tuple]:
        """校验候选集合后恢复每个束内部的成员顺序。"""
        if triples != self._member_positions.keys():
            raise RuntimeError("重放首层候选集合与轨迹不一致")
        return sorted(triples, key=self._member_positions.__getitem__)

    def order_first_bundles(self, bundles: dict) -> list:
        """首层编号表示原始调度顺序，与并发写入轨迹的顺序无关。"""
        groups = {bundle_key(0, members): key for key, members in bundles.items()}
        if groups.keys() != self._first_bundles.keys():
            raise RuntimeError("重放首层候选分组与轨迹不一致")
        return [groups[group] for group in self._first_bundles]

    def judge_batch(self, items: list[dict[str, Any]], fingerprint: str) -> dict[str, Any]:
        """按当前批内每个束的 `(level, members)` 从缓存恢复结论，并将编号重映射为当前 `item['id']`。"""
        verdicts: dict[str, dict[str, Any]] = {}
        for item in items:
            key = (fingerprint, bundle_key(int(item["level"]), item.get("members") or ()))
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
