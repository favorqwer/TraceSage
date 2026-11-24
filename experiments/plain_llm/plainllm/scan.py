"""阶段一：全量边表逐批判定。

每批单独请求，批内边按时间稳定排序；批与批之间不共享上下文。结果逐批落盘，
进程中断后可从已完成批次续跑。
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .chunking import batches, format_edge_block, order_quads
from .client import LlmClient, LlmError, extract_json
from .settings import Config

_PROGRESS_LOCK = threading.Lock()


def normalize_id(value: Any) -> str:
    if isinstance(value, int):
        return f"E{value:06d}"
    text = str(value or "").strip().upper()
    if text.startswith("E") and text[1:].isdigit():
        return f"E{int(text[1:]):06d}"
    if text.isdigit():
        return f"E{int(text):06d}"
    return text


def _render(template: str, mapping: dict[str, str]) -> str:
    for token, value in mapping.items():
        template = template.replace(token, value)
    return template


def _parse_selection(payload: dict[str, Any] | None, valid: set[str]) -> tuple[list[str], list[str]]:
    if not payload:
        return [], []
    items = payload.get("attack_edges")
    if items is None:
        items = payload.get("edges") or payload.get("selected") or []
    if not isinstance(items, list):
        return [], []
    selected: list[str] = []
    invalid: list[str] = []
    for item in items:
        raw = item.get("id") if isinstance(item, dict) else item
        edge_id = normalize_id(raw)
        if edge_id in valid:
            if edge_id not in selected:
                selected.append(edge_id)
        elif edge_id:
            invalid.append(str(raw))
    return selected, invalid


def run_scan(
    cfg: Config,
    quads: list[dict[str, Any]],
    poi_text: str,
    stats_text: str,
    out_dir: Path,
    client: LlmClient,
) -> dict[str, Any]:
    system = (cfg.prompt_dir / "scan.system.txt").read_text(encoding="utf-8")
    user_template = (cfg.prompt_dir / "scan.user.txt").read_text(encoding="utf-8")
    ordered = order_quads(quads)
    if not ordered:
        print("  阶段一：边表为空，跳过", flush=True)
        return {"selected_ids": [], "chunks": 0, "failed_chunks": 0, "invalid_ids": 0}
    chunks = batches(ordered, cfg.chunk_size)
    # 检查点按批大小分目录：换批大小后不会误用上一轮的分批结论。
    ckpt_dir = out_dir / "scan" / f"chunk{cfg.chunk_size}"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    print(f"  阶段一：{len(ordered):,} 条边切成 {len(chunks)} 批，并发 {cfg.concurrency}", flush=True)

    def work(index: int, batch: list[dict[str, Any]]) -> dict[str, Any]:
        path = ckpt_dir / f"chunk_{index:05d}.json"
        if path.exists():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
                if not cached.get("error"):
                    return cached
            except json.JSONDecodeError:
                pass
        valid = {q["id"] for q in batch}
        user = _render(user_template, {
            "<<POI>>": poi_text,
            "<<STATS>>": stats_text,
            "<<CHUNK_NO>>": str(index),
            "<<CHUNK_TOTAL>>": str(len(chunks)),
            "<<EDGES>>": format_edge_block(batch, cfg.max_line_chars),
        })
        payload: dict[str, Any] | None = None
        error = ""
        try:
            result = client.chat(system, user, tag=f"scan/{index:05d}")
            payload = extract_json(result.text)
            if payload is None:
                repaired = client.chat(
                    system,
                    user + "\n\n上一次输出不是合法 JSON 对象。请只输出 JSON，不要任何其他文字。",
                    tag=f"scan/{index:05d}/repair",
                )
                payload = extract_json(repaired.text)
        except LlmError as exc:
            error = str(exc)
        if payload is None and not error:
            error = "响应无法解析为 JSON 对象"
        selected, invalid = _parse_selection(payload, valid)
        record = {
            "chunk": index,
            "total": len(chunks),
            "first_id": batch[0]["id"],
            "last_id": batch[-1]["id"],
            "size": len(batch),
            "ids": selected,
            "invalid_ids": invalid,
            "summary": (payload or {}).get("summary", ""),
            "error": error,
        }
        path.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
        return record

    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(cfg.concurrency, len(chunks)))) as pool:
        futures = {pool.submit(work, i, batch): i for i, batch in enumerate(chunks, start=1)}
        for done, future in enumerate(as_completed(futures), start=1):
            records.append(future.result())
            if done % 20 == 0 or done == len(futures):
                with _PROGRESS_LOCK:
                    print(f"    阶段一进度 {done}/{len(futures)} 批", flush=True)

    records.sort(key=lambda r: r["chunk"])
    selected_all: list[str] = []
    seen: set[str] = set()
    errors = 0
    invalid_total = 0
    for record in records:
        errors += 1 if record.get("error") else 0
        invalid_total += len(record.get("invalid_ids") or [])
        for edge_id in record.get("ids") or []:
            if edge_id not in seen:
                seen.add(edge_id)
                selected_all.append(edge_id)
    print(f"  阶段一完成：选中 {len(selected_all):,} 条，失败批 {errors}，非法 id {invalid_total}", flush=True)
    return {
        "selected_ids": selected_all,
        "chunks": len(chunks),
        "failed_chunks": errors,
        "invalid_ids": invalid_total,
    }
