"""阶段二：把候选边拼成一条攻击链。

按候选边的时间顺序分批请求，批间用上一批结论作为脉络继续；最后统一整理阶段编号。
只做取舍与分阶段，不新增任何边。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .chunking import batches, format_edge_block
from .checkpoint import load_checkpoint, request_identity, write_checkpoint
from .client import LlmClient, LlmError, extract_json
from .scan import normalize_id
from .settings import Config


def _render(template: str, mapping: dict[str, str]) -> str:
    for token, value in mapping.items():
        template = template.replace(token, value)
    return template


def _parse_keep(payload: dict[str, Any] | None, valid: set[str]) -> tuple[list[dict[str, str]], list[str]]:
    if not payload:
        return [], []
    items = payload.get("keep")
    if items is None:
        items = payload.get("kept") or payload.get("edges") or []
    if not isinstance(items, list):
        return [], []
    kept: list[dict[str, str]] = []
    invalid: list[str] = []
    for item in items:
        raw = item.get("id") if isinstance(item, dict) else item
        edge_id = normalize_id(raw)
        if edge_id in valid:
            phase = str(item.get("phase") or "").strip() if isinstance(item, dict) else ""
            kept.append({"id": edge_id, "phase": phase})
        elif edge_id:
            invalid.append(str(raw))
    return kept, invalid


def run_assemble(
    cfg: Config,
    selected_triples: list[dict[str, Any]],
    poi_text: str,
    out_dir: Path,
    client: LlmClient,
    *,
    scenario: str,
    resume: bool = True,
) -> dict[str, Any]:
    system = (cfg.prompt_dir / "assemble.system.txt").read_text(encoding="utf-8")
    user_template = (cfg.prompt_dir / "assemble.user.txt").read_text(encoding="utf-8")
    selected = sorted(selected_triples, key=lambda q: (
        q.get("first_ns") if q.get("first_ns") is not None else 0, q["id"]))
    if not selected:
        return {"kept": [], "entry": "", "story": "", "batches": 0, "failed_batches": 0}

    chunk_list = batches(selected, cfg.assemble_chunk)
    # 检查点按批大小分目录，避免不同批大小之间串用结论。
    ckpt_dir = out_dir / "assemble" / f"chunk{cfg.assemble_chunk}"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    print(f"  阶段二：候选 {len(selected):,} 条，切成 {len(chunk_list)} 批", flush=True)

    story = ""
    entry = ""
    kept: list[dict[str, str]] = []
    failed = 0
    for index, batch in enumerate(chunk_list, start=1):
        path = ckpt_dir / f"batch_{index:05d}.json"
        user = _render(user_template, {
            "<<POI>>": poi_text,
            "<<STORY>>": story or "（空）",
            "<<BATCH_NO>>": str(index),
            "<<BATCH_TOTAL>>": str(len(chunk_list)),
            "<<EDGES>>": format_edge_block(batch, cfg.max_line_chars),
        })
        identity = request_identity(cfg, scenario, system, user)
        record = load_checkpoint(path, identity) if resume else None
        if record is None:
            valid = {q["id"] for q in batch}
            payload: dict[str, Any] | None = None
            error = ""
            try:
                result = client.chat(system, user, tag=f"assemble/{index:05d}")
                payload = extract_json(result.text)
                if payload is None:
                    repaired = client.chat(
                        system,
                        user + "\n\n上一次输出不是合法 JSON 对象。请只输出 JSON，不要任何其他文字。",
                        tag=f"assemble/{index:05d}/repair",
                    )
                    payload = extract_json(repaired.text)
            except LlmError as exc:
                error = str(exc)
            if payload is None and not error:
                error = "响应无法解析为 JSON 对象"
            kept_batch, invalid = _parse_keep(payload, valid)
            record = {
                **identity,
                "batch": index,
                "total": len(chunk_list),
                "keep": kept_batch,
                "invalid_ids": invalid,
                "entry": str((payload or {}).get("entry") or ""),
                "story": str((payload or {}).get("story") or ""),
                "error": error,
            }
            write_checkpoint(path, record)
        if record.get("error"):
            failed += 1
        kept.extend(record.get("keep") or [])
        story = record.get("story") or story
        entry = record.get("entry") or entry

    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in kept:
        if item["id"] not in seen:
            seen.add(item["id"])
            deduped.append(item)

    deduped = _normalize_phases(deduped, {q["id"]: q for q in selected})
    entry_id = normalize_id(entry) if entry else ""
    if entry_id not in {item["id"] for item in deduped}:
        entry_id = ""
    print(f"  阶段二完成：保留 {len(deduped):,} 条，失败批 {failed}", flush=True)
    return {"kept": deduped, "entry": entry_id, "story": story,
            "batches": len(chunk_list), "failed_batches": failed}


def _normalize_phases(kept: list[dict[str, str]], triples_by_id: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """把各批给出的阶段名按最早时间重排成 A1、A2……，避免同名不同段。"""
    if not kept:
        return kept
    first_ns: dict[str, int] = {}
    for item in kept:
        label = item.get("phase") or "A1"
        triple = triples_by_id.get(item["id"]) or {}
        ts = triple.get("first_ns") or 0
        if label not in first_ns or ts < first_ns[label]:
            first_ns[label] = ts
    ordered_labels = sorted(first_ns, key=lambda label: (first_ns[label], label))
    mapping = {label: f"A{i}" for i, label in enumerate(ordered_labels, start=1)}
    return [{"id": item["id"], "phase": mapping[item.get("phase") or "A1"]} for item in kept]
