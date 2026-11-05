"""从留一折库构建 Rule KG 种子快照（不写 Neo4j）。

输出是纯 JSON，保证可复现、可评审；Neo4j 导入是后续独立步骤。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rag.attack import load_behavior_observables
from rag.link import link_motifs
from rag.schema import Hop, Motif
from rag.stats import RuleStats, load_fold_rule_stats


def _roles_and_syscalls(m: Dict[str, Any]) -> tuple[int, List[str], List[str], List[Hop]]:
    """从折库 motif 提取角色链、syscall 链与 Hop 列表。"""
    mid = str(m.get("id") or "")
    hops = int(m.get("hops") or 1)
    chain = m.get("chain") or []
    if hops >= 2 and len(chain) >= 2:
        role_chain = [str(chain[0].get("src_role") or "")]
        hop_records: List[Hop] = []
        for idx, hop in enumerate(chain, 1):
            src = str(hop.get("src_role") or "")
            dst = str(hop.get("dst_role") or "")
            sc = str(hop.get("syscall") or "")
            role_chain.append(dst)
            hop_records.append(Hop(mid, idx, src, sc, dst))
        syscall_chain = [h.syscall for h in hop_records]
        return hops, role_chain, syscall_chain, hop_records

    src = str(m.get("src_role") or "")
    dst = str(m.get("dst_role") or "")
    syscalls = [str(s) for s in (m.get("syscalls") or [])]
    sc_text = "+".join(syscalls)
    hop_records = [Hop(mid, 1, src, sc_text, dst)]
    return 1, [src, dst], syscalls, hop_records


def build_fold_kg(scenario: str, fold_library_path: str | Path, *,
                  version: str = "kg-v1", include_candidates: bool = False,
                  observables_path: str | Path | None = None) -> Dict[str, Any]:
    """构建单个折的 KG 快照。

    `include_candidates=False` 时只收录 `selected`（检索只应使用准入规则）；
    `True` 时把未入选形态以 `admitted=false` 一并存档，供分析使用。
    """
    fold = json.loads(Path(fold_library_path).read_text(encoding="utf-8"))
    selected = {str(x) for x in (fold.get("selected") or [])}
    all_motifs = fold.get("motifs") or []

    wanted = [str(m.get("id") or "") for m in all_motifs
              if include_candidates or str(m.get("id") or "") in selected]
    stats: Dict[str, RuleStats] = load_fold_rule_stats(
        scenario, fold_library_path, motif_ids=wanted)

    motifs: List[Motif] = []
    hops: List[Hop] = []
    for m in all_motifs:
        mid = str(m.get("id") or "")
        if mid not in stats:
            continue
        admitted = mid in selected
        if not include_candidates and not admitted:
            continue
        hops_n, role_chain, syscall_chain, hop_records = _roles_and_syscalls(m)
        motifs.append(Motif(
            motif_id=mid,
            name=str(m.get("name") or ""),
            hops=hops_n,
            role_chain=role_chain,
            syscall_chain=syscall_chain,
            support_scenarios=[str(s) for s in (m.get("support_scenarios_list") or [])],
            admitted=admitted,
            source="fold-library",
            version=version,
            stats=stats[mid].to_dict(),
        ))
        hops.extend(hop_records)

    links: List[Dict[str, Any]] = []
    if observables_path:
        observables = load_behavior_observables(observables_path)
        links = link_motifs(motifs, observables)

    return {
        "version": version,
        "fold_of": scenario,
        "train_scenarios": [str(s) for s in (fold.get("train_scenarios") or [])],
        "role_cuts": fold.get("role_cuts") or {},
        "observables_path": str(observables_path) if observables_path else "",
        "motifs": [m.to_dict() for m in motifs],
        "hops": [h.to_dict() for h in hops],
        "technique_links": links,
        "counts": {
            "motifs": len(motifs),
            "admitted": sum(1 for m in motifs if m.admitted),
            "hops": len(hops),
            "linked_motifs": sum(1 for m in motifs if m.techniques),
            "technique_links": len(links),
        },
    }


def save_fold_kg(kg: Dict[str, Any], out_dir: str | Path) -> Path:
    dest = Path(out_dir) / "folds" / f"{kg['fold_of']}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(kg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return dest


def build_all_folds(fold_dir: str | Path, out_dir: str | Path, *,
                    version: str = "kg-v1", include_candidates: bool = False,
                    observables_path: str | Path | None = None) -> Dict[str, Any]:
    """对 fold_dir 下全部折库构建 KG，并写 manifest。"""
    fold_dir = Path(fold_dir)
    latest = Path(__file__).resolve().parents[1] / "config" / "rules-library" / "latest.txt"
    source_library = latest.read_text(encoding="utf-8").strip() if latest.is_file() else ""
    manifest = {
        "version": version,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_library": source_library,
        "fold_dir": str(fold_dir),
        "counts_note": "各折计数之和；不同折的 selected 集合不同，不是去重后的全局规则数",
        "folds": {},
        "counts": {"motifs": 0, "admitted": 0, "hops": 0,
                   "linked_motifs": 0, "technique_links": 0},
    }
    for path in sorted(fold_dir.glob("*.json")):
        scenario = path.stem
        kg = build_fold_kg(scenario, path, version=version,
                           include_candidates=include_candidates,
                           observables_path=observables_path)
        dest = save_fold_kg(kg, out_dir)
        manifest["folds"][scenario] = {
            "path": str(dest), "counts": kg["counts"],
            "train_scenarios": kg["train_scenarios"],
        }
        for key in manifest["counts"]:
            manifest["counts"][key] += int(kg["counts"].get(key) or 0)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest
