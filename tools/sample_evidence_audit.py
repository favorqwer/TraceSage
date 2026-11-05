#!/usr/bin/env python
"""抽取 20 条 top-3 证据卡，做机械对齐核验并生成人工判定清单。

核验维度：
- 边 syscall 是否出现在 Motif 的 syscall_chain；
- 边的 src_role/dst_role 是否出现在 Motif 的 role_chain；
- 正确技术是否在 top-1 / top-3 展开技术里；
- top-3 展开技术的精度（正确数/展开数）。

输出：
- tmp/frozen_runs/PRECISION_AUDIT_20.md
"""
from __future__ import annotations

import glob
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
KG_DIR = ROOT / "output/rule-kg/v1"
OUT = ROOT / "tmp/frozen_runs/PRECISION_AUDIT_20.md"


def parent_of(tid: str) -> str:
    return str(tid).split(".", 1)[0]


def tech_match(ids: Set[str], correct: Set[str]) -> bool:
    if ids & correct:
        return True
    for r in ids:
        for c in correct:
            if parent_of(r) == c or parent_of(c) == r:
                return True
    return False


def load_motifs(scenario: str) -> Dict[str, Dict[str, Any]]:
    path = KG_DIR / "folds" / f"{scenario}.json"
    kg = json.loads(path.read_text(encoding="utf-8"))
    return {str(m["motif_id"]): m for m in kg.get("motifs") or []}


def parse_syscall(edge: str) -> str:
    m = re.search(r"--(.+?)-->", edge)
    return m.group(1) if m else ""


def hop_flags(motif: Dict[str, Any], syscall: str, src_role: str, dst_role: str) -> Tuple[bool, bool, bool]:
    """返回 (是否有一跳精确对齐, 是否有 syscall 对齐, 是否有 syscall+单角色对齐)。"""
    roles = motif.get("role_chain") or []
    syscalls = motif.get("syscall_chain") or []
    exact = sys_ok = one_role = False
    for i, sc in enumerate(syscalls):
        if i + 1 >= len(roles):
            break
        a, b = str(roles[i]), str(roles[i + 1])
        if sc != syscall:
            continue
        sys_ok = True
        if a == src_role and b == dst_role:
            exact = True
        if a == src_role or b == dst_role:
            one_role = True
    return exact, sys_ok, one_role


def main() -> None:
    rows_by_scenario: Dict[str, List[Dict[str, Any]]] = {}
    for path in sorted(glob.glob(str(KG_DIR / "graph_retrieval_*.json"))):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        scenario = data["scenario"]
        rows = [r for r in data.get("rows") or []
                if not r.get("symbolic_reachable") and r.get("motif_details")]
        rows_by_scenario[scenario] = rows

    selected: List[Tuple[str, Dict[str, Any], Dict[str, Dict[str, Any]]]] = []
    scenarios = sorted(rows_by_scenario, key=lambda s: int(s.split("_", 1)[0]))
    # 每个场景先取 2 条，凑满 20 条
    for sc in scenarios:
        rows = rows_by_scenario[sc]
        motifs = load_motifs(sc)
        for row in rows[:2]:
            selected.append((sc, row, motifs))
    for sc in scenarios:
        if len(selected) >= 20:
            break
        rows = rows_by_scenario[sc][2:]
        motifs = load_motifs(sc)
        for row in rows:
            if len(selected) >= 20:
                break
            selected.append((sc, row, motifs))

    lines: List[str] = [
        "# 20 条 top-3 证据卡机械核验",
        "",
        "- 日期：2026-11-05",
        "- 来源：`output/rule-kg/v1/graph_retrieval_*.json`",
        "- 选取：每个场景优先 2 条符号不可达且有 Motif 子图的边",
        "- 说明：机械核验只检查结构对齐与技术编号，不代替人工判断；请在「人工判定」列填写。",
        "",
    ]
    stats = {"cards": 0, "top1_exact_hop": 0, "top1_syscall": 0, "top1_one_role": 0,
             "any_exact_hop": 0, "any_syscall": 0, "any_one_role": 0,
             "top1_correct": 0, "top3_correct": 0,
             "exact_and_top3": 0, "partial_and_top3": 0}

    for idx, (sc, row, motifs) in enumerate(selected, 1):
        correct = {str(t) for t in row.get("correct_techniques") or []}
        details = (row.get("motif_details") or [])[:3]
        syscall = parse_syscall(str(row.get("edge") or ""))
        src_role = str(row.get("src_role") or "")
        dst_role = str(row.get("dst_role") or "")
        top1_tech: Set[str] = set()
        top3_tech: Set[str] = set()
        card_lines: List[str] = []
        any_exact = any_sys = any_one = False
        for rank, d in enumerate(details, 1):
            mid = str(d.get("motif_id"))
            m = motifs.get(mid) or {}
            techs = set(str(x) for x in (d.get("techniques") or []))
            if rank == 1:
                top1_tech = techs
            top3_tech |= techs
            role_chain = m.get("role_chain") or []
            sys_chain = m.get("syscall_chain") or []
            exact, sys_ok, one_role = hop_flags(m, syscall, src_role, dst_role)
            any_exact |= exact
            any_sys |= sys_ok
            any_one |= one_role
            card_lines.append(
                f"  - top{rank} `{mid}` precision={m.get('stats', {}).get('precision')} "
                f"syscalls={sys_chain} roles={role_chain} techniques={sorted(techs)} "
                f"[逐跳精确对齐={exact}, syscall对={sys_ok}, 单角色对={one_role}]"
            )
            if rank == 1:
                stats["top1_exact_hop"] += int(exact)
                stats["top1_syscall"] += int(sys_ok)
                stats["top1_one_role"] += int(one_role)
        top1_ok = bool(correct) and tech_match(top1_tech, correct)
        top3_ok = bool(correct) and tech_match(top3_tech, correct)
        stats["cards"] += 1
        stats["any_exact_hop"] += int(any_exact)
        stats["any_syscall"] += int(any_sys)
        stats["any_one_role"] += int(any_one)
        stats["top1_correct"] += int(top1_ok)
        stats["top3_correct"] += int(top3_ok)
        stats["exact_and_top3"] += int(any_exact and top3_ok)
        stats["partial_and_top3"] += int((not any_exact) and any_one and top3_ok)
        verdict = ("规则精确对齐且技术对" if any_exact and top3_ok
                   else "规则精确对齐但技术不对" if any_exact
                   else "仅部分对齐且技术对" if any_one and top3_ok
                   else "仅部分对齐且技术不对" if any_one
                   else "规则不对齐")
        lines.extend([
            f"## Card {idx} | {sc} | {row.get('phase')}",
            f"- 边：`{row.get('edge')}`",
            f"- 正确技术：{sorted(correct)}",
            f"- 机械判定：**{verdict}**（top1技术对={top1_ok}，top3技术对={top3_ok}，"
            f"任一top3逐跳精确对齐={any_exact}，任一top3单角色对齐={any_one}）",
            *card_lines,
            "- 人工判定：________（可用 / 规则对技术错 / 规则不对 / 不确定）",
            "",
        ])

    lines.insert(6, f"- 机械汇总：{stats}\n")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
