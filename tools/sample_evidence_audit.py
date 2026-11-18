"""抽取规则候选卡，机械检查逐跳系统调用与角色对齐，不推断攻击正确率。"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parent.parent
KG_DIR = ROOT / "output/rule-kg/v1"

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

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", type=Path, default=ROOT / "tmp/rule-retrieval")
    ap.add_argument("--out", type=Path, default=ROOT / "tmp/rule-evidence-audit.md")
    ap.add_argument("--samples", type=int, default=20)
    args = ap.parse_args()
    if args.samples < 1:
        ap.error("--samples 必须为正整数")
    selected = []
    for path in sorted(args.results_dir.glob("graph_retrieval_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        motifs = load_motifs(data["scenario"])
        for row in data.get("rows", []):
            if row.get("motif_details"):
                selected.append((data["scenario"], row, motifs))
    selected = selected[:args.samples]
    lines = ["# 规则证据卡结构对齐核验", "", "只检查已列出的候选规则与边的结构匹配，不计算规则正确率。", ""]
    for i, (scenario, row, motifs) in enumerate(selected, 1):
        lines += [f"## {i}. {scenario}", "", f"边：`{row['edge']}`", ""]
        for rank, candidate in enumerate(row["motif_details"][:3], 1):
            mid = candidate["motif_id"]
            exact, syscall, partial = hop_flags(motifs[mid], parse_syscall(row["edge"]), row["src_role"], row["dst_role"])
            lines.append(f"- 第 {rank} 项 `{mid}`：系统调用匹配={syscall}，两端角色匹配={exact}，至少一端角色匹配={partial}。")
        lines += ["", "人工判定：________", ""]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"sampled_edges": len(selected), "out": str(args.out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
