"""Motif → ATT&CK Technique 的规则化链接。

这是启发式链接，不是人工核验结论；`verified=False` 必须随链接一起保存。
打分只用现存字段：逐跳 syscall 命中率 + 角色前缀命中率。
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from rag.schema import BehaviorObservable, Motif


def _role_prefix(role: str) -> str:
    return str(role or "").split(".", 1)[0]


def link_motif(motif: Motif, observables: Sequence[BehaviorObservable]) -> List[Dict[str, Any]]:
    syscalls = [str(s).lower() for s in motif.syscall_chain]
    roles = [_role_prefix(r) for r in motif.role_chain]
    links: List[Dict[str, Any]] = []
    for obs in observables:
        if not obs.observable:
            continue
        patterns = {str(s).lower() for s in obs.syscall_pattern}
        if not patterns:
            continue
        sys_hits = sum(1 for s in syscalls if s in patterns)
        if sys_hits == 0:
            continue
        sys_score = sys_hits / len(syscalls) if syscalls else 0.0
        obs_roles = {_role_prefix(p) for p in obs.role_pattern}
        if obs_roles:
            role_hits = sum(1 for r in roles if r in obs_roles)
            role_score = role_hits / len(roles) if roles else 0.0
        else:
            role_hits = len(roles)
            role_score = 1.0
        score = 0.7 * sys_score + 0.3 * role_score
        if score < 0.5:
            continue
        links.append({
            "technique_id": obs.technique_id,
            "confidence": round(score * float(obs.confidence or 0.0), 4),
            "evidence": f"syscall {sys_hits}/{len(syscalls)}；role {role_hits}/{len(roles)}",
            "observable_id": obs.observable_id,
            "source": "observable-rule-link",
            "verified": False,
        })
    links.sort(key=lambda x: (-x["confidence"], x["technique_id"]))
    return links[:5]


def link_motifs(motifs: Sequence[Motif], observables: Sequence[BehaviorObservable]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for motif in motifs:
        motif.techniques = link_motif(motif, observables)
        for link in motif.techniques:
            out.append({"motif_id": motif.motif_id, **link})
    return out
