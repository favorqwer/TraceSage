"""MITRE ATT&CK STIX 2.1 读取与 BehaviorObservable 映射。

只读 STIX 文件，不做下载；下载与版本记录由调用方负责。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from rag.schema import BehaviorObservable, Technique


def _external_id(obj: Dict[str, Any], source_name: str = "mitre-attack") -> Tuple[str, str]:
    for ref in obj.get("external_references") or []:
        if str(ref.get("source_name") or "").lower() != source_name:
            continue
        ext_id = str(ref.get("external_id") or "")
        url = str(ref.get("url") or "")
        if ext_id:
            return ext_id, url
    return "", ""


def load_stix(path: str | Path) -> Tuple[Dict[str, Technique], Dict[str, Dict[str, Any]]]:
    """读取 ATT&CK Enterprise STIX bundle。

    返回 `(techniques, tactics)`：
    - techniques: `{Txxxx[.yyy]: Technique}`
    - tactics: `{TAxxxx: {"name":..., "shortname":..., "description":...}}`
    """
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    techniques: Dict[str, Technique] = {}
    tactics: Dict[str, Dict[str, Any]] = {}
    version = str(bundle.get("spec_version") or "2.1")

    for obj in bundle.get("objects") or []:
        otype = str(obj.get("type") or "")
        if otype == "attack-pattern":
            attack_id, url = _external_id(obj)
            if not attack_id:
                continue
            phases = [
                str(p.get("phase_name") or "")
                for p in (obj.get("kill_chain_phases") or [])
                if str(p.get("kill_chain_name") or "") == "mitre-attack"
            ]
            techniques[attack_id] = Technique(
                attack_id=attack_id,
                name=str(obj.get("name") or ""),
                tactics=[p for p in phases if p],
                description=str(obj.get("description") or ""),
                url=url,
                stix_version=version,
            )
        elif otype == "x-mitre-tactic":
            tactic_id, _url = _external_id(obj)
            if not tactic_id:
                continue
            tactics[tactic_id] = {
                "name": str(obj.get("name") or ""),
                "shortname": str(obj.get("x_mitre_shortname") or ""),
                "description": str(obj.get("description") or ""),
            }
    return techniques, tactics


def load_behavior_observables(path: str | Path) -> List[BehaviorObservable]:
    """读取人工核验的 BehaviorObservable 映射表。

    输入 JSON 是对象数组；每项字段见 `rag.schema.BehaviorObservable`。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("BehaviorObservable 映射表必须是 JSON 数组")
    out: List[BehaviorObservable] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append(BehaviorObservable(
            observable_id=str(item.get("observable_id") or ""),
            technique_id=str(item.get("technique_id") or ""),
            description=str(item.get("description") or ""),
            syscall_pattern=[str(x) for x in (item.get("syscall_pattern") or [])],
            role_pattern=[str(x) for x in (item.get("role_pattern") or [])],
            path_pattern=[str(x) for x in (item.get("path_pattern") or [])],
            process_pattern=[str(x) for x in (item.get("process_pattern") or [])],
            confidence=float(item.get("confidence") or 0.0),
            source=str(item.get("source") or ""),
            observable=bool(item.get("observable", True)),
            verified=bool(item.get("verified", False)),
        ))
    return out


def summarize(techniques: Dict[str, Technique], tactics: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "techniques": len(techniques),
        "tactics": len(tactics),
        "subtechniques": sum(1 for k in techniques if "." in k),
    }
