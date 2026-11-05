"""检索查询与规则卡文本构造。

只使用图里真实存在的字段；不引入场景名、GT 字段或答案分布。
"""
from __future__ import annotations

from typing import Any, Dict, List


def edge_text(edge: Dict[str, Any]) -> str:
    parts = [
        f"源 {edge.get('src_label') or '未知'}: {edge.get('src')}",
        f"系统调用/动作: {edge.get('syscall') or edge.get('action')}",
        f"目标 {edge.get('dst_label') or '未知'}: {edge.get('dst')}",
    ]
    if edge.get("rels"):
        parts.append("关系: " + "+".join(str(x) for x in edge["rels"]))
    if edge.get("network_protocol"):
        parts.append("网络协议: " + str(edge["network_protocol"]))
    if edge.get("bytes"):
        parts.append("字节: " + str(edge["bytes"]))
    return "；".join(parts)


def motif_text(motif: Dict[str, Any]) -> str:
    parts = [f"规则 {motif.get('motif_id')}：{motif.get('name')}"]
    chain = motif.get("role_chain") or []
    syscalls = motif.get("syscall_chain") or []
    if len(chain) >= 2:
        hops = []
        for i, sc in enumerate(syscalls):
            src = chain[i] if i < len(chain) else ""
            dst = chain[i + 1] if i + 1 < len(chain) else ""
            hops.append(f"第{i + 1}跳 {src} --{sc}--> {dst}")
        parts.append("；".join(hops))
    stats = motif.get("stats") or {}
    if stats:
        parts.append(
            f"历史命中攻击边 {stats.get('attack_hits')}、背景边 {stats.get('background_hits')}、"
            f"忽略边 {stats.get('ignore_hits')}；查准 {stats.get('precision')}"
        )
    techs = motif.get("techniques") or []
    if techs:
        rendered = []
        for t in techs[:3]:
            label = "已人工核验" if t.get("verified") else "未人工核验"
            rendered.append(f"{t.get('technique_id')}({t.get('confidence')}，{label})")
        parts.append("可能对应 ATT&CK：" + "、".join(rendered))
    return "；".join(parts)


def technique_text(tech: Dict[str, Any]) -> str:
    desc = str(tech.get("description") or "")
    if len(desc) > 1200:
        desc = desc[:1200]
    return (f"ATT&CK {tech.get('attack_id')} {tech.get('name')}；"
            f"战术 {', '.join(tech.get('tactics') or [])}；{desc}")


def observable_text(obs: Dict[str, Any]) -> str:
    return (f"行为观测 {obs.get('observable_id')} 对应 {obs.get('technique_id')}："
            f"{obs.get('description')}；syscall {', '.join(obs.get('syscall_pattern') or [])}；"
            f"角色 {', '.join(obs.get('role_pattern') or [])}")


def bundle_text(item: Dict[str, Any]) -> str:
    parts = [
        "程序 " + " / ".join(item.get("programs") or []),
        "动作 " + "+".join(item.get("rels") or []) + " " + str(item.get("syscall") or ""),
        "对象目录 " + " / ".join(item.get("dirs") or []),
        f"成员 {item.get('size')} 条",
    ]
    return "；".join(parts)
