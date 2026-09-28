"""攻击相位推导（表达层内部）：规则表在 `pagent/rules/phases.json`。

规则只用图上的事实（操作名 / 标签 / 路径 / 命令行原文），可复现、可审计；
`Initial Access` 在单主机图里通常判不出来（攻击机进程不在图里），因此基本恒缺。
"""

from __future__ import annotations

from typing import Any

from ...core import rules

_RULES = rules.load("phases.json")
_PHASES = tuple(_RULES["order"])
_PERSISTENCE_PATHS = tuple(_RULES["persistence_paths"])
_DISCOVERY_PATHS = tuple(_RULES["discovery_paths"])
_DISCOVERY_ARGS = tuple(_RULES["discovery_args"])
_ARCHIVE_ARGS = tuple(_RULES["archive_args"])
_ARCHIVE_EXT = tuple(_RULES["archive_ext"])


def derive_phases(confirmed: list[dict[str, Any]], metas: dict[str, dict[str, Any]]) -> list[str]:
    """从已确认边规则推导覆盖了哪些攻击相位。"""
    covered: set[str] = set()
    for edge in confirmed:
        syscall = str(edge.get("syscall") or "")
        if syscall in ("execve", "clone"):
            covered.add("Execution")
        if edge.get("dst_label") == "Network" and int(edge.get("bytes") or 0) > 0:
            covered.add("Exfiltration")
        for path, label in ((str(edge.get("src") or ""), edge.get("src_label")),
                            (str(edge.get("dst") or ""), edge.get("dst_label"))):
            if label != "File":
                continue
            low = path.lower()
            if any(pat in low for pat in _PERSISTENCE_PATHS):
                covered.add("Persistence")
            if any(pat in low for pat in _DISCOVERY_PATHS):
                covered.add("Discovery")
            if low.endswith(_ARCHIVE_EXT):
                covered.add("Collection")
        args = str((metas.get(str(edge.get("process_id") or "")) or {}).get("owner_args") or "")
        blob = args.lower()
        if blob:
            if any(tok in blob for tok in _ARCHIVE_ARGS):
                covered.add("Collection")
            if any(tok in blob for tok in _DISCOVERY_ARGS):
                covered.add("Discovery")
    return [phase for phase in _PHASES if phase in covered]
