"""复核目标选择（第 4 层内部）：只复核两类边——第一轮没给出结论的、置信度贴着阈值的。"""

from __future__ import annotations

from typing import Any

from ...contracts import conf

# 与判定阈值的距离在 ±0.1 内的边算"边界边"，进入第二轮对抗复核
PASS2_MARGIN = 0.1


def select_targets(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                   min_confidence: float) -> list[dict[str, Any]]:
    """按编号选复核目标：第一轮漏掉的 + 置信度贴阈值的；保持确定性、不重复。"""
    missing = [item for item in items if item["id"] not in verdicts]
    borderline = [item for item in items
                  if item["id"] in verdicts
                  and abs(conf(verdicts[item["id"]]) - min_confidence) <= PASS2_MARGIN]
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in missing + borderline:
        if item["id"] not in seen:
            seen.add(item["id"])
            targets.append(item)
    return targets
