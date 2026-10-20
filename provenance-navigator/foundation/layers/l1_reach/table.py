"""统一判据表的加载与校验（第 1 层）。

一张表装下第 1 层全部会改变结果的判据；每条记录的字段固定：

    id / label / input / match / effects / basis / why / evidence / exempt

加载时做结构校验（字段齐、后果词在白名单里、id 不重复、各输入类别的命中条件形状正确），
拼错当场报错，不静默忽略。表内容在 `foundation/rules/l1_judgments.json`；求值在 `judgments.py`。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ...core import rules

INPUTS = ("object", "event")
BASES = ("structure", "distribution", "mixed")
_REQUIRED = ("id", "label", "input", "match", "effects", "basis", "why")


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    input: str
    match: dict[str, Any]
    effects: tuple[str, ...]
    basis: str
    why: str
    evidence: str
    exempt: tuple[str, ...]

    def has(self, effect: str) -> bool:
        return effect in self.effects


class Table:
    """判据表：按输入类别取条目，顺序即优先级。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.effects: dict[str, dict[str, str]] = dict(data.get("effects") or {})
        self.exemptions: dict[str, str] = dict(data.get("exemptions") or {})
        self.stage_notes: dict[str, str] = dict(data.get("stage_notes") or {})
        self.defaults: dict[str, dict[str, Any]] = dict(data.get("defaults") or {})
        self.rules: list[Rule] = []
        self.by_id: dict[str, Rule] = {}
        problems: list[str] = []
        for raw in data.get("rules") or []:
            if not isinstance(raw, dict):
                problems.append(f"条目不是对象：{raw!r}")
                continue
            missing = [f for f in _REQUIRED if f not in raw or raw[f] in (None, "")]
            if not isinstance(raw.get("effects"), list):
                missing.append("effects(必须是数组)")
            if missing:
                problems.append(f"{raw.get('id') or raw!r} 缺字段或字段为空：{missing}")
                continue
            rule = Rule(
                id=str(raw["id"]),
                label=str(raw["label"]),
                input=str(raw["input"]),
                match=dict(raw.get("match") or {}),
                effects=tuple(str(e) for e in raw.get("effects") or ()),
                basis=str(raw["basis"]),
                why=str(raw["why"]),
                evidence=str(raw.get("evidence") or ""),
                exempt=tuple(str(e) for e in raw.get("exempt") or ()),
            )
            if rule.input not in INPUTS:
                problems.append(f"{rule.id} 的输入类别不认识：{rule.input}")
            if rule.basis not in BASES:
                problems.append(f"{rule.id} 的依据等级不认识：{rule.basis}")
            for effect in rule.effects:
                if effect not in self.effects:
                    problems.append(f"{rule.id} 用了未声明的后果：{effect}")
            for effect in rule.exempt:
                if effect not in self.exemptions:
                    problems.append(f"{rule.id} 用了未声明的豁免：{effect}")
            if rule.id in self.by_id:
                problems.append(f"id 重复：{rule.id}")
            problems.extend(_shape_problems(rule))
            self.by_id[rule.id] = rule
            self.rules.append(rule)
        if problems:
            raise ValueError("判据表校验失败：" + "；".join(problems))

    def of(self, input_kind: str) -> list[Rule]:
        """某一类输入的条目（保持表里的顺序）。"""
        return [rule for rule in self.rules if rule.input == input_kind]


def _shape_problems(rule: Rule) -> list[str]:
    """命中条件的形状必须与输入类别匹配（数据驱动，不许写代码）。"""
    m = rule.match
    if rule.input == "object":
        if not (m.get("prefixes") or m.get("regexes")):
            return [f"{rule.id} 是对象判据，但既没有 prefixes 也没有 regexes"]
    elif rule.input == "event":
        if not (m.get("rels") and m.get("syscalls")):
            return [f"{rule.id} 是事件判据，但缺 rels 或 syscalls"]
    return []


_CACHE: Optional[Table] = None


def load() -> Table:
    """加载判据表（进程内缓存一次）。"""
    global _CACHE
    if _CACHE is None:
        _CACHE = Table(rules.load("l1_judgments.json"))
    return _CACHE
