"""闭包取数期的判据表：加载、校验、求值。

判据表是 `config/closure_rules.json`，一条记录回答一个问题：
- 对象类（`input = object`）：从文件/网络顶点往回找写入者时，要不要继续展开；
- 事件类（`input = event`）：这次操作是否表示把内容写进了对象。

本文件只把表变成 `Ruling`，不写路径与阈值字面量；路径集合在 `domain.taxonomy`，
表里的条目只写判据数据。表的顺序就是优先级（先命中先赢）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, NamedTuple, Optional

import settings as cfg
from domain.taxonomy import is_dynamic_library

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


class Table:
    """判据表：按输入类别取条目，顺序即优先级。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.effects: dict[str, dict[str, str]] = dict(data.get("effects") or {})
        self.defaults: dict[str, dict[str, Any]] = dict(data.get("defaults") or {})
        self.rules: list[Rule] = []
        self.by_id: dict[str, Rule] = {}
        self._by_input: dict[str, list[Rule]] = {kind: [] for kind in INPUTS}
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
            )
            if rule.input not in INPUTS:
                problems.append(f"{rule.id} 的输入类别不认识：{rule.input}")
            if rule.basis not in BASES:
                problems.append(f"{rule.id} 的依据等级不认识：{rule.basis}")
            for effect in rule.effects:
                if effect not in self.effects:
                    problems.append(f"{rule.id} 用了未声明的后果：{effect}")
            if rule.id in self.by_id:
                problems.append(f"id 重复：{rule.id}")
            problems.extend(_shape_problems(rule))
            self.by_id[rule.id] = rule
            self.rules.append(rule)
            self._by_input.setdefault(rule.input, []).append(rule)
        if problems:
            raise ValueError("判据表校验失败：" + "；".join(problems))

    def of(self, input_kind: str) -> list[Rule]:
        """某一类输入的条目（保持表里的顺序）。"""
        return list(self._by_input.get(input_kind, ()))


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


class Ruling(NamedTuple):
    """一次判据查询的结果：命中的判据 + 它声明的后果。"""

    rule_id: str
    label: str
    effects: frozenset[str]
    basis: str
    why: str


NO_RULING = Ruling("", "", frozenset(), "structure", "")

# 进程内缓存：表只加载一次，matcher 与字节阈值随表一起建好。
_TABLE: Optional[Table] = None
_OBJECT_MATCHERS: list[tuple[Rule, tuple[str, ...], tuple[re.Pattern[str], ...]]] = []
_EVENT_RULES: list[Rule] = []
_BYTE_STEPS: tuple[int, ...] = ()
_DEFAULT_OBJECT: Ruling = NO_RULING

# 生命周期判据只看“读取类边 + 读操作”这一种事件形状；路径条件由 taxonomy 提供。
_STARTUP_LIB_EDGE = ("f2p", "read")

_OBJ_CACHE: dict[str, Ruling] = {}
_EVT_CACHE: dict[tuple[str, str, tuple[bool, ...]], Ruling] = {}


def _table() -> Table:
    """首次使用时加载判据表（不在模块导入时读配置）。"""
    global _TABLE, _OBJECT_MATCHERS, _EVENT_RULES, _BYTE_STEPS, _DEFAULT_OBJECT
    if _TABLE is not None:
        return _TABLE
    table = Table(cfg.load_rule_table("closure_rules.json"))
    _OBJECT_MATCHERS = [
        (rule,
         tuple(str(p) for p in rule.match.get("prefixes") or ()),
         tuple(re.compile(str(p)) for p in rule.match.get("regexes") or ()))
        for rule in table.of("object")
    ]
    _EVENT_RULES = table.of("event")
    # 表里出现过的字节阈值（升序）；缓存键把字节数折成「相对每个阈值是小于等于还是大于」。
    _BYTE_STEPS = tuple(sorted({int(rule.match["bytes_at_most"]) for rule in _EVENT_RULES
                                if rule.match.get("bytes_at_most") is not None}))
    default = dict(table.defaults.get("object") or {})
    _DEFAULT_OBJECT = Ruling("", str(default.get("label") or ""),
                             frozenset(str(e) for e in default.get("effects") or ()),
                             "structure", "")
    _TABLE = table
    return _TABLE


def load() -> Table:
    """加载判据表（进程内缓存一次）。"""
    return _table()


def object_ruling(key: str) -> Ruling:
    """文件顶点键的角色判定（按表顺序取第一个命中；命不中返回表里声明的默认值）。"""
    _table()
    key = str(key)
    cached = _OBJ_CACHE.get(key)
    if cached is not None:
        return cached
    result = _DEFAULT_OBJECT
    for rule, prefixes, regexes in _OBJECT_MATCHERS:
        if prefixes and key.startswith(prefixes):
            result = Ruling(rule.id, rule.label, frozenset(rule.effects), rule.basis, rule.why)
            break
        if any(pattern.match(key) for pattern in regexes):
            result = Ruling(rule.id, rule.label, frozenset(rule.effects), rule.basis, rule.why)
            break
    _OBJ_CACHE[key] = result
    return result


def event_ruling(rel: str, syscall: str, nbytes: object) -> Ruling:
    """事件判定：按表顺序取第一个命中。"""
    _table()
    try:
        issued = int(nbytes or 0)
    except (TypeError, ValueError):
        issued = 0
    key = (str(rel), str(syscall), tuple(issued <= step for step in _BYTE_STEPS))
    cached = _EVT_CACHE.get(key)
    if cached is not None:
        return cached
    result = NO_RULING
    for rule in _EVENT_RULES:
        if rule.match.get("rels") and str(rel) not in rule.match["rels"]:
            continue
        if rule.match.get("syscalls") and str(syscall) not in rule.match["syscalls"]:
            continue
        if rule.match.get("bytes_at_most") is not None and issued > int(rule.match["bytes_at_most"]):
            continue
        result = Ruling(rule.id, rule.label, frozenset(rule.effects), rule.basis, rule.why)
        break
    _EVT_CACHE[key] = result
    return result


def is_startup_dependency(rel: str, syscall: str, other_path: str, starttime: int,
                          first_action: float, written_targets: set[str]) -> bool:
    """判定是否为进程在启动期（首次对外写/派生动作之前）读入且未被篡改的标准动态共享库。"""
    if (rel, syscall) != _STARTUP_LIB_EDGE:
        return False
    return (is_dynamic_library(other_path) and other_path not in written_targets
            and starttime < first_action)
