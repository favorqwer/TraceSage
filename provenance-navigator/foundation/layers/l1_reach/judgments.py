"""第 1 层唯一求值入口：把判据表（`foundation/rules/l1_judgments.json`）变成两个后果。

对外只有两类问题：

- `object_ruling(键)`：这个文件顶点的角色，返回命中的判据（含后果集合）。
- `event_ruling(关系, 操作名, 字节数)`：这条事件是不是「不算交付」或「零字节读」。

后果词汇是闭集（表里声明、这里执行）：no_expand / not_delivery。
判据命中与否只看表里的数据；这里只做求值，不再自己写名单。
"""

from __future__ import annotations

import re
from typing import NamedTuple

from . import table

_T = table.load()


class Ruling(NamedTuple):
    """一次判据查询的结果：命中的判据 + 它声明的后果。"""

    rule_id: str
    label: str
    effects: frozenset[str]
    basis: str
    why: str


NO_RULING = Ruling("", "", frozenset(), "structure", "")


# --------------------------------------------------------------------------- #
# 对象（文件路径）
# --------------------------------------------------------------------------- #

_OBJ_CACHE: dict[str, Ruling] = {}
_OBJ_MATCHERS: list[tuple[table.Rule, tuple[str, ...], tuple[re.Pattern[str], ...]]] = [
    (rule,
     tuple(str(p) for p in rule.match.get("prefixes") or ()),
     tuple(re.compile(str(p)) for p in rule.match.get("regexes") or ()))
    for rule in _T.of("object")
]


def object_ruling(key: str) -> Ruling:
    """文件顶点键的角色判定（按表顺序取第一个命中；命不中返回空后果）。"""
    key = str(key)
    cached = _OBJ_CACHE.get(key)
    if cached is not None:
        return cached
    result = NO_RULING
    for rule, prefixes, regexes in _OBJ_MATCHERS:
        if prefixes and key.startswith(prefixes):
            result = Ruling(rule.id, rule.label, frozenset(rule.effects), rule.basis, rule.why)
            break
        if any(pattern.match(key) for pattern in regexes):
            result = Ruling(rule.id, rule.label, frozenset(rule.effects), rule.basis, rule.why)
            break
    _OBJ_CACHE[key] = result
    return result


# --------------------------------------------------------------------------- #
# 事件（关系类型 + 操作名 + 字节数）
# --------------------------------------------------------------------------- #

_EVT_RULES = _T.of("event")
_EVT_CACHE: dict[tuple[str, str, tuple[bool, ...]], Ruling] = {}
# 表里出现过的字节阈值（升序）；缓存键把字节数折成「相对每个阈值是小于等于还是大于」。
_BYTE_STEPS = tuple(sorted({int(rule.match["bytes_at_most"]) for rule in _EVT_RULES
                            if rule.match.get("bytes_at_most") is not None}))


def event_ruling(rel: str, syscall: str, nbytes: object) -> Ruling:
    """事件判定：按表顺序取第一个命中。"""
    try:
        issued = int(nbytes or 0)
    except (TypeError, ValueError):
        issued = 0
    key = (str(rel), str(syscall), tuple(issued <= step for step in _BYTE_STEPS))
    cached = _EVT_CACHE.get(key)
    if cached is not None:
        return cached
    result = NO_RULING
    for rule in _EVT_RULES:
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


# --------------------------------------------------------------------------- #
# 生命周期与通道判据
# --------------------------------------------------------------------------- #

def is_startup_dependency(rel: str, syscall: str, other_path: str, starttime: int,
                          first_action: float, written_targets: set[str]) -> bool:
    """判定是否为进程在启动期（首次对外写/派生动作之前）读入且未被篡改的标准动态共享库。"""
    if rel != "f2p" or syscall != "read":
        return False
    is_lib = (".so" in other_path or other_path.startswith(("/lib/", "/usr/lib/")))
    return is_lib and other_path not in written_targets and starttime < first_action


def is_forward_carrier(path: str) -> bool:
    """判定是否为可能承载跨进程内容交付的常规磁盘文件路径（排除套接字、管道与内核伪文件）。"""
    return not path.startswith(("unix:", "pipe:", "/dev/", "/proc/", "/sys/"))

