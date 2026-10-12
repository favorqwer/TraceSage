"""第 1 层唯一求值入口：把判据表（`pagent/rules/l1_judgments.json`）变成五个后果。

对外只有四类问题 + 一个执行器：

- `object_ruling(键)`：这个文件顶点的角色，返回命中的判据（含后果集合）。
- `event_ruling(关系, 操作名, 字节数)`：这条事件是不是「不算交付」或「零字节读」。
- `resident_processes(图)`：这批进程里哪些是常驻服务（对整图算一次）。
- `apply_item_drops(条目, ...)`：折叠之后按表里顺序执行条目类的「剔除条目」。

后果词汇是闭集（表里声明、这里执行）：no_expand / no_handoff / not_delivery / drop_item /
session_boundary。判据命中与否只看表里的数据；这里只做求值，不再自己写名单。
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, NamedTuple, Optional

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


def event_ruling(rel: str, syscall: str, nbytes: Any) -> Ruling:
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
# 进程（对整图算一次的图上事实）
# --------------------------------------------------------------------------- #

_QUERY_IS_INIT = "MATCH (p:Process {pid:'1'}) RETURN p.process_id AS id"
_QUERY_PARENT_IS_INIT = (
    "MATCH (p:Process {pid:'1'})-[e:p2p]->(c:Process) RETURN DISTINCT c.process_id AS id")
_QUERY_LISTEN = ("MATCH (p:Process)-[e:p2n]->(n:Network) WHERE e.syscall = 'bind' AND n.lport <> '0' "
                 "RETURN DISTINCT p.process_id AS id")
_QUERY_ACCEPT = ("MATCH (n:Network)-[e:n2p]->(p:Process) WHERE e.syscall = 'accept' "
                 "RETURN DISTINCT p.process_id AS id")
_QUERY_PREEXISTING_DAEMON = """
MATCH (p:Process)
WHERE p.exepath STARTS WITH '/usr/sbin/' OR p.exepath STARTS WITH '/sbin/'
   OR p.exepath STARTS WITH '/usr/lib/systemd/' OR p.exepath STARTS WITH '/lib/systemd/'
OPTIONAL MATCH ()-[e:p2p]->(p)
WITH p, count(e) AS started
WHERE started = 0
RETURN DISTINCT p.process_id AS id
"""


def _run_query(cypher: str):
    def run(graph: Any) -> set[str]:
        return {str(row["id"]) for row in graph.run(cypher) if row.get("id")}
    return run


def _run_same_program(graph: Any, found: set[str]) -> set[str]:
    """第 2 阶段：一个程序一旦被判为服务，它的所有实例都算服务（按可执行文件路径相同）。"""
    if not found:
        return set()
    paths = {str(row["e"]) for row in graph.run(
        "MATCH (p:Process) WHERE p.process_id IN $ids RETURN DISTINCT p.exepath AS e",
        {"ids": sorted(found)}) if row.get("e")}
    if not paths:
        return set()
    return {str(row["id"]) for row in graph.run(
        "MATCH (p:Process) WHERE p.exepath IN $paths RETURN DISTINCT p.process_id AS id",
        {"paths": sorted(paths)}) if row.get("id")}


# 测试名 -> (阶段, 执行函数)。表里写名字，这里给实现；写了没实现的测试名在加载时就会报错。
_GRAPH_TESTS: dict[str, tuple[int, Callable[..., set[str]]]] = {
    "is_init": (1, _run_query(_QUERY_IS_INIT)),
    "parent_is_init": (1, _run_query(_QUERY_PARENT_IS_INIT)),
    "listening_port": (1, _run_query(_QUERY_LISTEN)),
    "accepted": (1, _run_query(_QUERY_ACCEPT)),
    "preexisting_daemon": (1, _run_query(_QUERY_PREEXISTING_DAEMON)),
    "same_program_as_resident": (2, _run_same_program),
}


def _validate_process_tests() -> None:
    for rule in _T.of("process"):
        if str(rule.match.get("test")) not in _GRAPH_TESTS:
            raise ValueError(f"{rule.id} 引用了没实现的图上测试：{rule.match.get('test')}")


def resident_processes(graph: Any, *, log: Any = print) -> frozenset[str]:
    """对整图算一次常驻服务进程集合：先跑第 1 阶段各条，再跑第 2 阶段（按同程序扩展）。"""
    found: set[str] = set()
    for phase in (1, 2):
        for rule in _T.of("process"):
            test = str(rule.match.get("test"))
            rule_phase, runner = _GRAPH_TESTS[test]
            if rule_phase != phase:
                continue
            new = runner(graph) if phase == 1 else runner(graph, found)
            if not new:
                continue
            found |= new
            log(f"[process] 判据「{rule.label}」命中 {len(new)} 个进程（累计 {len(found)} 个）")
    log(f"[process] 常驻服务进程合计 {len(found)} 个")
    return frozenset(found)


# --------------------------------------------------------------------------- #
# 条目（折叠之后的内容三元组）
# --------------------------------------------------------------------------- #

_ITEM_RULES = _T.of("item")
_ITEM_REGEX: dict[str, re.Pattern[str]] = {
    rule.id: re.compile(str(rule.match["src_regex"]))
    for rule in _ITEM_RULES if rule.match.get("src_regex")
}


def poi_event_ids(poi_rows: list[dict[str, Any]]) -> set[int]:
    """终点事件的实例编号集合：这些实例在声明了 poi_instance 豁免的判据里不判。"""
    ids: set[int] = set()
    for row in poi_rows:
        try:
            event_id = int(row.get("event_id"))
        except (TypeError, ValueError):
            continue
        if event_id >= 0:
            ids.add(event_id)
    return ids


def _chain_pids(edges: list[Any], process_numbers: dict[str, str]) -> tuple[set[str], bool]:
    """候选表里出现过的进程号集合，以及「进程号解析不全」标志（失败即保留的前提）。"""
    chain: set[str] = set()
    unresolved = False
    for edge in edges:
        for kind, key in list(edge.src_identities) + list(edge.dst_identities):
            if kind != "Process" or not key:
                continue
            pid = process_numbers.get(key)
            if pid:
                chain.add(str(pid))
            else:
                unresolved = True
    return chain, unresolved


def _item_hits(rule: table.Rule, edge: Any, chain_pids: set[str], unresolved: bool,
               poi_ids: set[int]) -> bool:
    m = rule.match
    if rule.match.get("all_instances_of"):
        ref = str(m["all_instances_of"])
        if edge.instances <= 0 or edge.rule_hits.get(ref, 0) != edge.instances:
            return False
        if "poi_instance" in rule.exempt and (poi_ids & set(edge.event_ids)):
            return False
        return True
    if not m.get("src_regex"):
        return False
    if unresolved:
        # 失败即保留：进程号解析不全，依赖进程号的这条判据整条不生效
        return False
    if m.get("src_label") and str(edge.src_label) != str(m["src_label"]):
        return False
    if m.get("rels") and not set(str(r) for r in m["rels"]) <= set(edge.rels):
        return False
    match = _ITEM_REGEX[rule.id].match(str(edge.src))
    if not match:
        return False
    if m.get("pid_not_in_chain"):
        return match.group(1) not in chain_pids
    return True


def apply_item_drops(edges: Iterable[Any], *, poi_event_ids: set[int],
                     process_numbers: dict[str, str], log: Any = None) -> tuple[list[Any], dict[str, int]]:
    """折叠之后执行条目类判据：按表顺序先命中先剔除。返回（保留的条目, 每条判据剔除数）。"""
    items = list(edges)
    chain, unresolved = _chain_pids(items, process_numbers)
    if unresolved and log:
        log("[item] 进程号解析不全，跳过依赖进程号的条目判据（失败即保留）")
    kept: list[Any] = []
    counts: dict[str, int] = {rule.id: 0 for rule in _ITEM_RULES}
    for edge in items:
        hit: Optional[table.Rule] = None
        for rule in _ITEM_RULES:
            if _item_hits(rule, edge, chain, unresolved, poi_event_ids):
                hit = rule
                break
        if hit is None:
            kept.append(edge)
        else:
            counts[hit.id] = counts.get(hit.id, 0) + 1
    if log:
        for rule in _ITEM_RULES:
            if counts.get(rule.id):
                log(f"[item] 判据「{rule.label}」剔除 {counts[rule.id]} 条"
                    f"（依据等级 {rule.basis}）")
    return kept, counts


_validate_process_tests()
