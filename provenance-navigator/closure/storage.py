"""闭包取数层的存储格式与查询文本。

本文件只回答两件事：
1. 顶点-时间索引的二进制布局与容量参数（改 FORMAT_VERSION、BUCKET_COUNT 或记录结构会让旧索引失效）；
2. 访问图库的 Cypher 文本（顶点表、边表、POI、进程静态属性）。

它不判断一条边该不该收、不展开顶点、不写索引。所有查询文本由 `domain.edge` 的关系表生成，
关系类型与两端标签只在那里定义；本文件不再各写一份。
"""

from __future__ import annotations

import struct
from typing import Any

from domain.edge import (
    ALL_RELS,
    CONSUMER_RELS,
    PRODUCER_RELS,
    SCENARIO_KIND_LABELS,
    VERTEX_KINDS,
    cypher_rel_match,
    labels_of,
)

# ==== 1. 顶点-时间索引的二进制格式 ====

FORMAT_VERSION = 9   # 9：进程显示名增加命令行首词兜底、删除 cwd；8：索引记录增加成败（effect）
BUCKET_COUNT = 64

# 定长记录：'<' 无对齐填充
RECORD = struct.Struct("<IIBHqqqqB")          # 44 字节（一条入射记录，末位 = 成败码）
BUCKET_RECORD = struct.Struct("<IIIBHqqqqB")  # 48 字节（多一个 block_id）

PAGE = 20000          # 边表分页大小（构建索引时每次查询返回的行数）
CHUNK_RECORDS = 4096  # 读取索引时每块解包的记录数

# 关系名 -> 整数码（索引格式的一部分）。顺序由 `domain.edge.ALL_RELS` 唯一决定。
REL_CODES = {rel: code for code, rel in enumerate(ALL_RELS)}
REL_BY_CODE = {code: rel for rel, code in REL_CODES.items()}
PRODUCER_CODES = frozenset(REL_CODES[rel] for rel in PRODUCER_RELS)
CONSUMER_CODES = frozenset(REL_CODES[rel] for rel in CONSUMER_RELS)

# 图上 result 换算出的成败：0 = 未观测，1 = 成功，2 = 失败（与 `docs` 的评分口径一致）
EFFECT_NAMES = ("", "success", "failure")


def effect_code(result: Any) -> int:
    """数据库里的 result 字段 -> 索引里的成败码。"""
    if result is None:
        return 0
    return 1 if int(result) >= 0 else 2


def effect_name(code: int) -> str:
    """索引里的成败码 -> 报告与折叠使用的成败名。"""
    return EFFECT_NAMES[code] if 0 <= int(code) < len(EFFECT_NAMES) else ""


# ==== 2. Cypher 片段 ====
#
# 关系类型与顶点标签不能作为 Cypher 参数，只能写进查询文本；这里的取值来自
# `domain.edge` 的封闭常量表，不是外部数据。所有外部数据仍然走 $key / $sc / $last /
# $limit / $items / $pids 参数。

def _process_key(var: str) -> str:
    return (f"coalesce({var}.process_id, coalesce({var}.host_id, '') + '|' + "
            f"coalesce({var}.container_id, '') + '|' + toString({var}.pid) + '|' + "
            f"toString({var}.start_ns))")


def key_expr(var: str, kind: str) -> str:
    """顶点键表达式（索引的块主键；进程 / 文件 / 网络各一条口径）。"""
    if kind == "Process":
        return _process_key(var)
    if kind == "File":
        return (f"coalesce({var}.file_id, CASE WHEN {var}.container_id IS NOT NULL AND "
                f"{var}.container_id <> 'host' THEN {var}.container_id + '|' + {var}.path "
                f"ELSE {var}.path END)")
    if kind == "Network":
        return f"coalesce({var}.network_id, {var}.endpoints)"
    raise ValueError(f"未知顶点类别：{kind!r}")


def name_expr(var: str) -> str:
    """进程显示名取序：完整可执行路径 → 短路径 → name → 命令行首词（必须是绝对路径）。

    与调查引擎 `Neo4jNodeRegistry.buildNode` 的取序一致，避免两端对同一个进程显示不同名字。
    """
    return (f"coalesce({var}.exe_path, {var}.exepath, {var}.name, "
            f"CASE WHEN trim(coalesce({var}.cmdline, {var}.args, '')) STARTS WITH '/' "
            f"THEN split(trim(coalesce({var}.cmdline, {var}.args, '')), ' ')[0] END)")


def vertex_query(kind: str) -> str:
    """顶点表查询：返回 key / content 以及索引读取时要用的静态属性。"""
    if kind == "Process":
        return ("MATCH (p:Process) RETURN "
                f"{key_expr('p', kind)} AS key, "
                f"{name_expr('p')} AS content, "
                "p.pid AS pid, coalesce(p.name, '') AS name, "
                f"{name_expr('p')} AS exepath, "
                "coalesce(p.cmdline, p.args, '') AS args, "
                "coalesce(p.ppid, 0) AS ppid")
    if kind == "File":
        return ("MATCH (f:File) RETURN "
                f"{key_expr('f', kind)} AS key, f.path AS content")
    if kind == "Network":
        return ("MATCH (n:Network) RETURN "
                f"{key_expr('n', kind)} AS key, "
                "coalesce(n.endpoints, n.network_id) AS content, "
                "coalesce(n.proto, n.protocol, '') AS protocol")
    raise ValueError(f"未知顶点类别：{kind!r}")


VERTEX_QUERIES = {kind: vertex_query(kind) for kind in VERTEX_KINDS}


def _edge_return() -> str:
    return ("RETURN e.event_id AS event_id, "
            "coalesce(e.start_ns, e.starttime) AS starttime, "
            "coalesce(e.end_ns, e.endtime) AS endtime, "
            "coalesce(e.syscall, e.action) AS syscall, "
            "e.result AS res, "
            "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, ")


def edge_query(rel: str) -> str:
    """一条关系类型的边表分页查询（两端键都按顶点类别生成）。"""
    kind_a, kind_b = labels_of(rel)
    return (f"MATCH (a:{kind_a})-[e:{cypher_rel_match(rel)}]->(b:{kind_b}) "
            "WHERE e.event_id > $last "
            f"{_edge_return()}"
            f"{key_expr('a', kind_a)} AS a_key, "
            f"{key_expr('b', kind_b)} AS b_key "
            "ORDER BY e.event_id LIMIT $limit")


EDGE_QUERIES = {rel: edge_query(rel) for rel in ALL_RELS}


def poi_query(rel: str, kind: str) -> str:
    """终点事件（POI）查询：按配置里的键与操作名定位事件的原始实例。"""
    if kind not in SCENARIO_KIND_LABELS:
        raise ValueError(f"未知 POI 种类：{kind!r}")
    label = SCENARIO_KIND_LABELS[kind]
    return (f"MATCH (p:Process)-[e:{cypher_rel_match(rel)}]->(o:{label})\n"
            "WHERE (e.syscall = $sc OR e.action = $sc) AND (\n"
            "    (o.file_id IS NOT NULL AND o.file_id = $key) OR\n"
            "    (o.path IS NOT NULL AND o.path = $key) OR\n"
            "    (o.network_id IS NOT NULL AND o.network_id = $key) OR\n"
            "    (o.endpoints IS NOT NULL AND o.endpoints = $key)\n"
            ")\n"
            f"{_edge_return()}"
            f"{key_expr('p', 'Process')} AS process_id, "
            f"{name_expr('p')} AS process_content, "
            "coalesce(o.path, o.endpoints, o.file_id, o.network_id) AS other, "
            "labels(o)[0] AS other_label, "
            "coalesce(o.proto, o.protocol, '') AS other_protocol\n"
            "ORDER BY starttime")


def _process_info_return() -> str:
    return (f"{key_expr('p', 'Process')} AS process_id, "
            "p.pid AS pid, coalesce(p.name, '') AS name, "
            f"{name_expr('p')} AS exepath, "
            "coalesce(p.cmdline, p.args, '') AS args")


def process_info_query(many: bool) -> str:
    """进程静态属性查询（单条 / 批量）。只用于测试直查来源，索引来源直接读顶点表。"""
    if many:
        return (f"UNWIND $pids AS pid MATCH (p:Process) "
                f"WHERE (p.process_id = pid OR ({_process_key('p')} = pid)) "
                f"RETURN {_process_info_return()}")
    return (f"MATCH (p:Process) WHERE (p.process_id = $pid OR ({_process_key('p')} = $pid)) "
            f"RETURN {_process_info_return()}")
