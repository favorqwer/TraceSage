"""闭包引擎：POI 定位、顶点-时间索引、取数期判据、反向闭包、前向补链。

本文件不导入 `rules`、`llm`、`routing`，只依赖 `common`。
"""

from __future__ import annotations

import json
import os
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional, Protocol

from common import config as cfg
from common.graph import (
    CONSUMER_RELS,
    DERIVATION_REL,
    PRODUCER_RELS,
    content_triple_of,
    cypher_rel_match,
    endpoints_of,
    is_derivation,
    labels_of,
    normalize_rel,
    owner_is_source,
    split_process_key,
    trace_event,
)

# ==== 1. 取数期判据表 ====

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
        _CACHE = Table(cfg.load_rule_table("closure_rules.json"))
    return _CACHE


# ==== 2. 判据求值 ====

_T = load()

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



# ==== 3. 顶点-时间索引 ====
FORMAT_VERSION = 9   # 9：进程显示名增加命令行首词兜底、删除 cwd；8：索引记录增加成败（effect）
BUCKET_COUNT = 64

# 定长记录：'<' 无对齐填充
RECORD = struct.Struct("<IIBHqqqqB")      # 44 字节（一条入射记录，末位 = 成败码）
_BUCKET = struct.Struct("<IIIBHqqqqB")   # 48 字节（多一个 block_id）

# 关系类型 -> 两端标签与归属端由 `core/py` 唯一决定（这里不再各写一份）

_REL_CODE = {"p2f": 0, "f2p": 1, "p2n": 2, "n2p": 3, "p2p": 4}
REL_BY_CODE = {v: k for k, v in _REL_CODE.items()}   # 公开：取数来源按编号还原关系名

# 进程显示名取序：完整可执行路径 → 短路径 → name → 命令行首词（必须是绝对路径）。
# 与调查引擎 `Neo4jNodeRegistry.buildNode` 的取序一致，避免两端对同一个进程显示不同名字。
_PROC_NAME_EXPR = (
    "coalesce(p.exe_path, p.exepath, p.name, "
    "CASE WHEN trim(coalesce(p.cmdline, p.args, '')) STARTS WITH '/' "
    "THEN split(trim(coalesce(p.cmdline, p.args, '')), ' ')[0] END)"
)

_VERTEX_QUERIES = {
    "Process": (
        "MATCH (p:Process) RETURN "
        "coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS key, "
        f"{_PROC_NAME_EXPR} AS content, "
        "p.pid AS pid, coalesce(p.name, '') AS name, "
        f"{_PROC_NAME_EXPR} AS exepath, "
        "coalesce(p.cmdline, p.args, '') AS args, "
        "coalesce(p.ppid, 0) AS ppid"
    ),
    "File": (
        "MATCH (f:File) RETURN "
        "coalesce(f.file_id, CASE WHEN f.container_id IS NOT NULL AND f.container_id <> 'host' THEN f.container_id + '|' + f.path ELSE f.path END) AS key, "
        "f.path AS content"
    ),
    "Network": (
        "MATCH (n:Network) RETURN "
        "coalesce(n.network_id, n.endpoints) AS key, "
        "coalesce(n.endpoints, n.network_id) AS content, "
        "coalesce(n.proto, n.protocol, '') AS protocol"
    ),
}

_EDGE_QUERIES = {
    "p2f": (
        "MATCH (a:Process)-[e:ProcessToFile|p2f]->(b:File) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "e.result AS res, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.file_id, CASE WHEN b.container_id IS NOT NULL AND b.container_id <> 'host' THEN b.container_id + '|' + b.path ELSE b.path END) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "f2p": (
        "MATCH (a:File)-[e:FileToProcess|f2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "e.result AS res, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.file_id, CASE WHEN a.container_id IS NOT NULL AND a.container_id <> 'host' THEN a.container_id + '|' + a.path ELSE a.path END) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "p2n": (
        "MATCH (a:Process)-[e:ProcessToNetwork|p2n]->(b:Network) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "e.result AS res, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.network_id, b.endpoints) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "n2p": (
        "MATCH (a:Network)-[e:NetworkToProcess|n2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "e.result AS res, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.network_id, a.endpoints) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "p2p": (
        "MATCH (a:Process)-[e:ProcessToProcess|p2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "e.result AS res, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
}

PAGE = 20000


def snapshot_dir(database: str) -> Path:
    safe = database.replace("/", "_").replace("\\", "_")
    return cfg.L1_INDEX_DIR / safe


def meta_path(database: str) -> Path:
    return snapshot_dir(database) / "meta.json"


def read_meta(database: str) -> Optional[dict[str, Any]]:
    path = meta_path(database)
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - 缺失/损坏一律当作没有索引
        return None
    if int(meta.get("format", 0)) != FORMAT_VERSION:
        return None
    return meta


def db_fingerprint(graph: Any) -> dict[str, Any]:
    """索引失效判据：边数与最大事件编号（任一变化就重建）。"""
    rows = graph.run("MATCH ()-[e]->() RETURN count(e) AS edges, max(e.event_id) AS max_event_id")
    row = rows[0] if rows else {}
    return {"edges": int(row.get("edges") or 0), "max_event_id": int(row.get("max_event_id") or 0)}


def build_snapshot(graph: Any, *, log: Any = print) -> dict[str, Any]:
    """把整库导成快照。内存占用与"桶大小"同阶，不随库规模增长。

    **写入是"可中断不损坏"的**：开建第一件事是把描述文件（`meta.json`）撤掉；记录文件、顶点表、
    位置表都先写成同目录下的临时文件，再逐个原子改名替换；最后才写描述文件（提交）。因此任何一步
    中断，下一次运行只会看到"没有索引"并重建，绝不会读到半成品；中途失败（含 Ctrl-C）会清掉本次的
    临时文件（分桶文件与三份 `*.tmp`）。

    **同一个库不能同时跑两个构造**：临时文件名固定，两个构造会互相干扰（未加锁）。
    """
    database = graph.database
    out_dir = snapshot_dir(database)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    buckets = [out_dir / f"bucket-{i:02d}.tmp" for i in range(BUCKET_COUNT)]
    tmp_adj = out_dir / "adj.bin.tmp"
    tmp_vertices = out_dir / "vertices.json.tmp"
    tmp_offsets = out_dir / "offsets.json.tmp"
    commit = meta_path(database)
    commit.unlink(missing_ok=True)          # 先撤掉提交标记：之后的中断只会让下一次重跑

    try:
        # --- 1) 顶点表 ---
        vertex_ids: dict[tuple[str, str], int] = {}
        vertices: list[dict[str, Any]] = []
        for kind, cypher in _VERTEX_QUERIES.items():
            for row in graph.run(cypher):
                key = str(row.get("key") or "")
                if not key:
                    continue
                vertex_ids[(kind, key)] = len(vertices)
                item = {"kind": kind, "key": key, "content": str(row.get("content") or key)}
                for extra in ("pid", "name", "exepath", "args", "protocol", "ppid"):
                    if row.get(extra) is not None:
                        item[extra] = row[extra]
                vertices.append(item)
        log(f"[snapshot] 顶点 {len(vertices)} 个（{time.time() - t0:.1f}s）")

        # --- 2) 边 -> 桶文件（外部排序的第一趟） ---
        handles: list[Any] = []
        syscall_ids: dict[str, int] = {}
        incidences = 0
        edge_count = 0
        max_event_id = 0
        try:
            for path in buckets:
                handles.append(path.open("wb"))
            for rel, cypher in _EDGE_QUERIES.items():
                kind_a, kind_b = labels_of(rel)
                owner_side = "a" if owner_is_source(rel) else "b"
                other_side = "b" if owner_side == "a" else "a"
                last = 0
                while True:
                    rows = graph.run(cypher, {"last": last, "limit": PAGE})
                    if not rows:
                        break
                    for row in rows:
                        event_id = int(row["event_id"])
                        last = max(last, event_id)
                        max_event_id = max(max_event_id, event_id)
                        edge_count += 1
                        keys = {"a": (kind_a, str(row["a_key"] or "")),
                                "b": (kind_b, str(row["b_key"] or ""))}
                        owner_id = vertex_ids.get(keys[owner_side])
                        other_id = vertex_ids.get(keys[other_side])
                        if owner_id is None or other_id is None:
                            # 端点不在顶点表里（顶点表与边是同一个库的两次查询，理论上不该发生）：
                            # 这条边进不了索引；发生时会体现在下面的"边数 / 入射数"日志里。
                            continue
                        syscall = str(row.get("syscall") or "")
                        sid = syscall_ids.get(syscall)
                        if sid is None:
                            sid = syscall_ids[syscall] = len(syscall_ids)
                        start = int(row.get("starttime") or 0)
                        end = int(row.get("endtime") or start)
                        res = row.get("res")
                        effect_code = 0 if res is None else (1 if int(res) >= 0 else 2)
                        for block_id in (owner_id, other_id):
                            handles[block_id % BUCKET_COUNT].write(_BUCKET.pack(
                                block_id, owner_id, other_id, _REL_CODE[rel], sid, start, end,
                                event_id, int(row.get("bytes") or 0), effect_code))
                            incidences += 1
                    log(f"[snapshot] {rel} 已导 {last}（边 {edge_count} 条 / 入射 {incidences} 条）")
        finally:
            for fh in handles:
                fh.close()

        # --- 3) 逐桶排序后顺序写出（先写临时文件，成功后才替换正式文件） ---
        offsets: dict[int, list[int]] = {}
        record_index = 0
        with tmp_adj.open("wb") as out:
            for path in buckets:
                raw = path.read_bytes()
                records = [_BUCKET.unpack_from(raw, i) for i in range(0, len(raw), _BUCKET.size)]
                records.sort(key=lambda r: (r[0], r[5], r[7]))      # (block, start, event_id)
                for rec in records:
                    (block_id, owner_id, other_id, rel_code, sid, start, end,
                     event_id, nbytes, effect_code) = rec
                    if offsets.get(block_id) is None:
                        offsets[block_id] = [record_index, 0]
                    offsets[block_id][1] += 1
                    out.write(RECORD.pack(owner_id, other_id, rel_code, sid, start, end, event_id,
                                          nbytes, effect_code))
                    record_index += 1
                path.unlink(missing_ok=True)

        tmp_vertices.write_text(json.dumps(vertices, ensure_ascii=False), encoding="utf-8")
        tmp_offsets.write_text(json.dumps({str(k): v for k, v in offsets.items()}), encoding="utf-8")
        syscalls = [""] * len(syscall_ids)
        for name, sid in syscall_ids.items():
            syscalls[sid] = name
        meta = {"format": FORMAT_VERSION, "database": database, "edges": edge_count,
                "max_event_id": max_event_id, "vertices": len(vertices), "incidences": incidences,
                "syscalls": syscalls, "built_at": int(time.time()),
                "build_seconds": round(time.time() - t0, 1)}

        # --- 4) 提交：三份数据文件原子替换，最后写描述文件 ---
        os.replace(tmp_adj, out_dir / "adj.bin")
        os.replace(tmp_vertices, out_dir / "vertices.json")
        os.replace(tmp_offsets, out_dir / "offsets.json")
        commit.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    except BaseException:
        for path in (*buckets, tmp_adj, tmp_vertices, tmp_offsets):
            path.unlink(missing_ok=True)
        raise

    log(f"[snapshot] 完成：边 {edge_count} 条 / 入射 {incidences} 条 / "
        f"{(out_dir / 'adj.bin').stat().st_size / 1048576:.1f} MB / {meta['build_seconds']}s -> {out_dir}")
    return meta


def ensure_snapshot(graph: Any, *, log: Any = print) -> dict[str, Any]:
    """确保索引可用：缺失、损坏、过期（库的边总数/最大事件编号变了）就重建。

    索引里不存规则判定结果，所以规则表怎么改都不用重建（失效判据只有库本身）。

    索引建不出来（磁盘、权限等）就报错停下——**不做隐式降级**：慢与快两种取数方式
    混在一起会让"这次到底读了什么"变得不可确认。
    """
    meta = read_meta(graph.database)
    if meta is not None:
        fingerprint = db_fingerprint(graph)
        if ((meta.get("edges"), meta.get("max_event_id"))
                == (fingerprint["edges"], fingerprint["max_event_id"])):
            return meta
    return build_snapshot(graph, log=log)




# ==== 4. 进程静态属性 ====
_PROCESS_INFO_RETURN = (
    "coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS process_id, "
    "p.pid AS pid, coalesce(p.name, '') AS name, "
    f"{_PROC_NAME_EXPR} AS exepath, "
    "coalesce(p.cmdline, p.args, '') AS args"
)
_PROCESS_INFO_ONE = (
    f"MATCH (p:Process) WHERE (p.process_id = $pid OR "
    f"(coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) = $pid) "
    f"RETURN {_PROCESS_INFO_RETURN}"
)
_PROCESS_INFO_MANY = (
    f"UNWIND $pids AS pid MATCH (p:Process) "
    f"WHERE (p.process_id = pid OR "
    f"(coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) = pid) "
    f"RETURN {_PROCESS_INFO_RETURN}"
)

_PROCESS_INFO_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def process_info(graph: ReadOnlyGraph, process_id: str) -> dict[str, Any]:
    """进程静态属性（run 内不变）；进程身份摘要会反复用到，故缓存。"""
    key = (graph.database, process_id)
    cached = _PROCESS_INFO_CACHE.get(key)
    if cached is None:
        rows = graph.run(_PROCESS_INFO_ONE, {"pid": process_id})
        cached = rows[0] if rows else {}
        _PROCESS_INFO_CACHE[key] = cached
    return cached


def cache_process_info(database: str, process_id: str, info: dict[str, Any]) -> None:
    """把进程静态属性灌进内存缓存（索引来源用；零查询）。"""
    _PROCESS_INFO_CACHE[(database, process_id)] = info


def prefetch_process_info(graph: ReadOnlyGraph, process_ids: Iterable[str]) -> None:
    """按批查库并灌缓存（数据库直查来源用）：已经缓存过的进程不再查。"""
    missing = [pid for pid in process_ids if (graph.database, pid) not in _PROCESS_INFO_CACHE]
    for chunk in (missing[i:i + 5000] for i in range(0, len(missing), 5000)):
        if not chunk:
            continue
        for row in graph.run(_PROCESS_INFO_MANY, {"pids": chunk}):
            cache_process_info(graph.database, str(row["process_id"]), row)


# ==== 5. 反向闭包引擎 ====

_KIND_ORDER = ("File", "Network", "Process")
_PRODUCER_CODES = frozenset(code for code, rel in REL_BY_CODE.items()
                            if rel in PRODUCER_RELS)
_CONSUMER_CODES = frozenset(code for code, rel in REL_BY_CODE.items()
                            if rel in CONSUMER_RELS)
_CHUNK_RECORDS = 4096

CHANNEL_BITS = {"Process": 1, "File": 2, "Network": 4, "seed": 8}
_SEED_BIT = CHANNEL_BITS["seed"]


class Event:
    """一条图上的边（事件）。`pid` 是按归属规则拥有它的进程。

    用固定槽位的普通类而不是数据类：闭包在大日志上要建上百万个，构造开销直接落在总耗时里。
    规则命中与否不在这里预存：影响往回走的判定在取边时按边的形状现算并缓存（见 `include`）。
    """

    __slots__ = ("event_id", "rel", "syscall", "bytes", "start", "end", "pid", "owner",
                 "other", "other_label", "other_process_id", "effect",
                 "dist", "via_kind", "via_key", "support")

    def __init__(self, event_id: int, rel: str, syscall: str, bytes: int, start: int, end: int,
                 pid: str, owner: str, other: str, other_label: str, other_process_id: str = "",
                 effect: str = "",
                 dist: int = 0, via_kind: str = "", via_key: str = "", support: int = 0) -> None:
        self.event_id = event_id
        self.rel = rel
        self.syscall = syscall
        self.bytes = bytes
        self.start = start
        self.end = end
        self.pid = pid
        self.owner = owner
        self.other = other
        self.other_label = other_label
        self.other_process_id = other_process_id
        # 成败（图上 result 换算，与评分口径一致）：success / failure / 空 = 未观测
        self.effect = effect
        # 结构上下文（只用于判定时的渲染与束的细分，不参与收边判定）：离终点事件最少几跳
        # （种子 = 0）、这条边是从哪个顶点被回推出来的（`via_kind` 为空 = 终点事件本身）、
        # 以及入闭包通道的位掩码（见 `CHANNEL_BITS`）。
        self.dist = dist
        self.via_kind = via_kind
        self.via_key = via_key
        self.support = support


class GraphSource(Protocol):
    """取边的来源：数据库直查，或顶点-时间索引快照（两者必须给出相同结果）。

    `seen` 是"已经收进闭包的边（事件编号）集合"：给了它，来源就可以把这类边直接跳掉、
    不再重造内部表示。它是**只影响快慢的提示**：给了要跳过、不给也不影响收哪些边。
    """

    database: str

    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        """进程顶点：开始时刻落在 (lo, hi] 的全部入射事件（`p2p` 两个方向都取：
        自己是子进程的那条、以及自己派生出去的那些子进程）。"""

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        """文件 / 网络顶点：只取写入侧（开始时刻落在 (lo, hi]）——读不会把内容送回顶点。"""

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """某个文件 / 网络顶点在 (lo, hi] 里被读走的事件（前向补链用）。"""

    def process_info_many(self, pids: list[str]) -> None:
        """把进程静态属性灌进内存缓存（进程身份摘要要用，不算业务查询）。"""

    def network_protocols(self) -> dict[str, str]:
        """网络端点标识 -> 传输层协议。"""

    def close(self) -> None:
        """释放句柄（索引来源为空实现）。"""

    def stats(self) -> dict[str, Any]:
        """来源侧的计数（查询次数、扫到的记录数、非交付通道跳过的顶点展开次数等）。

        `nondelivery_not_expanded` 计的是**被跳过的非交付通道顶点展开次数**，不是被跳过的边数。
        """


@dataclass
class _Pending:
    threshold: int
    key: str
    dist: int = 0                  # 这个顶点离终点事件的最少跳数（只用于上下文渲染）


@dataclass
class _Stats:
    rounds: int = 0
    process_expands: int = 0
    object_expands: int = 0
    reexpands: int = 0
    rows_fetched: int = 0          # 进判定的行数（已被收过、在来源侧跳掉的不算；那是来源的 skipped）
    events_included: int = 0
    empty_reads: int = 0
    frontier_peak: int = 0         # 单轮待考察顶点的峰值（内存诊断）

    def as_dict(self) -> dict[str, Any]:
        return {"rounds": self.rounds, "process_expands": self.process_expands,
                "object_expands": self.object_expands, "reexpands": self.reexpands,
                "rows_fetched": self.rows_fetched, "events_included": self.events_included,
                "empty_reads": self.empty_reads,
                "frontier_peak": self.frontier_peak}


def run_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                log: Optional[Callable[[str], None]] = None,
                with_events: bool = True) -> dict[str, Any]:
    """算反向闭包。返回 `{"rows": [...], "stats": {...}}`，`with_events=True`（默认）时另有 `"events"`。

    `rows` 是折叠（`candidates.py`）能直接吃的边行：`rel / owner / other / other_label /
    syscall / bytes / starttime / endtime / event_id / process_id / dist / via_kind / via_key`
    （`process_id` 是按归属规则拥有这条边的进程的标识）。
    **不设任何条数上限。**（`dist` 是这条边离终点事件最少几跳，`via_*` 是它从哪个顶点被回推出来——
    只用干判定时的上下文渲染，不参与收边判定。）

    `with_events=False` 供"只要边行"的调用方使用：事件集合照样在内部用来生成边行，但不放进返回值。
    """
    included: dict[int, Event] = {}
    # 待考察清单与"已展开到哪一刻"都按顶点类型分开存：省掉每个顶点拼一个带前缀的字符串键，
    # 也省掉每一轮把两边混在一起比对。三类的处理顺序由 `_KIND_ORDER` 固定，结果与顺序无关。
    pending: dict[str, dict[str, _Pending]] = {kind: {} for kind in _KIND_ORDER}
    processed: dict[str, dict[str, int]] = {kind: {} for kind in _KIND_ORDER}
    stats = _Stats()

    def push(kind: str, key: str, threshold: int, dist: int = 0) -> None:
        """把一个顶点按门限放进待考察清单（门限不高于已展开过的就跳过）。

        `dist` 是这个顶点离终点事件的最少跳数：同一个顶点被多次推进时取最小的那个。
        """
        if not key:
            return
        if kind == "Process":
            # 进程状态通道的上界固定取终点事件时刻：同一主体在终点事件之前的活动都算可能影响它
            threshold = int(threshold)
            if threshold < poi_t0:
                threshold = poi_t0
        done = processed[kind]
        if done.get(key, -1) >= threshold:
            return                     # 这个顶点已经按不早于本门限展开过：连清单都不必进
        bucket = pending[kind]
        cur = bucket.get(key)
        if cur is None:
            bucket[key] = _Pending(threshold=int(threshold), key=key, dist=int(dist))
            return
        if dist < cur.dist:
            cur.dist = int(dist)
        if threshold > cur.threshold:
            cur.threshold = int(threshold)

    def include(ev: Event, *, from_dist: int = -1,
                via_kind: str = "", via_key: str = "") -> bool:
        """收一条事件。

        `from_dist` 是展开它的那个顶点离终点几跳（`-1` = 种子，即终点事件本身）：这条边的跳数
        = `from_dist + 1`，种子是 0；`via_kind` / `via_key` 记下是从哪个顶点回推出来的。
        这三个字段只用于上下文渲染，**不参与收边判定**。
        """
        dist = 0 if from_dist < 0 else int(from_dist) + 1
        mask = _SEED_BIT if from_dist < 0 else CHANNEL_BITS.get(via_kind, 0)
        edge_key = (ev.event_id, ev.rel)
        prev = included.get(edge_key)
        if prev is not None:
            # 同一条边可能从多个顶点被找到：留跳数最少的那一份（跳数相同则保留先到的）
            if dist < prev.dist:
                prev.dist = dist
                prev.via_kind, prev.via_key = via_kind, via_key
            prev.support |= mask
            return False
        # 判据在这里第一次生效：命中 no_expand 的读事件（当前只有零字节读）边照收，但不展开对象
        no_expand = "no_expand" in event_ruling(ev.rel, ev.syscall, ev.bytes).effects
        ev.dist = dist
        ev.via_kind, ev.via_key = via_kind, via_key
        ev.support = mask
        included[edge_key] = ev
        stats.events_included += 1
        if no_expand:
            stats.empty_reads += 1
            push("Process", ev.pid, ev.start, dist)      # 进程状态这条通道照走
            return True

        if ev.rel in PRODUCER_RELS:
            push("Process", ev.pid, ev.start, dist)
        elif ev.rel in CONSUMER_RELS:
            push("Process", ev.pid, ev.start, dist)
            # 写入者的时间界取读取的结束时刻：流式读写允许边写边读
            push(ev.other_label, ev.other, ev.end, dist)
        elif is_derivation(ev.rel):
            # 派生事件：父进程那一侧往回走；同一主体派生出去的其它子进程也算上游（有意识的超集口径）
            push("Process", ev.other_process_id, ev.start, dist)
            push("Process", ev.pid, ev.start, dist)
        return True

    # --- 种子：终点事件本身 + 它两端顶点的门限 ---
    for seed in seeds:
        include(seed)

    while pending["Process"] or pending["File"] or pending["Network"]:
        # 按门限从高到低、同门限按类型与顶点键排序：只影响处理顺序（可复现），不影响收哪些边。
        # 跳数为什么是最小值：种子先把跳数 0 的顶点推进清单，之后一个顶点的最小跳数只可能由上
        # 一轮里已推进的顶点带来，且推入的顶点最早在下一轮被展开——所以每个顶点第一次被展开时
        # 带的就是最小跳数，与轮内处理顺序无关。
        items: list[tuple[int, int, str, str, int]] = []
        for rank, kind in enumerate(_KIND_ORDER):
            bucket = pending[kind]
            if not bucket:
                continue
            items.extend((item.threshold, rank, kind, item.key, item.dist)
                         for item in bucket.values())
            bucket.clear()
        items.sort(key=lambda it: (-it[0], it[1], it[2]))
        stats.frontier_peak = max(stats.frontier_peak, len(items))

        proc_items: list[tuple[str, int, int, int]] = []
        file_items: list[tuple[str, int, int, int]] = []
        net_items: list[tuple[str, int, int, int]] = []
        for threshold, _rank, kind, key, dist in items:
            done = processed[kind]
            prev = done.get(key)
            if prev is not None and threshold <= prev:
                continue
            lo = prev if prev is not None else -1
            if prev is not None:
                stats.reexpands += 1
            done[key] = threshold
            if kind == "Process":
                # 记录到的父子关系（ppid）：展开一个进程时，把它记录的父进程一并推进待考察清单。
                # 门限取子进程出生时刻；不新增任何边——父进程的边本来就是图里的真实边。
                # 只在本容器内解析；容器进程的 ppid 属于宿主命名空间，本版不处理。
                resolver = getattr(source, "parent_of_process", None)
                if resolver is not None:
                    parent_key = resolver(key)
                    if parent_key:
                        push("Process", parent_key, source.birth_of_process(key), dist + 1)
                proc_items.append((key, lo, threshold, dist))
            elif kind == "Network":
                net_items.append((key, lo, threshold, dist))
            else:
                file_items.append((key, lo, threshold, dist))

        if proc_items:
            stats.process_expands += len(proc_items)
        if file_items or net_items:
            stats.object_expands += len(file_items) + len(net_items)
        # 逐顶点取边（而不是一批一起取）：这样每条边都能记下"是从哪个顶点展开出来的"。
        # 取数来源本身是按顶点逐块读的，逐顶点调用与批量调用的行集合、顺序完全一致。
        # 处理顺序固定为进程 → 文件 → 网络（同一轮里同一条边可能从两个顶点被找到，
        # 保持这个顺序结果才可复现；跳数最小的那一份仍然优先）。
        for kind, items in (("Process", proc_items), ("File", file_items), ("Network", net_items)):
            for key, lo, hi, dist in items:
                if kind == "Process":
                    found_events = source.expand_process([(key, lo, hi)], seen=included)
                else:
                    found_events = source.expand_object([(key, lo, hi)], kind, seen=included)
                for ev in found_events:
                    stats.rows_fetched += 1
                    include(ev, from_dist=dist, via_kind=kind, via_key=key)
        stats.rounds += 1
        if log:
            # 逐轮报进度：闭包在大日志上要跑几十秒，不报进度等于看不见
            log(f"[closure] 第 {stats.rounds} 轮：已收 {stats.events_included} 条事件 / "
                f"展开 {stats.process_expands} 进程 + {stats.object_expands} 文件或端点 / "
                f"待考察 {sum(len(bucket) for bucket in pending.values())} / "
                f"取回 {stats.rows_fetched} 行")

    events = sorted(included.values(), key=lambda e: (e.start, e.event_id))
    rows = _to_rows(events)               # 已经排好序，不再重复排一次
    out: dict[str, Any] = {"rows": rows, "stats": stats.as_dict()}
    if with_events:
        out["events"] = events
    return out


def _to_rows(events: list[Event]) -> list[dict[str, Any]]:
    """把事件转成第 1 层尾部的折叠能直接吃的边行（每行带归属进程的标识 `process_id`）。

    `events` 必须已经按（开始时刻, 事件编号）排好序——闭包引擎排过一次，这里不再排第二遍。

    **不写"另一端的进程标识"**：那个字段只有闭包引擎自己往回走父进程时要用（`Event` 上仍然有），
    折叠、上下文、报告都不读它，所以不进边行。**例外**：判定层的命令表要靠派生边的
    "另一端进程标识"往上找父进程的命令行（非派生边为空串），因此带出来；
    它不参与收边、分组与折叠。

    边行里多带 `dist` / `via_kind` / `via_key` / `support` 四样（结构上下文）：它们是**边上图事实的
    派生值**（这条边离终点最少几跳、展开时是从哪个顶点看到它的、从哪一类顶点被收进闭包的），
    判定时用于渲染给模型看、并作为束的细分键；不参与任何收边判定，也不进报告。
    """
    rows: list[dict[str, Any]] = []
    for ev in events:
        rows.append({
            "rel": ev.rel, "owner": ev.owner, "other": ev.other, "other_label": ev.other_label,
            "event_id": ev.event_id,
            "starttime": ev.start, "endtime": ev.end, "syscall": ev.syscall, "bytes": ev.bytes,
            "effect": ev.effect,
            "dist": ev.dist, "via_kind": ev.via_kind, "via_key": ev.via_key,
            "support": ev.support,
            "other_process_id": ev.other_process_id,
            "process_id": ev.pid,
        })
    return rows


def find_forward_seeds(source: Any, rows: list[dict[str, Any]], closed_processes: set[str],
                       poi_t0: int) -> list[Event]:
    """受限前向补链：闭包内写入的常规数据载体文件在写入后被闭包外进程读取。"""
    written_files: dict[str, int] = {}
    for r in rows:
        if (str(r.get("rel") or "") == "p2f"
                and str(r.get("other_label") or "") == "File"
                and int(r.get("bytes") or 0) > 0):
            path = str(r.get("other") or "")
            if not is_forward_carrier(path):
                continue
            start = int(r.get("starttime") or 0)
            if path not in written_files or start < written_files[path]:
                written_files[path] = start

    forward_seeds: list[Event] = []
    for path, t0 in written_files.items():
        reads = source.reads_after(path, "File", t0, poi_t0)
        external = [evt for evt in reads if str(evt.pid) not in closed_processes]
        if not external:
            continue
        pids = {str(evt.pid) for evt in external}
        if len(pids) <= 10:
            forward_seeds.extend(external)
        else:
            for evt in external:
                evts_p = source.expand_process([(evt.pid, evt.start, poi_t0)])
                has_sensitive = any(
                    e.rel in PRODUCER_RELS or is_derivation(e.rel)
                    for e in evts_p
                )
                if has_sensitive:
                    forward_seeds.append(evt)
    return forward_seeds


def run_causal_closure(source: Any, seeds: list[Event], *, poi_t0: int = 0,
                       forward_chain: bool = True, log: Optional[Callable[[str], None]] = None,
                       with_events: bool = False) -> dict[str, Any]:
    """计算因果闭包：反向闭包 +（可选）受限前向补链。

    统一执行：
    1. 沿时序因果规则回溯反向因果闭包；
    2. 基于常规数据载体文件，向前探测外部读者并补充因果种子；
    3. 预热灌入闭包涉及进程的静态身份缓存。
    """
    res = run_closure(source, seeds, poi_t0=poi_t0, log=log, with_events=with_events)
    rows = res["rows"]
    stats = dict(res["stats"])
    closed_processes = {str(r.get("process_id") or "") for r in rows} - {""}
    forward_seeds: list[Event] = []
    all_seeds = list(seeds)

    if forward_chain:
        forward_seeds = find_forward_seeds(source, rows, closed_processes, poi_t0)
        if forward_seeds:
            if log:
                log(f"[causal_closure] 前向补链：常规磁盘文件发现 {len(forward_seeds)} 条外部读取种子，重跑闭包")
            all_seeds = all_seeds + forward_seeds
            res = run_closure(source, all_seeds, poi_t0=poi_t0, log=log, with_events=with_events)
            rows = res["rows"]
            stats = dict(res["stats"])
            closed_processes = {str(r.get("process_id") or "") for r in rows} - {""}

    source.process_info_many(sorted(closed_processes))
    out: dict[str, Any] = {
        "rows": rows,
        "stats": stats,
        "closed_processes": closed_processes,
        "seeds": all_seeds,
        "forward_seeds": forward_seeds,
    }
    if with_events and "events" in res:
        out["events"] = res["events"]
    return out


# --------------------------------------------------------------------------- #
# 顶点-时间索引快照来源（正式流程唯一取数方式）
# --------------------------------------------------------------------------- #

class SnapshotReader:
    """读顶点-时间索引：零数据库查询。

    取数时执行两条判据（都走 `judgments`）：对象类的 `no_expand`（非交付通道不展开）
    与事件类的 `not_delivery`（连接建立类不算交付）。
    """

    def __init__(self, database: str) -> None:
        meta = read_meta(database)
        if meta is None:
            raise RuntimeError(f"索引不存在或格式不符：{meta_path(database)}")
        self.database = database
        self.meta = meta
        self.dir = snapshot_dir(database)
        self.vertices: list[dict[str, Any]] = json.loads(
            (self.dir / "vertices.json").read_text(encoding="utf-8"))
        self._id_of: dict[tuple[str, str], int] = {}
        for vid, item in enumerate(self.vertices):
            self._id_of[(str(item["kind"]), str(item["key"]))] = vid
        # 记录到的父子关系（进程顶点上的 ppid）：闭包除了沿边回溯，也按它上溯父进程。
        # 只在本容器内解析；容器进程的 ppid 属于宿主命名空间，本版不处理。
        self._ppid_of: dict[str, int] = {}
        self._by_pid: dict[tuple[str, int], list[tuple[int, str]]] = {}
        for item in self.vertices:
            if item["kind"] != "Process":
                continue
            parsed = split_process_key(item["key"])
            if not parsed:
                continue
            _host, container, pid, start = parsed
            self._by_pid.setdefault((container, pid), []).append((start, str(item["key"])))
            ppid = item.get("ppid")
            if ppid:
                self._ppid_of[str(item["key"])] = int(ppid)
        raw = json.loads((self.dir / "offsets.json").read_text(encoding="utf-8"))
        self._offsets: dict[int, tuple[int, int]] = {
            int(k): (int(v[0]), int(v[1])) for k, v in raw.items()}
        self._syscalls: list[str] = list(meta.get("syscalls") or [])
        self.queries = 0
        self.rows = 0
        self.skipped = 0            # 因已收进闭包而跳过的记录数（含在 rows 里，只影响快慢）
        self.nondelivery_not_expanded: dict[str, int] = {}   # 被跳过的非交付通道顶点展开次数（不是边数）
        self._adj = (self.dir / "adj.bin").open("rb")

    # --- 内部 ---
    def _block(self, vid: int) -> tuple[int, int]:
        return self._offsets.get(vid, (0, 0))

    def _record(self, index: int) -> tuple:
        self._adj.seek(index * RECORD.size)
        return RECORD.unpack(self._adj.read(RECORD.size))

    def _iter_block(self, vid: int, lo: int, hi: int):
        """块内取 (lo, hi] 的记录：先二分找起点，再按块读，不整块解码。"""
        off, count = self._block(vid)
        if count <= 0:
            return
        # 二分：第一条第 start > lo 的记录
        left, right = 0, count
        while left < right:
            mid = (left + right) // 2
            if self._record(off + mid)[4] <= lo:
                left = mid + 1
            else:
                right = mid
        index = off + left
        remaining = count - left
        while remaining > 0:
            take = min(_CHUNK_RECORDS, remaining)
            self._adj.seek(index * RECORD.size)
            raw = self._adj.read(take * RECORD.size)
            for rec in struct.iter_unpack(RECORD.format, raw):
                if rec[4] > hi:
                    return
                yield rec
            index += take
            remaining -= take

    def _syscall_of(self, rec: tuple) -> str:
        sid = int(rec[3])
        return str(self._syscalls[sid]) if sid < len(self._syscalls) else ""

    _EFFECT_BY_CODE = ("", "success", "failure")

    def _event(self, rec: tuple) -> Event:
        owner_id, other_id, rel_code, sid, start, end, event_id, nbytes, effect_code = rec
        owner_vertex = self.vertices[owner_id]
        other_vertex = self.vertices[other_id]
        other_kind = other_vertex["kind"]
        other = other_vertex["key"] if other_kind in ("File", "Network") else other_vertex["content"]
        return Event(event_id=event_id, rel=REL_BY_CODE[rel_code],
                     syscall=self._syscalls[sid] if sid < len(self._syscalls) else "",
                     bytes=nbytes, start=start, end=end,
                     effect=self._EFFECT_BY_CODE[effect_code] if effect_code < 3 else "",
                     pid=owner_vertex["key"], owner=owner_vertex["content"], other=other,
                     other_label=other_kind,
                     other_process_id=other_vertex["key"] if other_kind == "Process" else "")

    # --- 记录到的父子关系（ppid）---
    def parent_of_process(self, key: str) -> Optional[str]:
        """按进程节点上记录的 ppid 找父进程：同容器、pid 相等、出生不晚于子进程，取最近的一个。"""
        ppid = self._ppid_of.get(str(key))
        if not ppid:
            return None
        parsed = split_process_key(key)
        if not parsed:
            return None
        _host, container, _pid, start = parsed
        candidates = [(st, pkey) for st, pkey in self._by_pid.get((container, ppid), ()) if st <= start]
        if not candidates:
            return None
        parent = max(candidates)[1]
        return parent if parent != key else None

    def birth_of_process(self, key: str) -> int:
        parsed = split_process_key(key)
        return parsed[3] if parsed else 0

    # --- GraphSource ---
    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get(("Process", key))
            if vid is None:
                continue
            for rec in self._iter_block(vid, lo, hi):
                # 派生边在两端顶点的块里各有一条入射记录：子进程侧是"它自己被谁启动"，
                # 父进程侧是"它启动过谁"，两条都要（同一主体子进程算上游，见 `run_closure`）
                self.rows += 1
                rel = REL_BY_CODE[rec[2]]
                if seen is not None and ((rec[6], rel) in seen or rec[6] in seen):
                    self.skipped += 1          # 已经收进闭包：不重造内部表示
                    continue
                out.append(self._event(rec))
        return out

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get((kind, key))
            if vid is None:
                continue
            if kind == "File":
                ruling = object_ruling(key)
                if "no_expand" in ruling.effects:
                    # 非交付通道：只收边、不展开（判据现算，索引里不存标记）
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = \
                        self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
            for rec in self._iter_block(vid, lo, hi):
                rel_code = rec[2]
                if rel_code not in _PRODUCER_CODES:  # p2f / p2n
                    continue                # 只回溯写入侧：读不会把内容送回顶点
                rel = REL_BY_CODE[rel_code]
                syscall = self._syscall_of(rec)
                if "not_delivery" in event_ruling(rel, syscall, rec[8]).effects:
                    continue                # 连接建立类操作不传递内容
                self.rows += 1
                if seen is not None and ((rec[6], rel) in seen or rec[6] in seen):
                    self.skipped += 1
                    continue
                out.append(self._event(rec))
        return out

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """某个文件 / 网络顶点在 (lo, hi] 里**被读走**的事件（前向补链用：写下的东西后来被谁读走）。

        `lo` 一般是该对象被写入的最早时刻、`hi` 是锚点时刻。只取读取侧（对象 -> 进程）。
        这里不套用对象侧的交付判据：那些判据（非交付通道、不算交付的操作）管的是「往回找写入者」，
        与「往前找读者」是两件事；前向补链展开见 `orchestration/expand_closure.py`。
        """
        out: list[Event] = []
        vid = self._id_of.get((kind, key))
        if vid is None:
            return out
        for rec in self._iter_block(vid, lo, hi):
            if rec[2] not in _CONSUMER_CODES:
                continue
            self.rows += 1
            out.append(self._event(rec))
        return out

    def process_info_many(self, pids: list[str]) -> None:
        for pid in pids:
            vid = self._id_of.get(("Process", pid))
            if vid is None:
                continue
            vertex = self.vertices[vid]
            cache_process_info(self.database, pid, {
                "process_id": pid, "pid": vertex.get("pid"), "name": vertex.get("name"),
                "exepath": vertex.get("exepath"), "args": vertex.get("args"),
            })

    def network_protocols(self) -> dict[str, str]:
        """网络端点标识 -> 传输层协议（索引顶点表里有的才收录；空值不写）。"""
        out: dict[str, str] = {}
        for vertex in self.vertices:
            if vertex.get("kind") != "Network":
                continue
            protocol = str(vertex.get("protocol") or "").strip()
            if protocol:
                out[str(vertex.get("key") or "")] = protocol
        return out

    def close(self) -> None:
        if self._adj is not None:
            self._adj.close()
            self._adj = None

    def stats(self) -> dict[str, Any]:
        return {"source": "snapshot", "queries": 0, "rows": self.rows,
                "skipped_already_included": self.skipped,
                "nondelivery_not_expanded": dict(sorted(self.nondelivery_not_expanded.items())),
                "index_dir": str(self.dir), "index_edges": self.meta.get("edges")}


def open_source(graph: Any, *, log: Any = print) -> SnapshotReader:
    """打开取边来源：确保索引存在且不过期（否则重建），然后读它。没有别的取数方式。"""
    ensure_snapshot(graph, log=log)
    return SnapshotReader(graph.database)


# ==== 6. POI 定位 ====
_POI_EDGES_CYPHER = """
MATCH (p:Process)-[e:{rel_match}]->(o:{label})
WHERE (e.syscall = $sc OR e.action = $sc) AND (
    (o.file_id IS NOT NULL AND o.file_id = $key) OR
    (o.path IS NOT NULL AND o.path = $key) OR
    (o.network_id IS NOT NULL AND o.network_id = $key) OR
    (o.endpoints IS NOT NULL AND o.endpoints = $key)
)
RETURN e.event_id AS event_id,
       coalesce(e.start_ns, e.starttime) AS starttime,
       coalesce(e.end_ns, e.endtime) AS endtime,
       coalesce(e.syscall, e.action) AS syscall,
       CASE WHEN e.result > 0 THEN e.result
            WHEN e.bytes IS NOT NULL THEN e.bytes
            ELSE 0 END AS bytes,
       coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS process_id,
       {proc_name} AS process_content,
       coalesce(o.path, o.endpoints, o.file_id, o.network_id) AS other,
       labels(o)[0] AS other_label,
       coalesce(o.proto, o.protocol, '') AS other_protocol
ORDER BY starttime
"""


def intake(deps: "Deps") -> dict[str, Any]:
    """POI 命中校验 + 时间范围现算（实例数/时间范围不写进配置）。"""
    poi = deps.scenario.poi.as_dict()
    rel_match = cypher_rel_match(poi["rel"])
    cypher = _POI_EDGES_CYPHER.format(
        rel_match=rel_match, label="File" if poi["kind"] == "file" else "Network",
        proc_name=_PROC_NAME_EXPR)
    rows = deps.graph.run(cypher, {"key": poi["key"], "sc": poi["syscall"]})
    if not rows:
        raise RuntimeError(f"POI 在库中未命中：{poi}")

    process_ids = sorted({r["process_id"] for r in rows})
    owner = rows[0]["process_content"]
    t_first = min(int(r["starttime"]) for r in rows)
    t_last = max(int(r["endtime"]) for r in rows)

    inv = deps.record
    inv.poi_owner = owner
    inv.poi_instances = len(rows)
    inv.poi_t0 = t_first
    inv.poi_t1 = t_last
    # 终点事件的原文（闭包引擎的种子）
    normalized_rel = normalize_rel(poi["rel"])
    inv.poi_rows = [dict(row, rel=normalized_rel) for row in rows]
    inv.add_hypothesis("POI", f"POI: {owner} {poi['rel']} {poi['syscall']} {poi['key']}", status="confirmed")

    for pid in process_ids:
        inv.add_entity("Process", pid, status="tracing")
    deps.log(f"[intake] POI 命中 {len(rows)} 条实例；涉及进程 {process_ids}")
    trace_event(deps.trace, "intake", poi_rows=len(rows), processes=len(process_ids))
    return {"poi_rows": rows}
