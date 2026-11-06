"""图候选边多级聚类与束划分算法。

将候选边按层级进行等价类聚合（程序 -> 关系 -> 系统调用 -> 通道 -> 目录 -> 实体）。
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from domain.edge import CHANNEL_BITS

LEVEL_NAMES = (
    "第 1 级 程序+关系+系统调用",
    "第 2 级 +入闭包通道",
    "第 3 级 +对象所在目录",
    "第 4 级 +具体对象身份",
    "第 5 级 单条边（逐条判定）",
)


def channel_class(bits: Any) -> str:
    """通道位掩码 -> 可读类别（同一批边可能从多条通道进入闭包）。"""
    value = int(bits or 0)
    names = [name for name, bit in CHANNEL_BITS.items() if value & bit]
    return "+".join(names) if names else "(无)"


def object_side(src: str, syscall: str, dst: str, src_label: str, dst_label: str) -> tuple[str, str]:
    """提取边的对象端点（内容 + 标签）；当两端均为进程时默认以目标端为对象。"""
    if src_label != "Process":
        return src, src_label
    if dst_label != "Process":
        return dst, dst_label
    return dst, "Process"


def dir_class(obj: str, label: str) -> str:
    """对象分类：文件按所在目录；网络按两端主机对（不含端口）；进程归为(进程)。"""
    if label == "Process":
        return "(进程)"
    if label == "Network":
        left, _, right = str(obj).partition("->")
        if left and right and ":" in left and ":" in right:
            a = left.rsplit(":", 1)[0]
            b = right.rsplit(":", 1)[0]
            return "主机对 " + "|".join(sorted([a, b]))
        return "(网络四元组)"
    if str(obj).startswith("/"):
        return os.path.dirname(str(obj)) or "/"
    return "(非路径)"


def sort_text(key: Any) -> str:
    """束键的确定性排序序列化字符串。"""
    return json.dumps(key, ensure_ascii=False, default=str)


def program_of(metas: dict[str, dict[str, Any]], process_id: Any) -> str:
    """从进程身份元数据中提取进程可执行路径。"""
    meta = metas.get(str(process_id)) or {}
    return str(meta.get("owner") or process_id)


def program_table(metas: dict[str, dict[str, Any]]) -> dict[str, str]:
    """生成进程标识 -> 可执行路径的快速映射表。"""
    return {pid: str(meta.get("owner") or pid) for pid, meta in metas.items()}


class LevelKey:
    """把一条候选边映射为五个层级的束键（键相同表示落在同一个束中）。"""

    def __init__(self, program_of: dict[str, str]) -> None:
        self.program_of = program_of

    def programs(self, record: dict[str, Any]) -> tuple[str, ...]:
        return tuple(sorted({self.program_of.get(str(m), str(m))
                             for m in record.get("member_processes") or ()}))

    def keys(self, triple: tuple[str, str, str], record: dict[str, Any]) -> list[tuple]:
        obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                 str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
        base = (self.programs(record), tuple(sorted(record.get("rels") or ())), str(record["syscall"]))
        k1 = base + (channel_class(record.get("channels")),)
        k2 = k1 + (dir_class(obj, label),)
        return [base, k1, k2, k2 + (str(obj),), (triple,)]


def build_levels(triples: Iterable[tuple[str, str, str]], records: dict[Any, Any],
                 keyer: LevelKey) -> list[dict[tuple, list[tuple]]]:
    """构建候选边的五级细分映射：返回每级的 {束键: 成员三元组列表}。"""
    levels: list[dict[tuple, list[tuple]]] = [defaultdict(list) for _ in LEVEL_NAMES]
    for triple in triples:
        keys = keyer.keys(triple, records[triple])
        for level, key in enumerate(keys):
            levels[level][key].append(triple)
    return [dict(level) for level in levels]


def level_members(levels: list[dict[tuple, list[tuple]]]) -> list[dict[tuple, tuple]]:
    """生成每级的「成员三元组 -> 束键」反查字典。"""
    out: list[dict[tuple, tuple]] = []
    for level in levels:
        mapping: dict[tuple, tuple] = {}
        for key, members in level.items():
            for triple in members:
                mapping[triple] = key
        out.append(mapping)
    return out


def check_partition(levels: list[dict[tuple, list[tuple]]]) -> dict[str, Any]:
    """校验划分不变式：每级覆盖相同集合，且下一级是上一级的单调细化。"""
    base = {t for members in levels[0].values() for t in members}
    last = len(levels) - 1
    out: dict[str, Any] = {"level0_covers_all": True}
    for level, bundles in enumerate(levels):
        flat = [t for members in bundles.values() for t in members]
        out[f"L{level}_members"] = len(flat)
        out[f"L{level}_distinct_members"] = len(set(flat))
        out[f"L{level}_covers_same_set"] = set(flat) == base
    monotone = True
    for level in range(last):
        child_parent: dict[tuple, tuple] = {}
        for child, members in levels[level + 1].items():
            sample = members[0]
            for pkey, pmembers in levels[level].items():
                if sample in pmembers:
                    child_parent[child] = pkey
                    break
        for child, members in levels[level + 1].items():
            pkey = child_parent.get(child)
            if pkey is None or not set(members) <= set(levels[level][pkey]):
                monotone = False
                break
        if not monotone:
            break
    out["monotone_refinement"] = monotone
    return out


def sample_members(members: list[tuple[str, str, str]], limit: int) -> list[tuple[str, str, str]]:
    """确定性成员采样：优先覆盖不同对象，保证样本的多样性。"""
    picked: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for triple in sorted(members, key=lambda x: (str(x[2]), str(x[0]), str(x[1]))):
        if str(triple[2]) in seen and len(picked) + (len(members) - len(seen)) > limit:
            continue
        seen.add(str(triple[2]))
        picked.append(triple)
        if len(picked) >= limit:
            break
    return picked or members[:limit]


def build_items(keys: list[Any], level: int, levels: list[dict[Any, list[tuple]]],
                records: dict[Any, Any], metas: dict[str, dict[str, Any]], *,
                samples: int, next_id: Callable[[], str],
                parents: dict[Any, tuple] | None = None) -> list[dict[str, Any]]:
    """把指定层级的束键列表格式化为待评审的条目字典列表。"""
    parents = parents or {}
    items: list[dict[str, Any]] = []
    for key in keys:
        members = levels[level][key]
        rep = records[members[0]]
        sample = sample_members(members, samples)
        dirs, objects = set(), set()
        for triple in sample:
            rec = records[triple]
            obj, label = object_side(rec["src"], rec["syscall"], rec["dst"],
                                     str(rec.get("src_label") or ""),
                                     str(rec.get("dst_label") or ""))
            dirs.add(dir_class(obj, label))
            objects.add(str(obj))
        cmdlines = sorted({str((metas.get(str(m)) or {}).get("owner_args") or "")
                           for triple in sample
                           for m in (records[triple].get("member_processes") or ())
                           if (metas.get(str(m)) or {}).get("owner_args")})[:2]
        
        all_dirs = {dir_class(*object_side(records[t]["src"], records[t]["syscall"], records[t]["dst"],
                                           str(records[t].get("src_label") or ""),
                                           str(records[t].get("dst_label") or "")))
                    for t in members}
        objects_n = len({str(object_side(records[t]["src"], records[t]["syscall"], records[t]["dst"],
                                         str(records[t].get("src_label") or ""),
                                         str(records[t].get("dst_label") or ""))[0])
                         for t in members})

        entry: dict[str, Any] = {
            "id": next_id(), "key": key, "level": level, "members": list(members),
            "size": len(members),
            "programs": sorted({program_of(metas, m)
                                for m in (rep.get("member_processes") or ())}),
            "rels": sorted(rep.get("rels") or []), "syscall": str(rep.get("syscall") or ""),
            "dirs": sorted(dirs), "all_dirs": sorted(all_dirs),
            "objects": sorted(objects),
            "objects_n": objects_n,
            "t0": min(int(records[t].get("t0") or 0) for t in members),
            "t1": max(int(records[t].get("t1") or 0) for t in members),
            "bytes": sum(int(records[t].get("bytes") or 0) for t in members),
            "sample": sample, "cmdlines": cmdlines,
        }
        parent = parents.get(key)
        if parent:
            parent_item, parent_verdict, parent_reason = parent
            if int(parent_item["size"]) == len(members):
                entry["vacuous"] = True
            entry["parent"] = {
                "bid": parent_item["id"], "programs": parent_item["programs"],
                "rels": parent_item["rels"], "syscall": parent_item["syscall"],
                "size": parent_item["size"], "bytes": parent_item["bytes"],
                "objects_n": parent_item["objects_n"], "t0": parent_item["t0"],
                "t1": parent_item["t1"], "verdict": parent_verdict, "reason": parent_reason,
            }
        items.append(entry)
    return items


def build_scale_index(triples: Iterable[tuple[str, str, str]], records: dict[Any, Any],
                      keyer: LevelKey) -> dict[str, dict[str, Any]]:
    """按对象类别统计第 1 级束的规模分布（用于在渲染时向模型提示同类中的体量百分位）。"""
    per_bundle: dict[tuple, dict[str, Any]] = {}
    for triple in triples:
        record = records[triple]
        l0 = (keyer.programs(record), tuple(sorted(record.get("rels") or ())), str(record["syscall"]))
        obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                 str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
        rec = per_bundle.get(l0)
        if rec is None:
            rec = per_bundle[l0] = {"size": 0, "classes": set()}
        rec["size"] += 1
        rec["classes"].add(dir_class(obj, label))
    index: dict[str, list[int]] = {}
    for rec in per_bundle.values():
        for cls in rec["classes"]:
            index.setdefault(cls, []).append(int(rec["size"]))
    out: dict[str, dict[str, Any]] = {}
    for cls, sizes in index.items():
        sizes.sort()
        out[cls] = {"n": len(sizes), "median": sizes[len(sizes) // 2], "sizes": sizes}
    return out


def scale_stats(index: dict[str, dict[str, Any]], cls: str, size: int) -> dict[str, Any] | None:
    """计算当前束在同类对象中的体量排名与百分位；同类少于 3 个束时不提供统计。"""
    info = index.get(cls or "") or {}
    sizes = info.get("sizes") or []
    if len(sizes) < 3:
        return None
    rank = sum(1 for s in sizes if s > size) + 1
    return {"n": len(sizes), "median": info["median"], "rank": rank,
            "pct": max(1, int(round(rank / len(sizes) * 100)))}
