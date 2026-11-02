"""LLM 模式：束划分、四道结构闸门、提示词渲染、批调用、单轮推进与通道适配。

本文件只依赖 `domain`、`settings` 与 `llm.*`，不导入 `rules`、`closure`、`routing`。
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Iterable, List

import settings as cfg
from domain.edge import (
    CHANNEL_BITS,
    CONSUMER_RELS,
    DERIVATION_REL,
    PRODUCER_RELS,
    content_triple_of,
    labels_of,
)
from llm.text import rel_time, short
from llm.verdict import parse_bundle_verdicts
from llm.client import BudgetCallback, call_json, make_model

# ==== 1. 束划分与条目装配 ====
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


# ==== 2. 结构闸门与状态 ====
def anchor_facts(poi_rows: list[dict[str, Any]]) -> dict[str, set]:
    """提取起点告警锚点事件的客观事实（进程标识、对象及网络主机对）。"""
    out: dict[str, set] = {"procs": set(), "objs": set(), "pairs": set()}
    for row in poi_rows:
        rel = str(row.get("rel") or "")
        src_label, dst_label = labels_of(rel)
        src, _syscall, dst, _src_label = content_triple_of(
            rel, str(row.get("syscall") or ""), str(row.get("process_content") or ""),
            str(row.get("other") or ""))
        out["procs"].add(str(row.get("process_id") or ""))
        for label, content in ((src_label, src), (dst_label, dst)):
            if label == "Process":
                continue
            out["objs"].add((label, str(content)))
            if label == "Network":
                cls = dir_class(str(content), label)
                if cls.startswith("主机对"):
                    out["pairs"].add(cls)
    return out


def vacuous_ids(items: list[dict[str, Any]]) -> set[str]:
    """空拆闸门：筛选与上一级父束成员完全相同的子束编号集合。"""
    return {item["id"] for item in items if item.get("vacuous")}


def fanout_split(items: list[dict[str, Any]], vacuous: set[str], fanout_min: int,
                 ) -> tuple[list[dict[str, Any]], set[str], int]:
    """扇出闸门：分离出拆分产生的成员数不超过下限的单条边子束。"""
    ask: list[dict[str, Any]] = []
    skipped: set[str] = set()
    edges = 0
    for item in items:
        if item["id"] in vacuous:
            continue
        if item.get("parent") and item["size"] <= fanout_min:
            skipped.add(item["id"])
            edges += int(item["size"])
        else:
            ask.append(item)
    return ask, skipped, edges


def hot_guard(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]]) -> int:
    """类一致性闸门：同一对象类别中已有束判为整束相关时，同类的整束无关降级为混杂。"""
    hot: Counter = Counter()
    for item in items:
        row = verdicts.get(item["id"]) or {}
        if str(row.get("verdict", "")).lower() == "all":
            for cls in item.get("all_dirs", []):
                hot[cls] += 1
    if not hot:
        return 0
    downgraded = 0
    for item in items:
        row = verdicts.get(item["id"])
        if row is None or str(row.get("verdict", "")).lower() != "none":
            continue
        shared = [cls for cls in item.get("all_dirs", []) if hot.get(cls)]
        if shared:
            row["verdict"] = "mixed"
            row["_guard"] = "hot:" + "、".join(shared[:2])
            downgraded += 1
    return downgraded


def warrant_guard(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                  facts_of: Callable[[dict[str, Any]], dict[str, Any]],
                  rules: set[str]) -> tuple[int, dict[str, dict[str, Any]]]:
    """凭证闸门：判整束无关的束若命中已知误杀模式，降级为混杂继续拆分。"""
    downgraded = 0
    facts_by_id: dict[str, dict[str, Any]] = {}
    for item in items:
        row = verdicts.get(item["id"])
        if row is None or str(row.get("verdict", "")).lower() != "none":
            continue
        facts = facts_of(item)
        facts_by_id[item["id"]] = facts
        hits: list[str] = []
        if "deriv" in rules and facts.get("only_derivation"):
            hits.append("束内全是派生边")
        if "proc" in rules and facts.get("proc_confirmed"):
            hits.append("同一进程已出现在已确认相关的束里")
        if hits:
            row["verdict"] = "mixed"
            row["_warrant"] = "、".join(hits)
            downgraded += 1
    return downgraded, facts_by_id


def is_leaf(item: dict[str, Any], verdict: str, last_level: bool, fanout_min: int) -> bool:
    """叶子规则：已是单条边且没有更细级别可拆时，判混杂或判不了直接按未排除保留。"""
    return bool(verdict in ("mixed", "unknown") and not last_level
                and item.get("parent") and item["size"] <= fanout_min)


class BundleState:
    """调查状态机：滚动记录已确认实体并统一评估结构闸门。"""

    def __init__(self, anchor: dict[str, set] | None = None,
                 program_of: dict[str, str] | None = None) -> None:
        self.anchor: dict[str, set] = anchor or {"procs": set(), "objs": set(), "pairs": set()}
        self.program_of: dict[str, str] = program_of or {}
        self.mark_dirs: Counter = Counter()
        self.mark_programs: Counter = Counter()
        self.procs: set[str] = set()
        self.programs: set[str] = set()
        self.objs: set[tuple[str, str]] = set()
        self.pairs: set[str] = set()
        self.window: list[int] | None = None

    def facts(self, item: dict[str, Any], records: dict[Any, Any]) -> dict[str, Any]:
        """提取指定束在当前已知事实下的拓扑与时序特征。"""
        has_producer = has_consumer = has_deriv = False
        written_by_confirmed = is_anchor_object = False
        pairs: set[str] = set()
        procs: set[str] = set()
        programs: set[str] = set()
        for triple in item["members"]:
            record = records[triple]
            for member in record.get("member_processes") or ():
                procs.add(str(member))
                programs.add(str(self.program_of.get(str(member), str(member))))
            rels = set(record.get("rels") or ())
            if rels & set(PRODUCER_RELS):
                has_producer = True
            if rels & set(CONSUMER_RELS):
                has_consumer = True
            if DERIVATION_REL in rels:
                has_deriv = True
            obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                     str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
            if (label, str(obj)) in self.objs:
                written_by_confirmed = True
            if (label, str(obj)) in self.anchor["objs"]:
                is_anchor_object = True
            if label == "Network":
                cls = dir_class(str(obj), label)
                if cls.startswith("主机对"):
                    pairs.add(cls)
        window = self.window
        return {
            "proc_confirmed": bool(procs & self.procs),
            "proc_anchor": bool(procs & self.anchor["procs"]),
            "program_confirmed": bool(programs & self.programs),
            "obj_written_by_confirmed": written_by_confirmed,
            "obj_is_anchor": is_anchor_object,
            "pair_confirmed": bool(pairs & self.pairs),
            "pair_anchor": bool(pairs & self.anchor["pairs"]),
            "only_reader": has_consumer and not has_producer,
            "only_derivation": has_deriv and not has_producer and not has_consumer,
            "touches_producer": has_producer,
            "overlaps_confirmed_window": bool(window) and item["t0"] <= window[1] and item["t1"] >= window[0],
            "before_confirmed_window": bool(window) and item["t1"] < window[0],
        }

    def note_confirmed(self, item: dict[str, Any], records: dict[Any, Any]) -> None:
        """当某束被确认为整束相关时，将其实体、路径与时间窗沉淀到状态记忆中。"""
        for cls in item.get("all_dirs") or ():
            self.mark_dirs[cls] += 1
        for program in item.get("programs") or ():
            self.mark_programs[program] += 1
        for triple in item["members"]:
            record = records[triple]
            for member in record.get("member_processes") or ():
                self.procs.add(str(member))
                self.programs.add(str(self.program_of.get(str(member), str(member))))
            obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                     str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
            if label != "Process" and any(rel in PRODUCER_RELS for rel in record.get("rels") or ()):
                self.objs.add((label, str(obj)))
            if label == "Network":
                cls = dir_class(str(obj), label)
                if cls.startswith("主机对"):
                    self.pairs.add(cls)
        t0, t1 = int(item["t0"]), int(item["t1"])
        self.window = [t0, t1] if self.window is None else [min(self.window[0], t0), max(self.window[1], t1)]


# ==== 3. 渲染与模型调用 ====
# 判定文字说明字典
VERDICT_TEXT = {
    "all": "整束相关",
    "none": "整束无关",
    "mixed": "混杂（继续拆）",
    "unknown": "信息不足（继续拆）",
    "missing": "没给结论（继续拆）",
    "vacuous_kept": "空拆（与父束相同，按未排除留）",
    "fanout_kept": "扇出（拆分产生的单条边，按未排除留）",
    "leaf_kept": "单条边无可拆（按未排除留）",
    "cap_kept": "未判（达到调用上限）",
}

# 判定结论映射到三段来路的字典
TIERS = {"all": "confirmed", "none": "excluded"}

AGG_NOTE = """
本批开头可能有两张**共享表**，束行里用 C 编号 / P 编号引用它们：
- 「同类规模」表：本批涉及的每个对象类别下一共有多少个束、中位成员数；束行的「规模」行里给出本束
  在该类别里按成员数的排名与百分位。体量大本身不等于攻击（批量维护、包管理器、日志轮转都会很大）；
  但当"体量在同类里靠前 + 程序角色可疑 + 时间贴着攻击链"同时出现时，
  不要因为程序看着例行就整批判无关。
- 「上一级束」表：本批子束是从哪个更大的束拆出来的（程序、动作、成员数、总字节、对象个数、判定与理由）；
  束行的「上一级：P*」就是引用它。拆分不会让成员变多：上一级有上百条成员、命中同一个对端主机、
  字节量很大这类事实在本束仍然有效，不要因为本束只剩一两条成员就把上一级的事实丢掉。
"""

# 提示词系统模板
BUNDLE_SYSTEM = cfg.load_prompt("judge_bundle.md").replace(
    "{REASON_MAX_CHARS}", str(cfg.reason_max_chars())
)


def tier_of(verdict: str) -> str:
    """四值判定结论 -> 边级三段来路（只有 all/none 改变来路，其余一律保留为 kept）。"""
    return TIERS.get(str(verdict), "kept")


def level_name(level: int) -> str:
    """获取当前层级的规范显示名称。"""
    return LEVEL_NAMES[level] if 0 <= level < len(LEVEL_NAMES) else f"第 {level + 1} 级"


def fmt_bytes(value: Any) -> str:
    """字节数字节格式化为人类可读字符串。"""
    n = int(value or 0)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"


def edge_line(mid: str, record: dict[str, Any], ref_t: int) -> str:
    """将一条样本边格式化为紧凑行。"""
    members = sorted(record.get("member_processes") or [])
    return (f"    {mid} [进程 {members[0] if members else '?'}]"
            f" [{record.get('src_label')}] {short(record.get('src'), 70)} --{record.get('syscall')}-->"
            f" [{record.get('dst_label')}] {short(record.get('dst'), 70)}"
            f"（折叠事件数 {record.get('instances')}，字节 {record.get('bytes')}，"
            f"时间 {rel_time(record.get('t0'), ref_t)}）")


def build_task_header(poi_rows: list[dict[str, Any]]) -> str:
    """生成本批任务说明头（阐明调查终点、时间原点与规则口径）。"""
    if not poi_rows:
        return ""
    row = poi_rows[0]
    rel = str(row.get("rel") or "")
    other_label = str(row.get("other_label") or "")
    src_label, dst_label = labels_of(rel)
    owner = str(row.get("process_content") or "")
    other = str(row.get("other") or "")
    if other_label == "Network":
        protocol = str(row.get("other_protocol") or "").strip()
        if protocol:
            other = f"{other}（{protocol}）"
    syscall = str(row.get("syscall") or "")
    src, _syscall, dst, _src_label = content_triple_of(rel, syscall, owner, other)
    t0 = min(int(r.get("starttime") or 0) for r in poi_rows)
    return "\n".join([
        "## 本次调查的任务",
        "- 目标事件（本次调查的终点，往回追的起点）：",
        f"  [{src_label}] {src} --{syscall}--> [{dst_label}] {dst}",
        f"- 目标事件发生次数：{len(poi_rows)} 次；时间原点（最早一次发生的时刻）＝ {t0} 纳秒"
        "（下面进程表与边行里的时间都是相对这个原点算出的秒数）",
        "- 调查方向：只找**可能属于攻击路径**的上游活动（判断标准见系统说明）；目标事件本身也在清单里。",
        "- 调查方式：从目标事件出发，一层一层往回走；这一轮给你的不是单条边，而是**束**"
        "（同一程序、同一动作、同一类对象上的一批边）。",
        "- 相对时间的正负号：负号表示早于目标事件，正号表示晚于它。",
        "- 清单口径：清单 = 从目标事件往回走收集到的边，再按（源内容、操作名、目标内容）折叠；"
        "一条边可能代表多个折叠事件；清单之外没有需要判断的边。",
    ])


def _parent_of(item: dict[str, Any]) -> dict[str, Any] | None:
    parent = item.get("parent")
    if parent and parent["size"] >= max(4, 2 * item["size"]):
        return parent
    return None


def _batch_tables(items: list[dict[str, Any]], scale_index: dict[str, dict[str, Any]],
                  ) -> tuple[list[str], dict[str, str], dict[str, str], dict[str, dict]]:
    class_ids: dict[str, str] = {}
    parent_ids: dict[str, str] = {}
    parents: dict[str, dict[str, Any]] = {}
    for item in items:
        classes = item.get("all_dirs") or []
        cls = classes[0] if classes else ""
        if cls and cls not in class_ids and scale_stats(scale_index, cls, item["size"]):
            class_ids[cls] = f"C{len(class_ids) + 1}"
        parent = _parent_of(item)
        if parent:
            bid = str(parent.get("bid") or "?")
            if bid not in parent_ids:
                parent_ids[bid] = f"P{len(parent_ids) + 1}"
                parents[bid] = parent
    lines: list[str] = []
    if class_ids:
        lines.append("### 同类规模（本批涉及的类别；束行「规模」行里的 C 编号引用这里）")
        for cls, cid in sorted(class_ids.items(), key=lambda kv: kv[1]):
            info = scale_index.get(cls) or {}
            lines.append(f"{cid} {short(cls, 46)}｜共 {info.get('n', 0)} 个束"
                         f"（中位 {info.get('median', 0)} 条）")
        lines.append("")
    if parent_ids:
        lines.append("### 上一级束（本批子束拆自这些束；束行「上一级：P*」引用这里）")
        for bid, pid in sorted(parent_ids.items(), key=lambda kv: kv[1]):
            parent = parents.get(bid) or {}
            lines.append(
                f"{pid} {short(' / '.join(parent.get('programs') or []) or '(无属主)', 40)}"
                f" {parent.get('syscall', '')}｜{parent.get('size', 0)} 条／{fmt_bytes(parent.get('bytes', 0))}"
                f"／{parent.get('objects_n', 0)} 个对象"
                f"｜判定 {VERDICT_TEXT.get(parent.get('verdict'), parent.get('verdict'))}"
                f"｜{short(parent.get('reason', ''), 50) or '(未给理由)'}")
        lines.append("")
    return lines, class_ids, parent_ids, parents


def _extra_lines(item: dict[str, Any], class_ids: dict[str, str], parent_ids: dict[str, str],
                 scale_index: dict[str, dict[str, Any]]) -> list[str]:
    classes = item.get("all_dirs") or []
    cls = classes[0] if classes else ""
    stats = scale_stats(scale_index, cls, item["size"]) if cls else None
    tail = ""
    if stats and cls in class_ids:
        tail = f"；同类 {class_ids[cls]} 第 {stats['rank']}（前 {stats['pct']}%）"
    lines = [f"    规模：成员 {item['size']} 条／{fmt_bytes(item['bytes'])}／"
             f"不同对象 {item['objects_n']} 个{tail}"]
    parent = _parent_of(item)
    if parent:
        pid = parent_ids.get(str(parent.get("bid") or "?"))
        if pid:
            lines.append(f"    上一级：{pid}")
    return lines


def render(items: list[dict[str, Any]], records: dict[Any, Any], ref_t: int, *,
           level_name: str = "", header: str = "", scale_index: dict[str, dict[str, Any]] | None = None,
           aggregate: bool = False, annotate: bool = False, state: Any = None) -> str:
    """渲染待投递给模型的完整提示词文本。"""
    scale_index = scale_index or {}
    parts: list[str] = []
    if header:
        parts.extend([header, ""])
    parts.append(f"## 本批要判的束（{len(items)} 个，来自层级「{level_name}」）")
    parts.append("")
    class_ids: dict[str, str] = {}
    parent_ids: dict[str, str] = {}
    if aggregate:
        tables, class_ids, parent_ids, _parents = _batch_tables(items, scale_index)
        parts.extend(tables)
    lines = parts
    for item in items:
        lines.append(f"{item['id']}｜程序 {short(' / '.join(item['programs']) or '(无属主)')}"
                     f"｜动作 {'+'.join(item['rels'])} {item['syscall']}"
                     f"｜对象目录 {short(' / '.join(item['dirs']) or '(无)')}｜成员 {item['size']} 条")
        if aggregate:
            lines.extend(_extra_lines(item, class_ids, parent_ids, scale_index))
        if annotate and state is not None:
            hot_dirs = [d for d in item.get("all_dirs", []) if state.mark_dirs.get(d)]
            hot_programs = [p for p in item["programs"] if state.mark_programs.get(p)]
            if hot_dirs or hot_programs:
                bits = []
                if hot_dirs:
                    bits.append("对象类别 " + "、".join(
                        f"{d}（已判相关的束里出现 {state.mark_dirs[d]} 次）" for d in hot_dirs[:3]))
                if hot_programs:
                    bits.append("本束程序 " + "、".join(
                        f"{p}（已判相关的束里出现 {state.mark_programs[p]} 次）" for p in hot_programs[:2]))
                lines.append("    线索：" + "；".join(bits) + "——这些痕迹与已判相关的活动重合，"
                             "若本束样本与它们同类，倾向相关；若明显是例行对象，仍可判无关。")
        for cmdline in item["cmdlines"]:
            lines.append(f"    命令行：{short(cmdline, 140)}")
        for index, triple in enumerate(item["sample"]):
            lines.append(edge_line(f"M{index + 1}", records[triple], ref_t))
        if item["size"] > len(item["sample"]):
            lines.append(f"    （还有 {item['size'] - len(item['sample'])} 条成员未列出，样本覆盖不同对象）")
        lines.append("")
    lines.append("请按系统说明对每个束给出四值判定；每个 id 原样回抄。")
    return chr(10).join(lines)


def judge_bundles(model: Any, items: list[dict[str, Any]], listing: str, *, budget: Any,
                  ) -> dict[str, Any]:
    """单批模型判定：发出 JSON 结构化请求并解析结论字典。"""
    config = {"callbacks": [BudgetCallback(budget, node="bundle")]}
    result = call_json(model, BUNDLE_SYSTEM, listing, config=config, role="bundle")
    if not result.get("_raw_ok", True):
        return {"ok": False, "error": result.get("_error") or "未知错误", "calls": 1}
    verdicts, invalid = parse_bundle_verdicts(result, {item["id"] for item in items})
    return {"ok": True, "verdicts": verdicts, "invalid": invalid, "calls": 1}


def run_batches(deps: Any, items: list[dict[str, Any]], batches: list[list[dict[str, Any]]],
                inv: Any, ref_t: int, *, level_name: str, scale_index: dict[str, Any],
                aggregate: bool, state: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """将当级的批次切片并发投递模型，处理重发重试并汇聚统计。"""
    verdicts: dict[str, dict[str, Any]] = {}
    out = {"calls": 0, "chars_max": 0, "invalid": 0, "missing": 0, "failed_batches": 0}
    if not batches:
        return verdicts, out
    header = build_task_header(inv.poi_rows)
    annotate = cfg.annotate_marks_enabled()

    def run_single_batch(batch: list[dict[str, Any]]) -> dict[str, Any]:
        listing = render(batch, inv.edges, ref_t, level_name=level_name, header=header,
                         scale_index=scale_index, aggregate=aggregate, annotate=annotate,
                         state=state)
        result: dict[str, Any] = {}
        calls = 0
        for attempt in range(cfg.batch_attempts()):
            result = judge_bundles(deps.model, batch, listing, budget=deps.budget)
            calls += 1
            if result.get("ok"):
                break
            deps.log(f"    [judge] 一批调用失败（第 {attempt + 1}/{cfg.batch_attempts()} 次，"
                     f"{len(batch)} 个束 / {len(listing)} 字符）：{short(result.get('error'))}")
        ok = bool(result.get("ok"))
        return {
            "ok": ok, "verdicts": result.get("verdicts") or {}, "calls": calls,
            "invalid": int(result.get("invalid") or 0), "chars": len(listing),
            "missing": sum(1 for item in batch if item["id"] not in (result.get("verdicts") or {})),
        }

    with ThreadPoolExecutor(max_workers=min(cfg.max_concurrency(), max(1, len(batches)))) as pool:
        results = list(pool.map(run_single_batch, batches))
    for result in results:
        out["calls"] += int(result.get("calls") or 0)
        out["chars_max"] = max(out["chars_max"], int(result.get("chars") or 0))
        out["invalid"] += int(result.get("invalid") or 0)
        out["missing"] += int(result.get("missing") or 0)
        if not result.get("ok"):
            out["failed_batches"] += 1
        verdicts.update(result.get("verdicts") or {})
    return verdicts, out


# ==== 4. 单轮推进 ====
def _judge_pass(deps: "Deps", triples: set[Any], *, keyer: Any, state: Any,
                inv: Any, stats: dict[str, Any], detail: list[dict[str, Any]], pass_no: int,
                cap_calls: int) -> dict[str, Any]:
    """单轮判定推进：从第 1 级开始，对判为混杂的束逐级细化推进。"""
    started = time.time()
    levels = build_levels(triples, inv.edges, keyer)
    key_of = level_members(levels)
    last = len(levels) - 1
    scale_index = build_scale_index(triples, inv.edges, keyer)
    ref_t = int(inv.poi_t0 or 0)
    parent_map: dict[Any, tuple] = {}
    frontier = _frontier_order(levels[0], inv.edges, ref_t)
    seq = 0
    calls_before = stats["calls"]
    level_stats: list[dict[str, Any]] = []

    def next_id() -> str:
        nonlocal seq
        seq += 1
        return f"B{seq:04d}"

    for level in range(len(levels)):
        if not frontier:
            break
        items = build_items(frontier, level, levels, inv.edges, inv.process_context,
                               samples=cfg.bundle_samples(), next_id=next_id,
                               parents=parent_map)
        level_text = level_name(level)

        # 结构前置闸门：空拆检测与单条边扇出跳过
        vacuous = vacuous_ids(items) if cfg.vacuous_guard_enabled() else set()
        if vacuous:
            stats["guards"]["vacuous"] += len(vacuous)
            deps.log(f"    [vacuous] 空拆闸门：{len(vacuous)}/{len(items)} 个子束与上一级成员相同，直接归「未排除」")

        skipped: set[str] = set()
        ask_items = items
        if cfg.fanout_guard_enabled():
            ask_items, skipped, fanout_edges = fanout_split(items, vacuous, cfg.bundle_fanout_min())
            if skipped:
                stats["guards"]["fanout"]["bundles"] += len(skipped)
                stats["guards"]["fanout"]["edges"] += fanout_edges
                deps.log(f"    [fanout] 扇出闸门：跳过 {len(skipped)}/{len(items)} 个拆分产生的单条边子束")

        # 切批与预算配额控制
        batches = [ask_items[i:i + cfg.bundle_batch()]
                   for i in range(0, len(ask_items), cfg.bundle_batch())]
        kept_by_cap: list[dict[str, Any]] = []
        if stats["calls"] + len(batches) > cap_calls:
            keep = max(0, cap_calls - stats["calls"])
            deps.log(f"    [cap] 调用上限 {cap_calls}；本层只判 {keep}/{len(batches)} 批，其余按保留处理")
            kept_by_cap = [item for batch in batches[keep:] for item in batch]
            batches = batches[:keep]

        deps.log(f"  L{level + 1} {level_text}：{len(items)} 个束 / {len(batches)} 批（第 {pass_no} 轮）")
        verdicts, batch_stats = run_batches(
            deps, items, batches, inv, ref_t, level_name=level_text,
            scale_index=scale_index, aggregate=cfg.aggregate_enabled(), state=state
        )
        stats["calls"] += batch_stats["calls"]
        stats["missing_bundles"] += batch_stats["missing"]

        # 结构后置闸门：类一致性约束与误杀凭证校验
        if cfg.none_guard() == "hot":
            stats["guards"]["hot"] += hot_guard(items, verdicts)
        warrant_facts: dict[str, dict[str, Any]] = {}
        if cfg.warrant_guard_enabled():
            downgraded, warrant_facts = warrant_guard(
                items, verdicts, lambda item: state.facts(item, inv.edges),
                set(cfg.warrant_rules())
            )
            stats["guards"]["warrant"] += downgraded

        # 处理条目判定结论与来路沉淀
        counts: dict[str, int] = {}
        children: list[Any] = []
        cap_ids = {item["id"] for item in kept_by_cap}

        for item in items:
            v_info = _resolve_item_verdict(item, verdicts.get(item["id"]), vacuous, skipped, cap_ids,
                                           last == level, cfg.bundle_fanout_min())
            verdict, reason, witnesses = v_info["verdict"], v_info["reason"], v_info["witnesses"]
            counts[verdict] = counts.get(verdict, 0) + 1

            note = {"verdict": verdict, "verdict_reason": short(reason)}
            for member in item["members"]:
                inv.edges[member].update(note)

            detail.append({
                "pass": pass_no, "level": level, "level_name": level_text, "id": item["id"],
                "size": item["size"], "verdict": verdict, "tier": tier_of(verdict),
                "reason": short(reason), "witnesses": witnesses,
                "programs": item["programs"], "rels": item["rels"], "syscall": item["syscall"],
                "dirs": item["dirs"], "objects_n": item["objects_n"], "bytes": item["bytes"],
                "parent_bid": (item.get("parent") or {}).get("bid"),
                "sample": [list(t) for t in item["sample"][:4]],
                **({"warrant_facts": warrant_facts[item["id"]]} if item["id"] in warrant_facts else {}),
            })

            if verdict == "all":
                inv.mark(item["members"], "confirmed")
                state.note_confirmed(item, inv.edges)
            elif verdict == "none":
                inv.mark(item["members"], "excluded")
            elif verdict in ("mixed", "unknown", "missing"):
                if last == level:
                    inv.mark(item["members"], "kept")
                else:
                    for member in item["members"]:
                        child_key = key_of[level + 1][member]
                        children.append(child_key)
                        parent_map.setdefault(child_key, (item, verdict, reason))
            else:
                inv.mark(item["members"], "kept")

        level_stats.append({
            "level": level, "name": level_text, "bundles": len(items), "batches": len(batches),
            "verdicts": dict(sorted(counts.items())), "children": len(set(children)),
            "chars_max": batch_stats["chars_max"], "invalid": batch_stats["invalid"],
        })
        stats["levels"].append({"pass": pass_no, **level_stats[-1]})
        deps.log(f"    L{level + 1} 结论：{dict(sorted(counts.items()))}；"
                 f"拆出子束 {len(set(children))} 个；单批最大输入 {batch_stats['chars_max']} 字符")

        frontier = _frontier_order({key: levels[level + 1][key] for key in set(children)
                                    if level + 1 < len(levels)}, inv.edges, ref_t,
                                   risk=False) if children else []

    return {
        "pass": pass_no, "candidates": len(triples), "calls": stats["calls"] - calls_before,
        "levels": len(level_stats), "level_stats": level_stats,
        "seconds": round(time.time() - started, 1),
    }


def _resolve_item_verdict(item: dict[str, Any], row: dict[str, Any] | None,
                          vacuous: set[str], skipped: set[str], cap_ids: set[str],
                          last_level: bool, fanout_min: int) -> dict[str, Any]:
    """解析单束的有效结论、原因及闸门修饰。"""
    witnesses: dict[str, Any] = {}
    if item["id"] in vacuous:
        verdict, reason = "vacuous_kept", "（空拆闸门：与上一级成员相同、没有新信息，不重判）"
    elif item["id"] in skipped:
        verdict, reason = "skipped", "（扇出闸门：拆分产生的单条边子束，不判）"
    elif item["id"] in cap_ids:
        verdict, reason = "cap_kept", "（达到调用上限，按保留处理）"
    elif row is None:
        verdict, reason = "missing", "（模型没给这个束结论）"
    else:
        verdict = str(row.get("verdict") or "").lower()
        reason = str(row.get("reason") or "")
        witnesses = {k: row.get(k) for k in ("witness_relevant", "witness_irrelevant")}

    if (row or {}).get("_guard"):
        reason = f"（类一致性闸门：{row['_guard']}）" + reason
    if (row or {}).get("_warrant"):
        reason = f"（凭证闸门：{row['_warrant']}）" + reason
    if is_leaf(item, verdict, last_level, fanout_min):
        verdict = "leaf_kept"
        reason = "（单条边无可拆，按未排除留）" + reason

    return {"verdict": verdict, "reason": reason, "witnesses": witnesses}



def _frontier_order(bundles_at_level: dict[Any, list[Any]], edges: dict[Any, Any], ref_t: int,
                    *, risk: bool = True) -> list[Any]:
    """确定当前层级的待判束队列顺序（第 1 级支持风险分数调度，其余层级采用结构键）。"""
    keys = list(bundles_at_level)
    if risk and cfg.risk_schedule_enabled():
        return sorted(keys, key=lambda key: _risk_key(bundles_at_level[key], edges, ref_t))
    return sorted(keys, key=lambda key: sort_text(key))


def _risk_key(members: list[Any], edges: dict[Any, Any], ref_t: int) -> tuple:
    """计算束的风险排序元组（网络边优先、离锚点近优先、含写边优先）。"""
    records = [edges[t] for t in members]
    has_net = any(str(r.get("src_label") or "") == "Network"
                  or str(r.get("dst_label") or "") == "Network" for r in records)
    has_producer = any(set(r.get("rels") or ()) & set(("p2f", "p2n")) for r in records)
    min_dist = min(int(r.get("dist") or 0) for r in records)
    gap = max(0, int(ref_t) - max(int(r.get("t1") or 0) for r in records))
    return (0 if has_net else 1, min_dist, 0 if has_producer else 1, gap, -len(members))




# ==== 5. LLM 通道 ====
class LlmJudge:
    """大语言模型候选边语义仲裁客户端。"""
    def __init__(self, deps=None, max_calls=None):
        self.deps = deps
        cfg.load_dotenv()
        self.max_calls = max_calls if max_calls is not None else cfg.bundle_cap_calls()
        if self.deps is not None and self.deps.model is None:
            self.deps.model = make_model()

    def judge(self, ambiguous_candidates: List[Dict[str, Any]], topology_facts=None) -> Dict[str, Any]:
        if self.deps is None or not ambiguous_candidates:
            return {"confirmed": [], "excluded": [], "kept": ambiguous_candidates, "calls": 0, "seconds": 0.0}

        inv = self.deps.record
        t0 = time.time()

        # 1. 提取歧义候选边的三元组集合（不在候选清单里的边原样保留，绝不静默丢弃）
        triples_to_judge = set()
        missing_edges = []
        for e in ambiguous_candidates:
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            if key in inv.edges:
                triples_to_judge.add(key)
            else:
                missing_edges.append(e)

        if not triples_to_judge:
            return {"confirmed": [], "excluded": [], "kept": list(ambiguous_candidates), "calls": 0, "seconds": 0.0}

        # 2. 装配与 Agent 完全一致的判定上下文与状态
        program_of = program_table(inv.process_context)
        keyer = LevelKey(program_of)
        state = BundleState(anchor=anchor_facts(inv.poi_rows), program_of=program_of)

        stats: Dict[str, Any] = {
            "candidates": len(triples_to_judge), "calls": 0, "seconds": 0.0, "levels": [],
            "guards": {"vacuous": 0, "fanout": {"bundles": 0, "edges": 0}, "hot": 0, "warrant": 0},
            "cap_kept_edges": 0, "missing_bundles": 0,
        }
        detail: List[Dict[str, Any]] = []

        # 3. 运行束级推进判定（仅针对歧义候选边）
        pass_res = _judge_pass(
            self.deps, triples_to_judge, keyer=keyer, state=state, inv=inv,
            stats=stats, detail=detail, pass_no=1, cap_calls=self.max_calls
        )

        elapsed = time.time() - t0

        # 4. 结算判定结论
        confirmed_edges = []
        excluded_edges = []
        kept_edges = []

        for key in triples_to_judge:
            origin = inv.origin.get(key, "kept")
            edge_rec = dict(inv.edges[key])
            if origin == "confirmed":
                edge_rec["origin"] = "confirmed"
                edge_rec["class"] = "story"
                edge_rec["reason"] = f"慢速通道：大语言模型判定整束相关 ({edge_rec.get('verdict_reason', '')})"
                confirmed_edges.append(edge_rec)
            elif origin == "excluded":
                edge_rec["origin"] = "excluded"
                edge_rec["reason"] = f"慢速通道：大语言模型判定整束无关 ({edge_rec.get('verdict_reason', '')})"
                excluded_edges.append(edge_rec)
            else:
                edge_rec["origin"] = "kept"
                kept_edges.append(edge_rec)

        return {
            "confirmed": confirmed_edges,
            "excluded": excluded_edges,
            "kept": kept_edges + missing_edges,
            "calls": pass_res.get("calls", 0),
            "seconds": elapsed,
        }


# 提供别名
LlmJudgeClient = LlmJudge


# ==== 6. 统一促进通道接口 ====

class LlmChannel(LlmJudge):
    """与符号通道同形的 LLM 通道：只返回新增/排除/保留。"""

    def promote(self, pool: list[dict[str, Any]], confirmed: dict[Any, Any] | None = None,
                facts: Any = None) -> dict[str, Any]:
        return self.judge(list(pool), facts)


LlmChannel.__name__ = "LlmChannel"
