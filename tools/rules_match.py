#!/usr/bin/env python
"""规则（可能集合）匹配：把标准答案里的规则条件落到一条边上，判定是否命中。

规则写在 GT 文件 `attack_path[].rules` 里（gt-annotator 产出）；评分总口径见本目录 `score_graph_product.py` 头部注释。

规则形状（三段条件）：

    {
      "rule_id": "R1",
      "direction": "src_to_dst" | "either",
      "action": ["write", "rename", ...],
      "effect": "success" | "failure" | "any",           # 可选，缺省 any
      "source": <端点条件>,
      "target": <端点条件>,
      "edge": {"bytes": {"op": ">=", "value": 1024}}     # 可选，本模块按实例属性判定
    }

`action` 允许两种词表（GT 标注时混用是正常的）：

    · 图上的 syscall 名（read / write / rename / unlink / execve / accept / sendto / recvfrom …）
    · 图上的动作名（send / recv / create / exec / mmap_read / mmap_write / mmap_exec / stat …）

报告边只带 syscall，所以动作名按 ACTION_TO_SYSCALLS 展开成等价 syscall 集合再判定。
展开是“超集近似”，两处必须知道：`create` 收全部成功 `open`；`send`/`recv` 收普通文件
`write`/`read`（因为网络客体上的读写会被解析器改写成 send/recv 动作）。更完整的
来源说明与影响见 ACTION_TO_SYSCALLS 上方注释。

`effect` 可用于原始证据校验，正式评分按三元组匹配。

端点条件是：叶子字段（vertex / match / value / values）与组合字段（any_of / all_of / none_of）可同现，
同现时组合字段先算，叶子按“且”叠加：

    vertex:  process | file | network | any（缺省 any＝不限种类）
    match:   any（任意值）| exact | in | path_prefix | path_suffix | path_pattern（正则）
    value / values: match 对应的值

顶点种类（process / file / network）由场景库的顶点标签判定（VertexKinds）。同一个内容字符串可能
既是进程又是文件（例如 /usr/bin/shred），此时按“可能的种类里有一个相符即算满足”；取不到种类时
`vertex` 条件不参与判定，只按内容匹配（并在调用方以 degraded 标记提示）。

用法:
    rules = load_rules(gt)
    kinds = VertexKinds.for_gt(gt)
    m = evaluate_report(gt_triples, rules, report_triples, kinds)
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "parser"))
sys.path.insert(0, str(ROOT / "provenance"))

from provenance.core.syscalls import (  # noqa: E402
    CREATE_ALWAYS, OPEN_FAMILY, canonical_syscall,
)
from domain.keys import path_part  # noqa: E402

SCENARIOS = ROOT / "provenance" / "config" / "scenarios.json"

_LABEL_TO_KIND = {"Process": "process", "File": "file", "Network": "network"}
SCORING_PROTOCOL = "triplet-v1"

# 图上的动作名 -> 该动作可能落在哪些 syscall 上（家族基本名）。
#
# 事实来源是解析器自己的动词表 parser/data/verbs.toml（调用 -> 动作），
# 加上两处解析器代码里才有的规则：
#   1. open 家族（open/openat/openat2/creat…）由 flags 分流，O_CREAT/O_TRUNC 落 create；
#   2. mmap 一族按 prot/flags 拆成 mmap_read / mmap_write / mmap_exec 三个动作值。
#   3. 网络客体上，读/写家族的 syscall 会被 FlowRouter 改写成 recv / send（unix 套接字同理），
#      所以 send 还要收 write 家族、recv 还要收 read 家族的 syscall。
#
# 后果（必须知道的超集近似）：动作条件 `send`/`recv` 会同时接受普通文件 write/read 边，
# 动作条件 `create` 会接受任何成功 open 边。GT 规则一般都同时约束了两端内容与顶点种类，
# 这类近似被端点条件兜住；只写单个 action 条件的规则要自己承担这个宽松度。


def _load_action_syscalls():
    """从 verbs.toml 推出 动作名 -> syscall 家族名集合。"""
    verbs_path = ROOT / "parser" / "data" / "verbs.toml"
    if not verbs_path.exists():
        raise RuntimeError(f"缺解析器动词表，无法判定规则动作：{verbs_path}")
    verbs = tomllib.loads(verbs_path.read_text(encoding="utf-8"))["verb"]
    raw = {}
    for verb in verbs:
        name = "mmap_read" if verb["name"] == "mmap" else verb["name"]
        raw.setdefault(name, set()).update(verb["calls"])
    # mmap 的三个动作值共用同一批系统调用
    for action in ("mmap_write", "mmap_exec"):
        raw.setdefault(action, set()).update(raw.get("mmap_read", set()))
    # create 还要收 open 家族（flags 分流在 classify 里）
    raw.setdefault("create", set()).update(OPEN_FAMILY | CREATE_ALWAYS)
    # 网络客体上的读写会被改写成 send / recv
    raw.setdefault("send", set()).update(raw.get("write", set()))
    raw.setdefault("recv", set()).update(raw.get("read", set()))
    return {action: frozenset(canonical_syscall(call) for call in calls)
            for action, calls in raw.items()}


ACTION_TO_SYSCALLS = _load_action_syscalls()


def syscall_matches_actions(syscall, actions):
    """报告边的 syscall 是否落在规则 action 列表里（含动作名展开）。"""
    for action in actions or []:
        if syscall == action or syscall in ACTION_TO_SYSCALLS.get(action, ()):
            return True
    return False

# --------------------------------------------------------------------------- 规则装载


def load_rules(gt):
    """从 GT 取全部规则：[(动作 id, 规则 dict), ...]。没有可能集合时返回 []。"""
    out = []
    for step in gt.get("attack_path", []):
        for rule in step.get("rules", []) or []:
            out.append((step.get("id"), rule))
    return out


# --------------------------------------------------------------------------- 端点条件


def _leaf_matches(node, kind, content):
    content = path_part(content)          # 容器内文件在图里是 `容器ID|路径`，比内容时只看真实路径
    vertex = node.get("vertex", "any")
    if vertex != "any" and kind is not None and vertex not in kind:
        return False
    op = node.get("match", "exact")
    if op == "any":
        return True
    if op == "exact":
        return content == node.get("value")
    if op == "in":
        return content in (node.get("values") or [])
    if op == "path_prefix":
        return content.startswith(node.get("value") or "")
    if op == "path_suffix":
        return content.endswith(node.get("value") or "")
    if op == "path_pattern":
        return re.search(node.get("value") or "", content) is not None
    raise ValueError(f"未知的内容匹配算子: {op}")


def endpoint_matches(node, kind, content):
    """端点条件是否被 (kind, content) 这一端满足；kind 是种类集合或 None（不判定）。"""
    if node is None:
        return False
    for combinator, need in (("none_of", False), ("all_of", True), ("any_of", True)):
        if combinator in node:
            children = node[combinator] or []
            got = [endpoint_matches(c, kind, content) for c in children]
            if combinator == "none_of" and any(got):
                return False
            if combinator == "all_of" and not all(got):
                return False
            if combinator == "any_of" and not any(got):
                return False
    if any(key in node for key in ("vertex", "match", "value", "values")):
        return _leaf_matches(node, kind, content)
    return True


# --------------------------------------------------------------------------- 边属性


def _edge_matches(node, edge_attrs):
    """edge 块里的数值条件（bytes / duration_ns）；拿不到属性时该条件不参与判定，返回 (bool, 是否跳过)。"""
    if not node:
        return True, False
    ops = {
        ">=": lambda a, b: a >= b,
        ">": lambda a, b: a > b,
        "<=": lambda a, b: a <= b,
        "<": lambda a, b: a < b,
        "=": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }
    skipped = False
    for field, cond in node.items():
        if not isinstance(cond, dict) or "op" not in cond:
            continue
        value = (edge_attrs or {}).get(field)
        if value is None:
            skipped = True
            continue
        if not ops[cond["op"]](value, cond["value"]):
            return False, skipped
    return True, skipped


# --------------------------------------------------------------------------- 规则判定


def rule_matches(rule, src, syscall, dst, kinds=None, edge_attrs=None):
    """判断三元关系及当前记录的其他规则属性。"""
    if not syscall_matches_actions(syscall, rule.get("action") or []):
        return False
    ok, _ = _edge_matches(rule.get("edge"), edge_attrs)
    if not ok:
        return False
    sk = kinds.kind_of(src) if kinds is not None else None
    dk = kinds.kind_of(dst) if kinds is not None else None
    src_ok = endpoint_matches(rule.get("source"), sk, src)
    dst_ok = endpoint_matches(rule.get("target"), dk, dst)
    if src_ok and dst_ok:
        return True
    if rule.get("direction") == "either":
        return endpoint_matches(rule.get("source"), dk, dst) and endpoint_matches(rule.get("target"), sk, src)
    return False


# --------------------------------------------------------------------------- 顶点种类


class VertexKinds:
    """内容 -> 可能的顶点种类集合（{"process"}／{"file"}／{"process","file"}／…）。

    同一个内容字符串在图里可能既是进程又是文件（例如 /usr/bin/shred 既是进程、也有同路径的
    文件顶点），所以这里存的是集合而不是单值：端点条件里的 vertex 只要落在这个集合里就算满足；
    取不到种类（空集合）时不判定种类。
    """

    def __init__(self, mapping=None, degraded=False, database=None):
        self.mapping = mapping or {}
        self.degraded = degraded          # True 表示没拿到种类，vertex 条件不参与判定
        self.database = database

    def kind_of(self, content):
        """返回种类集合（frozenset）；查不到返回 None。"""
        return self.mapping.get(path_part(content))

    @classmethod
    def empty(cls, degraded=True, database=None):
        return cls({}, degraded=degraded, database=database)

    @classmethod
    def for_tsg(cls, tsg_path, database=None):
        """从单文件 .tsg 索引直接读取全部顶点的内容与种类（零 Neo4j 依赖）。"""
        import sys
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from tsg.format import TSGReader

        mapping = {}
        try:
            with TSGReader(tsg_path) as reader:
                for _vid, vp in reader.iter_vertices():
                    label = vp.get("kind")
                    kind = _LABEL_TO_KIND.get(label)
                    if not kind:
                        continue
                    content = vp.get("content")
                    if label == "Process":
                        if not content or (content == vp.get("key") and "|" in str(content)):
                            content = "<NA>"
                    if content is not None:
                        mapping.setdefault(content, set()).add(kind)
        except Exception:
            return cls.empty(database=database)
        return cls({k: frozenset(v) for k, v in mapping.items()}, degraded=False, database=database)

    @classmethod
    def for_database(cls, database):
        """从 Neo4j 读全部顶点的内容与种类；连不上就返回空表（degraded）。

        只认 -v2 图模型：Process.exe_path（缺失记 <NA>，与 GT 顶点键一致）、
        File.path、Network.endpoints。
        """
        try:
            from neo4j import GraphDatabase
        except ImportError:
            return cls.empty(database=database)
        uri, auth = _credentials()
        if not uri:
            return cls.empty(database=database)
        query = (
            "MATCH (n) RETURN labels(n)[0] AS label, "
            "CASE labels(n)[0] WHEN 'Process' THEN coalesce(n.exe_path, '<NA>') "
            "WHEN 'File' THEN n.path ELSE n.endpoints END AS key"
        )
        mapping = {}
        try:
            with GraphDatabase.driver(uri, auth=auth) as driver:
                with driver.session(database=database) as session:
                    for record in session.run(query):
                        kind = _LABEL_TO_KIND.get(record["label"])
                        if kind:
                            mapping.setdefault(record["key"], set()).add(kind)
        except Exception:
            return cls.empty(database=database)
        return cls({k: frozenset(v) for k, v in mapping.items()}, degraded=False, database=database)

    @classmethod
    def for_gt(cls, gt, database=None):
        """优先从单文件 graphs/<scenario>.tsg 读取顶点种类，缺失时才回退旧数据库。"""
        scenario = gt.get("scenario")
        db = database or scenario_database(scenario)
        if scenario:
            tsg_file = ROOT / "graphs" / f"{scenario}.tsg"
            if tsg_file.is_file():
                return cls.for_tsg(tsg_file, database=db)
        if not db:
            return cls.empty()
        return cls.for_database(db)


def _credentials():
    """从根 .env 读连接参数；读不到返回 (None, None)。"""
    env = {}
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    uri = env.get("NEO4J_URI")
    if not uri:
        return None, None
    return uri, (env.get("NEO4J_USER", "neo4j"), env.get("NEO4J_PASSWORD", ""))


def gt_path(scenario, gt_dir=None):
    """GT 文件路径：先在 gt_dir（缺省 groundtruth/）里找；找不到就回退 tmp/gt/backup-old/。"""
    base = Path(gt_dir) if gt_dir else ROOT / "groundtruth"
    path = base / f"{scenario}.groundtruth.json"
    if path.exists():
        return path
    alt = ROOT / "tmp" / "gt" / "backup-old" / f"{scenario}.groundtruth.json"
    return alt if alt.exists() else path


def scenario_database(scenario):
    """场景名 -> -v2 库名。

    默认按项目命名规范推导：attack-<场景名小写、下划线换连字符>-v2
    （例：9_Site_Defacement -> attack-9-site-defacement-v2）；
    provenance/config/scenarios.json 里若显式登记了 database，则用它覆盖。
    """
    if not scenario:
        return None
    if SCENARIOS.exists():
        data = json.loads(SCENARIOS.read_text(encoding="utf-8"))
        info = (data.get("scenarios") or {}).get(scenario) or {}
        if info.get("database"):
            return info["database"]
    return "attack-" + scenario.lower().replace("_", "-") + "-v2"


# --------------------------------------------------------------------------- 评分


def evaluate_report(gt_triples, rules, report_triples, kinds=None):
    """按标注步骤计算召回，按 (src, syscall, dst) 计算查准。

    标注行在三元组后携带阶段，报告行可在三元组后携带本条记录的属性。
    """
    report_records = {}
    for edge in report_triples:
        key = tuple(edge[:3])
        attrs = edge[3] if len(edge) > 3 else None
        report_records.setdefault(key, []).append(attrs)

    must_hits, must_misses = [], []
    for step in gt_triples:
        (must_hits if tuple(step[:3]) in report_records else must_misses).append(step)

    rule_hits, rule_misses = [], []
    edge_rule_hits = set()
    edge_attrs_skipped = set()
    for _, rule in rules:
        hit = False
        relation_rule = {**rule, "edge": None}
        for key, records in report_records.items():
            if not rule_matches(relation_rule, *key, kinds=kinds):
                continue
            for attrs in records:
                ok, skipped = _edge_matches(rule.get("edge"), attrs)
                if skipped:
                    edge_attrs_skipped.add(rule["rule_id"])
                if not ok or skipped:
                    continue
                hit = True
                edge_rule_hits.add(key)
        (rule_hits if hit else rule_misses).append(rule)

    correct_edges = {tuple(step[:3]) for step in must_hits} | edge_rule_hits
    extras = sorted(report_records.keys() - correct_edges)
    steps_total = len(gt_triples) + len(rules)
    steps_hit = len(must_hits) + len(rule_hits)
    return {
        "scoring_protocol": SCORING_PROTOCOL,
        "gt_edges": len(gt_triples),
        "rules_total": len(rules),
        "steps_total": steps_total,
        "must_hits": must_hits,
        "must_misses": must_misses,
        "rule_hits": [r["rule_id"] for r in rule_hits],
        "rule_misses": [r["rule_id"] for r in rule_misses],
        "steps_hit": steps_hit,
        "recall_steps": steps_hit / steps_total if steps_total else 0.0,
        "correct_edges": len(correct_edges),
        "reported_triples": len(report_records),
        "precision_edges": len(correct_edges) / len(report_records) if report_records else 0.0,
        "extras": extras,
        "kinds_degraded": bool(kinds is not None and kinds.degraded),
        "edge_attrs_skipped": sorted(edge_attrs_skipped),
    }
