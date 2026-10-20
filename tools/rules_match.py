#!/usr/bin/env python
"""规则（可能集合）匹配：把标准答案里的规则条件落到一条边上，判定是否命中。

规则形式写在 GT 文件的 `rule_form` 里，口径见 `docs/攻击路径评分口径.md`。

规则形状（三段条件）：

    {
      "rule_id": "R1",
      "direction": "src_to_dst" | "either",
      "action": ["write", "rename", ...],
      "source": <端点条件>,
      "target": <端点条件>,
      "edge": {"bytes": {"op": ">=", "value": 1024}},   # 可选，本模块按实例属性判定
      "covered_triples": 478                            # 只记账，不参与判定
    }

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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "provenance-navigator" / "config" / "scenarios.json"

_LABEL_TO_KIND = {"Process": "process", "File": "file", "Network": "network"}

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
    """一条报告边是否命中该规则。kinds 为 VertexKinds（或 None）；edge_attrs 为实例属性（可缺）。"""
    if syscall not in (rule.get("action") or []):
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
        return self.mapping.get(content)

    @classmethod
    def empty(cls, degraded=True, database=None):
        return cls({}, degraded=degraded, database=database)

    @classmethod
    def for_database(cls, database):
        """从 Neo4j 读全部顶点的内容与种类；连不上就返回空表（degraded）。"""
        try:
            from neo4j import GraphDatabase
        except ImportError:
            return cls.empty(database=database)
        uri, auth = _credentials()
        if not uri:
            return cls.empty(database=database)
        # 内容口径与评分一致：进程取可执行文件路径（无则名字），文件取路径，网络取 network_id
        query = (
            "MATCH (n) RETURN labels(n)[0] AS label, "
            "CASE labels(n)[0] WHEN 'Process' THEN coalesce(n.exepath, n.name) "
            "WHEN 'File' THEN coalesce(n.file_id, n.path) ELSE n.network_id END AS key"
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
        """按 GT 的 scenario 找场景库（provenance-navigator/config/scenarios.json），读顶点种类。"""
        db = database or scenario_database(gt.get("scenario"))
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
    if not scenario or not SCENARIOS.exists():
        return None
    data = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    info = (data.get("scenarios") or {}).get(scenario) or {}
    return info.get("database")


# --------------------------------------------------------------------------- 评分


def evaluate_report(gt_triples, rules, report_triples, kinds=None):
    """按 docs/攻击路径评分口径.md 算命中：召回按步骤（条目 + 规则），查准按边。

    gt_triples: [(src, syscall, dst, phase), ...]（必须集合条目）
    rules:      [(动作 id, 规则), ...]（可能集合）
    report_triples: [(src, syscall, dst), ...]（报告去重后的内容三元组）
    """
    report_keys = set(report_triples)
    must_hits = [t for t in gt_triples if (t[0], t[1], t[2]) in report_keys]
    must_misses = [t for t in gt_triples if (t[0], t[1], t[2]) not in report_keys]
    must_keys = {(t[0], t[1], t[2]) for t in gt_triples}

    rule_hits, rule_misses = [], []
    edge_rule_hits = set()
    edge_attrs_skipped = set()
    for step_id, rule in rules:
        hit = False
        for edge in report_triples:
            _, skipped = _edge_matches(rule.get("edge"), None)
            if skipped and rule.get("edge"):
                edge_attrs_skipped.add(rule["rule_id"])
            if rule_matches(rule, edge[0], edge[1], edge[2], kinds=kinds):
                hit = True
                edge_rule_hits.add(edge)
        (rule_hits if hit else rule_misses).append(rule)
    rule_hits = [r for r in rule_hits]

    correct_edges = (report_keys & must_keys) | edge_rule_hits
    extras = sorted(report_keys - correct_edges)
    steps_total = len(gt_triples) + len(rules)
    steps_hit = len(must_hits) + len(rule_hits)
    return {
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
        "reported_triples": len(report_keys),
        "precision_edges": len(correct_edges) / len(report_keys) if report_keys else 0.0,
        "extras": extras,
        "kinds_degraded": bool(kinds is not None and kinds.degraded),
        "edge_attrs_skipped": sorted(edge_attrs_skipped),
    }
