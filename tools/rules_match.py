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

`effect` 条件：报告边带成败时按 success/failure 严格判定；报告边不带成败时**不否决**该边，
但由 evaluate_report 记入 `effect_unchecked`，调用方必须把这一点显示出来。

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
sys.path.insert(0, str(ROOT / "provenance-parser"))
sys.path.insert(0, str(ROOT / "provenance-navigator"))

from provenance.core.syscalls import (  # noqa: E402
    CREATE_ALWAYS, OPEN_FAMILY, canonical_syscall,
)
from domain.keys import path_part  # noqa: E402

SCENARIOS = ROOT / "provenance-navigator" / "config" / "scenarios.json"

_LABEL_TO_KIND = {"Process": "process", "File": "file", "Network": "network"}

# 图上的动作名 -> 该动作可能落在哪些 syscall 上（家族基本名）。
#
# 事实来源是解析器自己的动词表 provenance-parser/data/verbs.toml（调用 -> 动作），
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
    verbs_path = ROOT / "provenance-parser" / "data" / "verbs.toml"
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


def rule_matches(rule, src, syscall, dst, kinds=None, edge_attrs=None,
                 effect=None):
    """一条报告边是否命中该规则。

    effect 为 success/failure/None（报告未给）。特定 effect 规则遇到未知 effect 时不否决，
    由 evaluate_report 记入 effect_unchecked 披露。
    """
    if not syscall_matches_actions(syscall, rule.get("action") or []):
        return False
    wanted_effect = rule.get("effect") or "any"
    if wanted_effect != "any" and effect is not None and effect != wanted_effect:
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
    """场景名 -> -v2 库名。

    默认按项目命名规范推导：attack-<场景名小写、下划线换连字符>-v2
    （例：9_Exposed_Container_Escape -> attack-9-exposed-container-escape-v2）；
    provenance-navigator/config/scenarios.json 里若显式登记了 database，则用它覆盖。
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
    """算命中：召回按步骤（条目 + 规则），查准按四元组 (src, syscall, dst, effect)。

    gt_triples:     [(src, syscall, dst, effect, phase), ...]（必须集合条目；effect 可为 None）
    rules:          [(动作 id, 规则), ...]（可能集合）
    report_triples: [(src, syscall, dst, effect[, attrs]), ...]；effect 为 None 表示报告侧没有成败证据

    成败判等：两侧都有值时必须相等；任一侧为空时按三元命中并在输出里披露出「成败未核」的条数。
    """
    report_keys = []
    seen = set()
    report_effects = {}
    report_attrs = {}
    for edge in report_triples:
        src, syscall, dst = edge[0], edge[1], edge[2]
        effect = None
        attrs = None
        if len(edge) > 3:
            if isinstance(edge[3], dict):
                attrs = edge[3]
            else:
                effect = edge[3]
        if len(edge) > 4 and isinstance(edge[4], dict):
            attrs = edge[4]
        key = (src, syscall, dst, effect)
        if key not in seen:
            seen.add(key)
            report_keys.append(key)
        report_effects.setdefault((src, syscall, dst), set()).add(effect)
        if attrs is not None:
            report_attrs[key] = attrs

    gt_effects = {}
    for t in gt_triples:
        gt_effects.setdefault((t[0], t[1], t[2]), set()).add(t[3] if len(t) > 3 else None)

    must_hits, must_misses = [], []
    effect_unchecked_gt = 0
    for t in gt_triples:
        triple = (t[0], t[1], t[2])
        gt_effect = t[3] if len(t) > 3 else None
        effects = report_effects.get(triple)
        if effects is None:
            must_misses.append(t)
            continue
        if gt_effect is None or None in effects:
            must_hits.append(t)
            effect_unchecked_gt += 1
        elif gt_effect in effects:
            must_hits.append(t)
        else:
            must_misses.append(t)

    rule_hits, rule_misses = [], []
    edge_rule_hits = set()
    edge_attrs_skipped = set()
    effect_unchecked = set()
    for step_id, rule in rules:
        hit = False
        for key in report_keys:
            src, syscall, dst, effect = key
            attrs = report_attrs.get(key)
            if rule.get("edge"):
                _, skipped = _edge_matches(rule["edge"], attrs)
                if skipped:
                    edge_attrs_skipped.add(rule["rule_id"])
            if rule_matches(rule, src, syscall, dst, kinds=kinds,
                            edge_attrs=attrs, effect=effect):
                hit = True
                edge_rule_hits.add(key)
                if (rule.get("effect") or "any") != "any" and effect is None:
                    effect_unchecked.add(rule["rule_id"])
        (rule_hits if hit else rule_misses).append(rule)
    rule_hits = [r for r in rule_hits]

    correct_edges = set()
    for key in report_keys:
        triple, report_effect = key[:3], key[3]
        gt_side = gt_effects.get(triple)
        if not gt_side:
            continue
        if report_effect is None or None in gt_side:
            correct_edges.add(key)
        elif report_effect in gt_side:
            correct_edges.add(key)
    correct_edges |= edge_rule_hits
    effect_unchecked_edges = sum(1 for k in correct_edges if k[3] is None)
    extras = sorted(set(report_keys) - correct_edges, key=lambda k: (k[0], k[1], k[2], k[3] or ""))
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
        "effect_unchecked": sorted(effect_unchecked),
        "effect_unchecked_gt": effect_unchecked_gt,
        "effect_unchecked_edges": effect_unchecked_edges,
    }
