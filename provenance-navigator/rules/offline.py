"""规则模式（离线）：标准答案端点、频繁子图挖掘、对抗蒸馏、规则库冻结。

蒸馏使用与在线相同的 `rules.online.MatchIndex` 谓词，候选池清洗使用
`common.facts.is_static_read_background`，不再导入在线剪枝模块。

`rules/offline.py` 不导入 `closure`：训练候选池必须由调用方通过 `pool_provider` 提供。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from common import config as cfg
from common.facts import TopologyFacts, abstract_node_role, is_static_read_background
from common.graph import process_content_or_na, split_container, split_process_id
from rules.online import MatchIndex, _key

REPO_ROOT = cfg.REPO_ROOT


# ==== 1. 标准答案端点 ====

_KEY_KINDS = {"p": "Process", "f": "File", "n": "Network"}


class EndpointFormatError(ValueError):
    """端点不是最新标准答案的写法。"""


@dataclass(frozen=True)
class Endpoint:
    kind: str          # "Process" | "File" | "Network"
    host: str
    container: str     # 网络端点没有容器，记 "host"
    content: str


def parse_gt(node: Any) -> Endpoint:
    """严格解析标准答案端点；不是 `p:/f:/n:` 新写法就抛 EndpointFormatError。"""
    s = "" if node is None else str(node)
    if len(s) < 4 or s[0] not in _KEY_KINDS or s[1] != ":":
        raise EndpointFormatError(f"不是标准答案端点写法（应以 p:/f:/n: 开头）：{s!r}")
    if s.count(":") < 2:
        raise EndpointFormatError(f"标准答案端点缺少内容段（应形如 p:主机/容器:内容）：{s!r}")
    kind = _KEY_KINDS[s[0]]
    token, content = s.split(":", 2)[1], s.split(":", 2)[2]
    if kind == "Network":
        if not token:
            raise EndpointFormatError(f"网络端点缺少主机段：{s!r}")
        return Endpoint(kind="Network", host=token, container="host", content=content)
    if "/" not in token:
        raise EndpointFormatError(f"{kind} 端点缺少“主机/容器”段：{s!r}")
    host, container = token.split("/", 1)
    if not host:
        raise EndpointFormatError(f"{kind} 端点主机段为空：{s!r}")
    return Endpoint(kind=kind, host=host, container=container or "host", content=content)


def render_gt(kind: str, host: str, container: str, content: str) -> str:
    """用图里的字段拼出与标准答案完全一致的端点字符串。"""
    if kind == "Network":
        return f"n:{host}:{content}"
    if kind not in ("Process", "File"):
        raise ValueError(f"未知端点种类：{kind!r}")
    return f"{kind[0].lower()}:{host}/{container or 'host'}:{content}"


def endpoint_of_content(kind: str, content: Any, host: str,
                        process_id: Any = None) -> str:
    """把一个图侧端点（内容 + 主机，进程可带标识）拼成标准答案写法。"""
    if kind == "Process":
        return render_gt("Process", host, split_process_id(process_id)[1],
                         process_content_or_na(content, process_id))
    if kind == "File":
        container, path = split_container(content)
        return render_gt("File", host, container, path)
    return render_gt("Network", host, "host", "" if content is None else str(content))


def strict_gt_key(node: Any, scenario: str) -> str:
    """标准答案端点 → 规范键。只认最新写法，不合规直接抛错。"""
    try:
        ep = parse_gt(node)
    except EndpointFormatError as exc:
        raise ValueError(f"场景 {scenario} 的标准答案端点不合规：{exc}") from exc
    return render_gt(ep.kind, ep.host, ep.container, ep.content)


def _endpoint_keys(label: str, content: Any, process_ids: List[str], hosts: Set[str]) -> Set[str]:
    """图侧一个端点 → 标准答案写法的候选键。"""
    if label == "Process":
        keys = set()
        for pid in process_ids:
            host, container = split_process_id(pid)
            if host:
                keys.add(render_gt("Process", host, container,
                                   process_content_or_na(content, pid)))
        if keys:
            return keys
        return {render_gt("Process", host, "host", process_content_or_na(content, None))
                for host in hosts}
    if label == "File":
        container, path = split_container(content)
        return {render_gt("File", host, container, path) for host in hosts}
    if label == "Network":
        return {render_gt("Network", host, "host", "" if content is None else str(content))
                for host in hosts}
    return set()


def keyed_variants(edge: Dict[str, Any]) -> Set[Tuple[str, str, str]]:
    """一条折叠候选边 → 标准答案写法下的全部候选三元组。"""
    syscall = str(edge.get("syscall") or "")
    src_label = str(edge.get("src_label") or "")
    dst_label = str(edge.get("dst_label") or "")

    def _pids(value: Any) -> List[str]:
        out = []
        for item in value or []:
            if isinstance(item, (list, tuple)) and len(item) >= 2 and str(item[0]) == "Process":
                out.append(str(item[1]))
        return out

    src_ids = _pids(edge.get("src_identities"))
    dst_ids = _pids(edge.get("dst_identities"))
    hosts = set()
    for pid in src_ids + dst_ids:
        host, _ = split_process_id(pid)
        if host:
            hosts.add(host)
    if not hosts:
        return set()
    src_keys = _endpoint_keys(src_label, edge.get("src"), src_ids, hosts)
    dst_keys = _endpoint_keys(dst_label, edge.get("dst"), dst_ids, hosts)
    return {(src, syscall, dst) for src in src_keys for dst in dst_keys}


# ==== 2. 频繁子图挖掘 ====

class FrequentSubgraphMiner:
    """频繁因果子图自动挖掘器。"""

    def __init__(self, min_support: int = 1):
        self.min_support = min_support

    def load_gt_graph(self, scenario: str) -> List[Dict[str, Any]]:
        gt_file = REPO_ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
        if not gt_file.exists():
            raise FileNotFoundError(f"未找到场景标准答案文件: {gt_file}")
        with open(gt_file, "r", encoding="utf-8") as f:
            gt = json.load(f)
        edges = []
        for phase in gt.get("attack_path", []):
            for e in phase.get("edges", []) or []:
                try:
                    src = parse_gt(e.get("src")).content
                    dst = parse_gt(e.get("dst")).content
                except EndpointFormatError as exc:
                    raise ValueError(f"场景 {scenario} 的标准答案端点不合规：{exc}") from exc
                edges.append({
                    "src": src,
                    "syscall": str(e.get("syscall")),
                    "dst": dst,
                    "phase": phase.get("id"),
                })
        return edges

    def mine(self, train_scenarios: List[str]) -> List[Dict[str, Any]]:
        scenario_graphs: Dict[str, List[Dict[str, Any]]] = {
            sc: self.load_gt_graph(sc) for sc in train_scenarios
        }

        pattern_scenarios_1hop: Dict[Tuple, Set[str]] = defaultdict(set)
        for sc, edges in scenario_graphs.items():
            for e in edges:
                src_role = abstract_node_role(e["src"], edges)
                dst_role = abstract_node_role(e["dst"], edges)
                pattern_scenarios_1hop[(src_role, e["syscall"], dst_role)].add(sc)

        pattern_scenarios_2hop: Dict[Tuple, Set[str]] = defaultdict(set)
        for sc, edges in scenario_graphs.items():
            out_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for e in edges:
                out_edges[e["src"]].append(e)
            for e1 in edges:
                mid = e1["dst"]
                for e2 in out_edges.get(mid, []):
                    r_src = abstract_node_role(e1["src"], edges)
                    r_mid = abstract_node_role(mid, edges)
                    r_dst = abstract_node_role(e2["dst"], edges)
                    pattern_scenarios_2hop[(r_src, e1["syscall"], r_mid, e2["syscall"], r_dst)].add(sc)

        mined_motifs: List[Dict[str, Any]] = []
        motif_counter = 1
        for (r_src, sc, r_dst), scs in pattern_scenarios_1hop.items():
            if len(scs) >= self.min_support:
                if r_src == "GENERIC_PROC_OR_FILE" and r_dst == "GENERIC_PROC_OR_FILE":
                    continue
                mined_motifs.append({
                    "id": f"MINED_{motif_counter:02d}_1HOP_{sc.upper()}",
                    "name": f"自动挖掘1跳骨架: {r_src} --{sc}--> {r_dst}",
                    "hops": 1,
                    "src_role": r_src,
                    "syscalls": [sc],
                    "dst_role": r_dst,
                    "mined_support_scenarios": len(scs),
                    "support_scenarios_list": sorted(list(scs)),
                })
                motif_counter += 1

        for (r_src, sc1, r_mid, sc2, r_dst), scs in pattern_scenarios_2hop.items():
            if len(scs) >= self.min_support:
                mined_motifs.append({
                    "id": f"MINED_{motif_counter:02d}_2HOP_CHAIN",
                    "name": f"自动挖掘2跳因果链: {r_src} --{sc1}--> {r_mid} --{sc2}--> {r_dst}",
                    "hops": 2,
                    "chain": [
                        {"src_role": r_src, "syscall": sc1, "dst_role": r_mid},
                        {"src_role": r_mid, "syscall": sc2, "dst_role": r_dst},
                    ],
                    "syscalls": [sc1, sc2],
                    "mined_support_scenarios": len(scs),
                    "support_scenarios_list": sorted(list(scs)),
                })
                motif_counter += 1

        return mined_motifs


# ==== 3. 离线蒸馏 ====

class OfflineDistiller:
    """离线知识蒸馏器：三值标签 + 贝叶斯经验提升度准入。"""

    def __init__(self, min_support: int = 1, min_lift: float = 3.0, m0: float = 2.0,
                 engine: Optional[str] = None, rule_matcher: Any = None):
        self.min_support = min_support
        self.min_lift = min_lift
        self.m0 = m0
        self.engine = engine or os.environ.get("DISTILL_ENGINE", "fast")
        if self.engine not in ("fast", "legacy"):
            raise ValueError(f"未知试模引擎：{self.engine!r}（只允许 fast / legacy）")
        self.rule_matcher = rule_matcher
        self.candidate_motifs: List[Dict[str, Any]] = []
        self.last_report: Dict[str, Any] = {}

    def _rm(self) -> Any:
        if self.rule_matcher is None:
            raise RuntimeError(
                "离线蒸馏必须提供 rule_matcher（tools/rules_match 适配器）；"
                "由 pipeline.load_rule_matcher() 或调用方注入"
            )
        return self.rule_matcher

    def _load_train_positive(self, scenario: str) -> Tuple[Set[Tuple[str, str, str]], list, Any]:
        """训练场景正样本（必须条目）与人工规则（忽略集）。"""
        gt_file = REPO_ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
        if not gt_file.exists():
            raise FileNotFoundError(f"训练场景标准答案缺失，无法蒸馏：{gt_file}")
        with open(gt_file, "r", encoding="utf-8") as f:
            gt = json.load(f)
        pos = set()
        for ph in gt.get("attack_path", []):
            for e in ph.get("edges", []) or []:
                pos.add((strict_gt_key(e.get("src"), scenario), str(e.get("syscall")),
                         strict_gt_key(e.get("dst"), scenario)))
        rm = self._rm()
        return pos, rm.load_rules(gt), rm.VertexKinds.for_gt(gt)

    @staticmethod
    def _load_pool(scenario: str,
                   pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None
                   ) -> List[Dict[str, Any]]:
        """训练候选池必须由调用方提供；本模块不导入闭包模块。"""
        if pool_provider is None:
            raise ValueError("离线蒸馏必须提供 pool_provider（训练候选池）；本模块不自行连接图数据库")
        edges = pool_provider(scenario)
        if not edges:
            raise RuntimeError(f"训练候选池为空，无法蒸馏：{scenario}")
        return list(edges)

    def distill(self, train_scenarios: List[str],
                pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                prepared_cache: Optional[Dict[str, Dict[str, Any]]] = None
                ) -> List[Dict[str, Any]]:
        if not train_scenarios:
            raise ValueError("离线蒸馏必须提供训练场景（禁止空训练集静默放行）")

        miner = FrequentSubgraphMiner(min_support=self.min_support)
        candidate_motifs = miner.mine(train_scenarios)
        self.candidate_motifs = candidate_motifs

        train_data = []
        for sc in train_scenarios:
            cached = prepared_cache.get(sc) if prepared_cache is not None else None
            if cached is not None:
                train_data.append(cached)
                continue
            pos_set, rules, kinds = self._load_train_positive(sc)
            raw_cands = self._load_pool(sc, pool_provider)
            tf = TopologyFacts(raw_cands)
            clean_cands = [e for e in raw_cands if not is_static_read_background(e, tf)]
            train_data.append({
                "scenario": sc,
                "pos_set": pos_set,
                "rules": rules,
                "kinds": kinds,
                "cands": clean_cands,
                "tf": tf,
                "ctx": MatchIndex(clean_cands, tf),
            })

        def classify(e: Dict[str, Any], item: Dict[str, Any]) -> str:
            t = (e.get("src"), e.get("syscall"), e.get("dst"))
            if keyed_variants(e) & item["pos_set"]:
                return "pos"
            rm = self._rm()
            if any(rm.rule_matches(r, t[0], t[1], t[2], kinds=item["kinds"])
                   for _, r in item["rules"]):
                return "ignore"
            return "neg"

        for item in train_data:
            item["labels"] = {_key(e): classify(e, item) for e in item["cands"]}
            item["label_counts"] = {
                "pos": sum(1 for v in item["labels"].values() if v == "pos"),
                "ignore": sum(1 for v in item["labels"].values() if v == "ignore"),
                "neg": sum(1 for v in item["labels"].values() if v == "neg"),
            }
        if prepared_cache is not None:
            for item in train_data:
                prepared_cache.setdefault(item["scenario"], item)

        prior_pos = sum(item["label_counts"]["pos"] for item in train_data)
        prior_ign = sum(item["label_counts"]["ignore"] for item in train_data)
        prior_neg = sum(item["label_counts"]["neg"] for item in train_data)
        gt_must_total = sum(len(item["pos_set"]) for item in train_data)
        per_scenario_pos = ", ".join(
            f"{item['scenario']}={item['label_counts']['pos']}" for item in train_data
        )
        if prior_pos != gt_must_total:
            print(f"  [蒸馏告警] 池内正样本 {prior_pos} 条 ≠ 标准答案必须条目 {gt_must_total} 条"
                  f"（存在不在候选池内的必须条目），先验按池内口径计算；逐场景命中：{per_scenario_pos}")
        if prior_pos == 0:
            raise RuntimeError(
                f"训练池里一条正样本都没命中（GT 必须条目合计 {gt_must_total} 条），蒸馏中止："
                "先验概率为 0，无法计算提升度。\n"
                f"  各训练场景命中数：{per_scenario_pos}\n"
                "  先查两边写法是否同一口径，再查候选池是否覆盖必须条目。"
            )
        pi = prior_pos / (prior_pos + prior_neg) if (prior_pos + prior_neg) > 0 else 0.005
        m0 = self.m0

        distilled_motifs: List[Dict[str, Any]] = []
        considered: List[Dict[str, Any]] = []

        for motif in candidate_motifs:
            tot_pos = 0
            tot_neg = 0
            tot_ign = 0
            sc_hits = 0

            for item in train_data:
                labels = item["labels"]
                matched_dict = item["ctx"].match([motif], min_conf=0.0)
                p_hit = 0
                n_ign = 0
                for k in matched_dict:
                    identity = labels.get(k, "neg")
                    if identity == "pos":
                        p_hit += 1
                    elif identity == "ignore":
                        n_ign += 1
                n_hit = len(matched_dict) - p_hit - n_ign
                if p_hit > 0:
                    sc_hits += 1
                tot_pos += p_hit
                tot_neg += n_hit
                tot_ign += n_ign

            precision = tot_pos / (tot_pos + tot_neg) if (tot_pos + tot_neg) > 0 else 0.0
            if tot_pos >= 1:
                p_bayes = (tot_pos + m0 * pi) / (tot_pos + tot_neg + m0)
                lift = p_bayes / pi
            else:
                p_bayes = (m0 * pi) / (tot_neg + m0)
                lift = p_bayes / pi
            passed = (tot_pos >= 1 and lift >= self.min_lift)

            considered.append({
                "id": motif["id"],
                "name": motif.get("name", ""),
                "positive_hits": tot_pos,
                "negative_alarms": tot_neg,
                "ignored_edges": tot_ign,
                "support_scenarios": sc_hits,
                "train_precision": round(precision, 6),
                "bayes_precision": round(p_bayes, 6),
                "bayes_lift": round(lift, 4),
                "passed": passed,
            })

            if passed:
                distilled = dict(motif)
                distilled["train_support_scenarios"] = sc_hits
                distilled["train_positive_hits"] = tot_pos
                distilled["train_negative_alarms"] = tot_neg
                distilled["train_ignored_edges"] = tot_ign
                distilled["train_precision"] = precision
                distilled["bayes_precision"] = p_bayes
                distilled["lift"] = lift
                distilled_motifs.append(distilled)

        self.last_report = {
            "train_scenarios": list(train_scenarios),
            "pool_source": "provided_in_run",
            "label_scheme": "three_valued(pos=must_entries, ignore=gt_rule_matched, neg=rest)",
            "thresholds": {
                "min_support": self.min_support,
                "m0_smoothing": self.m0,
                "prior_pi": round(pi, 6),
                "prior_components": {
                    "pool_positives": prior_pos,
                    "pool_ignored": prior_ign,
                    "pool_negatives": prior_neg,
                    "gt_must_entries": gt_must_total,
                },
                "min_lift": self.min_lift,
                "min_tp": 1,
            },
            "pool_engine": self.engine,
            "mined_raw_count": len(candidate_motifs),
            "distilled_count": len(distilled_motifs),
            "pool_sizes": {item["scenario"]: len(item["cands"]) for item in train_data},
            "positive_sizes": {item["scenario"]: len(item["pos_set"]) for item in train_data},
            "label_counts": {item["scenario"]: item["label_counts"] for item in train_data},
            "considered": considered,
            "distilled_ids": [m["id"] for m in distilled_motifs],
        }
        return distilled_motifs


# ==== 4. 规则库冻结 ====

SCHEMA = 2
LIBRARY_NAME = "rules-library.json"

def _code_files() -> tuple[str, ...]:
    """按目录自动收集蒸馏相关源码；新增/删除文件会直接改变指纹。"""
    nav = cfg.NAVIGATOR_DIR
    collected: list[str] = []
    for pattern in ("rules/*.py", "closure/*.py", "common/facts.py", "common/graph.py",
                    "routing/filters.py"):
        for path in sorted(nav.glob(pattern)):
            if path.name == "__init__.py":
                continue
            collected.append(str(path.relative_to(cfg.REPO_ROOT)).replace("\\", "/"))
    external = (
        "provenance-navigator/config/closure_rules.json",
        "tools/rules_match.py",
        "provenance-parser/provenance/core/syscalls.py",
        "provenance-parser/provenance/core/paths.py",
        "provenance-parser/provenance/core/kinds.py",
        "provenance-parser/provenance/graph/objects.py",
        "provenance-parser/provenance/graph/emitter.py",
        "provenance-parser/provenance/graph/state/proc.py",
        "provenance-parser/provenance/graph/state/fds.py",
    )
    return tuple(dict.fromkeys(collected + list(external)))


_CODE_FILES = _code_files()


def dir_path() -> Path:
    return cfg.CONFIG_DIR


def library_path() -> Path:
    return dir_path() / LIBRARY_NAME


def library_exists() -> bool:
    return library_path().is_file()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(train_scenarios: Iterable[str]) -> Dict[str, Any]:
    gt: Dict[str, str] = {}
    for sc in sorted(train_scenarios):
        path = REPO_ROOT / "groundtruth" / f"{sc}.groundtruth.json"
        if not path.is_file():
            raise RuntimeError(f"场景标准答案缺失，无法校验规则库：{path}")
        gt[sc] = _sha256_file(path)

    code: Dict[str, str] = {}
    for rel in _CODE_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            raise RuntimeError(f"指纹所需源码缺失：{path}")
        code[rel] = _sha256_file(path)

    scenarios_json = cfg.SCENARIOS_FILE
    if not scenarios_json.is_file():
        raise RuntimeError(f"场景清单缺失，无法校验规则库：{scenarios_json}")

    components = {"gt": gt, "code": code, "scenarios_json": _sha256_file(scenarios_json)}
    canonical = json.dumps(components, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {"digest": hashlib.sha256(canonical).hexdigest(), "components": components}


def _diff(recorded: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
    diffs: List[str] = []
    rec_comp, cur_comp = recorded.get("components") or {}, current.get("components") or {}
    for group in ("gt", "code"):
        rec, cur = rec_comp.get(group) or {}, cur_comp.get(group) or {}
        for key in sorted(set(rec) | set(cur)):
            if rec.get(key) != cur.get(key):
                diffs.append(f"{group}:{key}")
    if rec_comp.get("scenarios_json") != cur_comp.get("scenarios_json"):
        diffs.append("config/scenarios.json")
    return diffs


def save_library(patterns: List[Dict[str, Any]], report: Dict[str, Any],
                 train_scenarios: List[str]) -> Path:
    if not train_scenarios:
        raise ValueError("规则库必须提供训练场景（禁止空训练集）")
    payload = {
        "schema": SCHEMA,
        "train_scenarios": list(train_scenarios),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "fingerprint": fingerprint(train_scenarios),
        "thresholds": report.get("thresholds", {}),
        "pool_engine": report.get("pool_engine"),
        "pool_sizes": report.get("pool_sizes", {}),
        "label_counts": report.get("label_counts", {}),
        "positive_sizes": report.get("positive_sizes", {}),
        "mined_raw_count": report.get("mined_raw_count"),
        "considered": report.get("considered", []),
        "distilled_ids": [m["id"] for m in patterns],
        "patterns": patterns,
    }
    out = library_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(out)
    return out


def load_library() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """读规则库：返回（规则清单, 审计信息）。缺文件或指纹不符一律阻断。"""
    path = library_path()
    if not path.is_file():
        raise RuntimeError(
            f"缺少规则库：{path}\n"
            f"  先生成：python provenance-navigator/run_leave_one_out.py --mode rules "
            f"--rules-from fresh --freeze --freeze-only"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA:
        raise RuntimeError(f"规则库 schema 不匹配：{path} 是 {payload.get('schema')!r}，本版要求 {SCHEMA}")

    recorded_train = list(payload.get("train_scenarios") or [])
    current = fingerprint(recorded_train)
    if payload.get("fingerprint", {}).get("digest") != current["digest"]:
        diffs = _diff(payload.get("fingerprint", {}), current)
        reason = ", ".join(diffs) if diffs else "指纹摘要本身不一致（分项未变，文件被改动过）"
        raise RuntimeError(
            f"规则库已失效（指纹不匹配）：{path}\n  变化的输入：{reason}\n"
            f"  重建：python provenance-navigator/run_leave_one_out.py --mode rules "
            f"--rules-from fresh --freeze --freeze-only"
        )

    patterns = payload.get("patterns") or []
    audit = {
        "path": str(path),
        "train_scenarios": recorded_train,
        "generated_at": payload.get("generated_at"),
        "fingerprint": payload.get("fingerprint", {}).get("digest"),
        "thresholds": payload.get("thresholds", {}),
        "pool_engine": payload.get("pool_engine"),
        "pool_sizes": payload.get("pool_sizes", {}),
        "label_counts": payload.get("label_counts", {}),
        "positive_sizes": payload.get("positive_sizes", {}),
        "mined_raw_count": payload.get("mined_raw_count"),
        "considered": payload.get("considered", []),
        "distilled_ids": payload.get("distilled_ids", []),
    }
    return patterns, audit
