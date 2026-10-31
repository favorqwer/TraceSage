"""规则模式（离线）：标准答案端点、频繁子图挖掘、对抗蒸馏、规则库冻结。

蒸馏使用与在线相同的 `rules.online.MatchIndex` 谓词，候选池清洗使用
`common.facts.is_static_read_background`，不再导入在线剪枝模块。

`rules/offline.py` 不导入 `closure`：训练候选池必须由调用方通过 `pool_provider` 提供。
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

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

    def mine(self, scenario_pos_edges: Dict[str, List[Dict[str, Any]]],
             contexts: Dict[str, Any], cuts: Any) -> List[Dict[str, Any]]:
        """从每个场景的攻击边枚举 1 跳/2 跳形态。

        入参的边与角色上下文来自同一个候选池，端点字符串天然一致，
        不会出现「标准答案格式查不到候选池统计」的问题。
        """
        from common.roles import role_map

        tables = {sc: role_map(contexts[sc], cuts) for sc in scenario_pos_edges}
        self.last_cuts = cuts

        pattern_scenarios_1hop: Dict[Tuple, Set[str]] = defaultdict(set)
        for sc, edges in scenario_pos_edges.items():
            table = tables[sc]
            def role_of(ep: str) -> str:
                r = table.get(ep)
                if r is None:
                    r = abstract_node_role(ep, edges)
                return r
            for e in edges:
                pattern_scenarios_1hop[(role_of(e["src"]), e["syscall"], role_of(e["dst"]))].add(sc)

        pattern_scenarios_2hop: Dict[Tuple, Set[str]] = defaultdict(set)
        for sc, edges in scenario_pos_edges.items():
            table = tables[sc]
            def role_of(ep: str) -> str:
                r = table.get(ep)
                if r is None:
                    r = abstract_node_role(ep, edges)
                return r
            out_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for e in edges:
                out_edges[e["src"]].append(e)
            for e1 in edges:
                mid = e1["dst"]
                for e2 in out_edges.get(mid, []):
                    pattern_scenarios_2hop[(role_of(e1["src"]), e1["syscall"], role_of(mid),
                                            e2["syscall"], role_of(e2["dst"]))].add(sc)

        mined_motifs: List[Dict[str, Any]] = []
        motif_counter = 1
        for (r_src, sc, r_dst), scs in pattern_scenarios_1hop.items():
            if len(scs) < self.min_support:
                continue
            if _is_generic(r_src) and _is_generic(r_dst):
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
            if len(scs) < self.min_support:
                continue
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


def _is_generic(role: str) -> bool:
    """泛化角色：旧口径的 GENERIC，或新编码里"无任何结构信息"的端点。"""
    return role == "GENERIC_PROC_OR_FILE"


def motif_signature(m: Dict[str, Any]) -> Tuple:
    """提取因果基模的规范拓扑指纹，用于去重、对齐与防 ID 碰撞。"""
    hops = m.get("hops", 1)
    if hops == 1:
        scs = tuple(sorted(m.get("syscalls", [])))
        return (1, m.get("src_role"), scs, m.get("dst_role"))
    else:
        chain = m.get("chain", [])
        if chain:
            chain_tuple = tuple((step.get("src_role"), step.get("syscall"), step.get("dst_role")) for step in chain)
            return (2, chain_tuple)
        scs = tuple(sorted(m.get("syscalls", [])))
        return (2, m.get("src_role"), scs, m.get("dst_role"))


# ==== 3. 离线蒸馏（覆盖表 + 边际查准率贪心） ====

class OfflineDistiller:
    """规则库构建器：覆盖表 + 边际查准率贪心。

    三个入口：
      build_all()  全量建库（抽全部场景闭包 → 建覆盖表 → 选名单）
      ingest()     接入一个场景（只查它一次图 → 追加覆盖表 → 补新形态位图 → 选名单）
      reselect()   只重算名单（读覆盖表 → 贪心，约 0.1 秒）

    准入不含任何数值阈值：选谁由边际查准率比较决定，何时停由「没有新攻击边」决定。
    """

    def __init__(self, min_support: int = 1, rule_matcher: Any = None):
        self.min_support = min_support
        self.rule_matcher = rule_matcher
        self.last_report: Dict[str, Any] = {}

    def _rm(self) -> Any:
        if self.rule_matcher is None:
            raise RuntimeError(
                "离线蒸馏必须提供 rule_matcher（tools/rules_match 适配器）；"
                "由 pipeline.load_rule_matcher() 或调用方注入"
            )
        return self.rule_matcher

    # ---------- 单场景准备 ----------

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

    def prepare_scenario(self, scenario: str,
                         pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None
                         ) -> Dict[str, Any]:
        """抽候选池、剥离静态只读背景、打三值标签。返回可直接装进覆盖表的素材。"""
        pos_set, rules, kinds = self._load_train_positive(scenario)
        raw_cands = self._load_pool(scenario, pool_provider)
        tf = TopologyFacts(raw_cands)
        clean = [e for e in raw_cands if not is_static_read_background(e, tf)]
        rm = self._rm()

        def classify(e: Dict[str, Any]) -> str:
            t = (e.get("src"), e.get("syscall"), e.get("dst"))
            if keyed_variants(e) & pos_set:
                return "pos"
            if any(rm.rule_matches(r, t[0], t[1], t[2], kinds=kinds) for _, r in rules):
                return "ignore"
            return "neg"

        labels = {_key(e): classify(e) for e in clean}
        return {"scenario": scenario, "edges": clean, "labels": labels,
                "pos_set_count": len(pos_set)}

    # ---------- 选择 ----------

    def _select(self, store: Any, motifs: List[Dict[str, Any]]) -> Dict[str, Any]:
        from rules import admission

        keys = {str(m["id"]): admission.motif_sort_key(m) for m in motifs}
        out = admission.greedy_select(store, [str(m["id"]) for m in motifs], keys)
        by_id = {str(m["id"]): m for m in motifs}
        selected_motifs = []
        for step in out["trace"]:
            rec = dict(by_id[step["rule"]])
            rec["greedy_step"] = step["step"]
            rec["greedy_gain"] = step["gain"]
            rec["greedy_cost"] = step["cost"]
            rec["greedy_efficiency"] = step["efficiency"]
            selected_motifs.append(rec)
        return {
            "selected": out["selected"],
            "selected_motifs": selected_motifs,
            "greedy_trace": out["trace"],
            "stats": out["stats"],
        }

    # ---------- 入口一：全量建库 ----------

    def build_all(self, train_scenarios: List[str],
                  pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                  ) -> List[Dict[str, Any]]:
        """用给定场景全量建库：抽闭包 → 建覆盖表 → 选名单。"""
        from rules import admission
        from rules.coverage import CoverageStore, ScenarioShard

        if not train_scenarios:
            raise ValueError("离线蒸馏必须提供训练场景（禁止空训练集静默放行）")

        from common.roles import build_context, merge_contexts

        prepared: Dict[str, Dict[str, Any]] = {}
        contexts: Dict[str, Any] = {}
        for sc in train_scenarios:
            item = self.prepare_scenario(sc, pool_provider)
            prepared[sc] = item
            contexts[sc] = build_context(item["edges"])

        role_cuts = merge_contexts(contexts.values()).to_cuts()
        pos_edges = {sc: [e for e in prepared[sc]["edges"]
                          if prepared[sc]["labels"].get(_key(e)) == "pos"]
                     for sc in train_scenarios}

        miner = FrequentSubgraphMiner(min_support=self.min_support)
        motifs = admission.assign_ids(miner.mine(pos_edges, contexts, role_cuts))

        store = CoverageStore()
        label_counts: Dict[str, Dict[str, int]] = {}
        pool_sizes: Dict[str, int] = {}
        positive_sizes: Dict[str, int] = {}

        for sc in train_scenarios:
            item = prepared[sc]
            hits = admission.compute_hits(item["edges"], motifs, self._rm(), role_cuts=role_cuts)
            shard = ScenarioShard(sc)
            shard.load(item["edges"], item["labels"], hits)
            store.add(shard)
            label_counts[sc] = {lab: sum(1 for x in item["labels"].values() if x == lab)
                                for lab in ("pos", "ignore", "neg")}
            pool_sizes[sc] = len(item["edges"])
            positive_sizes[sc] = item["pos_set_count"]

        result = self._select(store, motifs)
        self.last_report = {
            "train_scenarios": list(train_scenarios),
            "role_cuts": role_cuts.to_dict() if role_cuts is not None else None,
            "motifs": motifs,
            "coverage": store,
            "label_counts": label_counts,
            "pool_sizes": pool_sizes,
            "positive_sizes": positive_sizes,
            **result,
        }
        return result["selected_motifs"]

    # ---------- 入口四：从既有覆盖表重建（不查图，改角色/改准则后用） ----------

    def rebuild_from_coverage(self, base_library: Union[str, Path, Dict[str, Any]] = None
                              ) -> List[Dict[str, Any]]:
        """用既有覆盖表里的边重建形态与位图，全程不查数据库。

        覆盖表存了每个场景的边键内容与进程标识，足以重放角色判定与匹配。
        """
        from rules import admission
        from rules.coverage import CoverageStore, ScenarioShard
        from common.roles import build_context, merge_contexts

        payload = read_library_payload(base_library)
        old = CoverageStore.from_payload(payload["coverage_table"])
        scenarios = old.names()

        prepared: Dict[str, Dict[str, Any]] = {}
        contexts: Dict[str, Any] = {}
        for sc in scenarios:
            shard = old.shards[sc]
            edges = shard.edge_dicts()
            pos, ign = set(shard.pos), set(shard.ignore)
            labels = {}
            for i, e in enumerate(edges):
                labels[_key(e)] = "pos" if i in pos else ("ignore" if i in ign else "neg")
            prepared[sc] = {"edges": edges, "labels": labels, "pos_set_count": len(pos)}
            contexts[sc] = build_context(edges)

        role_cuts = merge_contexts(contexts.values()).to_cuts()
        pos_edges = {sc: [e for e in prepared[sc]["edges"]
                          if prepared[sc]["labels"].get(_key(e)) == "pos"] for sc in scenarios}
        miner = FrequentSubgraphMiner(min_support=self.min_support)
        motifs = admission.assign_ids(miner.mine(pos_edges, contexts, role_cuts))

        store = CoverageStore()
        label_counts: Dict[str, Dict[str, int]] = {}
        pool_sizes: Dict[str, int] = {}
        positive_sizes: Dict[str, int] = {}
        for sc in scenarios:
            item = prepared[sc]
            hits = admission.compute_hits(item["edges"], motifs, self._rm(), role_cuts=role_cuts)
            shard = ScenarioShard(sc)
            shard.load(item["edges"], item["labels"], hits)
            store.add(shard)
            label_counts[sc] = {lab: sum(1 for x in item["labels"].values() if x == lab)
                                for lab in ("pos", "ignore", "neg")}
            pool_sizes[sc] = len(item["edges"])
            positive_sizes[sc] = item["pos_set_count"]

        result = self._select(store, motifs)
        self.last_report = {
            "train_scenarios": scenarios,
            "role_cuts": role_cuts.to_dict(),
            "motifs": motifs,
            "coverage": store,
            "label_counts": label_counts,
            "pool_sizes": pool_sizes,
            "positive_sizes": positive_sizes,
            **result,
        }
        return result["selected_motifs"]

    # 兼容旧调用名
    def distill(self, train_scenarios: List[str],
                pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                **_ignored: Any) -> List[Dict[str, Any]]:
        return self.build_all(train_scenarios, pool_provider)

    # ---------- 入口二：接入一个场景 ----------

    def ingest(self, base_library: Union[str, Path, Dict[str, Any]],
               new_scenario: str,
               pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
               ) -> List[Dict[str, Any]]:
        """接入一个场景：只查它一次图，历史场景零图查询；追加后立即重算名单。"""
        from rules import admission
        from rules.coverage import CoverageStore, ScenarioShard

        payload = read_library_payload(base_library)
        store: CoverageStore = CoverageStore.from_payload(payload["coverage_table"])
        if store.has(new_scenario):
            raise ValueError(
                f"[阻断] 场景 {new_scenario} 已在覆盖表中，禁止重复接入；"
                f"现有场景清单：{store.names()}"
            )

        from common.roles import RoleCuts, build_context

        known = list(payload.get("motifs") or [])
        item = self.prepare_scenario(new_scenario, pool_provider)
        new_ctx = build_context(item["edges"])
        role_cuts = RoleCuts.from_dict(payload.get("role_cuts")) if payload.get("role_cuts") else new_ctx.to_cuts()

        # 历史场景的 pos 边从覆盖表无法还原（已剥静态只读背景且丢了标签），
        # 因此这里只从新场景枚举形态；历史形态沿用 known，靠指纹去重合并。
        new_pos = [e for e in item["edges"] if item["labels"].get(_key(e)) == "pos"]
        miner = FrequentSubgraphMiner(min_support=self.min_support)
        fresh = miner.mine({new_scenario: new_pos}, {new_scenario: new_ctx}, role_cuts)
        motifs = admission.assign_ids(known + fresh)

        hits = admission.compute_hits(item["edges"], motifs, self._rm(), role_cuts=role_cuts)
        shard = ScenarioShard(new_scenario)
        shard.load(item["edges"], item["labels"], hits)
        store.add(shard)

        # 新形态在全部历史场景补齐位图（只读覆盖表，不查图）
        missing = [m for m in motifs
                   if any(str(m["id"]) not in store.shards[n].hits for n in store.names())]
        replay = admission.replay_missing(store, missing, self._rm(), role_cuts=role_cuts) if missing else {}

        label_counts = dict(payload.get("label_counts") or {})
        label_counts[new_scenario] = {lab: sum(1 for x in item["labels"].values() if x == lab)
                                      for lab in ("pos", "ignore", "neg")}
        pool_sizes = dict(payload.get("pool_sizes") or {})
        pool_sizes[new_scenario] = len(item["edges"])
        positive_sizes = dict(payload.get("positive_sizes") or {})
        positive_sizes[new_scenario] = item["pos_set_count"]

        result = self._select(store, motifs)
        self.last_report = {
            "train_scenarios": store.names(),
            "role_cuts": role_cuts.to_dict() if role_cuts is not None else None,
            "motifs": motifs,
            "coverage": store,
            "label_counts": label_counts,
            "pool_sizes": pool_sizes,
            "positive_sizes": positive_sizes,
            "replay_counts": replay,
            "added_scenario": new_scenario,
            **result,
        }
        return result["selected_motifs"]

    # 兼容旧调用名
    def distill_incremental(self, base_library: Union[str, Path, Dict[str, Any]],
                            new_scenario: str,
                            pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                            **_ignored: Any) -> List[Dict[str, Any]]:
        return self.ingest(base_library, new_scenario, pool_provider)

    # ---------- 入口三：只重算名单 ----------

    def reselect(self, base_library: Union[str, Path, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """不动覆盖表，只重跑贪心。读位图旁挂文件，不解析覆盖表正文。"""
        from rules.coverage import CoverageStore, load_bitmaps

        motif_payload = read_library_payload(base_library, with_coverage=False)
        motifs = list(motif_payload.get("motifs") or [])
        store = CoverageStore()
        if isinstance(base_library, (str, Path)):
            target = Path(base_library)
            bm = bitmaps_path_for(target)
            if bm.is_file():
                info = load_bitmaps(bm)
                store.attach_bitmaps(info["total"], info["pos"], info["ignore"],
                                     info["rule_bitmaps"])
            else:
                full = read_library_payload(base_library)
                store = CoverageStore.from_payload(full["coverage_table"])
        else:
            store = CoverageStore.from_payload(motif_payload["coverage_table"])
        if not motifs:
            raise RuntimeError("规则库里没有形态定义，无法重算名单")

        result = self._select(store, motifs)
        self.last_report = {
            "train_scenarios": list(motif_payload.get("train_scenarios") or []),
            "role_cuts": motif_payload.get("role_cuts"),
            "motifs": motifs,
            "coverage": store,
            "label_counts": motif_payload.get("label_counts") or {},
            "pool_sizes": motif_payload.get("pool_sizes") or {},
            "positive_sizes": motif_payload.get("positive_sizes") or {},
            **result,
        }
        return result["selected_motifs"]


# ==== 4. 规则库冻结（带版本目录） ====

SCHEMA = 4
LIBRARY_DIRNAME = "rules-library"
LATEST_POINTER = "latest.txt"


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
    """规则库版本目录。"""
    return cfg.CONFIG_DIR / LIBRARY_DIRNAME


def latest_pointer() -> Path:
    return dir_path() / LATEST_POINTER


def latest_path() -> Path:
    """读 latest.txt 得到当前生效的规则库路径；没有就阻断。"""
    ptr = latest_pointer()
    if not ptr.is_file():
        raise RuntimeError(
            f"缺少规则库指针：{ptr}\n"
            f"  先生成：python provenance-navigator/tools/rebuild_library.py"
        )
    name = ptr.read_text(encoding="utf-8").strip()
    if not name:
        raise RuntimeError(f"规则库指针为空：{ptr}")
    target = dir_path() / name
    if not target.is_file():
        raise RuntimeError(f"规则库指针指向的文件不存在：{target}")
    return target


def new_version_path() -> Path:
    """生成一个不冲突的版本路径（同一秒内重复调用自动加序号）。"""
    stamp = time.strftime("%Y%m%dT%H%M%S")
    base = dir_path() / f"rules-library-{stamp}"
    path = base.with_suffix(".json")
    n = 1
    while path.exists() or coverage_path_for(path).exists():
        n += 1
        path = dir_path() / f"rules-library-{stamp}-{n}.json"
    return path


def library_path() -> Path:
    """兼容入口：当前生效的规则库路径。"""
    return latest_path()


def library_exists() -> bool:
    try:
        latest_path()
        return True
    except RuntimeError:
        return False


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


def build_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """把蒸馏报告整成可落盘的规则库载荷（schema 4）。"""
    train = list(report["train_scenarios"])
    if not train:
        raise ValueError("规则库必须提供训练场景（禁止空训练集）")
    return {
        "schema": SCHEMA,
        "train_scenarios": train,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "fingerprint": fingerprint(train),
        "label_counts": report.get("label_counts", {}),
        "pool_sizes": report.get("pool_sizes", {}),
        "positive_sizes": report.get("positive_sizes", {}),
        "role_cuts": report.get("role_cuts"),
        "motifs": report.get("motifs") or [],
        "selected": list(report.get("selected") or []),
        "greedy_trace": report.get("greedy_trace", []),
        "stats": report.get("stats", {}),
        "coverage_table": report["coverage"].to_payload() if report.get("coverage") is not None else {},
    }


def coverage_path_for(lib_path: Path) -> Path:
    """覆盖表旁挂文件路径：<规则库名>.coverage.json.gz。"""
    return lib_path.with_name(lib_path.stem + ".coverage.json.gz")


def bitmaps_path_for(lib_path: Path) -> Path:
    """位图旁挂文件（贪心专用）：<规则库名>.bitmaps.bin。"""
    return lib_path.with_name(lib_path.stem + ".bitmaps.bin")


def save_library(report: Dict[str, Any],
                 out_path: Optional[Union[str, Path]] = None,
                 make_latest: bool = True) -> Path:
    """落盘一份新版本并用 latest.txt 指向它。覆盖表单独写 gzip 旁挂文件。"""
    payload = build_payload(report)
    out = new_version_path() if out_path is None else Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    coverage = payload.pop("coverage_table", None)
    if coverage is not None:
        cov_path = coverage_path_for(out)
        raw = json.dumps(coverage, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        tmp_cov = cov_path.with_suffix(cov_path.suffix + ".tmp")
        tmp_cov.write_bytes(gzip.compress(raw, 6))
        tmp_cov.replace(cov_path)
        payload["coverage_table_ref"] = cov_path.name

    store = report.get("coverage")
    if store is not None:
        from rules.coverage import save_bitmaps
        rule_ids = [str(m["id"]) for m in (report.get("motifs") or [])]
        bm_path = bitmaps_path_for(out)
        save_bitmaps(bm_path, store, rule_ids)
        bm_path.with_name(bm_path.stem.replace(".bitmaps", ".bitmaps.idx") + ".json").write_text(
            json.dumps(rule_ids, ensure_ascii=False), encoding="utf-8")
        payload["bitmaps_ref"] = bm_path.name

    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(out)

    if make_latest:
        ptr = latest_pointer()
        ptr.parent.mkdir(parents=True, exist_ok=True)
        ptr.write_text(out.name + "\n", encoding="utf-8")
    return out


def read_library_payload(path: Optional[Union[str, Path]] = None,
                         with_coverage: bool = True) -> Dict[str, Any]:
    """读规则库原始载荷；缺文件或 schema 不符一律阻断。"""
    if isinstance(path, dict):
        payload = dict(path)
        target_path = latest_path()
    elif path is not None and not isinstance(path, (str, Path)):
        raise TypeError(f"规则库路径必须是 str/Path/dict，实测 {type(path)!r}")
    else:
        target_path = latest_path() if path is None else Path(path)
        if not target_path.is_file():
            raise RuntimeError(f"缺少规则库：{target_path}")
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA:
        raise RuntimeError(
            f"规则库 schema 不匹配：{target_path} 是 {payload.get('schema')!r}，本版要求 {SCHEMA}；"
            f"请用 tools/rebuild_library.py 重新生成"
        )
    if not with_coverage:
        return payload
    ref = payload.get("coverage_table_ref")
    if ref:
        cov_path = target_path.with_name(str(ref))
        if not cov_path.is_file():
            raise RuntimeError(f"覆盖表缺失：{cov_path}（规则库声明了 coverage_table_ref）")
        payload["coverage_table"] = json.loads(gzip.decompress(cov_path.read_bytes()).decode("utf-8"))
    return payload


def load_library(path: Optional[Union[str, Path]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """读规则库：返回（准入形态清单, 审计信息）。

    准入形态 = motifs 里 id 在 selected 名单中的那些，现推，不落盘冗余。
    """
    payload = read_library_payload(path)
    motifs = payload.get("motifs") or []
    selected = list(payload.get("selected") or [])
    picked = set(selected)
    patterns = [m for m in motifs if str(m.get("id")) in picked]
    target = Path(path) if isinstance(path, (str, Path)) else latest_path()
    audit = {
        "path": str(target),
        "train_scenarios": list(payload.get("train_scenarios") or []),
        "generated_at": payload.get("generated_at"),
        "fingerprint": payload.get("fingerprint", {}).get("digest"),
        "pool_sizes": payload.get("pool_sizes", {}),
        "label_counts": payload.get("label_counts", {}),
        "positive_sizes": payload.get("positive_sizes", {}),
        "role_cuts": payload.get("role_cuts"),
        "motifs": motifs,
        "selected": selected,
        "greedy_trace": payload.get("greedy_trace") or [],
        "stats": payload.get("stats") or {},
        "coverage_table": payload.get("coverage_table") or {},
    }
    return patterns, audit


def update_library_incremental(base_library: Union[str, Path],
                               new_scenario: str,
                               output_path: Optional[Union[str, Path]] = None,
                               pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                               distiller: Optional[OfflineDistiller] = None) -> Path:
    """接入单个新场景：追加覆盖表 + 立即重算名单 + 落盘新版本。"""
    if distiller is None:
        from pipeline import load_rule_matcher
        distiller = OfflineDistiller(rule_matcher=load_rule_matcher())
    patterns = distiller.ingest(base_library, new_scenario, pool_provider=pool_provider)
    report = distiller.last_report
    return save_library(report, out_path=output_path)


if __name__ == "__main__":
    import argparse
    from pipeline import load_rule_matcher
    from pipeline import make_pool_provider

    ap = argparse.ArgumentParser(description="接入一个新场景并重算名单（全量建库用 tools/rebuild_library.py）")
    ap.add_argument("--add-scenario", required=True, help="新增接入的场景全名")
    ap.add_argument("--base-library", default=None, help="基线规则库路径（默认读 latest.txt）")
    ap.add_argument("--output", default=None, help="输出路径（默认生成新版本目录条目）")
    args = ap.parse_args()

    out = update_library_incremental(
        args.base_library or latest_path(),
        args.add_scenario,
        output_path=args.output,
        pool_provider=make_pool_provider(),
        distiller=OfflineDistiller(rule_matcher=load_rule_matcher()),
    )
    print(f"接入完成，新版本：{out}")
