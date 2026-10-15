import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import rules_match as rm
from closure.facts import TopologyFacts
from orchestrator.filter import CausalFilter
from rules.miner import FrequentSubgraphMiner
from rules.matcher import PatternMatcher, _key
from rules.motifs import abstract_node_role, evaluate_node_behavioral_role


class OfflineDistiller:
    """
    离线知识蒸馏器（基于全自动频繁子图挖掘与全背景对抗剪枝）：

    核心机制：
    1. 彻底淘汰人工硬编码的工具字典与先验基模列表；
    2. 自动从训练场景 Ground Truth 中挖掘跨场景 1-跳与 2-跳高频因果子图拓扑骨架 (min_support=1，废除人为数据集强绑定)；
    3. 在全量训练场景的真实候选闭包（经初筛后的干净候选池）中，逐个基模检验全背景信噪比 (Adversarial Signal-to-Noise Ratio)；
    4. 纯信噪比判别准入：
       - 敏感认证与持久化等特权模式：全背景对抗查准率 >= 0.50 且 误报 <= 5；
       - 通用系统因果模式：全背景对抗查准率 >= 0.30 且 误报 < 300；
    5. 严格保留审计流水与指标，保证闭环独立可复现。
    """

    def __init__(self, min_support: int = 1):
        self.min_support = min_support
        self.candidate_motifs: List[Dict[str, Any]] = []
        self.last_report: Dict[str, Any] = {}

    @staticmethod
    def _load_train_positive(scenario: str) -> Tuple[set, list, Any]:
        """训练场景正样本与规则判定（严格对齐官方评测工具口径）。"""
        gt_file = REPO_ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
        if not gt_file.exists():
            raise FileNotFoundError(f"训练场景标准答案缺失，无法蒸馏：{gt_file}")
        with open(gt_file, "r", encoding="utf-8") as f:
            gt = json.load(f)
        pos = set()
        for ph in gt.get("attack_path", []):
            for e in ph.get("edges", []) or []:
                pos.add((e.get("src"), e.get("syscall"), e.get("dst")))
        rules = rm.load_rules(gt)
        kinds = rm.VertexKinds.for_gt(gt)
        return pos, rules, kinds

    @staticmethod
    def _load_pool(scenario: str, pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None) -> List[Dict[str, Any]]:
        """训练候选池：优先取调用方显式提供的运行期闭包；否则逐场景现算轻量闭包。"""
        if pool_provider is not None:
            edges = pool_provider(scenario)
            if not edges:
                raise RuntimeError(f"训练候选池为空，无法蒸馏：{scenario}")
            return list(edges)
        from closure.extractor import extract_raw_closure
        edges, _stats = extract_raw_closure(scenario, light=True)
        if not edges:
            raise RuntimeError(f"训练候选池为空，无法蒸馏：{scenario}")
        return edges

    def distill(self, train_scenarios: List[str],
                pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None
                ) -> List[Dict[str, Any]]:
        """根据给定训练场景集执行自动挖掘与统计对抗剪枝，返回入选基模清单。"""
        if not train_scenarios:
            raise ValueError("离线蒸馏必须提供训练场景（禁止空训练集静默放行）")

        # 1. 全自动因果子图拓扑挖掘
        miner = FrequentSubgraphMiner(min_support=self.min_support)
        candidate_motifs = miner.mine(train_scenarios)
        self.candidate_motifs = candidate_motifs

        # 2. 载入训练场景的正样本与经初筛清洗后的候选池
        train_data = []
        for sc in train_scenarios:
            pos_set, rules, kinds = self._load_train_positive(sc)
            raw_cands = self._load_pool(sc, pool_provider)
            tf = TopologyFacts(raw_cands)
            cf = CausalFilter(tf)
            clean_cands, _pruned = cf.filter(raw_cands)
            train_data.append({
                "scenario": sc,
                "pos_set": pos_set,
                "rules": rules,
                "kinds": kinds,
                "cands": clean_cands,
                "tf": tf
            })

        def is_pos(e, item):
            t = (e.get("src"), e.get("syscall"), e.get("dst"))
            if t in item["pos_set"]:
                return True
            return any(rm.rule_matches(r, t[0], t[1], t[2], kinds=item["kinds"]) for _, r in item["rules"])

        # 3. 逐候选基模计算全背景对抗信噪比
        distilled_motifs: List[Dict[str, Any]] = []
        considered: List[Dict[str, Any]] = []

        for motif in candidate_motifs:
            tot_pos = 0
            tot_neg = 0
            sc_hits = 0
            per_sc_pos = {}
            per_sc_neg = {}

            for item in train_data:
                sc = item["scenario"]
                tf = item["tf"]
                clean_cands = item["cands"]

                # 使用严谨匹配器在该场景的全背景中进行检验
                matcher = PatternMatcher(tf, [motif], min_conf=0.0)
                matched_dict = matcher.match(clean_cands)

                p_hit = 0
                for e in clean_cands:
                    if _key(e) in matched_dict:
                        if is_pos(e, item):
                            p_hit += 1

                n_hit = len(matched_dict) - p_hit
                if p_hit > 0:
                    sc_hits += 1
                tot_pos += p_hit
                tot_neg += n_hit
                per_sc_pos[sc] = p_hit
                per_sc_neg[sc] = n_hit

            precision = tot_pos / (tot_pos + tot_neg) if (tot_pos + tot_neg) > 0 else 0.0

            # 纯对抗信噪比剪枝准入
            is_priv = any(k in motif.get("name", "") for k in ["SENSITIVE_AUTH", "PERSISTENCE"])
            if is_priv:
                passed = (tot_pos >= 1 and precision >= 0.50 and tot_neg <= 5)
            else:
                passed = (tot_pos >= 1 and precision >= 0.30 and tot_neg < 300)

            considered.append({
                "id": motif["id"],
                "name": motif.get("name", ""),
                "positive_hits": tot_pos,
                "negative_alarms": tot_neg,
                "support_scenarios": sc_hits,
                "train_precision": round(precision, 6),
                "passed": passed,
            })

            if passed:
                distilled = dict(motif)
                distilled["train_support_scenarios"] = sc_hits
                distilled["train_positive_hits"] = tot_pos
                distilled["train_negative_alarms"] = tot_neg
                distilled["train_precision"] = precision
                distilled_motifs.append(distilled)

        # 4. 审计信息沉淀
        self.last_report = {
            "train_scenarios": list(train_scenarios),
            "pool_source": "provided_in_run" if pool_provider is not None else "fresh_closure_per_scenario",
            "thresholds": {
                "min_support": self.min_support,
                "priv_min_precision": 0.50,
                "priv_max_neg": 5,
                "general_min_precision": 0.30,
                "general_max_neg": 300,
            },
            "mined_raw_count": len(candidate_motifs),
            "distilled_count": len(distilled_motifs),
            "pool_sizes": {item["scenario"]: len(item["cands"]) for item in train_data},
            "positive_sizes": {item["scenario"]: len(item["pos_set"]) for item in train_data},
            "considered": considered,
            "distilled_ids": [m["id"] for m in distilled_motifs],
        }
        return distilled_motifs
