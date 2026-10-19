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
    离线知识蒸馏器（基于全自动频繁子图挖掘与贝叶斯经验提升度检验 Bayesian Empirical Lift）：

    核心机制：
    1. 彻底淘汰人工硬编码的工具字典与先验基模列表；
    2. 自动从训练场景 Ground Truth 中挖掘跨场景 1-跳与 2-跳高频因果子图拓扑骨架 (min_support=1，废除人为数据集强绑定)；
    3. 三值标签（一条候选边只有一种身份）：
       - 正：命中标准答案的必须条目；
       - 忽略：未命中必须条目、但符合标准答案的人工规则（既不记命中也不记误报，整体剔除出统计）；
       - 负：其余候选边。
       规则所描述的步骤条数随环境变化，且在抽象拓扑上与良性操作同形，不能充当正样本；
       必须条目是唯一无歧义的正样本，保证先验概率停留在真实的稀有量级。
    4. 尺度不变性准入判定：
       - 先验概率 pi = 池内正样本数 / (池内正样本数 + 池内负样本数)（分子分母同源，忽略集不参与）；
       - 贝叶斯后验平滑精度 P_Bayes = (TP + m0 * pi) / (TP + FP + m0) (默认 m0 = 2.0)；
       - 经验提升度 Lift = P_Bayes / pi >= 3.0 且 TP >= 1；
    5. 严格保留审计流水与指标，保证闭环独立可复现。
    6. 已知局限：忽略集被剔除后，“命中正样本极少、但命中大量忽略边”的基模会缺少证伪证据；
       最小证据量约束属独立改动，本版不引入。
    """

    def __init__(self, min_support: int = 1, min_lift: float = 3.0, m0: float = 2.0):
        self.min_support = min_support
        self.min_lift = min_lift
        self.m0 = m0
        self.candidate_motifs: List[Dict[str, Any]] = []
        self.last_report: Dict[str, Any] = {}

    @staticmethod
    def _load_train_positive(scenario: str) -> Tuple[set, list, Any]:
        """训练场景的正样本（标准答案必须条目）与人工规则（用于构造忽略集）。"""
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

        def classify(e, item):
            """三值身份判定：正 = 必须条目；忽略 = 符合人工规则的边；负 = 其余背景。"""
            t = (e.get("src"), e.get("syscall"), e.get("dst"))
            if t in item["pos_set"]:
                return "pos"
            if any(rm.rule_matches(r, t[0], t[1], t[2], kinds=item["kinds"]) for _, r in item["rules"]):
                return "ignore"
            return "neg"

        # 3. 三值标注：身份与基模无关，逐训练场景只算一遍
        for item in train_data:
            item["labels"] = {_key(e): classify(e, item) for e in item["cands"]}
            item["label_counts"] = {
                "pos": sum(1 for v in item["labels"].values() if v == "pos"),
                "ignore": sum(1 for v in item["labels"].values() if v == "ignore"),
                "neg": sum(1 for v in item["labels"].values() if v == "neg"),
            }

        # 4. 训练期全局先验概率：分子分母同源（忽略集不参与；正样本限定在候选池内）
        prior_pos = sum(item["label_counts"]["pos"] for item in train_data)
        prior_ign = sum(item["label_counts"]["ignore"] for item in train_data)
        prior_neg = sum(item["label_counts"]["neg"] for item in train_data)
        gt_must_total = sum(len(item["pos_set"]) for item in train_data)
        if prior_pos != gt_must_total:
            print(f"  [蒸馏告警] 池内正样本 {prior_pos} 条 ≠ 标准答案必须条目 {gt_must_total} 条"
                  f"（存在不在候选池内的必须条目），先验按池内口径计算")
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
                tf = item["tf"]
                clean_cands = item["cands"]
                labels = item["labels"]

                # 使用严谨匹配器在该场景的全背景中进行检验
                matcher = PatternMatcher(tf, [motif], min_conf=0.0)
                matched_dict = matcher.match(clean_cands)

                # 三值身份：正样本记命中；忽略集既不计命中也不计误报；其余记误报
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

            # 贝叶斯经验提升度 (Bayesian Empirical Lift) 检验
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

        # 5. 审计信息沉淀
        self.last_report = {
            "train_scenarios": list(train_scenarios),
            "pool_source": "provided_in_run" if pool_provider is not None else "fresh_closure_per_scenario",
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
            "mined_raw_count": len(candidate_motifs),
            "distilled_count": len(distilled_motifs),
            "pool_sizes": {item["scenario"]: len(item["cands"]) for item in train_data},
            "positive_sizes": {item["scenario"]: len(item["pos_set"]) for item in train_data},
            "label_counts": {item["scenario"]: item["label_counts"] for item in train_data},
            "considered": considered,
            "distilled_ids": [m["id"] for m in distilled_motifs],
        }
        return distilled_motifs
