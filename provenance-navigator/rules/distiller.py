import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import rules_match as rm
from closure.facts import TopologyFacts
from rules.motifs import CANDIDATE_MOTIFS, check_entity_role, match_motif
from orchestrator.filter import CausalFilter

MIN_SUPPORT_SCENARIOS = 2
MIN_TRAIN_PRECISION = 0.25


class OfflineDistiller:
    """
    离线知识蒸馏器（数据驱动因果拓扑基模统计筛选引擎）：

    核心机制：
    1. 候选因果基模库定义：涵盖入站派生、载荷执行、网络工具、提权工具、系统探测、凭据修改、持久化等图拓扑；
    2. 实体角色去字面化抽象：剥离具体文件名与网络地址，映射为客观系统拓扑角色；
    3. 判别式统计双轨打分：在给定的训练场景集上，逐个候选基模统计正样本命中数、
       背景负样本触发数与跨场景支持度；
    4. 自动剪枝：通用基模考察多场景通用性，深度基模考察高纯度与良性隔离度。

    训练候选池与在线初筛口径保持严格对齐，绝不静默读取历史运行产物。
    """

    CANDIDATE_MOTIFS = CANDIDATE_MOTIFS

    def __init__(self, candidate_motifs: List[Dict[str, Any]] = None):
        self.candidate_motifs = candidate_motifs or list(self.CANDIDATE_MOTIFS)
        self.last_report: Dict[str, Any] = {}

    @staticmethod
    def check_entity_role(role: str, val: str, tf: TopologyFacts) -> bool:
        return check_entity_role(role, val, tf)

    @classmethod
    def match_motif(cls, motif: Dict[str, Any], e: Dict[str, Any], tf: TopologyFacts) -> bool:
        return match_motif(motif, e, tf)

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
        """根据给定训练场景集执行统计筛选，返回入选基模清单。

        双轨制准入要求：
        - 横向通用基模：正样本命中 >= 1 且 跨场景支持度 >= 2 且 训练期微平均查准率 >= 0.25；
        - 纵向专属基模：正样本命中 >= 1 且 主战场场景查准率 >= 0.50 且 无关场景误报数 <= 2。
        """
        if not train_scenarios:
            raise ValueError("离线蒸馏必须提供训练场景（禁止空训练集静默放行全量候选基模）")

        # 1. 载入训练场景的正样本与经初筛清洗后的候选池
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

        # 2. 逐候选基模计算打分
        distilled_motifs: List[Dict[str, Any]] = []
        considered: List[Dict[str, Any]] = []
        for motif in self.candidate_motifs:
            tot_pos = 0
            tot_neg = 0
            sc_hits = 0
            per_sc_pos = {}
            per_sc_neg = {}

            for item in train_data:
                sc = item["scenario"]
                tf = item["tf"]
                p_hit = 0
                n_hit = 0

                for e in item["cands"]:
                    if self.match_motif(motif, e, tf):
                        if is_pos(e, item):
                            p_hit += 1
                        else:
                            n_hit += 1

                if p_hit > 0:
                    sc_hits += 1
                tot_pos += p_hit
                tot_neg += n_hit
                per_sc_pos[sc] = p_hit
                per_sc_neg[sc] = n_hit

            precision = tot_pos / (tot_pos + tot_neg) if (tot_pos + tot_neg) > 0 else 0.0

            # 双轨制准入判断
            passed = False
            scope = motif.get("scope", "horizontal")
            if scope == "horizontal":
                passed = (tot_pos >= 1 and sc_hits >= MIN_SUPPORT_SCENARIOS and precision >= MIN_TRAIN_PRECISION)
            else: # vertical
                if sc_hits >= 1:
                    target_scs = [sc for sc in train_scenarios if per_sc_pos[sc] > 0]
                    target_p = sum(per_sc_pos[sc] for sc in target_scs)
                    target_n = sum(per_sc_neg[sc] for sc in target_scs)
                    target_prec = target_p / (target_p + target_n) if (target_p + target_n) > 0 else 0.0
                    other_n = sum(per_sc_neg[sc] for sc in train_scenarios if per_sc_pos[sc] == 0)
                    passed = (target_prec >= 0.50 and other_n <= 2)

            considered.append({
                "id": motif["id"],
                "name": motif.get("name", ""),
                "scope": scope,
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

        # 3. 审计信息沉淀
        self.last_report = {
            "train_scenarios": list(train_scenarios),
            "pool_source": "provided_in_run" if pool_provider is not None else "fresh_closure_per_scenario",
            "thresholds": {
                "min_positive_hits": 1,
                "min_support_scenarios": MIN_SUPPORT_SCENARIOS,
                "min_train_precision": MIN_TRAIN_PRECISION,
            },
            "pool_sizes": {item["scenario"]: len(item["cands"]) for item in train_data},
            "positive_sizes": {item["scenario"]: len(item["pos_set"]) for item in train_data},
            "considered": considered,
            "distilled_ids": [m["id"] for m in distilled_motifs],
        }
        return distilled_motifs
