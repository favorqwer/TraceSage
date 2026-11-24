"""拓扑基模似然比（Likelihood Ratio）索引模块。

职责：
1. 依据留一折隔离原则，从 Neo4j 规则库 trace-rules-kg-v1 中读取指定折（fold）的全部 Motif；
2. 依据 Motif 节点的 attack_hits 与 background_hits 属性，计算判别似然比 LR：
       P(m|Attack) = attack_hits / total_attack_hits
       P(m|Benign) = background_hits / total_background_hits
       LR(m) = ln( (P(m|Attack) + eps) / (P(m|Benign) + eps) )
3. 内存缓存各 Motif 的 LR 数值，为证据渲染排序提供攻击特异性依据。
"""
from __future__ import annotations

import math
import threading
from typing import Dict, Optional

from neo4j import GraphDatabase

import settings as cfg
from rag.neo4j_kg import DEFAULT_DATABASE


class MotifLikelihoodIndex:
    """某一折全部 Motif 的判别似然比内存索引。"""

    def __init__(
        self,
        fold: str,
        database: str = DEFAULT_DATABASE,
        eps: float = 1e-6,
    ) -> None:
        self.fold = fold
        self.database = database
        self.eps = eps
        self._lr_map: Dict[str, float] = {}
        self._weighted_lr_map: Dict[str, float] = {}
        self._loaded = False
        self._lock = threading.Lock()

    def load(self) -> None:
        """从 Neo4j 中加载当前折规则并计算似然比。"""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            cfg.load_dotenv()
            uri = cfg.neo4j_uri()
            auth = cfg.neo4j_auth()
            driver = GraphDatabase.driver(uri, auth=auth)
            try:
                with driver.session(database=self.database) as s:
                    tot_res = s.run(
                        """
                        MATCH (m:Motif {fold: $fold})
                        RETURN sum(coalesce(m.attack_hits, 0)) AS tot_att,
                               sum(coalesce(m.background_hits, 0)) AS tot_bg
                        """,
                        fold=self.fold,
                    ).single()
                    tot_att = int(tot_res["tot_att"] or 0)
                    tot_bg = int(tot_res["tot_bg"] or 0)

                    if tot_att == 0 or tot_bg == 0:
                        self._loaded = True
                        return

                    records = s.run(
                        """
                        MATCH (m:Motif {fold: $fold})
                        RETURN m.motif_id AS motif_id,
                               coalesce(m.attack_hits, 0) AS att,
                               coalesce(m.background_hits, 0) AS bg
                        """,
                        fold=self.fold,
                    ).data()

                    n_motifs = len(records)
                    alpha = 1.0
                    denom_att = tot_att + alpha * n_motifs
                    denom_bg = tot_bg + alpha * n_motifs

                    for r in records:
                        mid = str(r["motif_id"])
                        att = int(r["att"])
                        bg = int(r["bg"])
                        p_att = (att + alpha) / denom_att
                        p_bg = (bg + alpha) / denom_bg
                        lr = math.log(p_att / p_bg)
                        self._lr_map[mid] = float(lr)

                        if lr > 0:
                            conf_weight = 1.0 - (1.0 / math.sqrt(att + 1))
                            self._weighted_lr_map[mid] = float(lr * conf_weight)
                        else:
                            self._weighted_lr_map[mid] = float(lr)

                    self._loaded = True
            finally:
                driver.close()

    def get_lr(self, motif_id: str, default: float = 0.0) -> float:
        """获取指定 Motif 的判别似然比。未命中时返回中性默认值 0.0。"""
        if not self._loaded:
            self.load()
        return self._lr_map.get(str(motif_id), default)

    def get_weighted_lr(self, motif_id: str, default: float = 0.0) -> float:
        """获取经过历史频次置信度加权的判别似然比（小样本冷门规则折损，高频规则保留）。"""
        if not self._loaded:
            self.load()
        return self._weighted_lr_map.get(str(motif_id), default)
