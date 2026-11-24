"""拓扑基模似然比（Likelihood Ratio）内存索引模块（直读本地规则快照，零 Neo4j 连接）。

职责：
1. 依据留一折隔离原则，从本地规则快照 output/rule-kg/v1/folds/<fold>.json 读取指定折全部 Motif；
2. 依据 Motif 的 attack_hits 与 background_hits 属性计算拉普拉斯平滑判别似然比 LR；
3. 内存缓存各 Motif 的 LR 与频次加权 LR，为证据渲染排序提供攻击特异性依据。
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import threading
from typing import Dict, Optional

import settings as cfg


class MotifLikelihoodIndex:
    """某一折全部 Motif 的判别似然比内存索引。"""

    def __init__(
        self,
        fold: str,
        database: str = "",
        eps: float = 1e-6,
        *,
        kg_dir: Optional[Path] = None,
    ) -> None:
        self.fold = fold
        self.database = database
        self.eps = eps
        self._kg_dir = kg_dir
        self._lr_map: Dict[str, float] = {}
        self._weighted_lr_map: Dict[str, float] = {}
        self._loaded = False
        self._lock = threading.Lock()

    def load(self) -> None:
        """从本地规则快照 JSON 加载当前折规则并计算似然比（零数据库查询）。"""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            base = Path(self._kg_dir) if self._kg_dir is not None else cfg.rule_kg_dir()
            path = base / "folds" / f"{self.fold}.json"
            if not path.is_file():
                raise FileNotFoundError(f"本地规则知识快照缺失：{path}")
            kg = json.loads(path.read_text(encoding="utf-8"))
            motifs = kg.get("motifs") or []

            tot_att = sum(int((m.get("stats") or {}).get("attack_hits") or 0) for m in motifs)
            tot_bg = sum(int((m.get("stats") or {}).get("background_hits") or 0) for m in motifs)

            if tot_att == 0 or tot_bg == 0:
                self._loaded = True
                return

            n_motifs = len(motifs)
            alpha = 1.0
            denom_att = tot_att + alpha * n_motifs
            denom_bg = tot_bg + alpha * n_motifs

            for m in motifs:
                mid = str(m["motif_id"])
                stats = m.get("stats") or {}
                att = int(stats.get("attack_hits") or 0)
                bg = int(stats.get("background_hits") or 0)
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
