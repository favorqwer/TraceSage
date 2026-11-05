"""精确余弦向量索引（numpy 后端）。

语料只有数百条；主实验用精确检索，结果确定、可复现。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

import numpy as np


@dataclass
class SearchHit:
    doc_id: str
    score: float
    doc: Dict[str, Any]


class CosineIndex:
    def __init__(self, docs: Sequence[Dict[str, Any]], vectors: np.ndarray):
        if len(docs) != len(vectors):
            raise ValueError("docs 与 vectors 数量不一致")
        self.docs = list(docs)
        self.ids = [str(d.get("id")) for d in self.docs]
        mat = np.asarray(vectors, dtype=np.float32)
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self.vectors = mat / norms

    def search(self, query_vector: np.ndarray, top_k: int = 20) -> List[SearchHit]:
        q = np.asarray(query_vector, dtype=np.float32).reshape(-1)
        n = float(np.linalg.norm(q)) or 1.0
        scores = self.vectors @ (q / n)
        order = np.argsort(-scores)[:max(1, int(top_k))]
        return [SearchHit(self.ids[i], float(scores[i]), self.docs[i]) for i in order]
