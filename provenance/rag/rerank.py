"""Qwen3-Reranker-0.6B FP16 封装（CUDA）。"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

DEFAULT_MODEL = Path(r"D:\local_models\Qwen3-Reranker-0.6B")


class Qwen3Reranker:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL, device: str = "cuda"):
        import torch
        from sentence_transformers import CrossEncoder

        if not torch.cuda.is_available():
            raise RuntimeError("CUDA 不可用；按 AGENTS.md 禁止迁移 CPU")
        self.torch = torch
        self.model = CrossEncoder(
            str(model_path), device=device,
            model_kwargs={"torch_dtype": torch.float16, "low_cpu_mem_usage": True},
        )

    def score(self, query: str, docs: Iterable[str], *, batch_size: int = 8) -> List[float]:
        docs = list(docs)
        if not docs:
            return []
        pairs = [(query, d) for d in docs]
        with self.torch.no_grad():
            scores = self.model.predict(pairs, batch_size=batch_size, show_progress_bar=False)
        return [float(x) for x in scores]

    def close(self) -> None:
        self.model = None
        self.torch.cuda.empty_cache()
