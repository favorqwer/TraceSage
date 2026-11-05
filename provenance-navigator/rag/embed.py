"""Qwen3-Embedding-4B FP8 封装（CUDA，权重-only FP8）。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional

import numpy as np

DEFAULT_MODEL = Path(r"D:\local_models\Qwen3-Embedding-4B")
QUERY_INSTRUCTION = (
    "给定一条溯源图候选边的角色、系统调用与端点，检索可能解释它的攻击规则子图"
)


class Qwen3Embedder:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL, device: str = "cuda",
                 max_length: int = 512):
        import torch
        from transformers import AutoModel, AutoTokenizer
        from torchao.quantization import Float8WeightOnlyConfig, quantize_

        if not torch.cuda.is_available():
            raise RuntimeError("CUDA 不可用；按 AGENTS.md 禁止迁移 CPU")
        self.torch = torch
        self.device = device
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(str(model_path), trust_remote_code=False)
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = AutoModel.from_pretrained(
            str(model_path), torch_dtype=torch.bfloat16, device_map="cpu",
            low_cpu_mem_usage=True, trust_remote_code=False)
        quantize_(self.model, Float8WeightOnlyConfig(weight_dtype=torch.float8_e4m3fn))
        self.model.to(device)
        self.model.eval()
        self.dim = int(self.model.config.hidden_size)

    def encode(self, texts: Iterable[str], *, instruction: Optional[str] = None,
               batch_size: int = 8) -> np.ndarray:
        texts = list(texts)
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        if instruction:
            texts = [f"Instruct: {instruction}\nQuery: {t}" for t in texts]
        out: List[np.ndarray] = []
        with self.torch.no_grad():
            for start in range(0, len(texts), batch_size):
                batch = texts[start:start + batch_size]
                enc = self.tokenizer(batch, padding=True, truncation=True,
                                     max_length=self.max_length, return_tensors="pt").to(self.device)
                hidden = self.model(**enc).last_hidden_state[:, -1]
                vec = self.torch.nn.functional.normalize(hidden.float(), p=2, dim=1)
                out.append(vec.cpu().numpy())
        return np.concatenate(out, axis=0)

    def close(self) -> None:
        self.model = None
        self.tokenizer = None
        self.torch.cuda.empty_cache()
