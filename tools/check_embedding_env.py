"""本地检索模型可行性检查（G1 检查点）。

硬约束（AGENTS.md）：
- Qwen3-Embedding-4B 必须 FP8（Float8WeightOnlyConfig）运行于 CUDA；
- Qwen3-Reranker-0.6B 必须 FP16 运行于 CUDA；
- 任一步失败立即非零退出，禁止迁移 CPU、降精度或换模型。

用法：
    "C:/Users/Favor/AppData/Local/Programs/Python/Python312/python.exe" tools/check_embedding_env.py
    ... --skip-reranker
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

EMBED_PATH = Path(r"D:\local_models\Qwen3-Embedding-4B")
RERANK_PATH = Path(r"D:\local_models\Qwen3-Reranker-0.6B")


def fail(message: str) -> None:
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    sys.exit(1)


def check_embedding() -> dict:
    import torch
    from transformers import AutoModel, AutoTokenizer
    from torchao.quantization import Float8WeightOnlyConfig, quantize_

    if not torch.cuda.is_available():
        fail("CUDA 不可用")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(str(EMBED_PATH), trust_remote_code=False)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModel.from_pretrained(
        str(EMBED_PATH), torch_dtype=torch.bfloat16, device_map="cpu",
        low_cpu_mem_usage=True, trust_remote_code=False)
    quantize_(model, Float8WeightOnlyConfig(weight_dtype=torch.float8_e4m3fn))
    model.to("cuda")
    model.eval()
    load_s = time.time() - t0

    texts = [
        "进程角色 P.in.multi.few 通过 syscall write 作用于网络端点 N.listen.single",
        "文件角色 F.wr.single 通过 read 到进程角色 P.none.leaf.single",
        "进程通过 execve 派生 shell，随后 unlink 删除日志文件",
        "网络端点 recvfrom 到数据库进程，随后 write 到 /srv/bizapp 数据文件",
    ]
    torch.cuda.reset_peak_memory_stats()
    base_vram = torch.cuda.memory_allocated()
    with torch.no_grad():
        batch = tokenizer(texts, padding=True, truncation=True, max_length=512,
                          return_tensors="pt").to("cuda")
        t1 = time.time()
        out = model(**batch)
        hidden = out.last_hidden_state[:, -1]
        vec = torch.nn.functional.normalize(hidden.float(), p=2, dim=1)
        torch.cuda.synchronize()
        infer_s = time.time() - t1
        peak = max(base_vram, torch.cuda.max_memory_allocated()) / (1024 ** 3)
    if vec.shape[1] != 2560:
        fail(f"Embedding 维度异常：{tuple(vec.shape)}，期望 2560")
    return {
        "model": str(EMBED_PATH),
        "device": "cuda",
        "quantization": "torchao.Float8WeightOnlyConfig(float8_e4m3fn)",
        "dtype": "float8 weight-only",
        "hidden_dim": int(vec.shape[1]),
        "batch": len(texts),
        "load_seconds": round(load_s, 2),
        "infer_seconds": round(infer_s, 3),
        "base_vram_gb": round(base_vram / (1024 ** 3), 3),
        "peak_vram_gb": round(peak, 3),
        "norm_sample": [round(float(x), 4) for x in vec[0, :5]],
    }


def check_reranker() -> dict:
    import torch
    from sentence_transformers import CrossEncoder

    if not torch.cuda.is_available():
        fail("CUDA 不可用")
    t0 = time.time()
    model = CrossEncoder(
        str(RERANK_PATH), device="cuda",
        model_kwargs={"torch_dtype": torch.float16, "low_cpu_mem_usage": True},
    )
    load_s = time.time() - t0
    pairs = [
        ("进程通过 unlink 删除业务日志文件", "T1070.004 Indicator Removal: File Deletion"),
        ("进程通过 unlink 删除业务日志文件", "T1059 Command and Scripting Interpreter"),
        ("网络端点 recvfrom 到数据库进程后写入数据文件", "T1110 Brute Force"),
    ]
    torch.cuda.reset_peak_memory_stats()
    base_vram = torch.cuda.memory_allocated()
    t1 = time.time()
    scores = model.predict(pairs, batch_size=1, show_progress_bar=False)
    torch.cuda.synchronize()
    infer_s = time.time() - t1
    peak = max(base_vram, torch.cuda.max_memory_allocated()) / (1024 ** 3)
    return {
        "model": str(RERANK_PATH),
        "device": "cuda",
        "dtype": "float16",
        "pairs": len(pairs),
        "load_seconds": round(load_s, 2),
        "infer_seconds": round(infer_s, 3),
        "base_vram_gb": round(base_vram / (1024 ** 3), 3),
        "peak_vram_gb": round(peak, 3),
        "scores": [round(float(x), 4) for x in scores],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-reranker", action="store_true")
    args = ap.parse_args()

    result = {"ok": True, "embedding": check_embedding()}
    if not args.skip_reranker:
        # 顺序加载：先释放 embedding，再加载 reranker，避免 8GB 显存同时常驻。
        import gc
        import torch
        gc.collect()
        torch.cuda.empty_cache()
        result["reranker"] = check_reranker()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
