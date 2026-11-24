#!/usr/bin/env python
"""十个场景批量运行入口（场景逐个跑，场景内部并发）。

用法：
    python experiments/plain_llm/run_all.py
    python experiments/plain_llm/run_all.py --skip-existing
    python experiments/plain_llm/run_all.py --scenarios 1_Web_Exploit_Ransomware 7_DB_Bruteforce_Datawipe
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from plainllm.poi import load_scenarios  # noqa: E402
from plainllm.run_scenario import run_scenario  # noqa: E402
from plainllm.settings import load_config  # noqa: E402


def _scenario_order(name: str) -> tuple[int, str]:
    prefix = name.split("_", 1)[0]
    return (int(prefix) if prefix.isdigit() else 10_000, name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None)
    parser.add_argument("--output-root", default=None, help="覆盖 config.yaml 的 output_root")
    parser.add_argument("--scenarios", nargs="*", default=None, help="只跑指定场景")
    parser.add_argument("--chunk-size", type=int, default=None)
    parser.add_argument("--assemble-chunk", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--skip-existing", action="store_true", help="已有 report.json 的场景跳过")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--reexport", action="store_true")
    args = parser.parse_args()

    overrides = {
        "chunk_size": args.chunk_size,
        "assemble_chunk": args.assemble_chunk,
        "concurrency": args.concurrency,
    }
    if args.output_root:
        overrides["output_root"] = Path(args.output_root).resolve()
    cfg = load_config(args.config, **overrides)

    all_scenarios = load_scenarios(cfg.scenarios_file)
    names = args.scenarios or sorted(all_scenarios, key=_scenario_order)
    unknown = [n for n in names if n not in all_scenarios]
    if unknown:
        raise SystemExit(f"未知场景：{unknown}")

    print(f"模型 {cfg.model}；输出根目录 {cfg.output_root}；场景 {len(names)} 个", flush=True)
    started = time.time()
    manifests: list[dict] = []
    for index, name in enumerate(names, start=1):
        out = cfg.output_root / name
        if args.skip_existing and (out / "report.json").exists():
            print(f"\n[{index}/{len(names)}] {name} 已有报告，跳过", flush=True)
            manifest_path = out / "manifest.json"
            if manifest_path.exists():
                manifests.append(json.loads(manifest_path.read_text(encoding="utf-8")))
            continue
        print(f"\n[{index}/{len(names)}] {name}", flush=True)
        manifest = run_scenario(cfg, name, out_dir=out,
                                resume=not args.no_resume, reexport=args.reexport)
        manifests.append(manifest)

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": cfg.model,
        "chunk_size": cfg.chunk_size,
        "assemble_chunk": cfg.assemble_chunk,
        "concurrency": cfg.concurrency,
        "scenarios": [
            {
                "scenario": m["scenario"],
                "reported_edges": m["counts"]["reported_edges"],
                "scan_selected": m["counts"]["scan_selected"],
                "calls": m["llm"]["calls"],
                "prompt_tokens": m["llm"]["prompt_tokens"],
                "completion_tokens": m["llm"]["completion_tokens"],
                "wall_seconds": m["timings"]["total"],
                "failed_calls": m["llm"]["failures"],
            }
            for m in manifests
        ],
        "totals": {
            "calls": sum(m["llm"]["calls"] for m in manifests),
            "prompt_tokens": sum(m["llm"]["prompt_tokens"] for m in manifests),
            "completion_tokens": sum(m["llm"]["completion_tokens"] for m in manifests),
            "wall_seconds": round(sum(m["timings"]["total"] for m in manifests), 1),
            "failed_calls": sum(m["llm"]["failures"] for m in manifests),
        },
    }
    path = cfg.output_root / "run_summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n全部完成：{len(manifests)} 个场景，调用 {summary['totals']['calls']} 次，"
          f"墙钟 {time.time() - started:.0f}s；汇总写 {path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
