#!/usr/bin/env python
"""单场景运行入口。

用法：
    python experiments/plain_llm/run_scenario.py --scenario 1_Web_Exploit_Ransomware
    python experiments/plain_llm/run_scenario.py --scenario 1_Web_Exploit_Ransomware \
        --out output/plain-llm-runs/1_Web_Exploit_Ransomware --chunk-size 200 --concurrency 4
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from plainllm.run_scenario import run_scenario  # noqa: E402
from plainllm.settings import load_config  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", required=True, help="场景全名（与 groundtruth 文件名一致）")
    parser.add_argument("--config", default=None, help="配置文件，默认 experiments/plain_llm/config.yaml")
    parser.add_argument("--out", default=None, help="输出目录，默认 <output_root>/<场景>")
    parser.add_argument("--chunk-size", type=int, default=None, help="阶段一每批边数")
    parser.add_argument("--assemble-chunk", type=int, default=None, help="阶段二每批候选边数")
    parser.add_argument("--concurrency", type=int, default=None, help="阶段一并发数")
    parser.add_argument("--no-resume", action="store_true", help="忽略已有批次检查点，重新请求")
    parser.add_argument("--reexport", action="store_true", help="强制重新导出边表")
    args = parser.parse_args()

    cfg = load_config(
        args.config,
        chunk_size=args.chunk_size,
        assemble_chunk=args.assemble_chunk,
        concurrency=args.concurrency,
    )
    run_scenario(
        cfg,
        args.scenario,
        out_dir=Path(args.out) if args.out else None,
        resume=not args.no_resume,
        reexport=args.reexport,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
