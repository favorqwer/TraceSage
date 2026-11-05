"""B0：保留束级基模证据块，但 2 跳角色为空（复现历史旧解码）。

用法：
    .venv/Scripts/python.exe provenance-navigator/experiments/run_b0_empty_labels.py <场景全名>
输出：
    tmp/frozen_runs/b0/<场景>_b0.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import experiments.run_v4_frozen as m  # noqa: E402

m.REAL_2HOP = False
m.USE_MOTIF_EVIDENCE = True
m.VARIANT = "v4_empty_2hop"

scenario = sys.argv[1]
fold = str(ROOT / f"output/navigator-baseline/distill/fold-libraries/{scenario}.json")
out = str(ROOT / f"tmp/frozen_runs/b0/{scenario}_b0.json")

print("B0_RESULT " + json.dumps(
    m.run_single_scenario(scenario, fold, out), ensure_ascii=False))
