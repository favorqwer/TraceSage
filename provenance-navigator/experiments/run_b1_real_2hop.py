"""B1：束级基模证据块，2 跳角色真实解码。

用法：
    .venv/Scripts/python.exe provenance-navigator/experiments/run_b1_real_2hop.py <场景全名>
输出：
    tmp/frozen_runs/b1/<场景>_b1.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import experiments.run_v4_frozen as m  # noqa: E402

m.REAL_2HOP = True
m.USE_MOTIF_EVIDENCE = True
m.VARIANT = "v4_real_2hop"

scenario = sys.argv[1]
fold = str(ROOT / f"output/navigator-baseline/distill/fold-libraries/{scenario}.json")
out = str(ROOT / f"tmp/frozen_runs/b1/{scenario}_b1.json")

print("B1_RESULT " + json.dumps(
    m.run_single_scenario(scenario, fold, out), ensure_ascii=False))
