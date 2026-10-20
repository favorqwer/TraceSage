"""建 / 重建第 1 层的顶点-时间索引（本地索引；正式流程唯一取数方式）。

用法（在仓库根目录）：

    python tools/l1_index.py --database attack-3-phishing-beacon-cryptomining
    python tools/l1_index.py --database attack-3-phishing-beacon-cryptomining --force

正常跑导航器时不用手动建：索引缺失或过期会自动重建（见 `foundation/layers/l1_reach/graph_index.py`
的 `ensure_snapshot`）。这个脚本只用于「先建好再看，或者强制重建」。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "provenance-navigator"))

from foundation.core import settings  # noqa: E402
from foundation.core.db import ReadOnlyGraph  # noqa: E402
from foundation.layers.l1_reach import graph_index as snap  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="构建第 1 层的顶点-时间索引快照")
    parser.add_argument("--database", required=True, help="Neo4j 库名（见 provenance-navigator/config/scenarios.json）")
    parser.add_argument("--force", action="store_true", help="已存在也重建")
    args = parser.parse_args()

    settings.load_dotenv()
    settings.ensure_work_dirs()
    settings.ensure_index_dir()

    if not args.force:
        meta = snap.read_meta(args.database)
        if meta is not None:
            print(f"索引已存在：{snap.meta_path(args.database)}（--force 可重建）")
            return 0

    graph = ReadOnlyGraph(args.database, run_id=f"index-{os.getpid()}")
    try:
        snap.build_snapshot(graph, log=print)
    finally:
        graph.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
