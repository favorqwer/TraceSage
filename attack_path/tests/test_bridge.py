"""验证 attack_path 与 attack_graph 内部模块、单文件 .tsg 索引及基线产物的零 Neo4j 桥接复用。"""
from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attack_path import _bridge  # noqa: E402


class TestAttackGraphBridge(unittest.TestCase):
    """核对对 attack_graph 内部模块的导入与 10 场景 .tsg 路径解析。"""

    def test_settings_resolves_to_attack_graph(self) -> None:
        cfg = _bridge.attack_graph_settings()
        self.assertEqual(Path(cfg.__file__).resolve().parent, _bridge.ATTACK_GRAPH_DIR.resolve())

    def test_can_import_attack_graph_internals(self) -> None:
        _bridge.ensure_attack_graph_on_path()
        snapshot_mod = importlib.import_module("closure.snapshot")
        tp_mod = importlib.import_module("core.stages.temporal_pruning")
        self.assertTrue(hasattr(snapshot_mod, "TSGSource"))
        self.assertTrue(hasattr(snapshot_mod, "open_tsg_source"))
        self.assertTrue(hasattr(tp_mod, "run_bidirectional"))

    def test_ten_scenarios_and_assets_exist(self) -> None:
        scenarios = _bridge.available_scenarios()
        self.assertEqual(len(scenarios), 10)
        for name in scenarios:
            sc = _bridge.load_scenario(name)
            self.assertTrue(sc.database.endswith("-v2"))
            self.assertTrue(_bridge.baseline_report_path(name).is_file())
            self.assertTrue(_bridge.baseline_events_path(name).is_file())
            gpath = _bridge.graph_path(name)
            self.assertEqual(gpath.parent, _bridge.GRAPH_STORE_DIR)
            self.assertTrue(gpath.is_file())


if __name__ == "__main__":
    unittest.main()
