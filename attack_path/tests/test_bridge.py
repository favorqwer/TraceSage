"""验证 attack_path 与 attack_graph 内部模块及基线产物的桥接复用。"""
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
    """核对对 attack_graph 内部模块的导入与 10 场景路径解析。"""

    def test_settings_resolves_to_attack_graph(self) -> None:
        cfg = _bridge.attack_graph_settings()
        self.assertEqual(Path(cfg.__file__).resolve().parent, _bridge.ATTACK_GRAPH_DIR.resolve())

    def test_can_import_attack_graph_internals(self) -> None:
        _bridge.ensure_attack_graph_on_path()
        neo4j_mod = importlib.import_module("closure.neo4j")
        snapshot_mod = importlib.import_module("closure.snapshot")
        tp_mod = importlib.import_module("core.stages.temporal_pruning")
        self.assertTrue(hasattr(neo4j_mod, "ReadOnlyGraph"))
        self.assertTrue(hasattr(snapshot_mod, "snapshot_dir"))
        self.assertTrue(hasattr(tp_mod, "run_bidirectional"))

    def test_ten_scenarios_and_assets_exist(self) -> None:
        scenarios = _bridge.available_scenarios()
        self.assertEqual(len(scenarios), 10)
        for name in scenarios:
            sc = _bridge.load_scenario(name)
            self.assertTrue(sc.database.endswith("-v2"))
            cache_dir = _bridge.l1_cache_dir(sc.database)
            self.assertTrue((cache_dir / "vertices.json").is_file())
            self.assertTrue((cache_dir / "meta.json").is_file())
            self.assertTrue(_bridge.baseline_report_path(name).is_file())


if __name__ == "__main__":
    unittest.main()
