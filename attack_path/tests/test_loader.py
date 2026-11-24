"""验证 attack_path 零查库事件加载器（loader.py）的读取与完整性校验。"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attack_path.loader import load_scenario_events  # noqa: E402


class TestScenarioEventsLoader(unittest.TestCase):
    def _sample_payload(self) -> dict:
        return {
            "format_version": 1,
            "scenario": "1_Web_Exploit_Ransomware",
            "database": "attack-1-web-exploit-ransomware-v2",
            "poi_events": ["ProcessToFile:7080705:write"],
            "stats": {"retained_events": 1, "entities": 2},
            "events": [
                {
                    "id": "ProcessToFile:7080705:write",
                    "event_id": 7080705,
                    "rel": "p2f",
                    "rel_full": "ProcessToFile",
                    "action": "write",
                    "syscall": "write",
                    "start_ns": 1000,
                    "end_ns": None,
                    "result": 64,
                    "bytes": 64,
                    "effect": "success",
                    "src_kind": "Process",
                    "src_key": "h1|host|500|900",
                    "src_host": "h1",
                    "src_file_type": None,
                    "dst_kind": "File",
                    "dst_key": "/srv/data/README_RESTORE.txt",
                    "dst_host": "h1",
                    "dst_file_type": "file",
                    "agg_edge_index": 0,
                    "report_status": "confirmed",
                    "verdict": "all",
                    "verdict_reason": "anchor",
                    "origin": "confirmed",
                    "class": "anchor",
                    "reason": "告警事实锚点 (POI)",
                    "bundle_triple": ["/usr/bin/cat", "write", "/srv/data/README_RESTORE.txt"],
                    "memberships": [{"agg_edge_index": 0, "report_status": "confirmed"}],
                }
            ],
            "entities": {
                "Process:h1|host|500|900": {
                    "kind": "Process", "key": "h1|host|500|900", "content": "/usr/bin/cat",
                    "host_id": "h1", "container_id": "host", "pid": 500, "ppid": 499,
                    "exepath": "/usr/bin/cat", "args": "/usr/bin/cat", "uid": 0, "euid": 0,
                },
                "File:/srv/data/README_RESTORE.txt": {
                    "kind": "File", "key": "/srv/data/README_RESTORE.txt",
                    "content": "/srv/data/README_RESTORE.txt", "host_id": "h1",
                    "container_id": "host", "file_type": "file",
                },
            },
        }

    def test_load_gzip_events_and_normalize_missing_end_ns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "1_Web_Exploit_Ransomware.events.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                json.dump(self._sample_payload(), fh, ensure_ascii=False)
            ds = load_scenario_events(path)
            self.assertEqual(ds.scenario, "1_Web_Exploit_Ransomware")
            self.assertEqual(len(ds.events), 1)
            ev = ds.events[0]
            self.assertEqual(ev.end_ns, 1000)
            self.assertEqual(ev.report_status, "confirmed")
            proc = ds.entity_of("Process", "h1|host|500|900")
            self.assertIsNotNone(proc)
            self.assertEqual(proc.pid, 500)

    def test_rejects_non_v2_database_and_missing_entity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_db = self._sample_payload()
            bad_db["database"] = "attack-1-web-exploit-ransomware"
            p1 = Path(tmp) / "bad_db.events.json.gz"
            with gzip.open(p1, "wt", encoding="utf-8") as fh:
                json.dump(bad_db, fh)
            with self.assertRaises(ValueError):
                load_scenario_events(p1)

            bad_ent = self._sample_payload()
            del bad_ent["entities"]["File:/srv/data/README_RESTORE.txt"]
            p2 = Path(tmp) / "bad_ent.events.json.gz"
            with gzip.open(p2, "wt", encoding="utf-8") as fh:
                json.dump(bad_ent, fh)
            with self.assertRaises(ValueError):
                load_scenario_events(p2)


if __name__ == "__main__":
    unittest.main()
