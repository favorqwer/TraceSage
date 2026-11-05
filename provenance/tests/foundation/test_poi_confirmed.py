import unittest
from domain.state import Investigation

class DummyDeps:
    def __init__(self, record):
        self.record = record
        self.log = lambda x: None
        self.trace = []
        self.model = None

class TestPoiAnchorConfirmation(unittest.TestCase):
    def test_poi_forced_confirmed(self):
        inv = Investigation(run_id="test-poi", scenario="test")
        # 模拟 POI 命中的行
        inv.poi_rows = [{
            "process_content": "/usr/bin/cat",
            "syscall": "write",
            "other": "/srv/data/README_RESTORE.txt",
            "rel": "p2f"
        }]
        # 模拟候选边
        trip = ("/usr/bin/cat", "write", "/srv/data/README_RESTORE.txt")
        inv.edges[trip] = {
            "src": "/usr/bin/cat", "syscall": "write", "dst": "/srv/data/README_RESTORE.txt",
            "rels": ["p2f"], "member_processes": ["25140cat"]
        }
        
        # 模拟结算：在没有被模型标记的情况下
        for row in inv.poi_rows:
            rel = str(row.get("rel") or "")
            sc = str(row.get("syscall") or "")
            owner = str(row.get("process_content") or "")
            other = str(row.get("other") or "")
            t = (owner, sc, other) if rel in ("p2f", "p2n") else (other, sc, owner)
            if t in inv.edges and inv.origin.get(t) != "confirmed":
                inv.mark([t], "confirmed")
                inv.edges[t]["verdict_reason"] = "告警事实锚点（POI）"
        inv.settle()

        self.assertIn(trip, inv.confirmed)
        self.assertEqual(inv.confirmed[trip]["verdict_reason"], "告警事实锚点（POI）")

if __name__ == "__main__":
    unittest.main()
