import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_triplet_validation import sha256, stage_mainline_archive


class MainlineArchiveTest(unittest.TestCase):
    def test_archive_preserves_relative_paths_and_event_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {"report": root / "report.json", "events": root / "report.events.json.gz",
                       "trace": root / "report.trace.jsonl"}
            sources["report"].write_text('{"edges":[]}', encoding="utf-8")
            sources["trace"].write_text('{"input_protocol":"triplet-v1"}\n', encoding="utf-8")
            with gzip.open(sources["events"], "wb") as stream:
                stream.write(b'{"events":[]}')
            counts = {"steps_hit": 1, "steps_total": 2, "correct_edges": 1, "reported_triples": 3}
            row = {"scenario": "unit", "llm_request_attempts": 1, **counts,
                   **{name: {"path": str(path), "sha256": sha256(path)} for name, path in sources.items()}}
            stage_mainline_archive(root, {"git_head": "test", "inputs": {}, "code_sha256": {},
                                          "systems": {"attack_graph": {"micro": counts, "results": [row]}}})
            archive = root / "release-candidate"
            summary = json.loads((archive / "summary_v2.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["scoring_protocol"], "triplet-v1")
            archived = summary["results"][0]
            with gzip.open(archive / archived["gzip"], "rb") as stream:
                self.assertEqual(stream.read(), sources["report"].read_bytes())
            self.assertEqual((archive / archived["events_gzip"]).read_bytes(), sources["events"].read_bytes())
            self.assertEqual(sha256(archive / archived["trace"]), archived["trace_sha256"])
