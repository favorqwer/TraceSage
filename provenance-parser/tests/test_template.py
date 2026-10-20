import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.scap.template import STAR_TEMPLATE, TEMPLATE, decode  # noqa: E402
from provenance.core.stats import RunStats  # noqa: E402

LINE = "\t".join([
    "1",
    "123.000000000",
    ">",
    "read",
    "<NA>",
    "0",
    "<NA>",
    "<NA>",
    "<NA>",
    "<NA>",
    "<NA>",
    "fd=5(<f>/tmp/x) res=1",
    "<NA>",
    "1",
    "",
])


class TemplateTest(unittest.TestCase):
    def test_star_is_first_character(self):
        self.assertTrue(STAR_TEMPLATE.startswith("*%evt.num"))
        self.assertFalse(TEMPLATE.startswith("*"))

    def test_na_fields_are_missing(self):
        row = decode(LINE.encode("utf-8"))
        self.assertEqual(row.num, 1)
        self.assertEqual(row.call, "read")
        self.assertEqual(row.pid, 0)
        self.assertEqual(row.container_id, "host")
        self.assertEqual(row.exe, "")
        self.assertEqual(row.cwd, "")
        self.assertEqual(row.ppid, 0)
        self.assertEqual(row.ruid, "")
        self.assertEqual(row.proc_args, "")
        self.assertEqual(row.args["fd"], "5(<f>/tmp/x)")
        self.assertEqual(row.rawres, 1)
        self.assertEqual(row.buffer_b64, "")
        self.assertIn("proc.pid", row.na_fields)
        self.assertIn("container.id", row.na_fields)
        self.assertIn("proc.args", row.na_fields)

    def test_missing_container_with_pid_is_abnormal(self):
        line = LINE.replace("\t<NA>\t0\t<NA>", "\t42\t0\t<NA>", 1).encode("utf-8")
        with self.assertRaises(ValueError):
            decode(line)

    def test_stats_counts_placeholder_rows(self):
        row = decode(LINE.encode("utf-8"))
        stats = RunStats()
        stats.count_row(row)
        snap = stats.snapshot()
        self.assertEqual(snap.pid_present_rows, 0)
        self.assertEqual(snap.missing_by_field["proc.pid"]["read"], 1)
        self.assertEqual(snap.by_type["read"], 1)


if __name__ == "__main__":
    unittest.main()
