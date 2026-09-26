"""第 2 层：确定性粗筛（只作用于"文件被读"的边；标注里真实存在的路径不得被粗筛）。"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pagent.layers.l2_prepare import prefilter_reason


class PrefilterTest(unittest.TestCase):
    def test_system_routine_read_is_prefiltered(self) -> None:
        self.assertNotEqual(
            prefilter_reason({"syscall": "read", "src_label": "File",
                              "src": "/usr/share/locale/xx/LC_MESSAGES/a.mo"}),
            "", "系统例行文件读命中确定性粗筛")

    def test_gt_path_is_not_prefiltered(self) -> None:
        self.assertEqual(
            prefilter_reason({"syscall": "read", "src_label": "File", "src": "/etc/passwd"}),
            "", "标注里真实存在的路径不得被粗筛（/etc/passwd）")

    def test_only_file_read_edges(self) -> None:
        self.assertEqual(
            prefilter_reason({"syscall": "write", "src_label": "Process", "src": "/usr/bin/tar"}),
            "", "粗筛只作用于 File→Process 的 read")


if __name__ == "__main__":
    unittest.main()
