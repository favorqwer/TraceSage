import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm import archive as A  # noqa: E402


def _write_member(tar: tarfile.TarFile, name: str, lines: list[bytes]) -> None:
    payload = b"".join(lines)
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    import io

    tar.addfile(info, io.BytesIO(payload))


class MemberOrderTest(unittest.TestCase):
    def test_member_index(self):
        self.assertEqual(A.member_index("ta1-trace-e3-official-1.json"), 0)
        self.assertEqual(A.member_index("ta1-trace-e3-official-1.json.7"), 7)
        self.assertEqual(A.member_index("x.json.12"), 12)

    def _sample(self, tmp: str) -> Path:
        path = Path(tmp) / "sample.tar.gz"
        # 故意按 tar 物理顺序写入 .1, .10, .2（与 THEIA 归档同形态）
        with tarfile.open(path, "w:gz") as tar:
            _write_member(tar, "x.json", [b'{"a":0}\n'])
            _write_member(tar, "x.json.1", [b'{"a":1}\n'])
            _write_member(tar, "x.json.10", [b'{"a":10}\n'])
            _write_member(tar, "x.json.2", [b'{"a":2}\n'])
        return path

    def test_default_is_tar_order(self):
        """默认走单趟流式，产出顺序 = tar 物理顺序，不重排。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._sample(tmp)
            seen = [raw for _idx, _name, _line, raw in A.iter_lines(str(path))]
            self.assertEqual(
                seen,
                [b'{"a":0}\n', b'{"a":1}\n', b'{"a":10}\n', b'{"a":2}\n'],
            )

    def test_sort_members_restores_logical_order(self):
        """sort_members=True 按逻辑序号重排（时间顺序），供需要单调时间戳的场景使用。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._sample(tmp)
            seen = [
                raw for _idx, _name, _line, raw
                in A.iter_lines(str(path), sort_members=True)
            ]
            self.assertEqual(
                seen,
                [b'{"a":0}\n', b'{"a":1}\n', b'{"a":2}\n', b'{"a":10}\n'],
            )

    def test_member_window_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                for index in range(4):
                    name = "x.json" if index == 0 else f"x.json.{index}"
                    _write_member(tar, name, [f'{{"a":{index}}}\n'.encode()])
            rows = list(A.iter_lines(str(path), member_from=1, member_to=2,
                                     sort_members=True))
            self.assertEqual([raw for _i, _n, _l, raw in rows], [b'{"a":1}\n', b'{"a":2}\n'])

    def test_blank_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                _write_member(tar, "x.json", [b'{"a":0}\n', b"\n", b'{"a":1}\n'])
            rows = list(A.iter_lines(str(path)))
            self.assertEqual(len(rows), 2)
            # 行号保留原始位置（空行也被计数），便于回查原始文件
            self.assertEqual([line for _i, _n, line, _r in rows], [1, 3])


if __name__ == "__main__":
    unittest.main()
