"""第 1 层判据表的单测（不需要数据库、不需要模型）：对象角色、事件判定。

口径（`foundation/rules/l1_judgments.json` + `l1_reach/judgments.py`）：
- 对象判据按表顺序取第一个命中，后果是「不展开对象」与「不追交接」；
- 事件判据：零字节的数据读取（读类边、搬 0 字节）与连接建立类（不算交付）。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from foundation.layers.l1_reach import judgments as J
from foundation.layers.l1_reach import table as T


def row(event_id: int, *, pid: str = "7sshd", rel: str = "f2p", other: str = "/etc/passwd",
        syscall: str = "read", at: int = 10, other_process_id: str = "") -> dict:
    """一条候选边行：只带判据会看的字段。"""
    return {"event_id": event_id, "rel": rel, "syscall": syscall, "owner": "/usr/sbin/sshd",
            "other": other, "process_id": pid, "other_process_id": other_process_id,
            "starttime": at, "endtime": at + 1, "bytes": 0, "dist": 1,
            "via_kind": "", "via_key": "", "support": 8}


class ObjectRulingTest(unittest.TestCase):
    def test_nondelivery_paths(self) -> None:
        """内核现生成的伪文件、设备节点、系统运行目录：不展开（读边照收，但不往回找写入者）。"""
        for path in ("/proc/1/limits", "/proc/cpuinfo", "/proc/self/status", "/sys/kernel/x",
                     "/dev/null", "/dev/sda", "/run/utmp", "/var/run/utmp", "/var/lock/x",
                     "unix:[/run/systemd/private]"):
            ruling = J.object_ruling(path)
            self.assertIn("no_expand", ruling.effects, path)
            self.assertTrue(ruling.label, path)

    def test_content_carrying_objects_are_deliver(self) -> None:
        """能承载内容的对象必须走交付（内存盘放载荷、伪终端传输入、会话套接字提权）。"""
        for path in ("/dev/shm/payload", "/dev/pts/0", "/dev/tty", "/dev/stdin",
                     "unix:[/run/user/1000/bus]"):
            self.assertEqual(J.object_ruling(path).effects, frozenset(), path)

    def test_user_products_and_system_files_are_deliver(self) -> None:
        """系统提供的文件不再排除：图上证明不了它没被改过。"""
        for path in ("/usr/bin/tar", "/etc/passwd", "/var/lib/x", "/home/u/x", "/tmp/a",
                     "pipe:[7]", "unix:[/tmp/x]"):
            self.assertEqual(J.object_ruling(path).effects, frozenset(), path)

    def test_runtime_dir_aliases_share_one_label(self) -> None:
        label = J.object_ruling("/run/utmp").label
        self.assertEqual(J.object_ruling("/var/run/utmp").label, label)

    def test_content_carrying_entries_come_first(self) -> None:
        """能承载内容的条目排在 /dev、/run 大类之前（顺序即优先级）。"""
        ids = [rule.id for rule in T.load().of("object")]
        self.assertLess(ids.index("obj.deliver.memory_terminal_stdio"),
                        ids.index("obj.nondelivery.device_node"))
        self.assertLess(ids.index("obj.deliver.user_runtime_socket"),
                        ids.index("obj.nondelivery.system_socket"))


class EventRulingTest(unittest.TestCase):
    def test_zero_byte_read(self) -> None:
        for rel in ("f2p", "n2p"):
            for syscall in ("read", "recvfrom"):
                for nbytes in (0, -1, None):
                    ruling = J.event_ruling(rel, syscall, nbytes)
                    self.assertIn("no_expand", ruling.effects, (rel, syscall, nbytes))

    def test_non_empty_read_is_expanded(self) -> None:
        self.assertNotIn("no_expand", J.event_ruling("f2p", "read", 4096).effects)

    def test_setup_operations_are_not_delivery(self) -> None:
        for rel in ("p2f", "p2n"):
            for syscall in ("connect", "bind"):
                self.assertIn("not_delivery", J.event_ruling(rel, syscall, 0).effects)

    def test_write_is_delivery(self) -> None:
        self.assertNotIn("not_delivery", J.event_ruling("p2f", "write", 10).effects)


if __name__ == "__main__":
    unittest.main()
