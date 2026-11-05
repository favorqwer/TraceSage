import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm.emit import CdmEmitter  # noqa: E402
from provenance.adapters.cdm.mapping import (  # noqa: E402
    ALLOWED_ACTIONS,
    ALLOWED_SPECIALS,
    SKIP_BUCKETS,
    EventTable,
)
from provenance.core.kinds import Bucket, EdgeClass  # noqa: E402

#: schema/TCCDMDatum.avsc 里 EventType 枚举的全部 50 个符号。
#: 映射表必须逐条覆盖，缺一条就意味着该事件会静默落 UNMAPPED 桶。
SCHEMA_EVENT_TYPES = [
    "EVENT_ACCEPT", "EVENT_ADD_OBJECT_ATTRIBUTE", "EVENT_BIND", "EVENT_BLIND",
    "EVENT_BOOT", "EVENT_CHANGE_PRINCIPAL", "EVENT_CHECK_FILE_ATTRIBUTES",
    "EVENT_CLONE", "EVENT_CLOSE", "EVENT_CONNECT", "EVENT_CREATE_OBJECT",
    "EVENT_CREATE_THREAD", "EVENT_DUP", "EVENT_EXECUTE", "EVENT_EXIT",
    "EVENT_FLOWS_TO", "EVENT_FCNTL", "EVENT_FORK", "EVENT_LINK",
    "EVENT_LOADLIBRARY", "EVENT_LOGCLEAR", "EVENT_LOGIN", "EVENT_LOGOUT",
    "EVENT_LSEEK", "EVENT_MMAP", "EVENT_MODIFY_FILE_ATTRIBUTES",
    "EVENT_MODIFY_PROCESS", "EVENT_MOUNT", "EVENT_MPROTECT", "EVENT_OPEN",
    "EVENT_OTHER", "EVENT_READ", "EVENT_READ_SOCKET_PARAMS", "EVENT_RECVFROM",
    "EVENT_RECVMSG", "EVENT_RENAME", "EVENT_SENDTO", "EVENT_SENDMSG",
    "EVENT_SERVICEINSTALL", "EVENT_SHM", "EVENT_SIGNAL", "EVENT_STARTSERVICE",
    "EVENT_TRUNCATE", "EVENT_UMOUNT", "EVENT_UNIT", "EVENT_UNLINK",
    "EVENT_UPDATE", "EVENT_WAIT", "EVENT_WRITE", "EVENT_WRITE_SOCKET_PARAMS",
]


class MappingTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = EventTable.load(ROOT / "data" / "cdm_events.toml")

    def test_covers_every_schema_event_type(self):
        missing = [name for name in SCHEMA_EVENT_TYPES if self.table.get(name) is None]
        self.assertEqual(missing, [])

    def test_table_has_no_extra_names(self):
        extra = sorted(self.table.names - set(SCHEMA_EVENT_TYPES))
        self.assertEqual(extra, [])

    def test_all_specials_are_implemented(self):
        missing = [
            name for name, rule in self.table.rules.items()
            if rule.special and not hasattr(CdmEmitter, f"_on_{rule.special}")
        ]
        self.assertEqual(missing, [])

    def test_specials_are_declared(self):
        for rule in self.table.rules.values():
            if rule.special:
                self.assertIn(rule.special, ALLOWED_SPECIALS, rule.name)

    def test_branch_edges_and_actions_are_valid(self):
        for rule in self.table.rules.values():
            for cls, branch in rule.branches.items():
                if branch.skip:
                    continue
                self.assertIsInstance(branch.edge, EdgeClass, f"{rule.name}.{cls}")
                self.assertIn(branch.action, ALLOWED_ACTIONS, f"{rule.name}.{cls}")
                self.assertTrue(branch.syscall, f"{rule.name}.{cls}")

    def test_skip_branches_use_known_buckets(self):
        known = set(SKIP_BUCKETS)
        seen = 0
        for rule in self.table.rules.values():
            for cls, branch in rule.branches.items():
                if branch.skip:
                    seen += 1
                    self.assertIn(branch.skip, known, f"{rule.name}.{cls}")
        self.assertGreater(seen, 0, "至少应有一个 skip 分支（EVENT_ACCEPT.file）")

    def test_unknown_event_returns_none(self):
        self.assertIsNone(self.table.get("EVENT_FROM_THE_FUTURE"))

    def test_unnamed_object_data_flow_has_no_branch(self):
        # EVENT_WRITE 只声明 file/net：客体是 srcsink 时必须落 NO_OBJECT
        rule = self.table.get("EVENT_WRITE")
        self.assertNotIn("srcsink", rule.branches)
        self.assertEqual(set(rule.branches), {"file", "net"})


if __name__ == "__main__":
    unittest.main()
