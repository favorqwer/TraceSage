"""束的构造与五级细分（不需要数据库、不需要模型）。

钉住：五级键逐级细化（下一级是上一级的细分、每级覆盖同一集合）、通道位与对象类别的口径、
同类规模统计的百分位口径、束条目的样本确定性。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import llm.judge as bundles  # noqa: E402
import llm.judge as items_mod  # noqa: E402


def record(src, syscall, dst, *, src_label="Process", dst_label="File", rels=("f2p",),
           members=("p1",), channels=1, t0=10, bytes_=5):
    return {"src": src, "syscall": syscall, "dst": dst, "src_label": src_label,
            "dst_label": dst_label, "rels": list(rels), "member_processes": list(members),
            "channels": channels, "t0": t0, "t1": t0 + 1, "bytes": bytes_, "instances": 1,
            "event_ids": [t0], "dist": 0, "via": "", "via_kind": "", "via_key": ""}


def sample_records():
    records = {
        ("/bin/bash", "read", "/etc/a.conf"): record("/bin/bash", "read", "/etc/a.conf"),
        ("/bin/bash", "read", "/etc/b.conf"): record("/bin/bash", "read", "/etc/b.conf"),
        ("/bin/bash", "read", "/tmp/x.conf"): record("/bin/bash", "read", "/tmp/x.conf",
                                                     channels=3),
        ("/usr/bin/curl", "sendto", "10.0.0.5:1->1.2.3.4:80"):
            record("/usr/bin/curl", "sendto", "10.0.0.5:1->1.2.3.4:80", src_label="Process",
                   dst_label="Network", rels=("p2n",), members=("p2",), channels=4),
        ("/usr/bin/curl", "sendto", "10.0.0.5:2->1.2.3.4:443"):
            record("/usr/bin/curl", "sendto", "10.0.0.5:2->1.2.3.4:443", src_label="Process",
                   dst_label="Network", rels=("p2n",), members=("p2",), channels=4),
        ("/usr/sbin/sshd", "execve", "/bin/bash"): record("/usr/sbin/sshd", "execve", "/bin/bash",
                                                          dst_label="Process", rels=("p2p",),
                                                          members=("p3",), channels=0),
    }
    program_of = {"p1": "/bin/bash", "p2": "/usr/bin/curl", "p3": "/usr/sbin/sshd"}
    return records, program_of


class LevelKeyTest(unittest.TestCase):
    def test_partition_and_refinement(self) -> None:
        records, program_of = sample_records()
        levels = bundles.build_levels(set(records), records, bundles.LevelKey(program_of))
        self.assertEqual(len(levels), 5)
        check = bundles.check_partition(levels)
        for level in range(5):
            self.assertTrue(check[f"L{level}_covers_same_set"], check)
        self.assertTrue(check["monotone_refinement"], check)
        self.assertEqual(len(levels[4]), len(records), "最细一级是单条边")

    def test_keys_nest(self) -> None:
        records, program_of = sample_records()
        keyer = bundles.LevelKey(program_of)
        triple = ("/bin/bash", "read", "/etc/a.conf")
        keys = keyer.keys(triple, records[triple])
        # 前四级键逐级加一段（后一级以前一级为前缀）；最细一级就是这条边本身
        for index in range(3):
            self.assertEqual(keys[index + 1][:len(keys[index])], keys[index],
                             "下一级的键以上一级的键为前缀")
        self.assertEqual(keys[4], (triple,), "最细一级是单条边")
        self.assertEqual(keys[0][0], ("/bin/bash",), "第 1 级键的第一段是程序集合")
        self.assertEqual(keys[2][-1], "/etc", "第 3 级加了对象所在目录")
        self.assertEqual(keys[1][3], "Process", "第 2 级加了入闭包通道")

    def test_network_class_ignores_ports(self) -> None:
        records, program_of = sample_records()
        levels = bundles.build_levels(set(records), records, bundles.LevelKey(program_of))
        pairs = [key for key in levels[2] if "主机对" in str(key)]
        self.assertEqual(len(pairs), 1, "同一个主机对（端口不同）归成一类")

    def test_channel_and_dir_class(self) -> None:
        self.assertEqual(bundles.channel_class(0), "(无)")
        self.assertEqual(bundles.channel_class(5), "Process+Network")
        self.assertEqual(bundles.dir_class("/etc/ssh/sshd_config", "File"), "/etc/ssh")
        self.assertEqual(bundles.dir_class("10.0.0.5:1->1.2.3.4:80", "Network"),
                         "主机对 1.2.3.4|10.0.0.5")
        self.assertEqual(bundles.dir_class("/bin/bash", "Process"), "(进程)")

    def test_scale_stats_percentile(self) -> None:
        index = {"/etc": {"n": 4, "median": 2, "sizes": [1, 2, 2, 5]}}
        stats = bundles.scale_stats(index, "/etc", 2)
        self.assertEqual(stats["rank"], 2, "更大的只有那一束（5 条）")
        self.assertEqual(stats["pct"], 50)
        self.assertIsNone(bundles.scale_stats({"/etc": {"n": 2, "median": 1, "sizes": [1, 2]}},
                                              "/etc", 1), "同类少于 3 个束时不报规模")

    def test_scale_index_from_records(self) -> None:
        records, program_of = sample_records()
        index = bundles.build_scale_index(set(records), records, bundles.LevelKey(program_of))
        self.assertIn("/etc", index)
        self.assertEqual(index["/etc"]["n"], 1, "该程序在 /etc 上只有一个初始束")


class ItemTest(unittest.TestCase):
    def test_sample_prefers_distinct_objects_and_is_deterministic(self) -> None:
        records, program_of = sample_records()
        members = sorted(records)
        first = items_mod.sample_members(members, 2)
        second = items_mod.sample_members(list(reversed(members)), 2)
        self.assertEqual(first, second, "样本与成员顺序无关")

    def test_build_items_fields_and_vacuous(self) -> None:
        records, program_of = sample_records()
        metas = {"p1": {"owner": "/bin/bash", "owner_args": "/bin/bash -c x", "t0": 1},
                 "p2": {"owner": "/usr/bin/curl", "owner_args": "curl http://x", "t0": 1},
                 "p3": {"owner": "/usr/sbin/sshd", "owner_args": "", "t0": 1}}
        levels = bundles.build_levels(set(records), records, bundles.LevelKey(program_of))
        counter = {"n": 0}

        def next_id() -> str:
            counter["n"] += 1
            return f"B{counter['n']:04d}"

        keys = sorted(levels[0], key=bundles.sort_text)
        built = items_mod.build_items(keys, 0, levels, records, metas, samples=2, next_id=next_id)
        self.assertEqual(len(built), len(keys))
        for item in built:
            self.assertEqual(sorted(item["members"]), sorted(levels[0][item["key"]]))
            self.assertEqual(item["size"], len(item["members"]))
            self.assertTrue(item["programs"])
            self.assertLessEqual(len(item["sample"]), 2)

        parent = {}
        for child_key in levels[1]:
            member = levels[1][child_key][0]
            for parent_key, parent_members in levels[0].items():
                if member in parent_members:
                    parent[child_key] = (built[keys.index(parent_key)], "mixed", "理由")
                    break
        children = items_mod.build_items(sorted(levels[1], key=bundles.sort_text), 1, levels,
                                         records, metas, samples=2, next_id=next_id,
                                         parents=parent)
        for item in children:
            self.assertIn("parent", item)
            same = item["size"] == item["parent"]["size"]
            self.assertEqual(bool(item.get("vacuous")), same)


if __name__ == "__main__":
    unittest.main()
