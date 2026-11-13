"""判定驱动（假模型，不连数据库、不调真实 LLM）：束级四值、四道闸门与三段恒等式。

假模型的判定策略（只看渲染文本里出现的程序，确定性）：

- 含 `/usr/bin/curl` 的束 → 整束相关（all）；
- 含 `/usr/sbin/sshd` 的束 → 整束无关（none）；
- 含 `/bin/bash` 的束 → 混杂（mixed，会被拆到更细的级）；
- 其余 → 判不了（unknown）。

由此可以钉住：只有 none 删边、mixed/unknown 继续拆、凭证闸门把「无凭证的 none」降级、
扇出闸门与叶子规则把单条边留在未排除集、调用上限按「保留」处理，以及三条恒等式
（每条边有来路、已确认 ⊆ 未排除、未排除 + 已排除 = 候选）。
"""

from __future__ import annotations

import importlib
import json
import pathlib
import re
import sys
import unittest
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from config_support import temp_config  # noqa: E402
from closure.intake import Deps  # noqa: E402
import settings as settings  # noqa: E402
from llm.client import LlmBudget  # noqa: E402
from domain.state import Investigation  # noqa: E402
import llm.judge as l2  # noqa: E402
import llm.judge as judging_mod  # noqa: E402


class FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content
        self.usage_metadata = {"input_tokens": 1, "output_tokens": 1}
        self.generations = None
        self.response_metadata = {}


class ScriptedBundleModel:
    """按每个束块里出现的程序给出四值结论；另刻意多写一个字段（必须被忽略）。"""

    def __init__(self, drop_ids: bool = False, drop_all: bool = False) -> None:
        self.calls = 0
        self.drop_ids = drop_ids
        self.drop_all = drop_all
        self.texts: list[str] = []

    def invoke(self, messages, config=None):
        self.calls += 1
        user = messages[-1].content
        self.texts.append(user)
        verdicts = []
        if self.drop_all:
            return FakeResponse(json.dumps({"verdicts": []}))
        blocks = re.split(r"^(?=B\d+｜)", user, flags=re.M)
        for block in blocks:
            match = re.match(r"^(B\d+)｜", block)
            if not match:
                continue
            bid = match.group(1)
            if self.drop_ids and bid.endswith("2"):
                continue                                   # 故意漏一个编号
            if "/usr/bin/curl" in block:
                verdict = "all"
            elif "/usr/sbin/sshd" in block:
                verdict = "none"
            elif "/bin/bash" in block:
                verdict = "mixed"
            else:
                verdict = "unknown"
            verdicts.append({"id": bid, "verdict": verdict, "reason": f"scripted-{bid}",
                             "confidence": 0.99, "witness_relevant": "M1",
                             "witness_irrelevant": "M2"})
        return FakeResponse(json.dumps({"verdicts": verdicts}))


def build_record() -> Investigation:
    """七个候选边：curl 的两个动作（含网络）、sshd 的派生与读配置、bash 的读与写。

    三元组方向与生产流水线一致（读边的源是对象、派生边的源是父进程）。
    """
    from domain import edge as graph_facts

    inv = Investigation(run_id=f"unit-{uuid.uuid4().hex[:8]}", scenario="unit")
    inv.poi_rows = [{"process_content": "/bin/bash", "other": "/srv/marker", "rel": "p2f",
                     "syscall": "write", "starttime": 100, "event_id": 1, "process_id": "p1"}]
    inv.poi_t0 = 100
    inv.add_hypothesis("POI", "POI: bash write /srv/marker", status="confirmed")
    raw = [
        ("p2f", "p1", "/srv/marker", 0, ["p2f"], 2),
        ("p2p", "p2", "/sbin/init", 1, ["p2p"], 0),
        ("f2p", "p1", "/srv/deploy.sh", 1, ["f2p"], 2),
        ("f2p", "p2", "/etc/ssh/sshd_config", 2, ["f2p"], 2),
        ("p2f", "p3", "/tmp/payload.bin", 2, ["p2f"], 2),
        ("p2n", "p3", "10.0.0.5:1->1.2.3.4:80", 2, ["p2n"], 2),
        ("f2p", "p3", "/tmp/payload.bin", 3, ["f2p"], 2),
    ]
    owner_content = {"p1": "/bin/bash", "p2": "/usr/sbin/sshd", "p3": "/usr/bin/curl"}
    for index, (rel, pid, other, dist, rels, channels) in enumerate(raw, 1):
        src, syscall, dst, src_label = graph_facts.content_triple_of(
            rel, {"p2f": "write", "p2n": "sendto", "f2p": "read", "p2p": "execve"}[rel],
            owner_content[pid], other)
        _src_label, dst_label = graph_facts.labels_of(rel)
        inv.edges[(src, syscall, dst)] = {
            "src": src, "syscall": syscall, "dst": dst, "src_label": src_label,
            "dst_label": dst_label, "instances": 1, "bytes": 10, "t0": 100 + index,
            "t1": 100 + index, "event_ids": [index], "process_id": pid, "dist": dist,
            "rels": rels, "channels": channels, "member_processes": [pid],
            "src_identities": [[src_label, src]], "dst_identities": [[dst_label, dst]],
            "via": "", "via_kind": "", "via_key": "", "network_protocol": "",
        }
    for pid, owner in owner_content.items():
        inv.process_context[pid] = {"process_id": pid, "owner": owner, "owner_args": f"{owner} -x",
                                    "cwd": "/root", "t0": 101, "t1": 110, "n_edges": 2,
                                    "origin": {"kind": "none", "parent": "", "parent_content": "",
                                               "t": 0, "n": 0}}
    return inv


def run_once(config: dict | None = None, drop_ids: bool = False, drop_all: bool = False):
    logs: list[str] = []
    inv = build_record()
    model = ScriptedBundleModel(drop_ids=drop_ids, drop_all=drop_all)
    deps = Deps(scenario=None, graph=None, model=model, budget=LlmBudget(), record=inv,
                log=logs.append, trace=[])
    base = {"bundle": {"aggregate": True, "annotate_marks": True, "forward": False}}
    if config:
        base["bundle"].update(config.get("bundle") or {})
        for section in ("judge", "render", "logging"):
            if section in config:
                base[section] = config[section]
    stats = {
        "candidates": len(inv.edges), "calls": 0, "seconds": 0.0, "levels": [],
        "guards": {"vacuous": 0, "fanout": {"bundles": 0, "edges": 0}, "hot": 0, "warrant": 0},
        "missing_bundles": 0,
    }
    detail: list[dict] = []
    with temp_config(base):
        program_of = l2.program_table(inv.process_context)
        keyer = l2.LevelKey(program_of)
        state = l2.BundleState(anchor=l2.anchor_facts(inv.poi_rows), program_of=program_of)
        judging_mod._judge_pass(
            deps, set(inv.edges), keyer=keyer, state=state, inv=inv, stats=stats,
            detail=detail, pass_no=1, cap_calls=settings.bundle_cap_calls())
    # 没轮到判定的束一律保留（与导航器主流程一致：失败即展开）
    for key in inv.edges:
        if key not in inv.origin:
            inv.mark([key], "kept")
    inv.settle()
    return inv, stats, model, logs


class BundleProtocolTest(unittest.TestCase):
    def test_three_tiers_are_consistent(self) -> None:
        inv, stats, model, logs = run_once()
        self.assertEqual(len(inv.confirmed) + len(inv.kept) + len(inv.excluded), len(inv.edges),
                         "每条候选边都有一段（已确认 / 未排除 / 已排除）")
        self.assertEqual(set(inv.origin), set(inv.edges))
        self.assertTrue(set(inv.confirmed) <= set(inv.unexcluded()))
        self.assertGreater(len(inv.confirmed), 0)
        self.assertGreater(len(inv.kept), 0)
        self.assertFalse(any("confidence" in edge or "witness_relevant" in edge
                             for edge in inv.edges.values()),
                         "模型多写的字段不得进入记录")
        self.assertTrue(stats["calls"] > 0)

    def test_only_none_deletes_edges_without_credential(self) -> None:
        """只有「整束无关」删边；命中已知误杀模式（全是派生边）的无关束降级为要拆。"""
        inv, stats, _model, logs = run_once()
        excluded = set(inv.excluded)
        self.assertEqual(excluded, {("/etc/ssh/sshd_config", "read", "/usr/sbin/sshd")},
                         "只读、无凭证的无关束才真的删边")
        self.assertNotIn(("/sbin/init", "execve", "/usr/sbin/sshd"), excluded,
                         "全是派生边的束命中误杀模式 → 降级为要拆（留在未排除集）")
        self.assertIn(("/sbin/init", "execve", "/usr/sbin/sshd"), inv.unexcluded())
        self.assertEqual(stats["guards"]["warrant"], 1)

    def test_confirmed_and_kept_edges(self) -> None:
        """判「整束相关」的进已确认；判「混杂」的一路拆到底、最后留在未排除集。"""
        inv, stats, _model, _logs = run_once()
        self.assertIn(("/tmp/payload.bin", "read", "/usr/bin/curl"), inv.confirmed)
        self.assertIn(("/srv/deploy.sh", "read", "/bin/bash"), inv.unexcluded())
        self.assertNotIn(("/srv/deploy.sh", "read", "/bin/bash"), inv.confirmed)

    def test_mixed_goes_deeper_and_lands_in_unexcluded(self) -> None:
        """判「混杂」的束被拆到更深层；最深层仍非「无关」的边留在未排除集。"""
        inv, stats, _model, _logs = run_once()
        self.assertGreater(len(stats["levels"]), 1, "混杂的束应产生更深一级")
        self.assertIn(("/srv/deploy.sh", "read", "/bin/bash"), inv.unexcluded())

    def test_cap_keeps_edges(self) -> None:
        """达到调用上限：没判到的束按「未排除」保留，不删边。"""
        inv, stats, model, logs = run_once({"bundle": {"cap_calls": 1, "fanout_guard": False}})
        self.assertEqual(stats["calls"], 1)
        self.assertGreater(len(inv.kept), 0)
        self.assertTrue(any("调用上限" in line for line in logs), logs)
        self.assertEqual(len(inv.confirmed) + len(inv.kept) + len(inv.excluded), len(inv.edges))

    def test_guard_switches_off(self) -> None:
        """关掉凭证闸门后，命中误杀模式的无关束也会真的删边（对照口径）。"""
        inv, stats, _model, _logs = run_once({"bundle": {"warrant_guard": False,
                                                         "none_guard": "off"}})
        self.assertEqual(stats["guards"]["warrant"], 0)
        self.assertIn(("/sbin/init", "execve", "/usr/sbin/sshd"), inv.excluded)

    def test_missing_bundle_is_kept_not_excluded(self) -> None:
        """模型一条结论都不给：全部按「没给结论」处理，一条都不许被删（失败即展开）。"""
        inv, stats, _model, _logs = run_once({"bundle": {"aggregate": False}}, drop_all=True)
        self.assertEqual(stats["missing_bundles"], len(inv.edges), "每一条都该记成没给结论")
        self.assertFalse(inv.excluded, "没给结论不得当成无关")
        self.assertEqual(len(inv.unexcluded()), len(inv.edges))

    def test_render_carries_task_header_and_scale_lines(self) -> None:
        _inv, _stats, model, _logs = run_once()
        text = model.texts[0]
        self.assertIn("本次调查的任务", text)
        self.assertIn("本批要判的束", text)
        self.assertIn("规模：成员", text)
        self.assertIn("命令行：", text)
        self.assertNotIn("E001", text)

    def test_shared_tables_render_when_class_has_enough_bundles(self) -> None:
        """批头两张共享表：类别够大时出「同类规模」，子束明显更小时出「上一级束」。"""
        render_module = importlib.import_module("llm.judge")
        scale = {"/etc": {"n": 5, "median": 2, "sizes": [1, 2, 2, 3, 9]}}
        child = {"id": "B0002", "size": 1, "all_dirs": ["/etc"], "bytes": 10,
                 "objects_n": 1, "parent": {
            "bid": "B0001", "size": 8, "bytes": 100, "objects_n": 3, "t0": 0, "t1": 1,
            "programs": ["/usr/bin/apt"], "rels": ["f2p"], "syscall": "read",
            "verdict": "mixed", "reason": "r"}}
        lines, class_ids, parent_ids, _parents = render_module._batch_tables([child], scale)
        text = "\n".join(lines)
        self.assertIn("同类规模", text)
        self.assertIn("上一级束", text)
        self.assertEqual(class_ids, {"/etc": "C1"})
        self.assertEqual(parent_ids, {"B0001": "P1"})
        extra = render_module._extra_lines(child, class_ids, parent_ids, scale)
        self.assertTrue(any("同类 C1 第" in line for line in extra))
        self.assertTrue(any("上一级：P1" in line for line in extra))

    def test_deterministic_between_runs(self) -> None:
        first = run_once()[0]
        second = run_once()[0]
        self.assertEqual(first.origin, second.origin)


if __name__ == "__main__":
    unittest.main()
