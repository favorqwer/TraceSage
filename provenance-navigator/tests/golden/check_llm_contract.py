"""阶段 4 假模型契约测试：不调用真实模型，验证 LLM 模式的输入输出。

用法：
    python tests/golden/check_llm_contract.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

NAV_DIR = Path(__file__).resolve().parents[2]
if str(NAV_DIR) not in sys.path:
    sys.path.insert(0, str(NAV_DIR))

import llm.judge as J  # noqa: E402
from common.graph import Investigation  # noqa: E402
from common.model import LlmBudget  # noqa: E402


class _Deps:
    def __init__(self, record):
        self.record = record
        self.model = object()
        self.budget = LlmBudget()
        self.log = lambda message: None


def _edge(src, dst, syscall="write", src_label="Process", dst_label="File", pid="p1"):
    return {
        "src": src, "dst": dst, "syscall": syscall,
        "src_label": src_label, "dst_label": dst_label,
        "member_processes": [pid], "rels": ["p2f"] if src_label == "Process" else ["f2p"],
        "instances": 1, "bytes": 10, "t0": 1, "t1": 2, "channels": 1, "dist": 1,
    }


def _fake_call_json(model, system, user, **kwargs):
    ids = sorted(set(re.findall(r"^(B\d{4})｜", user, re.M)))
    return {"_raw_ok": True, "verdicts": [
        {"id": bid, "verdict": "all", "reason": "fake", "witness_relevant": "w"}
        for bid in ids
    ]}


def main() -> int:
    edges = {
        ("/bin/bash", "write", "/tmp/a"): _edge("/bin/bash", "/tmp/a"),
        ("/bin/bash", "write", "/tmp/b"): _edge("/bin/bash", "/tmp/b"),
        ("/bin/bash", "write", "/tmp/c"): _edge("/bin/bash", "/tmp/c"),
        ("/bin/sh", "execve", "/bin/bash"): _edge(
            "/bin/sh", "/bin/bash", syscall="execve",
            src_label="Process", dst_label="Process",
        ),
    }
    record = Investigation(run_id="fake", scenario="fake")
    record.edges.update(edges)
    record.poi_rows = []
    record.poi_t0 = 0
    deps = _Deps(record)

    # 1. 束划分不变式
    program_of = J.program_table(record.process_context)
    keyer = J.LevelKey(program_of)
    levels = J.build_levels(set(edges), record.edges, keyer)
    partition = J.check_partition(levels)
    assert partition["level0_covers_all"] is True
    assert partition["L0_covers_same_set"] is True
    assert partition["monotone_refinement"] is True
    print(f"[束划分] 5 级成员数: {[partition[f'L{i}_members'] for i in range(5)]}")

    # 2. 渲染与结论解析
    items = J.build_items(list(levels[0]), 0, levels, record.edges, record.process_context,
                          samples=2, next_id=lambda: f"B{len(record.origin) + 1:04d}")
    listing = J.render(items, record.edges, 0, level_name=J.level_name(0))
    assert "B0001｜" in listing, listing[:200]
    parsed, invalid = J.parse_bundle_verdicts(
        {"verdicts": [{"id": items[0]["id"], "verdict": "all"}]},
        {item["id"] for item in items},
    )
    assert invalid == 0 and items[0]["id"] in parsed
    bad, bad_n = J.parse_bundle_verdicts(
        {"verdicts": [{"id": "B9999", "verdict": "all"}, {"id": items[0]["id"], "verdict": "wat"}]},
        {item["id"] for item in items},
    )
    assert bad == {} and bad_n == 2
    print(f"[渲染] 字符 {len(listing)}；束 {len(items)} 个；非法结论 {bad_n} 条被拒")

    # 3. 假模型跑一轮：所有束判 all，应全部确认
    original = J.call_json
    J.call_json = _fake_call_json
    try:
        channel = J.LlmChannel(deps)
        result = channel.promote(list(edges.values()), {})
    finally:
        J.call_json = original

    assert result["calls"] >= 1, result
    assert result["excluded"] == [], result
    confirmed_keys = {(e["src"], e["syscall"], e["dst"]) for e in result["confirmed"]}
    assert confirmed_keys == set(edges), (confirmed_keys, set(edges))
    assert all(record.origin.get(key) == "confirmed" for key in edges)
    print(f"[LLM 通道] calls={result['calls']}；confirmed={len(result['confirmed'])}；"
          f"excluded={len(result['excluded'])}；kept={len(result['kept'])}")
    print("[结论] 假模型契约通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
