#!/usr/bin/env python3
"""汇总所有场景的覆盖度缺口报告成一份 SUMMARY.md。

    python tools/coverage_summary.py --coverage-dir output/coverage
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
NL = chr(10)


def fmt(n) -> str:
    return "—" if n is None else f"{n:,}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--coverage-dir", default=str(ROOT / "output" / "coverage"))
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    files = sorted(Path(args.coverage_dir).glob("*.coverage-gap.json"))
    if not files:
        print("没有 coverage-gap.json")
        return 1
    reports = [json.loads(f.read_text(encoding="utf-8")) for f in files]

    out = Path(args.out) if args.out else Path(args.coverage_dir) / "SUMMARY.md"
    L: List[str] = ["# 覆盖度缺口汇总", ""]

    # --- 总览 ---
    L += ["## 1. 总览", "",
          "| 场景 | 日志行 | 事件类型 | 已建模 | 未建模 | 参数名 | 未消费参数 | "
          "图顶点 | 图边 | 哨兵(可疑丢边) |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in reports:
        m = r["meta"]
        ev = r["events"]
        mod = sum(1 for e in ev if e["status"].startswith("已建模"))
        unm = sum(1 for e in ev if e["status"] == "未建模")
        ar = r["arg_keys"]
        unmapped = sum(1 for a in ar
                       if not a["mapped"] and not a.get("suspected_payload_key"))
        gv = sum(m["graph_vertices"].values())
        ge = sum(m["graph_edges"].values())
        L.append(f"| {m['database']} | {fmt(m['log_valid_lines'])} | {m['log_events']} "
                 f"| {mod} | {unm} | {len(ar)} | {unmapped} | {fmt(gv)} | {fmt(ge)} "
                 f"| {len(r['sentinel_modeled_but_zero_edges'])} |")

    # --- 哨兵 ---
    L += ["", "## 2. 可疑丢边（声明已建模、端点齐全、却 0 条边）", ""]
    any_sentinel = False
    for r in reports:
        for e in r["sentinel_modeled_but_zero_edges"]:
            any_sentinel = True
            L.append(f"- `{r['meta']['database']}`：`{e['evt_type']}` 退出 "
                     f"{fmt(e['exit'])} 条 → 归一 `{e['canonical']}`，图中 0 条边"
                     f"（{e['zero_edge_reason']}）")
    if not any_sentinel:
        L.append("（无）")

    # --- 未建模事件类型（跨场景合并） ---
    ev_records: Counter = Counter()
    ev_scen: Dict[str, List[str]] = defaultdict(list)
    for r in reports:
        db = r["meta"]["database"]
        for e in r["events"]:
            if e["status"] == "未建模":
                ev_records[e["evt_type"]] += e["enter"] + e["exit"]
                ev_scen[e["evt_type"]].append(db)
    L += ["", "## 3. 未建模事件类型（跨场景合并，按记录数降序）", "",
          "| evt.type | 记录数合计 | 出现场景数 |", "|---|---|---|"]
    for et, c in ev_records.most_common():
        L.append(f"| `{et}` | {fmt(c)} | {len(ev_scen[et])} |")

    # --- 未消费参数名（跨场景合并；排除疑似多 token 取值噪声） ---
    arg_freq: Counter = Counter()
    arg_scen: Dict[str, List[str]] = defaultdict(list)
    for r in reports:
        db = r["meta"]["database"]
        for a in r["arg_keys"]:
            if not a["mapped"] and not a.get("suspected_payload_key"):
                arg_freq[a["arg_key"]] += a["freq"]
                arg_scen[a["arg_key"]].append(db)
    L += ["", "## 4. 未消费参数名（跨场景合并，按次数降序）", "",
          "| 参数 | 出现次数合计 | 出现场景数 |", "|---|---|---|"]
    for k, c in arg_freq.most_common():
        L.append(f"| `{k}` | {fmt(c)} | {len(arg_scen[k])} |")

    # --- fd 类型符（区分部分建模 / 未建模） ---
    fd_count: Counter = Counter()
    fd_partial: Counter = Counter()
    for r in reports:
        for f in r["fd_types"]:
            if f["mapped"]:
                continue
            if f.get("partial"):
                fd_partial[f["type"]] += f["count"]
            else:
                fd_count[f["type"]] += f["count"]
    L += ["", "## 5. fd 类型符覆盖（部分建模 / 未建模，按次数降序）", "",
          "| 类型符 | 含义 | 出现次数合计 | 状态 |", "|---|---|---|---|"]
    labels = {}
    for r in reports:
        for f in r["fd_types"]:
            labels.setdefault(f["type"], f.get("label") or "")
    for t, c in fd_partial.most_common():
        L.append(f"| `<{t}>` | {labels.get(t) or '—'} | {fmt(c)} | **部分建模** |")
    for t, c in fd_count.most_common():
        L.append(f"| `<{t}>` | {labels.get(t) or '—'} | {fmt(c)} | 未建模 |")

    # --- 图侧 syscall 全集 ---
    all_sys = Counter()
    for r in reports:
        for k, v in r["graph_syscalls"].items():
            all_sys[k] += v
    L += ["", "## 6. 图中出现的 syscall 全集", "",
          "| syscall | 边数合计 |", "|---|---|"]
    for k, v in all_sys.most_common():
        L.append(f"| `{k}` | {fmt(v)} |")

    out.write_text(NL.join(L) + NL, encoding="utf-8")
    print(f"汇总 {len(reports)} 个场景 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
