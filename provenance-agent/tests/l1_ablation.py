"""第 1 层指标表：不调模型，量出每个场景的“闭包大小 / 耗时 / 内存 / 标注覆盖”。

一次运行只跑一个场景，结果写 `tmp/provenance-agent/l1-ablation/<场景>.json`；
`--report` 把已有结果合并成一张表（Markdown + JSON）。**不调模型、不写 output/**。

口径：

- “墙钟秒”是不带任何测量工具的净跑耗时（早先那版表挂内存追踪工具，实测把时间放大约 3.8 倍，
  那些数已不可比）。
- “进程峰值MB”是**进程占用内存的峰值**（Windows 读系统记录的峰值工作集，
  Linux 读 `/proc/self/status` 的 `VmHWM`），含解释器与文件缓冲；与早先那版的
  “程序分配峰值”不是同一口径，不能直接比。本次若同时新建了索引，峰值里也包含构造那一段。

用途：第 1 层的任何改动（因果规则、门限、索引格式与读取……）跑一遍这张表，
看候选边、命中标注、事件数、步骤数、顶点数与改前是否逐项相同。取数方式只有一种
（读本地索引快照，缺失或过期自动重建），不再有变体；删档前的两档结果（带 `variant`
字段的历史文件）不进表。

用法：

    python provenance-agent/tests/l1_ablation.py --all                 # 逐个子进程跑六个场景
    python provenance-agent/tests/l1_ablation.py --scenario 3_SSH_Spray
    python provenance-agent/tests/l1_ablation.py --report
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pagent.core import scenarios, settings

OUT_DIR = settings.WORK_DIR / "l1-ablation"
GT_DIR = settings.REPO_ROOT / "groundtruth"


class _ProcessMemoryCounters(ctypes.Structure):
    """Windows 的进程内存计数器（只用到峰值工作集那一个字段）。"""

    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def peak_rss_mb() -> Optional[float]:
    """进程占用内存的峰值（兆字节）：Windows 读系统记录的峰值工作集，Linux 读 VmHWM。

    用系统记的峰值，不用“追踪每次分配”（那会拖慢程序，把耗时数字带偏）；测不到就返回 None。
    """
    try:
        if sys.platform.startswith("win"):
            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            for dll, name in (("psapi", "GetProcessMemoryInfo"),
                              ("kernel32", "K32GetProcessMemoryInfo")):
                func = getattr(getattr(ctypes.windll, dll), name, None)
                if func is None:
                    continue
                func.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessMemoryCounters), wintypes.DWORD]
                func.restype = wintypes.BOOL
                counters = _ProcessMemoryCounters()
                counters.cb = ctypes.sizeof(counters)
                if func(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                    return round(counters.PeakWorkingSetSize / 1048576, 1)
            return None
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return round(int(line.split()[1]) / 1024, 1)     # 千字节 -> 兆字节
    except Exception:  # noqa: BLE001 - 测量拿不到不该让整次运行失败
        return None
    return None


def gt_triples(scenario: str) -> set[tuple[str, str, str]]:
    data = json.loads((GT_DIR / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    return {(e["src"], e["syscall"], e["dst"])
            for phase in data["attack_path"] for e in (phase.get("edges") or [])}


def run_one(scenario: str, *, log: Any = print) -> dict[str, Any]:
    """跑一个场景，返回指标（不调模型、不落报告）。"""
    from pagent import app
    from pagent.core.db import ReadOnlyGraph
    from pagent.layers.l1_reach import snapshot as snap
    from pagent.orchestration import expand_closure as expand_closure_mod
    from pagent.orchestration import intake as intake_mod

    settings.load_dotenv()
    settings.ensure_work_dirs()
    sc = scenarios.load_scenario(scenario)
    run_id = f"ablate-{scenario}"

    # 索引先建好（单独句柄、单独计时），不把构建开销算进闭包测量
    graph = ReadOnlyGraph(sc.database, run_id=f"{run_id}-index")
    try:
        before = snap.read_meta(sc.database)
        meta = snap.ensure_snapshot(graph, log=log)
        index_build: dict[str, Any] = {k: meta.get(k) for k in ("edges", "incidences", "build_seconds")}
        index_build["rebuilt"] = before is None or before.get("built_at") != meta.get("built_at")
        index_build["mb"] = round((snap.snapshot_dir(sc.database) / "adj.bin").stat().st_size / 1048576, 1)
    finally:
        graph.close()

    deps = app.build_deps(sc, run_id, model=None, log=log)

    t0 = time.perf_counter()
    try:
        intake_mod.intake(deps)
        expand = expand_closure_mod.expand_closure(deps)
    finally:
        wall = time.perf_counter() - t0
        peak = peak_rss_mb()
        db_ms = sum(r.ms for r in deps.graph.records)
        queries = deps.graph.query_count
        rows = deps.graph.total_rows
        deps.graph.close()

    got = set(deps.record.edges.keys())
    gt = gt_triples(scenario)
    missing = sorted(gt - got)
    vertices = {t[0] for t in got} | {t[2] for t in got}
    record = {
        "scenario": scenario,
        "candidates": len(got), "events": int((expand.get("closure") or {}).get("events_included") or 0),
        "steps": len(deps.record.steps), "vertices": len(vertices),
        "gt_total": len(gt), "gt_hit": len(gt & got), "gt_missing": [list(t) for t in missing],
        "gt_ratio": round(len(got) / max(1, len(gt)), 1),
        "queries": queries, "query_rows": rows, "db_ms": round(db_ms, 1),
        "wall_s": round(wall, 2), "peak_rss_mb": peak,
        "expand": {"rounds": expand.get("rounds"), "fold": expand.get("fold"),
                   "closure": {k: v for k, v in (expand.get("closure") or {}).items()
                               if k not in ("dropped_samples",)}},
        "index": index_build,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"{scenario}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"[ablate] {scenario}：候选 {record['candidates']} 条 / "
        f"命中标注 {record['gt_hit']}/{record['gt_total']} / 查询 {queries} 次 / "
        f"{record['wall_s']}s / 峰值 {record['peak_rss_mb']} MB")
    return record


def _spawn_all(scenarios_list: list[str]) -> int:
    """逐个子进程跑：内存峰值互不污染，单次失败不影响其余场景。"""
    failed = 0
    for scenario in scenarios_list:
        cmd = [sys.executable, str(Path(__file__).resolve()), "--scenario", scenario]
        print(f"\n$ {' '.join(cmd[1:])}", flush=True)
        proc = subprocess.run(cmd, cwd=str(settings.AGENT_DIR))
        if proc.returncode != 0:
            failed += 1
    return failed


def report() -> str:
    """把 tmp 下的结果合并成表。"""
    rows: list[dict[str, Any]] = []
    for path in sorted(OUT_DIR.glob("*.json")):
        if path.name.startswith("SUMMARY"):
            continue                  # 别把汇总文件自己当结果读进来
        record = json.loads(path.read_text(encoding="utf-8"))
        if "variant" in record:
            continue                  # 删档前的两档结果不进表（取边来源变体已不存在）
        rows.append(record)
    if not rows:
        return "（没有结果；先跑 --all 或 --scenario）"
    rows.sort(key=lambda r: r["scenario"])
    head = ("| 场景 | 候选边 | 命中标注 | 标注总数 | 倍数 | 顶点 | 步骤 | 事件 | 查询 | 库侧毫秒 | "
            "墙钟秒 | 进程峰值MB |")
    lines = [head, "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['scenario']} | {r['candidates']} | {r['gt_hit']} | "
                     f"{r['gt_total']} | {r['gt_ratio']} | {r['vertices']} | {r['steps']} | "
                     f"{r['events']} | {r['queries']} | {r['db_ms']} | {r['wall_s']} | {r['peak_rss_mb']} |")
    out = "\n".join(lines)
    (OUT_DIR / "SUMMARY.md").write_text(out + "\n", encoding="utf-8")
    (OUT_DIR / "SUMMARY.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    return out


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="第 1 层指标表（不调模型）")
    parser.add_argument("--scenario", help="场景名（见 config/scenarios.json）")
    parser.add_argument("--all", action="store_true", help="六个场景（逐个子进程）")
    parser.add_argument("--only", help="配合 --all：只跑这些场景（逗号分隔的前缀或全名）")
    parser.add_argument("--report", action="store_true", help="只合并已有结果并打印表")
    args = parser.parse_args(argv)

    if args.report:
        print(report())
        return 0
    if args.all:
        names = scenarios.available_scenarios()
        if args.only:
            picks = [p.strip() for p in args.only.split(",") if p.strip()]
            names = [n for n in names if any(n.startswith(p) for p in picks)]
        return _spawn_all(names)
    if not args.scenario:
        parser.error("需要 --scenario，或 --all/--report")
    run_one(args.scenario)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
