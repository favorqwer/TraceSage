#!/usr/bin/env python
"""评分与三方汇总：纯 LLM 基线 / provenance 基线 / 引擎基线。

用法：
    python experiments/plain_llm/score_and_summarize.py
    python experiments/plain_llm/score_and_summarize.py --rescore
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from plainllm.poi import load_scenarios  # noqa: E402
from plainllm.settings import load_config  # noqa: E402

SCORE_TOOL = ROOT / "tools" / "score_report_product.py"
GT_DIR = ROOT / "groundtruth"
PROVENANCE_SUMMARY = ROOT / "output" / "provenance-baseline" / "summary_v2.json"
ENGINE_DIR = ROOT / "output" / "engine-baseline"

RECALL_RE = re.compile(r"召回（按步骤）\s*(\d+)/(\d+)")
PRECISION_RE = re.compile(r"查准（按四元组）\s*(\d+)/(\d+)")


def _order(name: str) -> tuple[int, str]:
    prefix = name.split("_", 1)[0]
    return (int(prefix) if prefix.isdigit() else 10_000, name)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _pct(hit: int, total: int) -> Optional[float]:
    return (hit / total * 100.0) if total else None


def _fmt_pct(value: Optional[float]) -> str:
    return f"{value:.2f}%" if value is not None else "—"


def _fmt_delta(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return f"{value:+.2f}pp"


def _micro(rows: list[dict[str, Any]]) -> dict[str, Any]:
    steps_hit = sum(r["steps_hit"] for r in rows)
    steps_total = sum(r["steps_total"] for r in rows)
    correct = sum(r["correct_edges"] for r in rows)
    reported = sum(r["reported_triples"] for r in rows)
    return {
        "scenarios": len(rows),
        "steps_hit": steps_hit,
        "steps_total": steps_total,
        "correct_edges": correct,
        "reported_triples": reported,
        "recall": _pct(steps_hit, steps_total),
        "precision": _pct(correct, reported),
    }


def collect_reports(out_root: Path) -> list[str]:
    names = [p.name for p in out_root.iterdir()
             if p.is_dir() and (p / "report.json").exists()]
    return sorted(names, key=_order)


def score_scenario(name: str, report: Path, metrics_path: Path, rescore: bool) -> Optional[dict[str, Any]]:
    if metrics_path.exists() and not rescore:
        data = _read_json(metrics_path)
        return data.get("totals")
    gt = GT_DIR / f"{name}.groundtruth.json"
    if not gt.exists():
        print(f"  跳过 {name}: 缺少 {gt}")
        return None
    cmd = [sys.executable, str(SCORE_TOOL),
           "--report", str(report), "--gt", str(gt),
           "--scenario", name, "--json-out", str(metrics_path)]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        print(f"  评分失败 {name}: {proc.stderr.strip()[:400]}")
        return None
    return _read_json(metrics_path).get("totals")


def load_provenance(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = _read_json(path)
    out: dict[str, dict[str, Any]] = {}
    for row in data.get("results") or []:
        out[row["scenario"]] = {
            "steps_hit": row.get("steps_hit", 0),
            "steps_total": row.get("steps_total", 0),
            "correct_edges": row.get("correct_edges", 0),
            "reported_triples": row.get("reported_triples", 0),
            "calls": row.get("llm_calls"),
            "elapsed_seconds": row.get("elapsed_seconds"),
        }
    return out


def load_engine(engine_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not engine_dir.exists():
        return out
    for scenario_dir in sorted(engine_dir.iterdir()):
        eval_path = scenario_dir / "groundtruth-eval.txt"
        if not scenario_dir.is_dir() or not eval_path.exists():
            continue
        text = eval_path.read_text(encoding="utf-8")
        recall = RECALL_RE.search(text)
        precision = PRECISION_RE.search(text)
        if not (recall and precision):
            continue
        out[scenario_dir.name] = {
            "steps_hit": int(recall.group(1)),
            "steps_total": int(recall.group(2)),
            "correct_edges": int(precision.group(1)),
            "reported_triples": int(precision.group(2)),
        }
    return out


def _distribution(values: list[float]) -> tuple[float, float, float]:
    return (min(values), statistics.median(values), max(values))


def write_overview(
    out_path: Path,
    *,
    scenarios: list[str],
    plain: dict[str, dict[str, Any]],
    provenance: dict[str, dict[str, Any]],
    engine: dict[str, dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    cfg_model: str,
) -> dict[str, Any]:
    plain_rows = [(s, plain[s]) for s in scenarios if s in plain]
    prov_rows = [(s, provenance[s]) for s in scenarios if s in provenance]
    eng_rows = [(s, engine[s]) for s in scenarios if s in engine]
    plain_micro = _micro([r for _, r in plain_rows])
    prov_micro = _micro([r for _, r in prov_rows])
    eng_micro = _micro([r for _, r in eng_rows])

    lines: list[str] = [
        "# 纯 LLM 溯源基线（对照实验）",
        "",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 判定模型：`{cfg_model}`（与 provenance 基线同一模型）",
        "- 评分：`tools/score_report_product.py`；召回按标注步骤、查准按四元组，与另两个基线同一工具、同一分母口径",
        f"- 覆盖：纯 LLM {len(plain_rows)}/{len(scenarios)} 个场景，provenance {len(prov_rows)} 个，engine {len(eng_rows)} 个",
        "",
        "## 口径与边界",
        "",
        "1. **前置输入**：解析器建图、-v2 图库、POI 都是外部前置输入；纯 LLM 与另两个基线共用同一套图与同一个 POI。",
        "2. **输入形态**：模型看到的是全图按内容四元组去重后的边表（含实例数、首末时间、成败、载荷预览），不是原始 syscall 流；"
        "去重丢失“同一行为第几次发生”，只留计数与首末时间。",
        "3. **无其他机制**：没有规则库、没有 embedding 检索、没有图遍历、没有时间窗、没有白名单、没有按场景调整的阈值；十场景共用同一套提示词。",
        "4. **评定只看边**：模型自报的阶段名、理由、入口判断都不参与评分。",
        "5. **成败口径**：图上 `result < 0` 判 failure、`result ≥ 0` 判 success，与既有基线同一规则。",
        "6. **不承诺零波动**：每场景只跑一次，服务端即使在温度 0 下仍可能非确定；未测重复运行波动。",
        "7. **产物归属**：本目录是当次运行产物，不覆盖 `output/engine-baseline/` 与 `output/provenance-baseline/`。",
        "",
        "## 三方合并平均",
        "",
        "| 系统 | 召回（按步骤） | 查准（按四元组） | 报告四元组 | 覆盖场景 |",
        "|---|---:|---:|---:|---:|",
        f"| 纯 LLM | {_fmt_pct(plain_micro['recall'])}（{plain_micro['steps_hit']}/{plain_micro['steps_total']}） | "
        f"{_fmt_pct(plain_micro['precision'])}（{plain_micro['correct_edges']}/{plain_micro['reported_triples']}） | "
        f"{plain_micro['reported_triples']:,} | {plain_micro['scenarios']} |",
        f"| provenance | {_fmt_pct(prov_micro['recall'])}（{prov_micro['steps_hit']}/{prov_micro['steps_total']}） | "
        f"{_fmt_pct(prov_micro['precision'])}（{prov_micro['correct_edges']}/{prov_micro['reported_triples']}） | "
        f"{prov_micro['reported_triples']:,} | {prov_micro['scenarios']} |",
        f"| engine（纯图遍历） | {_fmt_pct(eng_micro['recall'])}（{eng_micro['steps_hit']}/{eng_micro['steps_total']}） | "
        f"{_fmt_pct(eng_micro['precision'])}（{eng_micro['correct_edges']}/{eng_micro['reported_triples']}） | "
        f"{eng_micro['reported_triples']:,} | {eng_micro['scenarios']} |",
        "",
        "口径说明：合并平均按判定对象加权（先把命中数与分母分别相加再相除），不是每场景一票的算术平均；"
        "召回与查准分母不同，不合成 F1。",
        "",
        "## 逐场景",
        "",
        "| 场景 | 纯LLM 召回 | 纯LLM 查准 | provenance 召回 | provenance 查准 | engine 召回 | engine 查准 | "
        "Δ召回（LLM−prov） | Δ查准（LLM−prov） | Δ召回（LLM−engine） | Δ查准（LLM−engine） |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    per_scenario: list[dict[str, Any]] = []
    for name in scenarios:
        p = plain.get(name)
        v = provenance.get(name)
        e = engine.get(name)
        p_rec = _pct(p["steps_hit"], p["steps_total"]) if p else None
        p_pre = _pct(p["correct_edges"], p["reported_triples"]) if p else None
        v_rec = _pct(v["steps_hit"], v["steps_total"]) if v else None
        v_pre = _pct(v["correct_edges"], v["reported_triples"]) if v else None
        e_rec = _pct(e["steps_hit"], e["steps_total"]) if e else None
        e_pre = _pct(e["correct_edges"], e["reported_triples"]) if e else None
        lines.append(
            f"| {name} | {_fmt_pct(p_rec)} | {_fmt_pct(p_pre)} | {_fmt_pct(v_rec)} | {_fmt_pct(v_pre)} | "
            f"{_fmt_pct(e_rec)} | {_fmt_pct(e_pre)} | "
            f"{_fmt_delta(p_rec - v_rec if p_rec is not None and v_rec is not None else None)} | "
            f"{_fmt_delta(p_pre - v_pre if p_pre is not None and v_pre is not None else None)} | "
            f"{_fmt_delta(p_rec - e_rec if p_rec is not None and e_rec is not None else None)} | "
            f"{_fmt_delta(p_pre - e_pre if p_pre is not None and e_pre is not None else None)} |"
        )
        per_scenario.append({
            "scenario": name,
            "plain": {"recall": p_rec, "precision": p_pre, **(p or {})},
            "provenance": {"recall": v_rec, "precision": v_pre, **(v or {})},
            "engine": {"recall": e_rec, "precision": e_pre, **(e or {})},
            "delta_vs_provenance": {
                "recall_pp": (p_rec - v_rec) if p_rec is not None and v_rec is not None else None,
                "precision_pp": (p_pre - v_pre) if p_pre is not None and v_pre is not None else None,
            },
            "delta_vs_engine": {
                "recall_pp": (p_rec - e_rec) if p_rec is not None and e_rec is not None else None,
                "precision_pp": (p_pre - e_pre) if p_pre is not None and e_pre is not None else None,
            },
        })

    recall_values = [x for x in (p["recall"] for _, p in plain_rows) if x is not None]
    precision_values = [x for x in (p["precision"] for _, p in plain_rows) if x is not None]

    lines += ["", "## 分布（纯 LLM 侧）", "", "| 指标 | 最小值 | 中位数 | 最大值 |", "|---|---:|---:|---:|"]
    if recall_values and precision_values:
        r_min, r_med, r_max = _distribution(recall_values)
        p_min, p_med, p_max = _distribution(precision_values)
        lines.append(f"| 召回 | {_fmt_pct(r_min)} | {_fmt_pct(r_med)} | {_fmt_pct(r_max)} |")
        lines.append(f"| 查准 | {_fmt_pct(p_min)} | {_fmt_pct(p_med)} | {_fmt_pct(p_max)} |")
    else:
        lines.append("| 召回 | — | — | — |")
        lines.append("| 查准 | — | — | — |")

    lines += ["", "## 成本（纯 LLM 侧）", "",
              "| 场景 | 调用次数 | 输入 token | 输出 token | 失败调用 | 墙钟秒 |",
              "|---|---:|---:|---:|---:|---:|"]
    total_calls = total_in = total_out = total_fail = 0
    total_wall = 0.0
    for name in scenarios:
        m = manifests.get(name)
        if not m:
            continue
        llm = m.get("llm") or {}
        total_calls += int(llm.get("calls") or 0)
        total_in += int(llm.get("prompt_tokens") or 0)
        total_out += int(llm.get("completion_tokens") or 0)
        total_fail += int(llm.get("failures") or 0)
        wall = float((m.get("timings") or {}).get("total") or 0)
        total_wall += wall
        lines.append(f"| {name} | {int(llm.get('calls') or 0):,} | {int(llm.get('prompt_tokens') or 0):,} | "
                     f"{int(llm.get('completion_tokens') or 0):,} | {int(llm.get('failures') or 0)} | {wall:.1f} |")
    lines.append(f"| **合计** | **{total_calls:,}** | **{total_in:,}** | **{total_out:,}** | "
                 f"**{total_fail}** | **{total_wall:.1f}** |")
    if not manifests:
        lines.append("| — | — | — | — | — | — |")

    lines += [
        "",
        "## 复现",
        "",
        "```bash",
        "# 单场景",
        "python experiments/plain_llm/run_scenario.py --scenario 1_Web_Exploit_Ransomware",
        "# 十场景",
        "python experiments/plain_llm/run_all.py",
        "# 评分与汇总（写本文件与 summary.json）",
        "python experiments/plain_llm/score_and_summarize.py",
        "```",
        "",
        f"- 纯 LLM 报告：`{out_path.parent}/<场景>/report.json`；调用日志：同目录 `calls.jsonl`；"
        "输入指纹与代码/提示词哈希：同目录 `manifest.json`。",
        f"- provenance 数字取自 `{PROVENANCE_SUMMARY.relative_to(ROOT)}`；"
        f"engine 数字取自 `{ENGINE_DIR.relative_to(ROOT)}/<场景>/groundtruth-eval.txt`。",
        "",
    ]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": cfg_model,
        "protocol": {
            "score_tool": "tools/score_report_product.py",
            "recall": "命中标注步骤 / 标注步骤总数（必须条目 + 规则）",
            "precision": "命中四元组 / 报告去重四元组",
            "aggregation": "合并平均（按判定对象加权）",
        },
        "micro": {"plain": plain_micro, "provenance": prov_micro, "engine": eng_micro},
        "per_scenario": per_scenario,
        "cost": {
            "calls": total_calls,
            "prompt_tokens": total_in,
            "completion_tokens": total_out,
            "failed_calls": total_fail,
            "wall_seconds": round(total_wall, 1),
        },
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None)
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--rescore", action="store_true", help="忽略已缓存的 metrics.json，重新评分")
    args = parser.parse_args()

    overrides = {"output_root": Path(args.output_root).resolve()} if args.output_root else {}
    cfg = load_config(args.config, **overrides)
    out_root = cfg.output_root
    if not out_root.exists():
        raise SystemExit(f"输出目录不存在：{out_root}（先运行 run_all.py）")

    report_dirs = collect_reports(out_root)
    if not report_dirs:
        raise SystemExit(f"{out_root} 下没有 report.json，无法评分")
    all_scenarios = load_scenarios(cfg.scenarios_file)
    scenarios = sorted(all_scenarios, key=_order)
    missing = [s for s in scenarios if s not in report_dirs]
    if missing:
        print(f"注意：{len(missing)} 个场景还没有报告，表中按空值处理：{', '.join(missing)}")

    print(f"评分 {len(scenarios)} 个场景 …", flush=True)
    plain: dict[str, dict[str, Any]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for name in report_dirs:
        scenario_dir = out_root / name
        totals = score_scenario(name, scenario_dir / "report.json",
                                scenario_dir / "metrics.json", args.rescore)
        if totals:
            plain[name] = totals
        manifest_path = scenario_dir / "manifest.json"
        if manifest_path.exists():
            manifests[name] = _read_json(manifest_path)

    provenance = load_provenance(PROVENANCE_SUMMARY)
    engine = load_engine(ENGINE_DIR)

    overview_path = out_root / "OVERVIEW.md"
    summary = write_overview(
        overview_path,
        scenarios=scenarios, plain=plain, provenance=provenance,
        engine=engine, manifests=manifests, cfg_model=cfg.model,
    )
    summary_path = out_root / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    m = summary["micro"]
    print(f"\n纯 LLM   召回 {_fmt_pct(m['plain']['recall'])}  查准 {_fmt_pct(m['plain']['precision'])}")
    print(f"provenance 召回 {_fmt_pct(m['provenance']['recall'])}  查准 {_fmt_pct(m['provenance']['precision'])}")
    print(f"engine     召回 {_fmt_pct(m['engine']['recall'])}  查准 {_fmt_pct(m['engine']['precision'])}")
    print(f"\n汇总写 {overview_path}\n机器可读写 {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
