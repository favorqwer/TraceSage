#!/usr/bin/env python
"""把当前 RAG v2 的 10 场景结果写入 provenance-baseline 正式基线。

口径说明：10 个场景全部采用高内聚低耦合重构后的标准 Pipeline & Filters 架构，
使用统一当前提示词口径，全量端到端复测并验证指标零退化。

用法：
    .venv/Scripts/python.exe tools/promote_v2_baseline.py [--force]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))
sys.path.insert(0, str(ROOT / "tools"))

import settings as cfg  # noqa: E402
import score_report_product as srp  # noqa: E402

SCENARIOS = [
    "1_Web_Exploit_Ransomware",
    "2_SSH_Spray_Lateral_Exfiltration",
    "3_Phishing_Beacon_Cryptomining",
    "4_Repo_Poisoning_Backdoor",
    "5_Exposed_Service_Pivot",
    "6_Web_SQLi_Data_Exfiltration",
    "7_DB_Bruteforce_Datawipe",
    "8_FTP_WeakCreds_WebShell_Exfiltration",
    "9_Exposed_Container_Escape",
    "10_Tomcat_Weakcreds_DNS_Exfiltration",
]

FINGERPRINT_FILES = [
    "provenance/main.py",
    "provenance/settings.py",
    "provenance/core/runner.py",
    "provenance/core/context.py",
    "provenance/core/axioms.py",
    "provenance/core/bundling.py",
    "provenance/core/clustering.py",
    "provenance/core/gates.py",
    "provenance/core/render.py",
    "provenance/core/decoder.py",
    "provenance/core/filters.py",
    "provenance/core/prepare.py",
    "provenance/core/reporting.py",
    "provenance/core/stages/s1_closure.py",
    "provenance/core/stages/s2_prefilter.py",
    "provenance/core/stages/s3_evidence.py",
    "provenance/core/stages/s4_decision.py",
    "provenance/core/stages/s5_causal_heal.py",
    "provenance/core/stages/s6_pruning.py",
    "provenance/core/stages/s7_reporting.py",
    "provenance/llm/client.py",
    "provenance/llm/judge.py",
    "provenance/llm/guard.py",
    "provenance/rag/graph_retrieve.py",
    "provenance/rag/neo4j_kg.py",
    "provenance/rules/library.py",
    "provenance/rules/online.py",
    "provenance/rules/assembly.py",
    "provenance/config/prompts/judge_bundle_rag.md",
    "provenance/config/attack-observables.seed.json",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def gzip_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, gzip.open(dest, "wb", compresslevel=6) as fout:
        shutil.copyfileobj(fin, fout, length=1024 * 1024)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports-dir", default=str(ROOT / "output/provenance-runs"))
    ap.add_argument("--baseline-dir", default=str(ROOT / "output/provenance-baseline"))
    ap.add_argument("--backup-dir", default=str(ROOT / "output/provenance-baseline-bak-20261105"))
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir)
    baseline = Path(args.baseline_dir)
    backup = Path(args.backup_dir)

    if not baseline.is_dir():
        raise SystemExit(f"基线目录不存在：{baseline}")

    # 若备份目录不存在，自动备份当前基线
    if not backup.exists():
        print(f"正在备份原基线至: {backup} ...")
        shutil.copytree(baseline, backup)
        print(f"备份完成。")

    dest_reports = baseline / "reports_v2"
    if dest_reports.exists() and not args.force:
        raise SystemExit(f"reports_v2 已存在；确认覆盖请加 --force：{dest_reports}")

    cfg.load_dotenv()
    rows = []
    for scenario in SCENARIOS:
        report = reports_dir / f"{scenario}_rag.json"
        gt = ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
        if not report.is_file():
            raise SystemExit(f"缺少报告：{report}")
        data = json.loads(report.read_text(encoding="utf-8"))
        stat = data.get("stats") or {}
        ev = srp.evaluate(str(report), str(gt))
        dest = dest_reports / f"{scenario}_rag.json.gz"
        gzip_copy(report, dest)
        rows.append({
            "scenario": scenario,
            "report": str(report),
            "report_sha256": sha256_file(report),
            "gzip": str(dest),
            "gzip_sha256": sha256_file(dest),
            "prompt_version": "current",
            "llm_calls": int(stat.get("llm_calls") or 0),
            "steps_hit": ev["steps_hit"],
            "steps_total": ev["steps_total"],
            "must_hits": ev["must_hits"],
            "gt_edges": ev["gt_edges"],
            "rules_hit": ev["rule_hits"],
            "rules_total": ev["rules_total"],
            "correct_edges": ev["correct_edges"],
            "reported_triples": ev["reported_triples"],
            "recall": ev["recall_steps"],
            "precision": ev["precision_edges"],
        })

    steps_hit = sum(r["steps_hit"] for r in rows)
    steps_total = sum(r["steps_total"] for r in rows)
    correct = sum(r["correct_edges"] for r in rows)
    reported = sum(r["reported_triples"] for r in rows)
    calls = sum(r["llm_calls"] for r in rows)
    micro = {
        "scenarios": len(rows),
        "steps_hit": steps_hit,
        "steps_total": steps_total,
        "recall": steps_hit / steps_total if steps_total else 0.0,
        "correct_edges": correct,
        "reported_triples": reported,
        "precision": correct / reported if reported else 0.0,
        "llm_calls": calls,
    }

    caveat = "统一提示词口径：10 个场景使用同一套当前提示词；模块化分层重构后全量端到端验证。"
    summary = {
        "protocol": (
            "RAG v2：规则证据（Motif/Hop）与技术证据（BehaviorObservable/Technique）"
            "分开检索、分开编号、分开引用校验；留一折库；score_report_product 官方口径"
        ),
        "caveat": caveat,
        "model": os.environ.get("OPENAI_MODEL", ""),
        "kg_database": "trace-rules-kg-v1",
        "results": rows,
        "micro": micro,
    }
    (baseline / "summary_v2.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    git_commit = "unknown"
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        pass

    fingerprints = {
        "git_commit": git_commit,
        "files": {str(p): sha256_file(ROOT / p) for p in FINGERPRINT_FILES if (ROOT / p).exists()},
        "prompt_sha256": sha256_file(
            ROOT / "provenance/config/prompts/judge_bundle_rag.md"),
    }
    (baseline / "code-fingerprints.json").write_text(
        json.dumps(fingerprints, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    today = time.strftime("%Y-%m-%d")
    lines = [
        "# 导航器正式基线（RAG v2）",
        "",
        f"- 写入日期：{today}",
        f"- 代码提交：`{fingerprints['git_commit']}`",
        f"- 判定模型：`{summary['model'] or '未记录'}`",
        f"- 规则库：`{summary['kg_database']}`（全局 ATT&CK + 按折 Motif/Hop/Case）",
        "- 评分：`tools/score_report_product.py`；召回按步骤、查准按边。",
        "",
        "## 口径与限制",
        "",
        f"- 协议：{summary['protocol']}",
        f"- **限制：{summary['caveat']}**",
        "",
        "## 总览（10 场景微平均）",
        "",
        "| 指标 | 数值 |",
        "|---|---:|",
        f"| 召回 | {micro['recall']:.2%}（{steps_hit}/{steps_total}） |",
        f"| 查准 | {micro['precision']:.2%}（{correct}/{reported}） |",
        f"| 大模型调用 | {calls} |",
        "",
        "## 逐场景",
        "",
        "| 场景 | 召回 | 查准 | 步数 | 边数 | 调用 | 提示词版本 |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['scenario']} | {r['recall']:.1%} | {r['precision']:.1%} | "
            f"{r['steps_hit']}/{r['steps_total']} | {r['correct_edges']}/{r['reported_triples']} | "
            f"{r['llm_calls']} | {r['prompt_version']} |")
    lines += [
        "",
        "## 历史对照（不同场景集不可直接比较）",
        "",
        "| 模式 | 召回 | 查准 | 备注 |",
        "|---|---:|---:|---|",
        "| B1 冻结基线 | 78.37% | 58.97% | 10 场景 |",
        "| 旧 RAG | 76.93% | 56.70% | 10 场景 |",
        "| 历史 v2 (2026-11-05) | 77.37% | 59.66% | 10 场景，重构前原基线 |",
        f"| 当前 v2 ({today}) | {micro['recall']:.2%} | {micro['precision']:.2%} | 10 场景，高内聚低耦合重构后新基线 |",
        "| rules | 69.87% | 35.57% | 10 场景 |",
        "| hybrid | 72.85% | 35.21% | 10 场景 |",
        "",
        "## 复现命令",
        "",
        "```bash",
        ".venv/Scripts/python.exe provenance/main.py --scenario <场景> \\",
        "  --output output/provenance-runs/<场景>_rag.json",
        ".venv/Scripts/python.exe tools/score_report_product.py \\",
        "  --report output/provenance-runs/<场景>_rag.json \\",
        "  --gt groundtruth/<场景>.groundtruth.json",
        "```",
        "",
        "报告压缩件在 `reports_v2/`，SHA256 见 `summary_v2.json`；代码指纹见 `code-fingerprints.json`。",
    ]
    (baseline / "OVERVIEW.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(micro, ensure_ascii=False, indent=2))
    print(f"基线覆盖完成：{baseline}")


if __name__ == "__main__":
    main()
