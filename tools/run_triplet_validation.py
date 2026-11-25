"""Run and validate the replacement baselines in a new, isolated directory."""
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
from statistics import median

import score_report_product as report_score
from rules_match import SCORING_PROTOCOL

ROOT = Path(__file__).resolve().parents[1]
SYSTEMS = ("attack_graph", "provenance", "plain_llm", "engine")
COUNTS = ("steps_hit", "steps_total", "correct_edges", "reported_triples")


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_checked(args, log, timeout):
    print(f"开始 {log}，上限 {timeout} 秒", flush=True)
    started = time.monotonic()
    with log.open("wb") as stream:
        with subprocess.Popen([sys.executable, "-B", "-u", *map(str, args)],
                              cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT) as process:
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    raise TimeoutError(f"运行超时：{log}")
                try:
                    status = process.wait(timeout=min(15, remaining))
                    break
                except subprocess.TimeoutExpired:
                    print(f"{log.parent.name}/{log.name} 已运行 {time.monotonic() - started:.0f} 秒",
                          flush=True)
    if status:
        raise RuntimeError(f"运行失败，退出码 {status}：{log}")
    return time.monotonic() - started


def trace_calls(path):
    calls = 0
    batches = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("input_protocol") != SCORING_PROTOCOL:
                raise ValueError(f"判定轨迹协议不符：{path}")
            if row.get("kind") == "detail":
                continue
            result = row["result"]
            if not result.get("ok") or result.get("_replayed"):
                raise ValueError(f"存在失败或重放判定：{path}")
            calls += result.get("calls", 0)
            batches += 1
    if not batches or not calls:
        raise ValueError(f"未观察到实时判定：{path}")
    return calls


def validate_event_mapping(path, edges):
    import gzip
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        events = json.load(stream)["events"]
    for event in events:
        for membership in event["memberships"]:
            index = membership["agg_edge_index"]
            if not 0 <= index < len(edges):
                raise ValueError(f"事件 {event['event_id']} 的报告关系编号越界：{path}")
            edge = edges[index]
            if list(membership["bundle_triple"]) != [edge["src"], edge["syscall"], edge["dst"]]:
                raise ValueError(f"事件 {event['event_id']} 的报告关系不一致：{path}")


def summarize(rows):
    totals = {key: sum(row[key] for row in rows) for key in COUNTS}
    for stem, hit, total in (("recall", "steps_hit", "steps_total"),
                              ("precision", "correct_edges", "reported_triples")):
        if not totals[total]:
            raise ValueError(f"无法汇总空分母：{total}")
        totals[stem] = totals[hit] / totals[total]
        ratios = []
        for row in rows:
            denom = row[total]
            row[stem] = row[hit] / denom if denom else 0.0
            row[f"{stem}_denominator_share"] = denom / totals[total]
            ratios.append(row[stem])
        totals[f"{stem}_distribution"] = {
            "min": min(ratios), "median": median(ratios), "max": max(ratios)}
    return totals


def stage_mainline_archive(run, result):
    """Prepare the archive layout consumed by attack_path without activating it."""
    archive = run / "release-candidate"
    reports = archive / "reports_v2"
    events = archive / "events_v2"
    traces = archive / "traces"
    for path in (reports, events, traces):
        path.mkdir(parents=True, exist_ok=False)
    rows = []
    for row in result["systems"]["attack_graph"]["results"]:
        name = row["scenario"]
        report = reports / f"{name}.json.gz"
        event_file = events / f"{name}.events.json.gz"
        trace = traces / f"{name}.trace.jsonl"
        with Path(row["report"]["path"]).open("rb") as source, report.open("xb") as dest:
            with gzip.GzipFile(fileobj=dest, mode="wb", filename="", mtime=0) as zipped:
                shutil.copyfileobj(source, zipped)
        with gzip.open(report, "rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != row["report"]["sha256"]:
                raise ValueError(f"归档报告无法回读：{report}")
        shutil.copyfile(row["events"]["path"], event_file)
        shutil.copyfile(row["trace"]["path"], trace)
        if sha256(event_file) != row["events"]["sha256"] or sha256(trace) != row["trace"]["sha256"]:
            raise ValueError(f"归档事件或轨迹指纹不符：{name}")
        rows.append({
            **{key: value for key, value in row.items() if key not in ("report", "events", "trace")},
            "gzip": report.relative_to(archive).as_posix(),
            "gzip_sha256": sha256(report),
            "events_gzip": event_file.relative_to(archive).as_posix(),
            "events_gzip_sha256": row["events"]["sha256"],
            "trace": trace.relative_to(archive).as_posix(),
            "trace_sha256": row["trace"]["sha256"],
        })
    write_json(archive / "summary_v2.json", {"scoring_protocol": SCORING_PROTOCOL,
                                           "evaluation_mode": "live",
                                           "results": rows,
                                           "micro": result["systems"]["attack_graph"]["micro"]})
    write_json(archive / "input-fingerprints.json", {"files": result["inputs"]})
    write_json(archive / "code-fingerprints.json", {"git_head": result["git_head"],
                                                  "files": result["code_sha256"]})
    overview = [
        "# Attack Graph 三元组正式候选基线", "",
        "评分协议 `triplet-v1`。十场景实时判定，召回按标注步骤，查准按三元组。", "",
        "| 场景 | 召回 | 查准 | 模型请求（含重试） |",
        "|---|---:|---:|---:|",
    ]
    for row in rows:
        overview.append(
            f"| {row['scenario']} | {row['steps_hit']}/{row['steps_total']} | "
            f"{row['correct_edges']}/{row['reported_triples']} | {row['llm_request_attempts']} |"
        )
    totals = result["systems"]["attack_graph"]["micro"]
    overview.append(
        f"| 合计 | {totals['steps_hit']}/{totals['steps_total']} | "
        f"{totals['correct_edges']}/{totals['reported_triples']} | "
        f"{sum(row['llm_request_attempts'] for row in rows)} |"
    )
    (archive / "OVERVIEW.md").write_text("\n".join(overview) + "\n", encoding="utf-8")


def dependencies(scenario):
    graph_root = Path(os.environ.get("TRACESAGE_GRAPH_DIR") or ROOT / "graphs")
    rules_root = Path(os.environ.get("TRACESAGE_RULE_KG_DIR") or ROOT / "output/rule-kg/v1")
    return (graph_root / f"{scenario}.tsg",
            ROOT / "groundtruth" / f"{scenario}.groundtruth.json",
            rules_root / "folds" / f"{scenario}.json",
            ROOT / "output/provenance-baseline/distill/fold-libraries" / f"{scenario}.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--scene-timeout", type=int, required=True, help="经报备的单进程时间上限（秒）")
    parser.add_argument("--attack-graph-only", action="store_true", help="只重建 attack_graph，零 Neo4j")
    parser.add_argument("--request-limit", type=int, help="主线十场景合计的模型请求上限")
    parser.add_argument("--run-timeout", type=int, help="主线十场景运行的墙钟上限（秒）")
    args = parser.parse_args()
    if args.scene_timeout <= 0:
        parser.error("--scene-timeout 必须大于零")
    if args.attack_graph_only and (not args.request_limit or args.request_limit < 1
                                   or not args.run_timeout or args.run_timeout < 1):
        parser.error("主线独立验证需指定正数 --request-limit 和 --run-timeout")
    run = args.run_dir.resolve()
    allowed = (ROOT / "output/attack-graph-runs" if args.attack_graph_only
               else ROOT / "output/agent-vs-engine/triplet-v1")
    if run == allowed or not run.is_relative_to(allowed):
        parser.error("--run-dir 必须是三元组测试目录下的独立子目录")
    selected_systems = ("attack_graph",) if args.attack_graph_only else SYSTEMS
    if not args.attack_graph_only:
        subprocess.run([sys.executable, "-B", str(ROOT / "tools/preflight_triplet.py")],
                       cwd=ROOT, check=True, timeout=180)
    scenarios = list(json.loads((ROOT / "attack_graph/config/scenarios.json").read_text(
        encoding="utf-8"))["scenarios"])
    if len(scenarios) != 10:
        raise RuntimeError("重建需要完整十场景清单")
    if not args.attack_graph_only:
        from run_all_engine_v2 import SCENARIOS
        if set(scenarios) != set(SCENARIOS):
            raise RuntimeError("四套系统需要使用同一份十场景清单")
    inputs = {str(path): sha256(path) for scenario in scenarios for path in dependencies(scenario)}
    root_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    code_paths = [
        p for directory in ("tools", "attack_graph", "attack_path", "provenance", "parser", "tsg",
                            "experiments/plain_llm", "experiments/DEPIMPACT/src",
                            "experiments/DEPIMPACT/baseline")
        for p in (ROOT / directory).rglob("*")
        if p.is_file() and p.suffix in (".py", ".toml", ".md", ".txt", ".java", ".yaml")
        and "config/rules-library" not in p.as_posix()
    ]
    code_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in sorted(set(code_paths))}
    run.mkdir(parents=True, exist_ok=False)
    timeout = args.scene_timeout
    remaining_requests = args.request_limit
    started = time.monotonic()
    results = {name: [] for name in selected_systems}
    from attack_path.diagnose import run_phase1_for_scenario
    for scenario in scenarios:
        _, gt, _, fold = dependencies(scenario)
        for name in selected_systems:
            folder = run / name / scenario
            folder.mkdir(parents=True, exist_ok=False)
            if name == "engine":
                path = folder / "baseline.json"
                command = ["tools/run_all_engine_v2.py", "--scenario", scenario,
                           "--output-root", folder.parent, "--timeout", str(timeout)]
            elif name == "plain_llm":
                path = folder / "report.json"
                command = ["experiments/plain_llm/run_scenario.py", "--scenario", scenario,
                           "--out", folder, "--no-resume"]
            else:
                path = folder / "report.json"
                command = [f"{name}/main.py", "--scenario", scenario, "--output", path]
                if name == "provenance":
                    command.extend(("--fold", fold))
            scene_timeout = timeout + 150 if name == "engine" else timeout
            if args.attack_graph_only:
                if remaining_requests <= 0:
                    raise RuntimeError("模型请求预算已用尽，未完成的场景停止执行")
                command.extend(("--request-limit", remaining_requests))
                scene_timeout = min(scene_timeout, args.run_timeout - (time.monotonic() - started))
                if scene_timeout <= 0:
                    raise TimeoutError("主线总运行超时")
            elapsed = run_checked(command, folder / "run.log", scene_timeout)
            data = json.loads(path.read_text(encoding="utf-8"))
            artifacts = {"report": {"path": str(path), "sha256": sha256(path)}}
            if name == "engine":
                evaluated = json.loads((folder / "metrics.json").read_text(encoding="utf-8"))
                metrics = evaluated["totals"]
                if evaluated["scoring_protocol"] != SCORING_PROTOCOL or metrics["skipped_edges"]:
                    raise ValueError(f"引擎产物缺失评分字段：{path}")
                calls = 0
                elapsed = json.loads((folder / "run-timing.json").read_text(encoding="utf-8"))["wall_time_seconds"]
            else:
                if (data.get("input_protocol") or data.get("scoring_protocol")) != SCORING_PROTOCOL:
                    raise ValueError(f"报告协议不符：{path}")
                metrics = report_score.evaluate(path, gt, scenario=scenario)
                if metrics["skipped_edges"] or metrics["kinds_degraded"]:
                    raise ValueError(f"评分输入不完整：{path}")
                if name == "plain_llm":
                    calls = data["llm"]["calls"]
                    if calls <= 0:
                        raise ValueError(f"未观察到实时模型调用：{path}")
                else:
                    trace = path.with_suffix(".trace.jsonl")
                    trace_calls(trace)
                    calls = data["stats"]["llm_calls"]
                    artifacts["trace"] = {"path": str(trace), "sha256": sha256(trace)}
            if name == "attack_graph":
                events = path.with_suffix(".events.json.gz")
                validate_event_mapping(events, data["edges"])
                _, _, diagnosis = run_phase1_for_scenario(scenario, events_path=events)
                if not diagnosis.dag_stats.is_acyclic:
                    raise ValueError(f"事件图未通过无环验证：{events}")
                artifacts["events"] = {"path": str(events), "sha256": sha256(events)}
                if args.attack_graph_only:
                    attempts = data["stats"]["llm_request_attempts"]
                    if not calls or not calls <= attempts <= remaining_requests:
                        raise ValueError(f"模型调用计数与本次预算不符：{path}")
                    remaining_requests -= attempts
                    artifacts["llm_request_attempts"] = attempts
                    artifacts["llm_tokens_in"] = data["stats"]["llm_tokens_in"]
                    artifacts["llm_tokens_out"] = data["stats"]["llm_tokens_out"]
            if metrics["steps_hit"] > metrics["steps_total"] or metrics["correct_edges"] > metrics["reported_triples"]:
                raise ValueError(f"评分计数越界：{path}")
            write_json(folder / "validation.json", {"metrics": metrics, "artifacts": artifacts})
            results[name].append({
                "scenario": scenario,
                **{key: metrics[key] for key in COUNTS},
                "rules_hit": metrics["rule_hits"],
                "rules_total": metrics["rules_total"],
                "elapsed_seconds": elapsed,
                "llm_calls": calls,
                **artifacts,
            })
            print(f"通过 {name}/{scenario}", flush=True)

    if any(sha256(Path(path)) != digest for path, digest in inputs.items()):
        raise RuntimeError("运行期间输入指纹变化")
    if any(sha256(ROOT / path) != digest for path, digest in code_hashes.items()):
        raise RuntimeError("运行期间代码指纹变化")
    systems = {name: {"micro": summarize(rows), "results": rows} for name, rows in results.items()}
    paired = {
        name: [{"scenario": current["scenario"], "recall_delta": current["recall"] - other["recall"],
                "precision_delta": current["precision"] - other["precision"]}
               for current, other in zip(results["attack_graph"], rows, strict=True)]
        for name, rows in results.items() if name != "attack_graph"
    }
    result = {"scoring_protocol": SCORING_PROTOCOL, "git_head": root_commit,
              "scope": "attack_graph" if args.attack_graph_only else "comparison",
              "inputs": inputs, "code_sha256": code_hashes, "systems": systems, "paired": paired}
    if args.attack_graph_only:
        stage_mainline_archive(run, result)
    write_json(run / "summary.json", result)
    print(f"{', '.join(selected_systems)} 验证通过：{run / 'summary.json'}", flush=True)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    main()
