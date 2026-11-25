#!/usr/bin/env python
"""
运行 DEPIMPACT 在 10 个攻击场景 -v2 图库上的全量测试，并用当前 GT 评测。
产出写入显式指定的当次评测目录。
遵循 AGENTS.md 四大工程法则与对比实验底线（只跑 -v2 图，不碰旧库）。
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "experiments" / "DEPIMPACT"
M2_REPO = Path(os.environ.get("USERPROFILE", "C:/Users/Favor")) / ".m2" / "repository"

SCENARIOS = {
    "1_Web_Exploit_Ransomware": {
        "db_new": "attack-1-web-exploit-ransomware-v2",
        "poi_args": ["--poi-file", "/srv/data/README_RESTORE.txt", "--poi-optype", "write"],
        "gt": "groundtruth/1_Web_Exploit_Ransomware.groundtruth.json",
    },
    "2_SSH_Spray_Lateral_Exfiltration": {
        "db_new": "attack-2-ssh-spray-lateral-exfiltration-v2",
        "poi_args": ["--poi-endpoints", "100.116.135.31:45794->100.86.108.4:22", "--poi-optype", "write"],
        "gt": "groundtruth/2_SSH_Spray_Lateral_Exfiltration.groundtruth.json",
    },
    "3_Phishing_Beacon_Cryptomining": {
        "db_new": "attack-3-phishing-beacon-cryptomining-v2",
        "poi_args": ["--poi-endpoints", "100.86.108.4:59062->100.84.151.2:8080", "--poi-optype", "sendto"],
        "gt": "groundtruth/3_Phishing_Beacon_Cryptomining.groundtruth.json",
    },
    "4_Repo_Poisoning_Backdoor": {
        "db_new": "attack-4-repo-poisoning-backdoor-v2",
        "poi_args": ["--poi-endpoints", "100.74.213.15:53648->100.86.108.4:22", "--poi-optype", "write"],
        "gt": "groundtruth/4_Repo_Poisoning_Backdoor.groundtruth.json",
    },
    "5_Exposed_Service_Pivot": {
        "db_new": "attack-5-exposed-service-pivot-v2",
        "poi_args": ["--poi-endpoints", "100.86.108.4:52972->100.116.135.31:6379", "--poi-optype", "write"],
        "gt": "groundtruth/5_Exposed_Service_Pivot.groundtruth.json",
    },
    "6_Web_SQLi_Data_Exfiltration": {
        "db_new": "attack-6-web-sqli-data-exfiltration-v2",
        "poi_args": ["--poi-endpoints", "100.74.213.15:40316->100.86.108.4:80", "--poi-optype", "write"],
        "gt": "groundtruth/6_Web_SQLi_Data_Exfiltration.groundtruth.json",
    },
    "7_DB_Bruteforce_Datawipe": {
        "db_new": "attack-7-db-bruteforce-datawipe-v2",
        "poi_args": ["--poi-file", "/srv/bizapp/logs/bizapp-sync.log", "--poi-optype", "unlink"],
        "gt": "groundtruth/7_DB_Bruteforce_Datawipe.groundtruth.json",
    },
    "8_FTP_WeakCreds_WebShell_Exfiltration": {
        "db_new": "attack-8-ftp-weakcreds-webshell-exfiltration-v2",
        "poi_args": ["--poi-endpoints", "100.86.108.4:48182->100.74.213.15:8888", "--poi-optype", "sendto"],
        "gt": "groundtruth/8_FTP_WeakCreds_WebShell_Exfiltration.groundtruth.json",
    },
    "9_Exposed_Container_Escape": {
        "db_new": "attack-9-exposed-container-escape-v2",
        "poi_args": ["--poi-endpoints", "172.17.0.2:56186->100.74.213.15:8808", "--poi-optype", "sendto"],
        "gt": "groundtruth/9_Exposed_Container_Escape.groundtruth.json",
    },
    "10_Tomcat_Weakcreds_DNS_Exfiltration": {
        "db_new": "attack-10-tomcat-weakcreds-dns-exfiltration-v2",
        "poi_args": ["--poi-endpoints", "100.74.213.15:48370->100.86.108.4:8080", "--poi-optype", "write"],
        "gt": "groundtruth/10_Tomcat_Weakcreds_DNS_Exfiltration.groundtruth.json",
    },
}

CP_ITEMS = [
    M2_REPO / "org/jgrapht/jgrapht-core/1.1.0/jgrapht-core-1.1.0.jar",
    M2_REPO / "org/jgrapht/jgrapht-ext/1.1.0/jgrapht-ext-1.1.0.jar",
    M2_REPO / "org/jgrapht/jgrapht-io/1.1.0/jgrapht-io-1.1.0.jar",
    M2_REPO / "org/neo4j/driver/neo4j-java-driver/4.1.1/neo4j-java-driver-4.1.1.jar",
    M2_REPO / "org/reactivestreams/reactive-streams/1.0.4/reactive-streams-1.0.4.jar",
    M2_REPO / "io/netty/netty-buffer/4.1.105.Final/netty-buffer-4.1.105.Final.jar",
    M2_REPO / "io/netty/netty-common/4.1.105.Final/netty-common-4.1.105.Final.jar",
    M2_REPO / "io/netty/netty-transport/4.1.105.Final/netty-transport-4.1.105.Final.jar",
    M2_REPO / "io/netty/netty-resolver/4.1.105.Final/netty-resolver-4.1.105.Final.jar",
    M2_REPO / "io/netty/netty-handler/4.1.105.Final/netty-handler-4.1.105.Final.jar",
    M2_REPO / "io/netty/netty-codec/4.1.105.Final/netty-codec-4.1.105.Final.jar",
    M2_REPO / "org/neo4j/neo4j-graphdb-api/3.5.11/neo4j-graphdb-api-3.5.11.jar",
    M2_REPO / "org/neo4j/neo4j-resource/3.5.11/neo4j-resource-3.5.11.jar",
    M2_REPO / "org/neo4j/neo4j/3.5.11/neo4j-3.5.11.jar",
    M2_REPO / "com/fathzer/javaluator/3.0.3/javaluator-3.0.3.jar",
    M2_REPO / "org/apache/commons/commons-jexl3/3.0/commons-jexl3-3.0.jar",
    M2_REPO / "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
    M2_REPO / "org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar",
    M2_REPO / "guru/nidi/graphviz-java/0.18.1/graphviz-java-0.18.1.jar",
    M2_REPO / "org/json/json/20180813/json-20180813.jar",
    M2_REPO / "com/google/guava/guava/32.1.0-jre/guava-32.1.0-jre.jar",
    M2_REPO / "junit/junit/4.13.2/junit-4.13.2.jar",
    M2_REPO / "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
]
CP = os.pathsep.join(str(p) for p in CP_ITEMS)


def ensure_compiled(build_classes):
    missing = [str(path) for path in CP_ITEMS if not path.is_file()]
    if missing:
        raise RuntimeError("引擎依赖缺失：" + ", ".join(missing))
    build_classes.mkdir(parents=True, exist_ok=True)
    sources = sorted(path.relative_to(ENGINE).as_posix()
                     for path in (ENGINE / "src/main/java").rglob("*.java")
                     if path.name != "BreadthFirstIterator.java")
    sources.append("baseline/BaselineRunner.java")
    source_list = build_classes.with_name("sources.txt")
    source_list.write_text("\n".join(sources) + "\n", encoding="utf-8")
    subprocess.run(["javac", "-encoding", "UTF-8", "-nowarn", "-d", str(build_classes),
                    "-cp", CP, f"@{source_list}"], cwd=ENGINE, check=True, timeout=120)


def run_engine(scenario_name, db_name, out_dir, poi_args, build_classes, timeout):
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    from dotenv import dotenv_values
    env = {**{key: value for key, value in dotenv_values(ROOT / ".env").items() if value is not None},
           **os.environ}
    env["NEO4J_DATABASE"] = db_name

    cmd = [
        "java",
        "-cp", os.pathsep.join((str(build_classes), CP)),
        "baseline.BaselineRunner",
        scenario_name,
        str(out_dir_path),
    ] + poi_args

    print(f"[{scenario_name}] Executing engine on {db_name}...", flush=True)
    started = time.monotonic()
    log = out_dir_path / "engine.log"
    with log.open("wb") as stream:
        subprocess.run(cmd, env=env, cwd=ENGINE, stdout=stream, stderr=subprocess.STDOUT,
                       check=True, timeout=timeout)
    elapsed = time.monotonic() - started
    print(f"[{scenario_name}] Finished in {elapsed:.1f}s", flush=True)
    return elapsed


def eval_result(baseline_json, gt_path):
    metrics_path = baseline_json.with_name("metrics.json")
    cmd = [
        sys.executable,
        str(ROOT / "tools" / "score_graph_product.py"),
        str(baseline_json),
        "--gt", str(gt_path),
        "--json-out", str(metrics_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    return metrics["totals"], res.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", help="指定单个场景名")
    parser.add_argument("--force", action="store_true", help="强制重新运行，即使 baseline.json 已存在")
    parser.add_argument("--skip-run", action="store_true", help="跳过执行，仅重新评分现有产物")
    parser.add_argument("--output-root", type=Path, required=True, help="本次运行的独立输出目录")
    parser.add_argument("--timeout", type=int, default=600, help="单场景引擎墙钟超时（秒）")
    args = parser.parse_args()

    build_classes = args.output_root.resolve() / ".build" / "classes"
    if not args.skip_run:
        ensure_compiled(build_classes)

    target_scenarios = [args.scenario] if args.scenario else list(SCENARIOS.keys())

    results = []

    for name in target_scenarios:
        info = SCENARIOS[name]
        out_dir = args.output_root.resolve() / name
        baseline = out_dir / "baseline.json"
        gt_path = ROOT / info["gt"]

        wall_time = 0.0
        need_run = (not args.skip_run) and (args.force or not baseline.exists())
        if need_run:
            wall_time = run_engine(name, info["db_new"], out_dir, info["poi_args"],
                                   build_classes, args.timeout)
        elif baseline.exists():
            print(f"[{name}] Reusing existing {baseline}")

        metrics, evaluation = eval_result(baseline, gt_path)
        (out_dir / "groundtruth-eval.txt").write_text(evaluation, encoding="utf-8")
        data = json.loads(baseline.read_text(encoding="utf-8"))
        (out_dir / "run-timing.json").write_text(
            json.dumps({"wall_time_seconds": wall_time}, indent=2) + "\n", encoding="utf-8")

        results.append({
            "scenario": name,
            "wall_time": wall_time,
            "stages": data.get("stages", {}),
            "metrics": metrics,
        })

    # Summary table
    print("\n" + "=" * 80)
    print("-v2 图基线评测汇总")
    print("=" * 80)
    for r in results:
        print(f"\n场景: {r['scenario']} (运行耗时: {r['wall_time']:.1f}s)")
        print(f"  阶段: b_raw={r['stages'].get('b_raw')}, final={r['stages'].get('final')}")
        m = r["metrics"]
        print(f"  召回：{m['steps_hit']}/{m['steps_total']} | 查准：{m['correct_edges']}/{m['reported_triples']}")


if __name__ == "__main__":
    main()
