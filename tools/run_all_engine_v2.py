#!/usr/bin/env python
"""
运行并对比 provenance-engine 在 5 个攻击场景新旧图库上的全量测试与评测。
遵循 AGENTS.md 四大工程法则与对比实验底线。
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "provenance-engine"
BUILD_CLASSES = ENGINE / "build" / "classes"
M2_REPO = Path(os.environ.get("USERPROFILE", "C:/Users/Favor")) / ".m2" / "repository"

SCENARIOS = {
    "1_Web_Exploit_Ransomware": {
        "db_old": "attack-1-web-exploit-ransomware",
        "db_new": "attack-1-web-exploit-ransomware-v2",
        "poi_args": ["--poi-file", "/srv/data/README_RESTORE.txt", "--poi-optype", "write"],
        "gt": "groundtruth/1_Web_Exploit_Ransomware.groundtruth.json",
    },
    "2_SSH_Spray_Lateral_Exfiltration": {
        "db_old": "attack-2-ssh-spray-lateral-exfiltration",
        "db_new": "attack-2-ssh-spray-lateral-exfiltration-v2",
        "poi_args": ["--poi-endpoints", "100.116.135.31:45794->100.86.108.4:22", "--poi-optype", "write"],
        "gt": "groundtruth/2_SSH_Spray_Lateral_Exfiltration.groundtruth.json",
    },
    "3_Phishing_Beacon_Cryptomining": {
        "db_old": "attack-3-phishing-beacon-cryptomining",
        "db_new": "attack-3-phishing-beacon-cryptomining-v2",
        "poi_args": ["--poi-endpoints", "100.86.108.4:59062->100.84.151.2:8080", "--poi-optype", "sendto"],
        "gt": "groundtruth/3_Phishing_Beacon_Cryptomining.groundtruth.json",
    },
    "4_Repo_Poisoning_Backdoor": {
        "db_old": "attack-4-repo-poisoning-backdoor",
        "db_new": "attack-4-repo-poisoning-backdoor-v2",
        "poi_args": ["--poi-endpoints", "100.74.213.15:53648->100.86.108.4:22", "--poi-optype", "write"],
        "gt": "groundtruth/4_Repo_Poisoning_Backdoor.groundtruth.json",
    },
    "5_Exposed_Service_Pivot": {
        "db_old": "attack-5-exposed-service-pivot",
        "db_new": "attack-5-exposed-service-pivot-v2",
        "poi_args": ["--poi-endpoints", "100.86.108.4:52972->100.116.135.31:6379", "--poi-optype", "write"],
        "gt": "groundtruth/5_Exposed_Service_Pivot.groundtruth.json",
    },
}

CP_ITEMS = [
    BUILD_CLASSES,
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
CP = ";".join(str(p) for p in CP_ITEMS)


def ensure_compiled():
    if (BUILD_CLASSES / "baseline" / "BaselineRunner.class").exists():
        return
    print("Classes not found, compiling...")
    res = subprocess.run([sys.executable, str(ROOT / "tmp" / "compile_engine.py")], capture_output=True, text=True)
    if res.returncode != 0:
        print("Compile failed:", res.stderr)
        sys.exit(1)


def run_engine(scenario_name, db_name, out_dir, poi_args):
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    
    env = dict(os.environ)
    env["NEO4J_DATABASE"] = db_name

    cmd = [
        "java",
        "-cp", CP,
        "baseline.BaselineRunner",
        scenario_name,
        str(out_dir_path),
    ] + poi_args

    print(f"[{scenario_name}] Executing engine on {db_name}...")
    t0 = time.time()
    proc = subprocess.Popen(
        cmd, env=env, cwd=str(ENGINE),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="gbk", errors="replace"
    )

    stdout_lines = []
    for line in proc.stdout:
        stdout_lines.append(line)
        line_s = line.strip()
        if any(k in line_s for k in ["b_raw:", "b_cpr:", "forward from entry", "forward_union:", "final:", "baseline written:"]):
            print(f"  {line_s}")

    stderr = proc.stderr.read()
    proc.wait()
    dt = time.time() - t0

    if proc.returncode != 0:
        print(f"[{scenario_name}] Run failed with code {proc.returncode}:\n{stderr}\n{''.join(stdout_lines)}")
        return False, dt, stderr

    print(f"[{scenario_name}] Finished in {dt:.1f}s")
    return True, dt, "".join(stdout_lines)


def eval_result(baseline_json, gt_path):
    cmd = [
        sys.executable,
        str(ROOT / "tools" / "evaluate_gt.py"),
        str(baseline_json),
        "--gt", str(gt_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    
    # Parse evaluation metrics
    recall_str = ""
    prec_str = ""
    for line in res.stdout.splitlines():
        if "召回（按步骤）" in line:
            recall_str = line.strip()
        elif "查准（按边）" in line:
            prec_str = line.strip()
    return recall_str, prec_str, res.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", help="指定单个场景名")
    parser.add_argument("--force", action="store_true", help="强制重新运行，即使 baseline.json 已存在")
    parser.add_argument("--skip-run", action="store_true", help="跳过执行，仅重新评分现有产物")
    args = parser.parse_args()

    ensure_compiled()

    target_scenarios = [args.scenario] if args.scenario else list(SCENARIOS.keys())

    results = []

    for name in target_scenarios:
        info = SCENARIOS[name]
        out_dir = ROOT / "output" / "engine-runs" / "new-parser-v2" / name
        baseline_new = out_dir / "baseline.json"
        baseline_old = ROOT / "output" / "engine-baseline" / name / "baseline.json"
        gt_path = ROOT / info["gt"]

        wall_time = 0.0
        need_run = (not args.skip_run) and (args.force or not baseline_new.exists())
        if need_run:
            success, wall_time, _ = run_engine(name, info["db_new"], out_dir, info["poi_args"])
            if not success:
                print(f"FAILED on {name}")
                continue
        elif baseline_new.exists():
            print(f"[{name}] Reusing existing {baseline_new}")
        
        # Evaluate New
        rec_new, prec_new, _ = eval_result(baseline_new, gt_path)
        # Evaluate Old
        rec_old, prec_old, _ = eval_result(baseline_old, gt_path)

        data_new = json.loads(baseline_new.read_text(encoding="utf-8"))
        data_old = json.loads(baseline_old.read_text(encoding="utf-8"))

        results.append({
            "scenario": name,
            "wall_time": wall_time,
            "old_stages": data_old.get("stages", {}),
            "new_stages": data_new.get("stages", {}),
            "old_recall": rec_old,
            "new_recall": rec_new,
            "old_prec": prec_old,
            "new_prec": prec_new,
        })

    # Summary table
    print("\n" + "=" * 80)
    print("全场景新旧基线评测对比汇总")
    print("=" * 80)
    for r in results:
        print(f"\n场景: {r['scenario']} (新图运行耗时: {r['wall_time']:.1f}s)")
        print(f"  旧基线阶段: b_raw={r['old_stages'].get('b_raw')}, final={r['old_stages'].get('final')}")
        print(f"  新图阶段:   b_raw={r['new_stages'].get('b_raw')}, final={r['new_stages'].get('final')}")
        print(f"  旧基线评分: {r['old_recall']} | {r['old_prec']}")
        print(f"  新图评分:   {r['new_recall']} | {r['new_prec']}")


if __name__ == "__main__":
    main()
