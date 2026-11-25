"""Check local inputs and read-only database access before live evaluation."""
import argparse
import json
import os
import shutil
from pathlib import Path

from dotenv import dotenv_values
from neo4j import GraphDatabase
from run_all_engine_v2 import CP_ITEMS

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-only", action="store_true")
    args = parser.parse_args()
    config = {**dotenv_values(ROOT / ".env"), **os.environ}
    scenarios = json.loads((ROOT / "attack_graph/config/scenarios.json").read_text(encoding="utf-8"))["scenarios"]
    failures = []
    print(f"场景数：{len(scenarios)}", flush=True)
    for scenario in scenarios:
        paths = (ROOT / "graphs" / f"{scenario}.tsg",
                 ROOT / "groundtruth" / f"{scenario}.groundtruth.json",
                 ROOT / "output/rule-kg/v1/folds" / f"{scenario}.json",
                 ROOT / "output/provenance-baseline/distill/fold-libraries" / f"{scenario}.json")
        for path in paths:
            if not path.is_file() or not path.stat().st_size:
                failures.append(f"缺少输入：{path}")
    for command in ("java", "javac"):
        if not shutil.which(command):
            failures.append(f"缺少命令：{command}")
    failures.extend(f"缺少引擎依赖：{path.name}" for path in CP_ITEMS if not path.is_file())
    if not config.get("OPENAI_API_KEY"):
        failures.append("未配置模型 API 密钥")
    if not args.local_only:
        old_scenarios = json.loads((ROOT / "provenance/config/scenarios.json").read_text(encoding="utf-8"))["scenarios"]
        databases = [old_scenarios[name]["database"] for name in scenarios]
        uri = config.get("NEO4J_URI") or "bolt://localhost:7687"
        auth = (config.get("NEO4J_USER") or "neo4j", config.get("NEO4J_PASSWORD") or "")
        try:
            with GraphDatabase.driver(uri, auth=auth, connection_timeout=5,
                                      connection_acquisition_timeout=7, max_transaction_retry_time=0) as driver:
                driver.verify_connectivity()
                for database in databases:
                    if not database.endswith("-v2"):
                        failures.append(f"场景数据库版本错误：{database}")
                        continue
                    driver.execute_query("RETURN 1 AS ok", database_=database)
                    print(f"场景库可读：{database}", flush=True)
                driver.execute_query("RETURN 1 AS ok", database_="trace-rules-kg-v1")
        except Exception as error:
            failures.append(f"Neo4j 预检失败：{type(error).__name__}")
    for message in failures:
        print(message, flush=True)
    if failures:
        raise SystemExit(1)
    print("输入预检通过，模型请求 0 次。", flush=True)


if __name__ == "__main__":
    main()
