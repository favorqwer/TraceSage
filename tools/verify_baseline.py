"""Verify the inputs, outputs, and totals of a staged triplet baseline."""
import argparse
import json
from pathlib import Path

from run_triplet_validation import COUNTS, ROOT, SYSTEMS, SCORING_PROTOCOL, sha256


def verify(run: Path) -> None:
    result = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    if result.get("scoring_protocol") != SCORING_PROTOCOL:
        raise ValueError("评分协议不匹配")
    systems = result["systems"]
    selected_systems = ("attack_graph",) if result.get("scope") == "attack_graph" else SYSTEMS
    if set(systems) != set(selected_systems):
        raise ValueError("对照系统不齐全")
    scenarios = set(json.loads((ROOT / "attack_graph/config/scenarios.json").read_text(
        encoding="utf-8"))["scenarios"])
    for name in selected_systems:
        rows = systems[name]["results"]
        if len(rows) != len(scenarios) or {row["scenario"] for row in rows} != scenarios:
            raise ValueError(f"{name} 场景清单不符")
        for row in rows:
            outputs = ["report"]
            if name == "attack_graph":
                outputs.append("events")
            if name in ("attack_graph", "provenance"):
                outputs.append("trace")
            for output in outputs:
                artifact = row[output]
                path = Path(artifact["path"])
                if sha256(path) != artifact["sha256"]:
                    raise ValueError(f"输出指纹不符：{path}")
            if row["steps_hit"] > row["steps_total"] or row["correct_edges"] > row["reported_triples"]:
                raise ValueError(f"计数越界：{name}/{row['scenario']}")
        for key in COUNTS:
            if sum(row[key] for row in rows) != systems[name]["micro"][key]:
                raise ValueError(f"计数汇总不符：{name}/{key}")
    for path, digest in result["inputs"].items():
        if sha256(Path(path)) != digest:
            raise ValueError(f"输入指纹不符：{path}")
    for path, digest in result["code_sha256"].items():
        if sha256(ROOT / path) != digest:
            raise ValueError(f"代码指纹不符：{path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    verify(args.run_dir)
    print(f"通过三元组基线校验：{args.run_dir}")


if __name__ == "__main__":
    main()
