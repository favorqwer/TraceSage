#!/usr/bin/env python
"""构建 ATT&CK 知识快照（技术 + 战术 + BehaviorObservable）。

用法：
    .venv/Scripts/python.exe tools/build_attack_kg.py \
        --stix tmp/attack-stix/enterprise-attack.json \
        --observables provenance-navigator/config/attack-observables.seed.json \
        --out output/rule-kg/v1/attack.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))

from rag.attack import load_behavior_observables, load_stix, summarize  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", default=str(ROOT / "tmp/attack-stix/enterprise-attack.json"))
    ap.add_argument("--observables", default=str(ROOT / "provenance-navigator/config/attack-observables.seed.json"))
    ap.add_argument("--out", default=str(ROOT / "output/rule-kg/v1/attack.json"))
    args = ap.parse_args()

    techniques, tactics = load_stix(args.stix)
    observables = load_behavior_observables(args.observables)
    payload = {
        "techniques": {k: v.to_dict() for k, v in techniques.items()},
        "tactics": tactics,
        "observables": [o.to_dict() for o in observables],
        "counts": {
            **summarize(techniques, tactics),
            "observables": len(observables),
            "observable_techniques": sum(1 for o in observables if o.observable),
            "not_observable_techniques": sum(1 for o in observables if not o.observable),
            "verified_observables": sum(1 for o in observables if o.verified),
        },
    }
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["counts"], ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
