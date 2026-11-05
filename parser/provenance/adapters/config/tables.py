"""分类表的文件加载器（适配器层）。

core 只接收内存字典；TOML 读取与重复归属校验放在这里。
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from ...core.classify import Classifier, VerbSpec
from ...core.kinds import EdgeClass, ObjSource, Verdict
from ...core.syscalls import OPEN_FAMILY


def load_classifier(data_dir: str | Path) -> Classifier:
    data = Path(data_dir)
    verbs_doc = tomllib.loads((data / "verbs.toml").read_text(encoding="utf-8"))
    calls_doc = tomllib.loads((data / "calls.toml").read_text(encoding="utf-8"))

    verbs: dict[str, VerbSpec] = {}
    by_call: dict[str, VerbSpec] = {}
    for item in verbs_doc.get("verb", []):
        spec = VerbSpec(
            name=item["name"],
            edge=EdgeClass(item["edge"]),
            source=ObjSource(item["source"]),
            gate=item.get("gate", "always"),
            calls=tuple(item.get("calls", [])),
            note=item.get("note", ""),
        )
        if spec.name in verbs:
            raise ValueError(f"动词重复：{spec.name}")
        verbs[spec.name] = spec
        for call in spec.calls:
            if call in by_call:
                raise ValueError(f"调用名重复归属：{call}")
            by_call[call] = spec

    ledger: dict[str, tuple[Verdict, str, str]] = {}
    ledger_value: dict[str, str] = {}
    for item in calls_doc.get("group", []):
        group = item["name"]
        verdict = Verdict(item["verdict"])
        reason = item.get("reason", "")
        value = item.get("value", "L3")
        for call in item.get("calls", []):
            if call in ledger or call in by_call:
                raise ValueError(f"调用名重复归属：{call}")
            ledger[call] = (verdict, reason, group)
            ledger_value[call] = value

    overlap = (set(ledger) | set(by_call)) & OPEN_FAMILY
    if overlap:
        raise ValueError(f"open 家族必须走分流规则，不应出现在表里：{sorted(overlap)}")

    return Classifier(verbs, by_call, ledger, ledger_value)
