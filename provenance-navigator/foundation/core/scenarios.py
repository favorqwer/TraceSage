"""场景配置（D5：POI 由配置文件指定）。

`config/scenarios.json` 是 POI 的唯一来源；`.query` 文件（含引擎方法描述）
不进入任何可见上下文。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from . import settings


@dataclass(frozen=True)
class Poi:
    kind: str                 # "file" | "network"
    rel: str                  # "p2f" | "p2n"
    syscall: str              # 家族基本名，如 "write" / "sendto"
    key: str                  # file_id 或 network_id

    def describe(self) -> str:
        return f"{self.rel} {self.syscall} -> {self.key}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "rel": self.rel,
            "syscall": self.syscall,
            "key": self.key,
        }


@dataclass(frozen=True)
class Scenario:
    name: str
    database: str
    poi: Poi


def _load_raw(path: Optional[Path] = None) -> dict[str, Any]:
    target = path or settings.SCENARIOS_FILE
    if not target.is_file():
        raise FileNotFoundError(f"场景配置不存在：{target}")
    return json.loads(target.read_text(encoding="utf-8"))


def available_scenarios(path: Optional[Path] = None) -> list[str]:
    return sorted(_load_raw(path)["scenarios"].keys())


def load_scenario(name: str, path: Optional[Path] = None) -> Scenario:
    raw = _load_raw(path)["scenarios"]
    if name not in raw:
        raise KeyError(f"未知场景 {name!r}；可选：{sorted(raw)}")
    entry = raw[name]
    poi = entry["poi"]
    key_name = "file_id" if poi["kind"] == "file" else "network_id"
    poi_key = poi.get("key") or poi.get(key_name) or poi.get("path") or poi.get("endpoints") or ""
    db = os.environ.get("NAVIGATOR_DB_OVERRIDE") or (entry["database"] + os.environ.get("NAVIGATOR_DB_SUFFIX", ""))
    return Scenario(
        name=name,
        database=db,
        poi=Poi(kind=poi["kind"], rel=poi["rel"], syscall=poi["syscall"], key=poi_key),
    )
