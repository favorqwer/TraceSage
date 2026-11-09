"""配置、场景、路径与规则表加载：四块共用的最底层。

- 参数文件：`config/navigator.toml`
- 场景与 POI：`config/scenarios.json`
- 提示词：`config/prompts/`
- 取数期判据表：`config/closure_rules.json`

本模块不读取规则库，也不读取取数期判据表的内容；只提供统一的路径解析与文件读取。
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

# --- 路径 ---
PKG_DIR = Path(__file__).resolve().parent          # provenance
NAVIGATOR_DIR = PKG_DIR                           # provenance
REPO_ROOT = NAVIGATOR_DIR.parent                   # 仓库根
CONFIG_DIR = NAVIGATOR_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "navigator.toml"
SCENARIOS_FILE = CONFIG_DIR / "scenarios.json"
PROMPTS_DIR = CONFIG_DIR / "prompts"
RULES_DIR = CONFIG_DIR
WORK_DIR = REPO_ROOT / "tmp" / "provenance"
STATE_DIR = WORK_DIR / "state"
LOG_DIR = WORK_DIR / "logs"
L1_INDEX_DIR = WORK_DIR / "l1-index"

def groundtruth_dir() -> Path:
    return REPO_ROOT / "groundtruth"

def fold_library_dir() -> Path:
    return REPO_ROOT / "output" / "provenance-baseline" / "distill" / "fold-libraries"


_ENV_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

_PROMPT_CACHE: dict[str, str] = {}
_TABLE_CACHE: dict[str, Any] = {}


def load_dotenv(path: Optional[str] = None) -> None:
    """Minimal .env loader（stdlib only）：KEY=VALUE、# 注释、无变量展开、不覆盖已有环境变量。"""
    target: Optional[Path] = None
    if path is not None:
        candidate = Path(path)
        if candidate.is_file():
            target = candidate
    else:
        candidate = REPO_ROOT / ".env"
        if candidate.is_file():
            target = candidate
    if target is None:
        return
    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _ENV_PATTERN.match(line)
            if match:
                os.environ.setdefault(match.group(1), match.group(2))


# --- 参数文件：读、校验、缓存 ---
_CONFIG: Optional[dict[str, Any]] = None
_CONFIG_PATH: Path = CONFIG_FILE
_WARNINGS: list[str] = []


def config_path() -> Path:
    return _CONFIG_PATH


def use_config(path: Optional[str] = None) -> Path:
    """换一份参数文件（None = 回到默认那份）；下一次读参数时重新加载。测试与对照实验用。"""
    global _CONFIG_PATH, _CONFIG
    _CONFIG_PATH = Path(path) if path is not None else CONFIG_FILE
    _CONFIG = None
    _WARNINGS.clear()
    return _CONFIG_PATH


def config_warnings() -> list[str]:
    _config()
    return list(_WARNINGS)


def _config() -> dict[str, Any]:
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG
    data: dict[str, Any] = {}
    if _CONFIG_PATH.is_file():
        try:
            with _CONFIG_PATH.open("rb") as fh:
                loaded = tomllib.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except Exception as exc:  # noqa: BLE001 - 读不了就全部用默认值，启动时打印
            _warn(f"参数文件 {_CONFIG_PATH} 读不了（{type(exc).__name__}），全部用默认值")
    _CONFIG = data
    return _CONFIG


def _warn(message: str) -> None:
    if message not in _WARNINGS:
        _WARNINGS.append(message)


def _raw(section: str, key: str) -> Any:
    node = _config().get(section)
    return node.get(key) if isinstance(node, dict) else None


def _pick_int(section: str, key: str, default: int, minimum: int) -> int:
    value = _raw(section, key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        _warn(f"{section}.{key} 要整数，现在写的是 {value!r}；用默认值 {default}")
        return default
    if value < minimum:
        _warn(f"{section}.{key} 不能小于 {minimum}，现在写的是 {value}；用默认值 {default}")
        return default
    return value


def _pick_float(section: str, key: str, default: float, minimum: float) -> float:
    value = _raw(section, key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _warn(f"{section}.{key} 要数字，现在写的是 {value!r}；用默认值 {default}")
        return default
    if float(value) < minimum:
        _warn(f"{section}.{key} 不能小于 {minimum}，现在写的是 {value}；用默认值 {default}")
        return default
    return float(value)


def _pick_bool(section: str, key: str, default: bool) -> bool:
    value = _raw(section, key)
    if value is None:
        return default
    if not isinstance(value, bool):
        _warn(f"{section}.{key} 要 true/false，现在写的是 {value!r}；用默认值 {default}")
        return default
    return value


def ensure_work_dirs() -> None:
    for d in (WORK_DIR, STATE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)


def ensure_index_dir() -> None:
    L1_INDEX_DIR.mkdir(parents=True, exist_ok=True)


# --- Neo4j（只读）---
def neo4j_uri() -> str:
    return os.environ.get("NEO4J_URI", "bolt://localhost:7687")


def neo4j_auth() -> tuple[str, str]:
    return os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")


# --- LLM ---
def llm_model() -> str:
    return os.environ.get("OPENAI_MODEL", "gpt-5.4")


def llm_base_url() -> Optional[str]:
    return os.environ.get("OPENAI_BASE_URL") or None


def llm_api_key() -> Optional[str]:
    return os.environ.get("OPENAI_API_KEY") or None


# --- 参数：全部从 `config/navigator.toml` 读 ---
def max_concurrency() -> int:
    return _pick_int("judge", "concurrency", 12, 1)


def thinking_enabled() -> bool:
    return _pick_bool("judge", "thinking", False)


def batch_attempts() -> int:
    return _pick_int("judge", "batch_attempts", 2, 1)


def bundle_batch() -> int:
    return _pick_int("bundle", "batch", 40, 1)


def bundle_samples() -> int:
    return _pick_int("bundle", "samples", 2, 1)


def bundle_cap_calls() -> int:
    return _pick_int("bundle", "cap_calls", 60, 1)


def bundle_fanout_min() -> int:
    return _pick_int("bundle", "fanout_min", 1, 1)


def risk_schedule_enabled() -> bool:
    return _pick_bool("bundle", "risk_schedule", True)


def aggregate_enabled() -> bool:
    return _pick_bool("bundle", "aggregate", True)


def annotate_marks_enabled() -> bool:
    return _pick_bool("bundle", "annotate_marks", True)


def fanout_guard_enabled() -> bool:
    return _pick_bool("bundle", "fanout_guard", True)


def vacuous_guard_enabled() -> bool:
    return _pick_bool("bundle", "vacuous_guard", True)


def none_guard() -> str:
    value = str(_raw("bundle", "none_guard") or "hot").strip().lower()
    return value if value in ("off", "hot") else "hot"


def warrant_guard_enabled() -> bool:
    return _pick_bool("bundle", "warrant_guard", True)


def warrant_rules() -> list[str]:
    raw = _raw("bundle", "warrant_rule")
    items = [str(item).strip() for item in str(raw or "deriv,proc").split(",")]
    return [item for item in items if item in ("deriv", "proc")]


def _csv(section: str, key: str, default: str) -> tuple[str, ...]:
    raw = _raw(section, key)
    return tuple(item.strip() for item in str(raw or default).split(",") if item.strip())


def prune_managers() -> tuple[str, ...]:
    return _csv("prune", "managers",
                "dpkg,dpkg-deb,dpkg-split,dpkg-preconfigure,mandb,ldconfig,ldconfig.real")


def prune_internal_sinks() -> tuple[str, ...]:
    return _csv("prune", "internal_sinks",
                ".dpkg-new,.dpkg-tmp,.triggers,/usr/share/doc/,/usr/share/man/,/usr/share/locale/,"
                "/var/cache/man/,/var/cache/apt/,/var/lib/apt/lists/")


def prune_postinst_tokens() -> tuple[str, ...]:
    return _csv("prune", "postinst_tokens", "postinst")


def reason_max_chars() -> int:
    return _pick_int("render", "reason_max_chars", 40, 1)


def log_text_limit() -> int:
    return _pick_int("logging", "text_limit", 120, 1)


def audit_sample_n() -> int:
    return _pick_int("logging", "sample_n", 5, 1)


def diagnostic_keep() -> int:
    return _pick_int("logging", "diagnostic_keep", 2000, 1)


def llm_timeout_seconds() -> int:
    return _pick_int("llm", "timeout_seconds", 120, 1)


def llm_sdk_retries() -> int:
    return _pick_int("llm", "sdk_retries", 0, 0)


def llm_plain_retries() -> int:
    return _pick_int("llm", "plain_retries", 3, 0)


def llm_plain_retry_base_seconds() -> float:
    return _pick_float("llm", "plain_retry_base_seconds", 2.0, 0.0)


def llm_rate_limit_waits() -> int:
    return _pick_int("llm", "rate_limit_waits", 8, 0)


def llm_rate_limit_wait_start_seconds() -> float:
    return _pick_float("llm", "rate_limit_wait_start_seconds", 5.0, 0.0)


def llm_rate_limit_wait_max_seconds() -> float:
    return _pick_float("llm", "rate_limit_wait_max_seconds", 60.0, 0.0)


def llm_format_retries() -> int:
    return _pick_int("llm", "format_retries", 2, 0)


# ---- 场景清单与配置文件读取 ----

@dataclass(frozen=True)
class EndpointSpec:
    """场景的调查起点事件（POI）描述。"""

    kind: str          # "file" | "network"
    rel: str           # "p2f" | "p2n" | "n2p" | "f2p" ...
    syscall: str
    key: str           # file_id 或 network_id
    raw: dict = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "rel": self.rel, "syscall": self.syscall, "key": self.key}


@dataclass(frozen=True)
class Scenario:
    """一个采集场景的配置：数据库名 + POI。"""

    name: str
    database: str
    poi: EndpointSpec


def _endpoint_spec(node: Any) -> EndpointSpec:
    if not isinstance(node, dict):
        raise ValueError(f"场景端点必须是对象，实测 {type(node)!r}")
    kind = str(node.get("kind") or "")
    rel = str(node.get("rel") or "")
    syscall = str(node.get("syscall") or "")
    key = node.get("file_id") or node.get("network_id") or node.get("key") or ""
    if not (kind and rel and syscall and key):
        raise ValueError(f"场景端点缺字段（kind/rel/syscall/file_id|network_id）：{node!r}")
    return EndpointSpec(kind=kind, rel=rel, syscall=syscall, key=str(key), raw=dict(node))


def _load_raw(path: Optional[Path] = None) -> dict:
    target = SCENARIOS_FILE if path is None else Path(path)
    if not target.is_file():
        raise RuntimeError(f"场景清单缺失：{target}")
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), dict):
        raise RuntimeError(f"场景清单结构不符（需要顶层 scenarios 对象）：{target}")
    return data


def available_scenarios(path: Optional[Path] = None) -> list[str]:
    """全部场景名，按字符串排序（与历史一致）。"""
    return sorted(_load_raw(path)["scenarios"].keys())


def load_scenario(name: str, path: Optional[Path] = None) -> Scenario:
    raw = _load_raw(path)["scenarios"]
    if name not in raw:
        raise KeyError(f"未知场景 {name}；可选：{sorted(raw.keys())}")
    node = raw[name]
    return Scenario(
        name=name,
        database=str(node["database"]),
        poi=_endpoint_spec(node["poi"]),
    )


def load_prompt(name: str) -> str:
    target = CONFIG_DIR / "prompts" / name
    if not target.is_file():
        raise RuntimeError(f"提示词缺失：{target}")
    return target.read_text(encoding="utf-8")


def load_rule_table(name: str) -> Any:
    target = CONFIG_DIR / name
    if not target.is_file():
        raise RuntimeError(f"规则表缺失：{target}")
    return json.loads(target.read_text(encoding="utf-8"))


def load_json(name: str) -> Any:
    return load_rule_table(name)
