"""配置（横切）：路径、凭据（`.env`）、以及全部参数（`config/agent.toml`）。

**参数只有一个入口**：`provenance-agent/config/agent.toml`。本模块负责读它、校验它、缓存它，
对外只暴露“取某个数”的函数；别的模块不再自己写数字。

凭据与连接信息（数据库地址与口令、接口地址与密钥、模型名）不走那份文件，仍然从环境变量或
仓库根 `.env` 读，`setdefault` 不覆盖已有环境变量，凭据绝不硬编码。

容错口径：某一项没写就用本模块内置的默认值；类型不对或小于下限也用默认值，并在启动时打印一行
说明（不报错、不崩）；文件整份缺失时全部用默认值。

展开侧**不设任何条数上限**（理由见下方注释）。
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any, Optional

# --- 路径 ---
PKG_DIR = Path(__file__).resolve().parent          # provenance-agent/pagent/core
AGENT_DIR = PKG_DIR.parent.parent                  # provenance-agent
REPO_ROOT = AGENT_DIR.parent                       # 仓库根
CONFIG_DIR = AGENT_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "agent.toml"            # 全部参数（唯一真源）
SCENARIOS_FILE = CONFIG_DIR / "scenarios.json"
PROMPTS_DIR = PKG_DIR.parent / "prompts"           # provenance-agent/pagent/prompts
RULES_DIR = PKG_DIR.parent / "rules"               # provenance-agent/pagent/rules
WORK_DIR = REPO_ROOT / "tmp" / "provenance-agent"  # 运行态产物（缓存/日志/记录）
STATE_DIR = WORK_DIR / "state"
LOG_DIR = WORK_DIR / "logs"

_ENV_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


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


# --- 参数文件（config/agent.toml）：读、校验、缓存 ---
_CONFIG: Optional[dict[str, Any]] = None
_CONFIG_PATH: Path = CONFIG_FILE
_WARNINGS: list[str] = []


def config_path() -> Path:
    """当前用的参数文件路径。"""
    return _CONFIG_PATH


def use_config(path: Optional[str] = None) -> Path:
    """换一份参数文件（None = 回到默认那份）；下一次读参数时重新加载。

    测试与对照实验用（换一份文件跑，不改默认那份）。
    """
    global _CONFIG_PATH, _CONFIG
    _CONFIG_PATH = Path(path) if path is not None else CONFIG_FILE
    _CONFIG = None
    _WARNINGS.clear()
    return _CONFIG_PATH


def config_warnings() -> list[str]:
    """加载参数文件时发现的问题（缺项不算问题；类型不对、超范围、读不了才算）。

    空表表示没问题；入口启动时把非空的内容打印一行。
    """
    _config()
    return list(_WARNINGS)


def _config() -> dict[str, Any]:
    """读一次、缓存住（一次运行只读一次文件）。"""
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


# --- 展开侧（确定性，不花模型）---
# 展开侧**不设任何条数上限**：上游候选条数、子进程条数、管道组成员数、待处理清单长度、
# 单进程边数、查询返回行数，全部不设限。
#
# 理由：任何条数上限都是按数据分布随机丢边——同一条攻击链在不同场景里的长度不一样，
# 上限只要小于真实长度就会掉召回，而"真实长度"事先不知道。实测：子进程上限 8 让场景 4 的
# 标注覆盖从 100% 掉到 74.6%、场景 5 从 100% 掉到 94.1%；把上限提到 50 两者都回到 100%。
# 展开的终止条件只有一个：待考察清单（前沿）耗尽。


# 第 1 层只有一个开关：输出期过滤（`output_filter_enabled`，默认开，只用于对照实验）。
# 其余语义口径全部写死在 `l1_reach/` 里（方向约束、遍历期规则、无条数上限、
# 同一主体子进程算上游、写入者时间界取读取结束时刻、进程状态上界取终点事件时刻、不设时间窗）；
# 取数方式也固定：读本地顶点-时间索引快照，缺失或过期就重建（见 `l1_reach/snapshot.py`）。
# 定成读索引的理由：直查数据库按行计价（实测每行约 27~39 微秒），三个大闭包场景（3/4/5）要
# 取回几十万到上百万行，同一个闭包读索引只花几秒。代价是每个库第一次跑要先建索引
# （一次性 7~37 秒、19~93 兆字节，放 `tmp/provenance-agent/l1-index/<库名>/`）。


L1_INDEX_DIR = WORK_DIR / "l1-index"


def ensure_index_dir() -> None:
    L1_INDEX_DIR.mkdir(parents=True, exist_ok=True)


# --- 参数：全部从 `config/agent.toml` 读，括号里是文件里的位置 ---
# 每一项的“为什么是这个值”写在参数文件里；这里只写它管什么。取值都走 `_pick_*`：
# 缺项、类型不对、超范围都回到默认值（默认值仅用于容错，日常改值请改参数文件）。

# 第 1 层：输出期过滤（`layers/l1_reach/output_filter.py`）。
# 它决定第二层能看到哪些候选边：折叠前先剔掉“属主进程不在终点事件那次执行范围内”的实例，
# 再按剔除表的 output 段（`rules/filters.json`）剔掉整类例行活动。
def output_filter_enabled() -> bool:
    return _pick_bool("judge", "output_filter", True)


def judge_batch() -> int:
    """每批边数上限（波内切批）。"""
    return _pick_int("judge", "batch", 70, 1)


def max_concurrency() -> int:
    """同一波的批的并发上限。"""
    return _pick_int("judge", "concurrency", 12, 1)


def thinking_enabled() -> bool:
    """模型是否先内部推理再回答（官方接口上的那个字段）。"""
    return _pick_bool("judge", "thinking", False)


def wave_attempts() -> int:
    """一批最多尝试几次（首次 + 失败后重发，不切割波）。"""
    return _pick_int("judge", "wave_attempts", 2, 1)


def upstream_limit() -> int:
    """每条边下面最多列几条「上层顶点上已判过的边」（第 1 层明细）。"""
    return _pick_int("judge", "upstream_limit", 3, 0)


def state_chain_limit() -> int:
    """状态摘要里「已确认链片段」最多列几条。"""
    return _pick_int("judge", "state_chain_limit", 20, 1)


def neighbor_per_side() -> int:
    """同一对象上前侧、后侧各最多列几条时间邻居（0 = 不列这一项）。"""
    return _pick_int("judge", "neighbor_per_side", 2, 0)


def overlap_neighbor_count() -> int:
    """同一对象上前侧或后侧为空时，补几条时间重叠的邻居。"""
    return _pick_int("render", "overlap_neighbor", 1, 0)


def reason_max_chars() -> int:
    """判定理由长度：提示词按它要求模型，代码按同一个数截断渲染出来的理由。"""
    return _pick_int("render", "reason_max_chars", 40, 1)


def via_max_chars() -> int:
    """状态摘要里「上层顶点」文字的截断长度。"""
    return _pick_int("render", "via_max_chars", 60, 1)


def session_overview_lines() -> int:
    """状态摘要里「服务会话一览」最多列几条有命令活动的会话。"""
    return _pick_int("render", "session_overview_lines", 8, 1)


def log_text_limit() -> int:
    """日志、审计文件、原始输出样本的统一截断长度（报告里判定理由的长度也是它）。"""
    return _pick_int("logging", "text_limit", 120, 1)


def audit_sample_n() -> int:
    """报告与统计里举几条样例（未判定的边举例、最慢的调用列表共用）。"""
    return _pick_int("logging", "sample_n", 5, 1)


def diagnostic_keep() -> int:
    """诊断保留量：每次调用保留多少字符的原文样本 = 内存里最多留多少条调用明细。"""
    return _pick_int("logging", "diagnostic_keep", 2000, 1)


# 模型通道（`core/llm.py`）：超时、两层重试、退避与限流等待。
def llm_timeout_seconds() -> int:
    return _pick_int("llm", "timeout_seconds", 120, 1)


def llm_sdk_retries() -> int:
    """接口库自身的重试次数（设 0 关掉它，重试交给程序自己的退避逻辑）。"""
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
    """模型输出不是合法结构时，把错误灌回去再要一次的次数。"""
    return _pick_int("llm", "format_retries", 2, 0)


# --- 服务会话一览（第 1 层算、第 2 层摘要里渲染）---
# 始终产出：把“每次连接：服务进程、命令活动条数、候选条数”写进调查状态摘要，
# 让模型能比较同一服务进程的多次连接（命令活动 0 的那几次没有引出后续活动）。
# 只增上下文，不参与收边、不过滤候选。
# 会话命令活动口径见 `l1_reach/sessions.py`（零活动 = 这次会话除连接本身与自身的读写之外
# 没有留下任何候选记录；没有阈值，判断仍由模型做）。
