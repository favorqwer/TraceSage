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


# 第 1 层没有任何开关，也没有尾部裁剪：闭包收到什么就折叠出什么（取边时会「少收」的只有
# 取数/收边阶段的两处判据：非交付通道不往回找写入者、算不算交付）。
# 其余语义口径全部写死在 `l1_reach/` 里（方向约束、取边时不剔边、无条数上限、
# 同一主体子进程算上游、写入者时间界取读取结束时刻、进程状态上界取终点事件时刻、不设时间窗）；
# 取数方式也固定：读本地顶点-时间索引快照，缺失或过期就重建（见 `l1_reach/graph_index.py`）。
# 定成读索引的理由：直查数据库按行计价（实测每行 20~30 微秒），三个大闭包场景（3/4/5）要
# 取回几十万行，同一个闭包读索引只花几秒（六场合计 4.15 秒 vs 直查 47.94 秒）。
# 代价是每个库第一次跑要先建索引（一次性 7.3~37.7 秒、18~87 兆字节，放 `tmp/provenance-agent/l1-index/<库名>/`）。


L1_INDEX_DIR = WORK_DIR / "l1-index"


def ensure_index_dir() -> None:
    L1_INDEX_DIR.mkdir(parents=True, exist_ok=True)


# --- 参数：全部从 `config/agent.toml` 读，括号里是文件里的位置 ---
# 每一项的“为什么是这个值”写在参数文件里；这里只写它管什么。取值都走 `_pick_*`：
# 缺项、类型不对、超范围都回到默认值（默认值仅用于容错，日常改值请改参数文件）。

# 第 1 层：没有可选开关。

def max_concurrency() -> int:
    """同一级的批的并发上限。"""
    return _pick_int("judge", "concurrency", 12, 1)


def thinking_enabled() -> bool:
    """模型是否先内部推理再回答（官方接口上的那个字段）。"""
    return _pick_bool("judge", "thinking", False)


def batch_attempts() -> int:
    """一批最多尝试几次（首次 + 失败后重发，不改批划分）。"""
    return _pick_int("judge", "batch_attempts", 2, 1)


# --- 束级判定与闸门（`bundle` 段；驱动在 `orchestration/judging.py`）---

def bundle_batch() -> int:
    """每批最多几个束。"""
    return _pick_int("bundle", "batch", 40, 1)


def bundle_samples() -> int:
    """每个束最多列几条成员样本（前向闸门同理）。"""
    return _pick_int("bundle", "samples", 2, 1)


def bundle_cap_calls() -> int:
    """第一轮调用上限（超了的束按「未排除」保留）。"""
    return _pick_int("bundle", "cap_calls", 60, 1)


def bundle_fanout_min() -> int:
    """扇出闸门跳过的最大成员数（默认 1：只跳拆分产生的单条边子束）。"""
    return _pick_int("bundle", "fanout_min", 1, 1)


def risk_schedule_enabled() -> bool:
    """第 1 级按风险分数排序（网络边、离锚点近、含写边优先）；关掉则按结构键排序。"""
    return _pick_bool("bundle", "risk_schedule", True)


def aggregate_enabled() -> bool:
    """聚合共享表（批头列「同类规模」与「上一级束」两张表，只改渲染）。"""
    return _pick_bool("bundle", "aggregate", True)


def annotate_marks_enabled() -> bool:
    """跨束痕迹：把已判相关的束留下的对象类别 / 程序痕迹标给后续批。"""
    return _pick_bool("bundle", "annotate_marks", True)


def fanout_guard_enabled() -> bool:
    """扇出闸门：拆分产生的单条边子束不判、直接归未排除。"""
    return _pick_bool("bundle", "fanout_guard", True)


def vacuous_guard_enabled() -> bool:
    """空拆闸门：子束与上一级成员相同时不重判、直接归未排除。"""
    return _pick_bool("bundle", "vacuous_guard", True)


def none_guard() -> str:
    """类一致性闸门的档位（`hot` = 同类里已有束判相关时，同类判无关的降级为要拆）。"""
    value = str(_raw("bundle", "none_guard") or "hot").strip().lower()
    return value if value in ("off", "hot") else "hot"


def warrant_guard_enabled() -> bool:
    """凭证闸门：判「整束无关」必须过结构凭证，否则降级为要拆（须与空拆闸门同开）。"""
    return _pick_bool("bundle", "warrant_guard", True)


def warrant_rules() -> list[str]:
    """启用的凭证名单（`deriv` = 束内全是派生边；`proc` = 同一进程已确认）。"""
    raw = _raw("bundle", "warrant_rule")
    items = [str(item).strip() for item in str(raw or "deriv,proc").split(",")]
    return [item for item in items if item in ("deriv", "proc")]


# --- 渲染（`render` 段）---

def reason_max_chars() -> int:
    """判定理由长度：提示词按它要求模型，代码按同一个数截断渲染出来的理由。"""
    return _pick_int("render", "reason_max_chars", 40, 1)


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
