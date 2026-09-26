"""配置（横切）：.env 加载、路径、模型与判定侧参数。

口径与 `sysdig-parser/parsers/config.py` 一致：stdlib-only 的 .env 加载器，
`setdefault` 不覆盖已有环境变量，凭据绝不硬编码。

展开侧**不设任何条数上限**（理由见下方注释）；旋钮只剩判定侧三类：批大小、并发、单次调查的调用上限。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

# --- 路径 ---
PKG_DIR = Path(__file__).resolve().parent          # provenance-agent/pagent/core
AGENT_DIR = PKG_DIR.parent.parent                  # provenance-agent
REPO_ROOT = AGENT_DIR.parent                       # 仓库根
CONFIG_DIR = AGENT_DIR / "config"
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


def resolve_int_env(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is not None:
        try:
            value = int(raw.strip())
            if value >= minimum:
                return value
        except ValueError:
            pass
    return default


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
# 展开的终止条件只有两个：前沿耗尽、或同一个步骤连续失败两次。


# 第 1 层：没有开关。语义口径全部写死在 `l1_reach/` 里（方向约束、遍历期规则、无条数上限、
# 同一主体子进程算上游、写入者时间界取读取结束时刻、进程状态上界取终点事件时刻、不设时间窗）；
# 取数方式也固定：读本地顶点-时间索引快照，缺失或过期就重建（见 `l1_reach/snapshot.py`）。
# 定成读索引的理由：直查数据库按行计价（实测每行约 27~39 微秒），三个大闭包场景（3/4/5）要
# 取回几十万到上百万行，同一个闭包读索引只花几秒。代价是每个库第一次跑要先建索引
# （一次性 7~37 秒、19~93 兆字节，放 `tmp/provenance-agent/l1-index/<库名>/`）。


L1_INDEX_DIR = WORK_DIR / "l1-index"


def ensure_index_dir() -> None:
    L1_INDEX_DIR.mkdir(parents=True, exist_ok=True)


# --- 判定侧（唯一的模型调用）---
# 批大小：一批里放多少条边。批次只影响"重复发送的上下文"总量与并行度，不影响判定结果：
# - 批越大 → 调用越少、重复的上下文越少（省输入 token）；
# - 批越小 → 并行度越高（池子里的调用数更多）。
# 经验值：批数应 ≥ 并发数，否则池子填不满（636 条边 / 50 = 13 批 ≈ 12 并发）。
# 单批过大还会顶到网关的超时，因此判定失败时会自动二分拆批重试（见 judge.py）。
DEFAULT_JUDGE_BATCH = 50


def judge_batch() -> int:
    return resolve_int_env("PAGENT_JUDGE_BATCH", DEFAULT_JUDGE_BATCH, minimum=1)


# 判定池的并发上限。网关实测限流是 20，超了会 429（24 次重试把 judge 阶段从 281s 拉到 333s）。
DEFAULT_MAX_CONCURRENCY = 12


def max_concurrency() -> int:
    return resolve_int_env("PAGENT_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY, minimum=1)


# 单次调查的模型调用上限（超过就停止判定，未判定的边显式记成 unjudged）
DEFAULT_MAX_LLM_CALLS = 150


def max_llm_calls() -> int:
    return resolve_int_env("PAGENT_MAX_LLM_CALLS", DEFAULT_MAX_LLM_CALLS, minimum=1)
