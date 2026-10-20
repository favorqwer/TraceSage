"""判定层：把候选表打成「束」，逐级四值判定，最后按「只有整束无关删边」定来路。

本层是模型调用唯一发生的地方，职责顺序是「纯代码准备 → 束级判定（调模型）→ 纯代码定来路」。

模块构成：
- `bundles.py`：五级细分键、划分不变式校验、样本确定性采样、条目装配与同类规模统计；
- `guards.py`：四道结构闸门（空拆/扇出/一致性/凭证/叶子）与调查状态滚动记忆；
- `judge.py`：提示词渲染、批头共享表生成、模型并发通信与三段来路映射；
- `context.py`：进程身份摘要提取。
"""

from .bundles import (
    CHANNEL_BITS,
    LEVEL_NAMES,
    LevelKey,
    build_items,
    build_levels,
    build_scale_index,
    channel_class,
    check_partition,
    dir_class,
    level_members,
    object_side,
    program_of,
    program_table,
    sample_members,
    scale_stats,
    sort_text,
)
from .context import build_process_context, summarize_process
from .guards import (
    BundleState,
    anchor_facts,
    fanout_split,
    hot_guard,
    is_leaf,
    vacuous_ids,
    warrant_guard,
)
from .judge import (
    AGG_NOTE,
    BUNDLE_SYSTEM,
    TIERS,
    VERDICT_TEXT,
    build_task_header,
    edge_line,
    fmt_bytes,
    judge_bundles,
    level_name,
    render,
    run_batches,
    tier_of,
)

# 兼容性别名（平滑兼容历史单测对旧拆分模块的导入）
from . import bundles as items
from . import guards as state
from . import judge as outcome
from . import judge as rendering

__all__ = [
    "AGG_NOTE",
    "BUNDLE_SYSTEM",
    "BundleState",
    "CHANNEL_BITS",
    "LEVEL_NAMES",
    "LevelKey",
    "TIERS",
    "VERDICT_TEXT",
    "anchor_facts",
    "build_items",
    "build_levels",
    "build_process_context",
    "build_scale_index",
    "build_task_header",
    "channel_class",
    "check_partition",
    "dir_class",
    "edge_line",
    "fanout_split",
    "fmt_bytes",
    "hot_guard",
    "is_leaf",
    "items",
    "judge_bundles",
    "level_members",
    "level_name",
    "object_side",
    "outcome",
    "program_of",
    "program_table",
    "render",
    "rendering",
    "run_batches",
    "sample_members",
    "scale_stats",
    "sort_text",
    "state",
    "summarize_process",
    "tier_of",
    "vacuous_ids",
    "warrant_guard",
]
