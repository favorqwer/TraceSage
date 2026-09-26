"""第 2 层 压缩与准备：在不降低上限的前提下把图变小、把判断依据组织好、把批次装好。

三件事，规则都是固定的、可复现的：折叠（有损，压的是判定与报告的单位）、两类结构性伪边剔除
（恒开）、步骤摘要 + 确定性粗筛 + 切批 + 提示词渲染。粗筛是唯一会直接排除边的规则，单独核、
逐条记理由，不计入上限（上限口径 = 折叠与伪边剔除之后、粗筛之前的候选集）。

包内文件：`fold.py`（折叠与伪边剔除）、`summary.py`（步骤摘要）、`prefilter.py`（粗筛）、
`batching.py`（切批与提示词渲染）。
"""

from .batching import index_items, make_batches, render
from .fold import CollapsedEdge, FoldResult, fold, is_r1, is_r2
from .prefilter import prefilter_reason
from .summary import summarize

__all__ = [
    "CollapsedEdge", "FoldResult", "fold", "index_items", "is_r1", "is_r2", "make_batches",
    "prefilter_reason", "render", "summarize",
]
