"""第 1 层 结构可达：从终点事件出发、沿因果规则往回走的**反向闭包**。

- `closure.py`：闭包引擎（三条因果规则、时间门限推进、逐类计数）。**不设任何条数上限**；
  语义口径全部写死，没有语义开关。五条结构式规则的**判定都在取边时完成**（同一个规则模块
  `core/edge_rules.py`），后果只有一档：命中就不收这条边，两端也不会被推进待考察清单。
- `fold.py`：折叠（紧接闭包之后，把重复的事件实例按内容三元组合并成一条）。**不做任何规则判定、
  也不删边**；它的输出就是候选表。
- `siblings.py`：子进程把关（主干名单 + "和主干有过写-读配对才跟着进"）。正式流程走两遍
  （`run_gated_closure`）；单测与对照可以走一遍（`run_closure`，不传把关 = 全收）。
- `sources.py`：取边来源。正式流程读顶点-时间索引（`SnapshotReader`）；`DbSource`（数据库直查）
  作为参考实现保留，给单测与一次性对照用，两者必须给出完全相同的事件。
- `snapshot.py`：顶点-时间索引的格式、构建与失效判据。
- `processes.py`：进程静态属性（只用于判定时的进程身份摘要，不参与可达性计算）。
"""

from .closure import Event, GraphSource, labels_of, run_closure
from .fold import CollapsedEdge, FoldResult, fold
from .siblings import SiblingGate, build_gate, run_gated_closure
from .sources import DbSource, SnapshotReader, open_source
from .processes import process_info
from . import snapshot

__all__ = [
    "CollapsedEdge", "DbSource", "Event", "FoldResult", "GraphSource", "SiblingGate",
    "SnapshotReader", "build_gate", "fold", "labels_of", "open_source",
    "process_info", "run_closure", "run_gated_closure",
]
