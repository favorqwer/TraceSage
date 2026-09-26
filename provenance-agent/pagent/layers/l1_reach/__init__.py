"""第 1 层 结构可达：从终点事件出发、沿因果规则往回走的**反向闭包**。

- `closure.py`：闭包引擎（三条因果规则、时间门限推进、逐类计数）。**不设任何条数上限**；
  语义口径全部写死，没有语义开关。
- `siblings.py`：子进程把关（主干名单 + "和主干有过写-读配对才跟着进"）。正式流程走两遍
  （`run_gated_closure`）；单测与对照可以走一遍（`run_closure`，不传把关 = 全收）。
- `sources.py`：取边来源。正式流程读顶点-时间索引（`SnapshotReader`）；`DbSource`（数据库直查）
  作为参考实现保留，给单测与一次性对照用，两者必须给出完全相同的事件。
- `snapshot.py`：顶点-时间索引的格式、构建与失效判据。
- `steps.py`：步骤定义与进程静态属性（只用于判定时的上下文渲染，不参与可达性计算）。
"""

from .closure import Event, GraphSource, run_closure
from .siblings import SiblingGate, build_gate, run_gated_closure
from .sources import DbSource, SnapshotReader, open_source
from .steps import Step, parse_step_key, process_info
from . import snapshot

__all__ = [
    "DbSource", "Event", "GraphSource", "SiblingGate", "SnapshotReader", "Step",
    "build_gate", "open_source", "parse_step_key", "process_info", "run_closure",
    "run_gated_closure",
]
