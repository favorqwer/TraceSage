"""第 1 层 结构可达与候选表：往回走算出反向闭包，输出期过滤，折叠成内容三元组。

判据只有两张表（都在 `pagent/rules/` 下），按后果使用：

- **顶点表**（`core/vertices.py`，`vertices.json`）：文件段三种角色（普通交付对象 / 系统提供的
  文件 / 非交付通道）、进程段三个类别（常驻系统进程 / shell / 普通命令）。闭包、输出期过滤
  共用这一份。
- **剔除表**（`core/edge_rules.py`，`filters.json`）：两种后果——影响往回走的在取边时剔，
  影响进候选表的在闭包之后剔。

本层各模块：

- `closure.py`：闭包引擎（三条因果规则、时间门限推进、逐类计数）。**不设任何条数上限**；
  语义口径全部写死，没有语义开关。影响往回走的判定在取边时完成，后果只有一档：命中就不收这条边，
  两端也不会被推进待考察清单。
- `siblings.py`：子进程把关（主干名单 +"和主干有过写-读配对才跟着进"）。对外只有一个入口
  （`run_gated_closure`），内部两遍（先定主干，再带把关）。
- `output_filter.py`：输出期过滤（闭包之后、折叠之前），一次遍历里同时判实例范围与例行活动。
- `fold.py`：折叠（紧接输出过滤之后，把重复的事件实例按内容三元组合并成一条）。**不做任何规则
  判定、也不删边**；它的输出就是候选表。
- `sources.py`：取边来源。正式流程读顶点-时间索引（`SnapshotReader`）；`DbSource`（数据库直查）
  作为参考实现保留，给单测与一次性对照用，两者必须给出完全相同的事件。
- `snapshot.py`：顶点-时间索引的格式、构建与失效判据（索引里不存规则判定结果）。
- `process_attributes.py`：进程静态属性（只用于判定时的进程身份摘要，不参与可达性计算）。
"""

from .closure import Event, GraphSource, run_closure
from .fold import CollapsedEdge, FoldResult, fold
from .sessions import (attach_session_activity, session_command_activity, session_overview,
                       session_tables)
from .siblings import SiblingGate, run_gated_closure
from .sources import DbSource, SnapshotReader, open_source
from .process_attributes import process_info
from .output_filter import filter_output_rows
from . import snapshot

__all__ = [
    "CollapsedEdge", "DbSource", "Event", "FoldResult", "GraphSource", "SiblingGate",
    "SnapshotReader", "attach_session_activity", "filter_output_rows", "fold", "open_source",
    "process_info", "run_closure", "run_gated_closure", "session_command_activity",
    "session_overview", "session_tables", "snapshot",
]
