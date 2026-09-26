"""第 1 层 结构可达：从终点事件出发，沿图上的连接关系往回走，算出**反向闭包**。

**事件**＝图上的一条边（两个端点、操作名、字节数、起止时刻）。**反向闭包**是"能沿三条声明的
因果规则走回终点事件"的全部事件（这套规则下的最小集合）。规则与推进方式写在 `closure.py` 的
模块说明里，逐条可核。

- `closure.py`：闭包引擎（因果规则、门限推进、统计、来源追踪）；语义口径全部写死，
  取值表 `Options` 里只剩一个诊断项（记录每条边是被哪个顶点带进来的）。
- `sources.py`：取边来源。正式流程固定读顶点-时间索引（`SnapshotReader`）；`DbSource`（数据库直查）
  只作为参考实现保留，给单测与一次性对照用，两者必须给出完全相同的事件。
- `snapshot.py`：顶点-时间索引快照的格式、构建与失效判据。
- `steps.py`：步骤定义（一个步骤 = 一个进程实例，**只用于渲染上下文**，不参与可达性计算）。
- `queries.py`：与来源无关的通用查询（进程静态属性等）。

**不设任何条数上限**；闭包的终止条件是"待考察清单耗尽"。
"""

from .closure import Event, Options, run_closure, vkey
from .snapshot import build_snapshot, ensure_snapshot, read_meta, snapshot_dir
from .sources import DbSource, SnapshotReader, open_source
from .steps import (Step, cache_process_info, has_process_info, make_step_key, parse_step_key,
                    process_info)

__all__ = [
    "DbSource", "Event", "Options", "SnapshotReader", "Step", "build_snapshot", "cache_process_info",
    "ensure_snapshot", "has_process_info", "make_step_key", "open_source", "parse_step_key",
    "process_info", "read_meta", "run_closure", "snapshot_dir", "vkey",
]
