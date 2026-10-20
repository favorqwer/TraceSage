"""第 1 层：从终点事件往回走出反向闭包，折叠成内容三元组（= 候选表）。

流水线只有三步，各占一个模块：

1. `graph_index.py`：本地顶点-时间索引的格式、构建与失效判据（取数的前提，零数据库查询）。
2. `walk.py`：往回走的闭包引擎（`run_closure`）与取数来源（`SnapshotReader` / `open_source`）；
   来源另有「前向取边」入口（`reads_after`，供前向补链问「写下的对象后来被谁读走」）。
3. `judgments.py` + `table.py`：本层唯一的判据入口与判据表——对象角色 / 事件判定，
   两条查询路径共用一份声明（`foundation/rules/l1_judgments.json`）；`candidates.py`：折叠。

取边时不按规则剔边；会「少收」的地方只有两处：命中 `no_expand` 的对象（非交付通道）的读边
不往回找写入者，以及零字节的数据读取不再往下展开（两者都只影响是否继续往上找，边本身照样收）。
折叠只合并不删边：**本层没有任何尾部裁剪，闭包收到什么就折叠出什么**。
"""

from .candidates import CollapsedEdge, FoldResult, fold, fold_records
from .judgments import event_ruling, is_forward_carrier, is_startup_dependency, object_ruling
from .process_info import cache_process_info, prefetch_process_info, process_info
from .walk import (
    CHANNEL_BITS,
    Event,
    GraphSource,
    SnapshotReader,
    find_forward_seeds,
    open_source,
    run_causal_closure,
    run_closure,
)
from . import graph_index, judgments, table

__all__ = [
    "CHANNEL_BITS", "CollapsedEdge", "Event", "FoldResult", "GraphSource", "SnapshotReader",
    "cache_process_info", "event_ruling", "find_forward_seeds", "fold", "fold_records",
    "graph_index", "is_forward_carrier", "is_startup_dependency", "judgments", "object_ruling",
    "open_source", "prefetch_process_info", "process_info", "run_causal_closure", "run_closure", "table",
]
