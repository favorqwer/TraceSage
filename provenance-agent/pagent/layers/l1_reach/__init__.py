"""第 1 层：从终点事件往回走出反向闭包，经「实例范围」筛选后折叠成内容三元组（= 候选表）。

流水线只有四步，各占一个模块：

1. `graph_index.py`：本地顶点-时间索引的格式、构建与失效判据（取数的前提，零数据库查询）。
2. `walk.py`：往回走的闭包引擎（`run_closure`）与取数来源（`SnapshotReader` / `open_source`）。
3. `judgments.py` + `table.py`：本层唯一的判据入口与判据表——对象角色 / 事件判定 /
   常驻服务进程（对整图算一次）/ 条目剔除，四条查询路径共用一份声明
   （`pagent/rules/l1_judgments.json`）。
4. `candidates.py`：划「同一次执行」的实例范围 → 折叠成内容三元组 → 条目剔除。

取边时不按规则剔边；会「少收」的地方只有两处：命中 `no_expand` 的对象（非交付通道）的读边
不往回找写入者，以及零字节的数据读取不再往下展开（两者都只影响是否继续往上找，边本身照样收）。
折叠之后还有两道**固定**的条目剔除（读无关进程的运行状态数值与属性文件、「全部实例都是零字节读」
的内容三元组，两者的终点事件实例均豁免），同样来自判据表。
"""

from .candidates import (CollapsedEdge, FoldResult, build_scope, filter_output_rows, fold)
from .judgments import (apply_item_drops, event_ruling, object_ruling, poi_event_ids,
                        resident_processes)
from .process_info import cache_process_info, prefetch_process_info, process_info
from .walk import Event, GraphSource, SnapshotReader, open_source, run_closure
from . import graph_index, judgments, table

__all__ = [
    "CollapsedEdge", "Event", "FoldResult", "GraphSource", "SnapshotReader",
    "apply_item_drops", "build_scope",
    "cache_process_info", "event_ruling", "filter_output_rows", "fold",
    "graph_index", "judgments", "object_ruling", "open_source", "poi_event_ids",
    "prefetch_process_info", "process_info", "resident_processes", "run_closure", "table",
]
