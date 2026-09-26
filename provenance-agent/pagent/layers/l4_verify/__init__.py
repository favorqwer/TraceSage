"""第 4 层 全局校验：复核不确定的边、看链条、出理由，把第一轮结论合并成最终结论。

**当前口径**：只复核"第一轮漏编号的边"与"置信度贴着阈值的边"，复核在同一批内进行（没有跨批
全局视角）。不变式：未判定不等于排除；争议边默认保留。模型调用点之一。

包内文件：`select.py`（复核目标选择）、`merge.py`（反向提问、结论合并、判定明细日志）。
"""

from .merge import REFUTE_SYSTEM, log_verdicts, verdict_log_record, verify
from .select import PASS2_MARGIN, select_targets

__all__ = ["PASS2_MARGIN", "REFUTE_SYSTEM", "log_verdicts", "select_targets",
           "verdict_log_record", "verify"]
