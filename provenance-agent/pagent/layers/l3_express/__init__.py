"""表达层：把结论写成人类可读的报告（纯代码，不做任何挑选，不决定召回与查准）。

当前口径：已确认边全部保留；叙述是确定性时间线；每条边必须有证据编号，
缺的回库按内容三元组补（只补证据，不改三元组）。

包内文件：`report.py`（报告装配）、`narrative.py`（叙述/入口点/自审）、
`evidence.py`（证据编号回填）。本包即当前第 3 层（表达层）。
"""

from .evidence import resolve_event_ids
from .report import build_report

__all__ = ["build_report", "resolve_event_ids"]
