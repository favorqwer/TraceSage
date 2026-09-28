"""判定层：把候选边按「离终点几跳」分成波，逐波切批投递判定，最后按阈值定结论。

本层是**原第 2 层（语义判别与上下文准备）与原第 3 层（全局校验）合并后的一个包**：模型调用只在
本层，职责顺序是「纯代码准备 → 逐波判定（调模型）→ 纯代码定结论（阈值）」。

- **上下文准备**（`context.py`，纯代码）：把闭包产出的事件行整理成每个进程的身份摘要
  （命令行、来源、活动时间范围）；必须在闭包刚跑完、事件行还在手上时调用；
- **波次与状态**（`waves.py`，纯代码为主）：按跳数分波、全局编号、按批大小切批（同一波的批共用
  冻结上下文并发投递）、双层滚动上下文——第 1 层「上游交接明细」（上层顶点上已判过的边）、
  第 2 层「调查状态摘要」（已确认链、本波工作面、相关顶点状态、计数，逐波更新）；
- **渲染**（`batching.py`，纯代码）：任务说明、状态摘要、进程身份表、本波边（每条带上游明细与
  同一对象接触者）；
- **第一轮判定**（`first_pass.py`，调模型）：每条边带全局编号、要求原样回抄；
- **定结论**（`decide.py`，纯代码）：相关且达到阈值 → 确认，否则排除；没给结论 → 未判定
  （不等于排除）；判定明细写审计日志。**没有第二轮复核**。

合并了包，**没有合并职责**：第一轮不排除任何边，排除这个决定只属于阈值；传输失败与输出不可解析
由 `core/llm` 处理，整批调用失败由编排器整批重试。
"""

from .batching import build_task_header, build_view_index, render
from .context import build_process_context
from .decide import decide_verdicts, log_verdicts, verdict_id, verdict_log_record
from .first_pass import JUDGE_SYSTEM, judge_first_pass
from .waves import JudgeState, chunk_wave, index_waves, make_waves, via_content

__all__ = ["JUDGE_SYSTEM", "JudgeState", "build_process_context", "build_task_header",
           "build_view_index", "chunk_wave", "decide_verdicts", "index_waves",
           "judge_first_pass", "log_verdicts", "make_waves", "render", "verdict_id",
           "verdict_log_record", "via_content"]
