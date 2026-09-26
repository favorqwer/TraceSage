"""第 3 层 语义判别：对每条边判断它是不是攻击活动（第一轮，模型调用点之一）。

本层不合并结论、不做复核、不写报告、不排除任何边；传输失败与输出不可解析由 `core/llm` 处理，
整批调用失败由编排器二分拆批重试。
"""

from .first_pass import JUDGE_SYSTEM, judge_first_pass

__all__ = ["JUDGE_SYSTEM", "judge_first_pass"]
