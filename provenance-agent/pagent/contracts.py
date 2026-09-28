"""层间契约：各层之间传递的数据结构（字段与含义）与共享的纯函数助手。

**数据结构**（各层仍用普通字典，字段名以本模块为准）：

- 边行（第 1 层输出，未折叠）：源与目标的内容和标签、关系类型、操作名、字节数、进入/退出时间、
  事件编号、归属进程的标识。
- 折叠边（第 1 层输出）：内容三元组 + 两端标签 + 实例数 + 累计字节 + 首末时间 + 全部事件编号 +
  归属进程的标识 + 来源进程集合。
- 进程身份摘要（判定层输出）：命令行原文、工作目录、来源（父进程与派生方式）、时间区间、边数。
- 判定条目（判定层输入/输出）：折叠边 + 批内编号（`E001` 形式）；边旁的“同进程前后活动”
  与“同一对象上的接触者”由渲染时从候选边现算，不进判定条目。
- 判定结论：是否相关、置信度、一句话理由、所属进程。

**本模块只放纯函数**（原先散在多个模块里各写一份的小助手）。
"""

from __future__ import annotations

from typing import Any


def triple(edge: dict[str, Any]) -> tuple[str, str, str]:
    """边的内容三元组（源、操作名、目标）——报告与评分口径的键。"""
    return (edge.get("src", ""), edge.get("syscall", ""), edge.get("dst", ""))


def short(text: Any, limit: int = 120) -> str:
    """一句话摘要：换行压成空格并截断。"""
    return str(text or "").replace("\n", " ")[:limit]


def rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数（省字符、也更利于模型比较先后）。"""
    try:
        t = int(value or 0)
    except (TypeError, ValueError):
        return "?"
    if not ref_t or not t:
        return str(t)
    return f"{(t - int(ref_t)) / 1e9:+.1f}s"


def conf(verdict: dict[str, Any]) -> float:
    """判定的置信度（缺失或非法按 0 处理）。"""
    try:
        return float(verdict.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def parse_verdicts(result: dict[str, Any], valid_ids: set[str]) -> tuple[dict[str, dict[str, Any]], int]:
    """按 **编号** 收判定（不是下标）：编号必须属于本批，重复/越界/缺失都计入 invalid。

    “是否相关”必须是布尔值：缺失或类型不对的结论计入 invalid（回到调用方就是未判定，
    不当成无关）。置信度缺失按 0 处理（有意设计，见 `l2_judge/decide.py`）。
    """
    verdicts: dict[str, dict[str, Any]] = {}
    invalid = 0
    for verdict in result.get("verdicts") or []:
        if not isinstance(verdict, dict):
            invalid += 1
            continue
        vid = str(verdict.get("id") or "").strip()
        if vid not in valid_ids or vid in verdicts:
            invalid += 1
            continue
        if not isinstance(verdict.get("is_relevant"), bool):
            invalid += 1
            continue
        verdicts[vid] = verdict
    return verdicts, invalid
