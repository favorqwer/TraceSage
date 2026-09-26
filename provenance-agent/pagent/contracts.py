"""层间契约：各层之间传递的数据结构（字段与含义）与共享的纯函数助手。

**数据结构**（各层仍用普通字典，字段名以本模块为准）：

- 步骤：步骤键、所属进程、时间区间、边数、管道组成员。
- 边行（第 1 层输出，未折叠）：源与目标的内容和标签、关系类型、操作名、字节数、进入/退出时间、
  事件编号、来源步骤键。
- 折叠边（第 2 层输出）：内容三元组 + 两端标签 + 实例数 + 累计字节 + 首末时间 + 全部事件编号 +
  所属步骤 + 来源成员。
- 步骤上下文（第 2 层输出）：命令行原文、工作目录、时间区间、规模、读/写文件清单、网络端点清单、
  系统调用分布、管道组各成员命令行。
- 判定条目（第 3 层输入/输出）：折叠边 + 所属步骤 + 批内编号（`E001` 形式）。
- 判定结论：是否相关、置信度、一句话理由、争议标记、两轮理由、所属步骤。

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


def conf(verdict: dict[str, Any]) -> float:
    """判定的置信度（缺失或非法按 0 处理）。"""
    try:
        return float(verdict.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def parse_verdicts(result: dict[str, Any], valid_ids: set[str]) -> tuple[dict[str, dict[str, Any]], int]:
    """按 **编号** 收判定（不是下标）：编号必须属于本批，重复/越界/缺失都计入 invalid。"""
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
        verdicts[vid] = verdict
    return verdicts, invalid
