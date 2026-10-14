"""层间契约：各层之间传递的数据结构（字段与含义）与共享的纯函数助手。

**数据结构**（各层仍用普通字典，字段名以本模块为准）：

- 边行（第 1 层输出，未折叠）：源与目标的内容和标签、关系类型、操作名、字节数、进入/退出时间、
  事件编号、归属进程的标识、离终点几跳、入闭包通道。
- 折叠边（第 1 层输出）：内容三元组 + 两端标签 + 实例数 + 累计字节 + 首末时间 + 全部事件编号 +
  归属进程的标识 + 来源进程集合 + 各实例按位合起来的入闭包通道 + 网络端点的传输层协议
  （渲染补出，不属于三元组）。
- 进程身份摘要（判定层输出）：命令行原文、工作目录、来源（父进程与派生方式）、时间区间、边数。
- 束条目（判定层的判定单位）：一批候选边 + 结构摘要（程序集合、关系类型、系统调用、对象类别、
  成员数、字节、首末时刻）+ 成员样本；字段见 `layers/l2_judge/items.py`。
- 束判定结论（判定层输入/输出）：四值之一——整束相关 / 整束无关 / 混杂 / 判不了；判「混杂」时
  附带一正一反两个成员编号（只用于排查，不参与任何判定）。模型多写的其它字段一律忽略。
- 来路（判定层输出）：每条候选边的归宿——`confirmed`（判整束相关）/ `kept`（未排除）/
  `excluded`（判整束无关）。**只有「整束无关」会删边**。

**本模块只放纯函数**（原先散在多个模块里各写一份的小助手）；唯一的例外是
`short()` 的默认截断长度从参数文件（`config/agent.toml` 的 `logging.text_limit`）取。
"""

from __future__ import annotations

from typing import Any

from .core import settings

# 束级四值判定：允许出现的结论（其余一律按「没给结论」处理）
BUNDLE_VERDICTS = ("all", "none", "mixed", "unknown")


def triple(edge: dict[str, Any]) -> tuple[str, str, str]:
    """边的内容三元组（源、操作名、目标）——报告与评分口径的键。"""
    return (edge.get("src", ""), edge.get("syscall", ""), edge.get("dst", ""))


def short(text: Any, limit: Any = None) -> str:
    """一句话摘要：换行压成空格并截断。

    `limit` 省略时用参数文件里的统一截断长度（`logging.text_limit`）：所有只进日志、
    审计文件、原始输出样本的截断都走这个默认值，调用处不再写数字。
    """
    if limit is None:
        limit = settings.log_text_limit()
    return str(text or "").replace("\n", " ")[:int(limit)]


def rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数（省字符、也更利于模型比较先后）。"""
    try:
        t = int(value or 0)
    except (TypeError, ValueError):
        return "?"
    if not ref_t or not t:
        return str(t)
    return f"{(t - int(ref_t)) / 1e9:+.1f}s"


def parse_bundle_verdicts(result: dict[str, Any], valid_ids: set[str]
                          ) -> tuple[dict[str, dict[str, Any]], int]:
    """按 **编号** 收束级结论（不是下标）：编号必须属于本批、结论必须是四值之一。

    重复/越界/缺失/结论不在四值里都计入 invalid——回到调用方就是「没给结论」，
    由调用方按「继续拆或保留」处理，**绝不当成无关**。
    """
    verdicts: dict[str, dict[str, Any]] = {}
    invalid = 0
    for row in result.get("verdicts") or []:
        if not isinstance(row, dict):
            invalid += 1
            continue
        bid = str(row.get("id") or "").strip()
        verdict = str(row.get("verdict") or "").strip().lower()
        if bid not in valid_ids or bid in verdicts or verdict not in BUNDLE_VERDICTS:
            invalid += 1
            continue
        verdicts[bid] = row
    return verdicts, invalid
