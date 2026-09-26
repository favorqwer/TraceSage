"""结构性伪边与系统例行文件的判定（横切）：第 1 层遍历期与第 2 层折叠/粗筛共用同一份判定。

三张规则表在 `pagent/rules/` 下：

- 动态库读取（`pseudo_edges.json` 的 `r1_regex`）：装载共享代码，不携带攻击者内容；
- 系统自带程序的自我执行（同文件的 `r2_prefixes`）：`src == dst` 的 execve；
- 系统例行文件读取（`prefilter.json`）：本地化/字符集、名字解析/服务配置。

判定只看内容三元组（源内容、操作名、目标内容）与源标签，**与"这条边在第几层被看到"无关**，
所以两层必须调用同一个函数：第 1 层在遍历期把边挡在闭包之外（连带它的另一端顶点也不扩展），
第 2 层作为兜底逐条记理由。同一批边在两层得到不同结论，就是缺陷。
"""

from __future__ import annotations

import re
from typing import Any

from . import rules

_PSEUDO = rules.load("pseudo_edges.json")
_R1_LIB = re.compile(_PSEUDO["r1_regex"])
_R2_PREFIXES = tuple(_PSEUDO["r2_prefixes"])
_PREFILTER = rules.load("prefilter.json")

# 建索引时要看的规则文件（内容一改，第 1 层索引快照就得重建）
_RULE_FILES = ("pseudo_edges.json", "prefilter.json")

# 规则编号 -> 给人读的理由（报告与统计里都用这一份，避免两处措辞不一致）
RULE_LABELS = {
    "r1": "动态库读取（装载共享代码，不携带内容）",
    "r2": "系统自带程序的自我执行",
}

# 规则编号 <-> 索引记录里的整型编码。第 1 层索引在建的时候就把"这条边命中哪条规则"算好写进
# 记录，遍历时只看这个整数，不再重算（`0` 就是不命中）。
RULE_CODE_OF = {"": 0, "r1": 1, "r2": 2, "prefilter": 3}
RULE_CODE_NAMES = {code: name for name, code in RULE_CODE_OF.items()}

# 系统例行文件读取的快通道：11 条子串合成一条正则，先看"一条都没中"（绝大多数情况走这里），
# 只有命中了才回落到逐条比对取理由标签。两者判据完全相同（都是子串出现），结论不变。
_PREFILTER_QUICK = re.compile(
    "|".join(re.escape(pattern) for rule in _PREFILTER for pattern in rule["patterns"]))


def rules_fingerprint() -> str:
    """参与本模块判定的规则表内容的校核值（第 1 层索引快照用它判自己是否过期）。"""
    return rules.fingerprint(_RULE_FILES)


def is_r1(src: str, syscall: str) -> bool:
    """动态库读取：`src` 是被读的文件路径（内容三元组的源）。"""
    return syscall == "read" and bool(_R1_LIB.match(src))


def is_r2(src: str, dst: str, syscall: str) -> bool:
    """系统自带程序的自我执行：执行事件的源与目标内容相同且落在系统目录前缀下。"""
    return syscall == "execve" and src == dst and src.startswith(_R2_PREFIXES)


def prefilter_reason(edge: dict[str, Any]) -> str:
    """系统例行文件读取的理由标签；不是"文件被读"这一类返回空串。"""
    if str(edge.get("syscall")) != "read" or edge.get("src_label") != "File":
        return ""
    path = str(edge.get("src") or "")
    if not _PREFILTER_QUICK.search(path):
        return ""                      # 快通道：一条子串都没出现（绝大多数情况）
    for rule in _PREFILTER:
        if any(pattern in path for pattern in rule["patterns"]):
            return str(rule["label"])
    return ""


def rule_of(src: str, syscall: str, dst: str, src_label: str = "") -> tuple[str, str]:
    """一条内容三元组命中的规则：返回（编号, 理由）；未命中返回两个空串。

    编号用于统计（`r1` / `r2` / `prefilter`），理由用于报告。
    """
    if is_r1(src, syscall):
        return "r1", RULE_LABELS["r1"]
    if is_r2(src, dst, syscall):
        return "r2", RULE_LABELS["r2"]
    reason = prefilter_reason({"syscall": syscall, "src_label": src_label, "src": src})
    if reason:
        return "prefilter", reason
    return "", ""
