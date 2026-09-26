"""结构性伪边、系统例行文件、共享通道的判定（横切）：第 1 层遍历期与第 2 层折叠/粗筛共用同一份判定。

四张规则表在 `pagent/rules/` 下：

- 动态库读取（`pseudo_edges.json` 的 `r1_regex`）：装载共享代码，不携带攻击者内容；
- 系统自带程序的自我执行（同文件的 `r2_prefixes`）：`src == dst` 的 execve；
- 系统例行文件读取（`prefilter.json`）：本地化/字符集、名字解析/服务配置；
- 共享 / 虚拟通道（`shared_channels.json`）：内容不是由图上某条写入边交付的那种文件顶点。

前三张是**边的判定**（只看内容三元组与源标签，与“这条边在第几层被看到”无关，所以两层必须调用同一个
函数：第 1 层在遍历期把边挡在闭包之外，第 2 层作为兜底逐条记理由）。最后一张是**顶点的判定**：
命中的文件顶点在第 1 层只收边、不再往回找写入者（见 `closure.py` 的规则说明与
`sources.py` 的两条来源），它不进第 2 层。

另有一份**只在第 2 层用**的表（`candidate_drops.json`，判据 `candidate_drop_reason`）：它在候选集
（交给模型逐条判断的那一堆内容三元组）里再去掉两类边——内核按进程现生成的伪文件（`/proc/<进程号>/`
下，被 `ps`、`ss`、`systemd` 这类工具成批例行读取），与写进共享 / 虚拟通道的边（内容流进一个永不
追溯的通道）。**这两类边在第 1 层照收**（它们是链上的真实操作，也可能把进程带进来），只是不进候选集。
"""

from __future__ import annotations

import re
from typing import Any

from . import rules

_PSEUDO = rules.load("pseudo_edges.json")
_R1_LIB = re.compile(_PSEUDO["r1_regex"])
_R2_PREFIXES = tuple(_PSEUDO["r2_prefixes"])
_PREFILTER = rules.load("prefilter.json")
_SHARED = rules.load("shared_channels.json")
_CANDIDATE = rules.load("candidate_drops.json")

# 候选集层面的两类剔除（只在第 2 层用）：内核按进程现生成的伪文件、写进共享 / 虚拟通道的边
_CANDIDATE_LABELS = {str(item["code"]): str(item["label"]) for item in _CANDIDATE["drops"]}
_CANDIDATE_REGEXES = {
    str(item["code"]): tuple(re.compile(pattern) for pattern in item.get("regexes") or ())
    for item in _CANDIDATE["drops"]}

# 共享 / 虚拟通道：先看终端（终端按普通文件处理），再看四类前缀
_SHARED_TERMINAL_PREFIXES = tuple(_SHARED["terminal_prefixes"])
_SHARED_CLASSES = tuple((str(item["label"]), tuple(item["prefixes"]))
                        for item in _SHARED["classes"])

# 建索引时要看的规则文件（内容一改，第 1 层索引快照就得重建）。
# `candidate_drops.json` 不在里面：它只在第 2 层用，索引里不存与它有关的任何标记。
_RULE_FILES = ("pseudo_edges.json", "prefilter.json", "shared_channels.json")

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


def candidate_drop_reason(edge: dict[str, Any]) -> str:
    """这条边要不要从**候选集**里去掉；要去掉则返回理由（中文），否则空串。

    **只在第 2 层折叠时调用**：第 1 层照收这些边（它们是链上的真实操作，也可能把进程带进来），
    只是没必要把每一条都交给模型判断。两类：

    1. 一端是内核按进程现生成的伪文件（`/proc/<进程号>/`、`/proc/self/` 下）：内容由内核当场生成，
       不是图上某条写入边交付的，而且被 `ps`、`ss`、`systemd` 这类工具成批例行读取；
    2. 进程**写进**共享 / 虚拟通道的边：内容流进一个永不追溯的通道（见 `shared_channel_label`），
       写出去就没有下文了。

    **读取共享通道的边不去掉**：它是链条上进程的输入（例如 `dd` 读 `/dev/urandom`）。
    """
    src = str(edge.get("src") or "")
    dst = str(edge.get("dst") or "")
    for key, label in ((src, edge.get("src_label")), (dst, edge.get("dst_label"))):
        if label != "File":
            continue
        for pattern in _CANDIDATE_REGEXES.get("kernel_pid_file", ()):
            if pattern.match(key):
                return _CANDIDATE_LABELS["kernel_pid_file"]
    if (edge.get("dst_label") == "File" and str(edge.get("rel") or "") in ("p2f", "p2n")
            and shared_channel_label(dst)):
        return _CANDIDATE_LABELS["shared_channel_write"]
    return ""


def shared_channel_label(path: str) -> str:
    """这个文件顶点属不属于共享 / 虚拟通道；属于则返回它属于哪一类（计数与报告用），否则空串。

    这是**顶点的判定**，不是边的判定：命中的顶点在第 1 层只收边、不再往回找写入者。
    判据只有路径前缀（终端列在 `terminal_prefixes` 里，按普通文件处理）。
    """
    if not path or path.startswith(_SHARED_TERMINAL_PREFIXES):
        return ""
    for label, prefixes in _SHARED_CLASSES:
        if path.startswith(prefixes):
            return label
    return ""


def is_shared_channel(path: str) -> bool:
    """是不是共享 / 虚拟通道（`shared_channel_label` 的布尔形式）。"""
    return bool(shared_channel_label(path))
