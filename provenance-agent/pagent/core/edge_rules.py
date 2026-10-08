"""第 1 层剔除表：两种后果，各由一个函数判定（判据唯一来源 `rules/filters.json`）。

- **影响往回走**（`traversal_drop_code`）：取边时执行，命中就不收这条边。判据有两部分：
  1. 顶点表文件段（`core/vertices.py`）：写非交付通道的边不收；读"内核按进程号现生成的伪文件"
     的边不收（其余非交付通道的读边收但不展开，见 `sources.py`）；
  2. 表的 traversal 段：动态库读取、系统程序自我执行、系统例行文件读取。
  逐类计数进闭包统计的 `dropped`（编号：`r1` / `r2` / `prefilter` / `kernel_pid_file` /
  `nondelivery_write`）。
- **影响进候选表**（`output_drop_code`）：闭包后执行，命中就不进候选表。表的 output 段，
  类别组合两种形状——属主类别 + 对象类别 + 方向（read / write）、系统调用 + 对象类别；
  另一端是进程（派生边）时不做对象分类（类别是 `process`，表里没有覆盖它的一行）。
  逐类计数进输出过滤统计。

边的方向、两端标签与内容三元组见 `core/graph_facts.py`（只写一份）。
"""

from __future__ import annotations

import re

from . import graph_facts, rules, vertices

_FILTERS = rules.load("filters.json")
_TRAVERSAL = list(_FILTERS["traversal"])
_OUTPUT = list(_FILTERS["output"])

# --- 影响往回走：三条内容形状规则 ---
_R1 = re.compile(str(next(item["regex"] for item in _TRAVERSAL if item["shape"] == "read_regex")))
_R2_PREFIXES = tuple(str(prefix) for prefix in
                     next(item["prefixes"] for item in _TRAVERSAL if item["shape"] == "self_exec"))
_PREFILTER = [(str(item["label"]), tuple(str(pattern) for pattern in item["patterns"]))
              for item in _TRAVERSAL if item["shape"] == "read_contains"]

# 系统例行文件的快通道：所有子串合成一条正则，先看"一条都没中"（绝大多数情况走这里），
# 只有命中了才回落到逐条比对取理由标签。两者判据完全相同（都是子串出现），结论不变。
_PREFILTER_QUICK = re.compile(
    "|".join(re.escape(pattern) for _label, patterns in _PREFILTER for pattern in patterns))

# --- 影响进候选表：两类类别组合 ---
# “属主类别 + 对象类别”这一组必须写方向：read = 对象到进程（读）、write = 进程到对象（写）。
# 不写方向就会把写边一起卷进来（见 filters.json 的说明）。
_OUTPUT_DIRECTIONS = ("read", "write")
_OUTPUT_OWNER = [(str(item["code"]), str(item.get("direction") or ""), str(item["owner"]),
                  frozenset(str(x) for x in item["objects"]))
                 for item in _OUTPUT if item["shape"] == "owner_object"]
_OUTPUT_SYSCALL = [(str(item["code"]), frozenset(str(x) for x in item["syscalls"]),
                    frozenset(str(x) for x in item["objects"]))
                   for item in _OUTPUT if item["shape"] == "syscall_object"]
for _code, _direction, _owner, _objects in _OUTPUT_OWNER:
    if _direction not in _OUTPUT_DIRECTIONS:
        raise ValueError("filters.json 的 owner_object 条目缺少或写错 direction："
                         f"{_code}（{_direction!r}）")


def _object_role_code(rel: str, other: str) -> str:
    """对象角色这一半：写入非交付通道的边不收；读内核按进程号现生成的伪文件也不收。"""
    if graph_facts.other_label_of(rel) != "File":
        return ""
    record = vertices.file_role(other)
    if graph_facts.owner_is_source(rel):
        return "nondelivery_write" if record.role == "nondelivery" else ""
    if rel in graph_facts.CONSUMER_RELS:
        return "kernel_pid_file" if record.drop_reads else ""
    return ""


def _content_shape_code(src: str, syscall: str, dst: str, src_label: str) -> str:
    """内容形状这一半：动态库读取、系统程序自我执行、系统例行文件读取。"""
    if syscall == "read" and _R1.match(src):
        return "r1"
    if syscall == "execve" and src == dst and src.startswith(_R2_PREFIXES):
        return "r2"
    if syscall == "read" and src_label == "File" and _PREFILTER_QUICK.search(src):
        for _label, patterns in _PREFILTER:
            if any(pattern in src for pattern in patterns):
                return "prefilter"
    return ""


def traversal_drop_code(rel: str, syscall: str, owner: str, other: str) -> str:
    """影响往回走：这条边命中哪条"不可能通向终点事件"的判据；未命中返回空串。

    内容形状先判，再判顶点表文件段（与旧的计数口径一致：两条都命中时记在内容形状那一类）。
    """
    src, _syscall, dst, src_label = graph_facts.content_triple_of(rel, syscall, owner, other)
    code = _content_shape_code(src, syscall, dst, src_label)
    if code:
        return code
    return _object_role_code(rel, other)


def output_drop_code(process_id: str, other: str, syscall: str, rel: str) -> str:
    """影响进候选表：这条边命中哪类例行活动；未命中返回空串（编号就是计数键）。

    方向与两端类别由 `rel` 唯一决定（`core/graph_facts.py`），不另外传一份、免得两处口径分岔：
    - “属主类别 + 对象类别”那一组还要方向对上（read = 对象到进程、write = 进程到对象）：
      不比方向就会把写边一起剔掉；
    - 另一端是进程（派生边）时，它的类别是 `process`：进程不是对象，这张按对象类别写的表
      没有任何一行覆盖它，所以派生边不会被它命中。
    """
    obj_class = vertices.object_class(str(other or ""), graph_facts.other_label_of(rel))
    owner_class = vertices.process_class(str(process_id or ""))
    is_read = rel in graph_facts.CONSUMER_RELS
    for code, direction, owner, objects in _OUTPUT_OWNER:
        if (direction == "read") != is_read:
            continue
        if owner_class == owner and obj_class in objects:
            return code
    for code, syscalls, objects in _OUTPUT_SYSCALL:
        if syscall in syscalls and obj_class in objects:
            return code
    return ""
