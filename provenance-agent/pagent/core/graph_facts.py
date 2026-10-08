"""边的形状事实：关系类型唯一决定方向与两端标签，内容三元组的投影只写这一份。

数据模型（六个库实测：每个关系类型恰好一种端点组合）：

    p2f  Process -> File        f2p  File -> Process
    p2n  Process -> Network     n2p  Network -> Process
    p2p  Process -> Process

"归属进程"（按归属规则拥有这条边的进程：写文件/网络归源进程，文件/网络被读写归目标进程，
进程派生归子进程）在内容三元组里是源端还是目标端，同样由关系类型决定（`owner_is_source`）：
只有把内容写进对象的 p2f / p2n 两类，归属进程在源侧。

闭包引擎、折叠、索引构建、判定层渲染都查这一份，不再各自传"另一端的标签"。
"""

from __future__ import annotations

# 关系类型 -> （源端标签, 目标端标签）
RELATION_LABELS: dict[str, tuple[str, str]] = {
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
    "p2p": ("Process", "Process"),
}

# 全部五类（查子句或查询分支用；顺序固定）
ALL_RELS = ("p2f", "f2p", "p2n", "n2p", "p2p")
# 归属进程在源侧（进程把内容写进对象）的两类
PRODUCER_RELS = ("p2f", "p2n")
# 归属进程在目标侧（对象被进程读写）的两类
CONSUMER_RELS = ("f2p", "n2p")
# 派生（父进程 -> 子进程，归属子进程）
DERIVATION_REL = "p2p"


def labels_of(rel: str) -> tuple[str, str]:
    """一条边的两端标签（源端, 目标端）。未知关系类型按 Process -> Process（与旧口径一致）。"""
    return RELATION_LABELS.get(rel, ("Process", "Process"))


def owner_is_source(rel: str) -> bool:
    """内容三元组的源端是不是"归属进程"那一端。"""
    return rel in PRODUCER_RELS


def is_derivation(rel: str) -> bool:
    """是不是派生边（父进程 → 子进程，归属子进程）。"""
    return rel == DERIVATION_REL


def other_label_of(rel: str) -> str:
    """"另一端"（非归属进程那一端）的标签：写对象的两类是目标端，其余是源端。"""
    src_label, dst_label = labels_of(rel)
    return dst_label if owner_is_source(rel) else src_label


def content_triple_of(rel: str, syscall: str, owner: str, other: str,
                      ) -> tuple[str, str, str, str]:
    """(源内容, 操作名, 目标内容, 源标签)。

    `owner` 是按归属规则拥有这条边的进程，`other` 是另一端；方向由 `rel` 唯一决定。
    """
    src_label, _dst_label = labels_of(rel)
    src, dst = (owner, other) if owner_is_source(rel) else (other, owner)
    return src, syscall, dst, src_label


def endpoints_of(rel: str, src: str, dst: str) -> tuple[str, str, str]:
    """从内容三元组视角反推 (归属进程, 另一端, 另一端标签)。"""
    src_label, dst_label = labels_of(rel)
    if owner_is_source(rel):
        return src, dst, dst_label
    return dst, src, src_label
