"""图事件语义：关系类型、端点方向、内容三元组、入闭包通道位。

本文件只描述图上的事实（关系名、两端标签、归属端、通道位），不涉及取数、索引格式或判定。
其它模块需要这些事实时一律从这里导入，不再各自写一份。
"""
from __future__ import annotations

from typing import Any

# ==== 1. 边语义：关系类型唯一决定方向与两端标签 ====

RELATION_LABELS: dict[str, tuple[str, str]] = {
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
    "p2p": ("Process", "Process"),
}

ALL_RELS = tuple(RELATION_LABELS)
PRODUCER_RELS = ("p2f", "p2n")
CONSUMER_RELS = ("f2p", "n2p")
DERIVATION_REL = "p2p"

# 顶点类别（图里的三种顶点标签）。顺序即索引顶点表的写入顺序，改动会使旧索引失效。
VERTEX_KINDS = ("Process", "File", "Network")

# 场景配置里的 POI 种类 -> 图里的顶点标签（只此一份）
SCENARIO_KIND_LABELS = {"file": "File", "network": "Network"}

# 入闭包通道位：一条边是从哪一类顶点被收进闭包的（各实例按位或）。
CHANNEL_BITS = {"Process": 1, "File": 2, "Network": 4, "seed": 8}


def _full_name(rel: str) -> str:
    """短关系名 -> 图里的完整关系类型名（由两端标签唯一决定）。"""
    src, dst = RELATION_LABELS[rel]
    return f"{src}To{dst}"


# 完整关系名与短名的双向归一；Cypher 里同时接受两种写法。
REL_NORM: dict[str, str] = {rel: rel for rel in ALL_RELS}
REL_NORM.update({_full_name(rel): rel for rel in ALL_RELS})

REL_CYPHER: dict[str, str] = {rel: f"{_full_name(rel)}|{rel}" for rel in ALL_RELS}
REL_CYPHER.update({_full_name(rel): match for rel, match in REL_CYPHER.items()})


def normalize_rel(rel: str) -> str:
    return REL_NORM.get(rel, rel)


def cypher_rel_match(rel: str) -> str:
    return REL_CYPHER.get(rel, rel)


def labels_of(rel: str) -> tuple[str, str]:
    return RELATION_LABELS.get(normalize_rel(rel), ("Process", "Process"))


def owner_is_source(rel: str) -> bool:
    return normalize_rel(rel) in PRODUCER_RELS


def is_derivation(rel: str) -> bool:
    return normalize_rel(rel) == DERIVATION_REL


def content_triple_of(rel: str, syscall: str, owner: str, other: str,
                      ) -> tuple[str, str, str, str]:
    src_label, _dst_label = labels_of(rel)
    src, dst = (owner, other) if owner_is_source(rel) else (other, owner)
    return src, syscall, dst, src_label


def endpoints_of(rel: str, src: str, dst: str) -> tuple[str, str, str]:
    src_label, dst_label = labels_of(rel)
    if owner_is_source(rel):
        return src, dst, dst_label
    return dst, src, src_label


def edge_key(edge: dict[str, Any]) -> tuple[Any, Any, Any]:
    """边的内容三元组键（报告与评分口径）。"""
    return (edge.get("src"), edge.get("syscall"), edge.get("dst"))


def triple(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (edge.get("src", ""), edge.get("syscall", ""), edge.get("dst", ""))
