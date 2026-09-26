"""子进程口径（第 1 层内部）：主干名单，以及"只有和主干有过来往的子进程才跟着进"的把关。

## 为什么需要它

闭包引擎里"一个进程被收进来，它在门限之前派生出去的其它子进程也算上游"这条口径
（人工标注把"脚本在终点事件之前跑过的命令"整段算进攻击路径）会一层传一层：父进程带走全部
子进程，每个子进程又带走自己的子进程，最后把"祖先往下的整棵进程树"都收进来。实测六个场景：
收进来的进程里九成以上是从这个口子进来的，而"读过 / 写过同一个东西"这条真正的交付通道
只带进来个位数的进程。

## 口径（写死，没有开关）

1. **主干**：先用"完全不带子进程"的方式跑一遍闭包（同一份索引、同一套规则），得到的进程集合，
   再加上它们的**直接子进程**（那些派生边已经在闭包里、自己还没被展开的进程）。
   前一部分包含终点事件涉及的进程、它们的历史、沿派生边往上追到的祖先进程，以及通过"谁写过这个
   文件或通道"接上的其它进程；后一部分就是"同一个脚本跑过的其它命令"那一层——人工标注把这层
   整段算进攻击路径，所以它不能靠把关去筛。
2. **把关**：父进程在主干里 → 子进程无条件收；父进程不在主干里（即第二层起）→
   子进程只有在**和主干之间有过一次写-读配对**时才收：
   - 它**读**的东西，主干里的进程写过；或者
   - 它**写**的东西，主干里的进程读过。
   共享 / 虚拟通道（`core/edge_rules.py` 的判定表）不算——这些是多对多广播，两个进程都用过它
   不代表它们之间传过东西；连接建立类操作（connect / bind）也不算（它不传递内容）。
3. 把关放行进来的进程就是普通成员：正常展开、正常往下走；它自己的子进程同样按第 2 条判。

## 为什么跑两遍

把关需要一个**固定的参照名单**。如果改成"看此刻已经收进来的进程有没有和它配对"，结果就会依赖
处理顺序（同一份日志换个顺序可能跑出不同结果），破坏"可复现"这条不变式。跑第一遍就是为了把名单
定死：判据只看静态数据（主干名单 + 各进程自己的边），与遍历顺序无关。

## 判据的边界（刻意选的）

- 写-读配对**不看时间先后**：只问"这两个进程之间有没有过这条通道上的来往"。加上时间条件更严，
  但会把"主干写在前、子进程读在后"这种真正的内容链之外的情况也切掉，本次没做。
- 主干名单由第一遍算出：第一遍少算了某个主干进程时，把关只会**更严**（少放），不会放进噪音。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from ...core import edge_rules
from .closure import Event, GraphSource, run_closure
from .sources import SETUP_SYSCALLS

_WRITE_RELS = ("p2f", "p2n")

def _no_children(parent: str, child: str) -> bool:
    """只用于第一遍：任何子进程都不跟着进（于是收到的就是主干）。"""
    return False


def _object_edges(source: GraphSource, pid: str) -> Iterator[tuple[str, str]]:
    """这个进程读写过的对象端点 (关系类型, 对象键)。

    与闭包引擎同一份口径：共享 / 虚拟通道不算（多对多广播，两个进程都用过它不代表传过东西），
    连接建立类操作（connect / bind）也不算（它不传递内容）。
    """
    for rel, syscall, key, label in source.iter_object_edges(pid):
        if not key or syscall in SETUP_SYSCALLS:
            continue
        if label == "File" and edge_rules.shared_channel_label(key):
            continue
        yield rel, key


@dataclass
class SiblingGate:
    """子进程把关：主干里的进程可以无条件带走子进程，其余的要有一次写-读配对。

    `allows` 是给闭包引擎的回调（`child_allowed`）；判定结果缓存，每个子进程只查一次自己的边。
    """

    source: GraphSource
    heads: frozenset[str]
    written_objects: frozenset[str]      # 主干进程写过的对象
    read_objects: frozenset[str]         # 主干进程读过的对象
    spine_events: int = 0                # 第一遍收进来的事件数（报告用）
    _cache: dict[str, bool] = field(default_factory=dict, repr=False)
    checked: int = 0                     # 查过几个非主干的子进程
    linked: int = 0                      # 其中判为"有来往"的

    def allows(self, parent: str, child: str) -> bool:
        if parent in self.heads:
            return True
        cached = self._cache.get(child)
        if cached is not None:
            return cached
        self.checked += 1
        ok = self._has_link(child)
        self._cache[child] = ok
        if ok:
            self.linked += 1
        return ok

    def _has_link(self, child: str) -> bool:
        """它读的东西主干写过，或它写的东西主干读过。"""
        for rel, key in _object_edges(self.source, child):
            if rel in _WRITE_RELS:
                if key in self.read_objects:
                    return True
            elif key in self.written_objects:
                return True
        return False

    def stats(self) -> dict[str, Any]:
        return {"heads": len(self.heads), "written_objects": len(self.written_objects),
                "read_objects": len(self.read_objects), "spine_events": self.spine_events,
                "checked": self.checked, "linked": self.linked}


def build_gate(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
               log: Optional[Callable[[str], None]] = None) -> SiblingGate:
    """第一遍：跑"不带子进程"的闭包得到主干；再算出主干读写过的对象，造出把关。"""
    if log:
        log("[closure] 第一遍：定主干（不带子进程；这一遍的结果只用来做参照，不进报告）")
    spine = run_closure(source, seeds, poi_t0=poi_t0, log=log, child_allowed=_no_children)
    # 主干 = 第一遍里被展开过的进程 + 它们的直接子进程。
    # 不能只拿"被展开过的"：那会把"同一个脚本跑过的命令"这一层也拒在门外；
    # 也不能拿"闭包里出现过的全部进程号"：那只在派生边上出现、自己没被展开的进程就是这里要算的
    # 第一层子进程，取全部会把它们后面的层也一起放宽。
    heads = set(spine["expanded_processes"])
    heads |= {ev.pid for ev in spine["events"] if ev.rel == "p2p" and ev.pid not in heads}
    written: set[str] = set()
    read: set[str] = set()
    for pid in sorted(heads):
        for rel, key in _object_edges(source, pid):
            (written if rel in _WRITE_RELS else read).add(key)
    gate = SiblingGate(source=source, heads=frozenset(heads), written_objects=frozenset(written),
                       read_objects=frozenset(read), spine_events=len(spine["events"]))
    if log:
        log(f"[closure] 主干（第一遍，不带子进程）：进程 {len(heads)} 个 / 事件 {gate.spine_events} 条 / "
            f"主干写过 {len(written)} 个对象、读过 {len(read)} 个对象")
    return gate


def run_gated_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                      log: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """两遍跑完一条闭包：第一遍定主干，第二遍带把关。返回结果里多一项 `gate`（把关计数）。"""
    gate = build_gate(source, seeds, poi_t0=poi_t0, log=log)
    if log:
        log("[closure] 第二遍：带子进程把关（主干里无条件收，第二层起要有写-读配对）")
    result = run_closure(source, seeds, poi_t0=poi_t0, log=log, child_allowed=gate.allows)
    result["gate"] = gate.stats()
    if log:
        stats = result["stats"]
        log(f"[closure] 子进程把关：查过 {gate.checked} 个非主干的子进程，放行 {gate.linked} 个，"
            f"挡下 {stats['dropped'].get('sibling_not_linked', 0)} 条派生边")
    return result
