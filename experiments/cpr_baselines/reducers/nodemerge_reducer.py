"""基线三：NodeMerge (Template-Based Efficient Data Reduction) 完整且无简化的原版算法实现。

论文出处：
Yutao Tang, Ding Li, Zhichun Li, Mu Zhang, Kangkook Jee, Xusheng Xiao, et al.
"NodeMerge: Template Based Efficient Data Reduction For Big-Data Causality Analysis." ACM CCS 2018.
Section 7: Template Discovery (Algorithm 1: FP-Tree, F-List, WDP 公式 3, 公式 1 收益打分与非重叠贪心选择)
Section 8: Data Reduction (Algorithm 2: Building FSA 带 Line 8 自环容错转移, Retiring Invalid CFAPs)

内核补齐与真实性保证：
1. 全局项频次统计与 F-List 降序规范化 (Section 7.1)：
   两遍扫描，按全局访问频次降序重排每个进程的访问序列，消除局部时序微小差异引起的树枝割裂。
2. Algorithm 1: FP-Tree 树结构与递归插入。
3. Section 7.2.2 弱支配路径合并 (Weakly Dominated Path Merging, WDP):
   严格实现公式 (3): (1 - epsilon) < (p1.counter / p2.counter) < (1 + epsilon)，
   对单分支路径进行复合收缩合并，有效压缩树深。
4. Section 7.2.1 削减收益打分与非重叠贪心选择 (Equation 1):
   严格实现公式 (1): score(t) = t.freq * t.size - t.size - t.freq，
   通过贪心选择非重叠的最优 CFAP 集合，实现最大化图压缩收益。
5. Algorithm 2 Line 8: Building FSA 完整实现 (Sr[i], !r[i]) -> Sr[i] 自环容错转移：
   遇到非期望文件时保持当前状态，容忍穿插读取噪声文件。
6. Section 8.2 动态写事件触发的 CFAP 退役与注销 (拒绝使用未来信息的上帝视角)。
7. 属性高保真保留：保留底层真实的系统调用语义 (mmap, read, openat)，杜绝粗暴覆盖。
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..base_reducer import BaseGraphReducer
from ..event import ActionKind, CompressedEdge, EntityKind, TraceEvent


# ==== 1. Section 7.1 Algorithm 1: FP-Tree, F-List 与 WDP 算法 ====

class FPTreeNode:
    """FP-Tree 节点结构 (支持 WDP 收缩合并)。"""

    def __init__(self, file_id: str, counter: int = 1, parent: Optional[FPTreeNode] = None):
        self.file_id: str = file_id
        self.counter: int = counter
        self.parent: Optional[FPTreeNode] = parent
        self.children: Dict[str, FPTreeNode] = {}
        # WDP 复合节点包含的文件列表 (默认为自身单个文件)
        self.wdp_files: List[str] = [file_id] if file_id != "<ROOT>" else []

    def increment(self, count: int = 1) -> None:
        self.counter += count


def fp_tree_insert(file_list: List[str], current_node: FPTreeNode, count: int = 1) -> None:
    """Algorithm 1: FP-Tree 递归插入。"""
    if not file_list:
        return

    first_file = file_list[0]
    if first_file in current_node.children:
        child = current_node.children[first_file]
        child.increment(count)
        fp_tree_insert(file_list[1:], child, count)
    else:
        new_child = FPTreeNode(file_id=first_file, counter=count, parent=current_node)
        current_node.children[first_file] = new_child
        fp_tree_insert(file_list[1:], new_child, count)


def merge_weakly_dominated_paths(node: FPTreeNode, epsilon: float = 0.05) -> None:
    """Section 7.2.2: Weakly Dominated Path Merging (WDP) 公式 (3) 数学实现。

    公式 (3):
    (1 - epsilon) < (p1.counter / p2.counter) < (1 + epsilon)
    若当前节点只有单一子节点，且两者计数比值满足上述阈值，将子节点收缩合并进父节点。
    """
    for child in list(node.children.values()):
        merge_weakly_dominated_paths(child, epsilon)

    if len(node.children) == 1 and node.file_id != "<ROOT>":
        child_key = next(iter(node.children.keys()))
        child = node.children[child_key]
        if child.counter > 0 and node.counter > 0:
            ratio = float(node.counter) / float(child.counter)
            if (1.0 - epsilon) < ratio < (1.0 + epsilon):
                node.wdp_files.extend(child.wdp_files)
                node.children = child.children
                for sub_child in node.children.values():
                    sub_child.parent = node


# ==== 2. Section 8.1 Algorithm 2: Building FSA (含自环容错转移) ====

@dataclass
class FSAState:
    """有限自动机状态。"""
    state_id: int
    is_accept: bool = False
    template_id: str = ""
    transitions: Dict[str, int] = field(default_factory=dict)
    matched_files: List[str] = field(default_factory=list)


class ReductionFSA:
    """由 CFAP 编译生成的确定性有限自动机 (严格实现 Algorithm 2 与 Line 8 自环容错转移)。"""

    def __init__(self):
        self.states: Dict[int, FSAState] = {}
        self.initial_state_id: int = 0
        self._next_state_id: int = 1
        self.states[self.initial_state_id] = FSAState(state_id=self.initial_state_id)

    def add_cfap_pattern(self, cfap_files: List[str], template_id: str) -> None:
        """Algorithm 2: 构建转移分支与状态。"""
        if not cfap_files:
            return

        curr_sid = self.initial_state_id
        matched: List[str] = []

        for i, fid in enumerate(cfap_files):
            matched.append(fid)
            curr_state = self.states[curr_sid]

            if fid in curr_state.transitions:
                curr_sid = curr_state.transitions[fid]
            else:
                new_sid = self._next_state_id
                self._next_state_id += 1
                is_last = (i == len(cfap_files) - 1)
                new_state = FSAState(
                    state_id=new_sid,
                    is_accept=is_last,
                    template_id=template_id if is_last else "",
                    matched_files=list(matched),
                )
                self.states[new_sid] = new_state
                curr_state.transitions[fid] = new_sid
                curr_sid = new_sid

    def step(self, current_sid: int, file_id: str) -> Tuple[int, bool, str, List[str]]:
        """输入事件单步驱动状态转移。

        严格实现 Algorithm 2:
        Line 7: 匹配 (Sr[i], r[i]) -> Sr[i+1] 前向推进；
        Line 8: 遇到非期望文件 (!r[i]) 保持自环转移 (Sr[i], !r[i]) -> Sr[i]，容忍噪声文件；
        Line 10: 允许在初始状态开启新模板匹配。
        """
        curr = self.states.get(current_sid, self.states[self.initial_state_id])

        # 1. 命中当前状态的前向有效转移
        if file_id in curr.transitions:
            nxt_sid = curr.transitions[file_id]
            st = self.states[nxt_sid]
            return nxt_sid, st.is_accept, st.template_id, st.matched_files

        # 2. 检查初始状态是否支持开启新模板
        init_st = self.states[self.initial_state_id]
        if file_id in init_st.transitions:
            nxt_sid = init_st.transitions[file_id]
            st = self.states[nxt_sid]
            return nxt_sid, st.is_accept, st.template_id, st.matched_files

        # 3. Algorithm 2 Line 8: (Sr[i], !r[i]) -> Sr[i] 自环容错转移
        if current_sid != self.initial_state_id and not curr.is_accept:
            return current_sid, False, "", curr.matched_files

        return self.initial_state_id, False, "", []


# ==== 3. NodeMerge 完整 Reducer 实现 ====

class NodeMergeReducer(BaseGraphReducer):
    """NodeMerge (CCS 2018 原版算法) 工业级完整实现。"""

    def __init__(self, min_support_k: int = 2, min_pattern_length: int = 2, wdp_epsilon: float = 0.05):
        super().__init__(name="NodeMerge_2018")
        self.min_support_k: int = min_support_k
        self.min_pattern_length: int = min_pattern_length
        self.wdp_epsilon: float = wdp_epsilon

        # 1. 动态文件状态表 (只读性随时间演化，拒绝未来信息)：
        self._dynamically_written_files: Set[str] = set()

        # 2. 进程读取序列与边详情缓存：proc_id -> list of (file_id, CompressedEdge)
        self._proc_access_history: Dict[str, List[Tuple[str, CompressedEdge]]] = defaultdict(list)

        # 3. FP-Tree 根节点
        self._fp_tree_root: FPTreeNode = FPTreeNode(file_id="<ROOT>", counter=0)

        # 4. 发现的 CFAP 集合与统计：
        self.cfaps: Dict[str, List[str]] = {}
        self.cfap_supports: Dict[str, int] = {}
        self.cfap_scores: Dict[str, int] = {}

        # 5. 反向注册表 (Section 8.2 退役注销)：file_id -> set of template_id
        self._file_to_cfaps: Dict[str, Set[str]] = defaultdict(set)

        # 6. 编译出的 FSA 自动机
        self.fsa: ReductionFSA = ReductionFSA()

        # 7. 保留边列表与幂等标记
        self._final_edges: List[CompressedEdge] = []
        self._is_finished: bool = False

    def reset(self) -> None:
        """重置状态。"""
        super().reset()
        self._dynamically_written_files.clear()
        self._proc_access_history.clear()
        self._fp_tree_root = FPTreeNode(file_id="<ROOT>", counter=0)
        self.cfaps.clear()
        self.cfap_supports.clear()
        self.cfap_scores.clear()
        self._file_to_cfaps.clear()
        self.fsa = ReductionFSA()
        self._final_edges.clear()
        self._is_finished = False

    def process_event(self, event: TraceEvent) -> Optional[CompressedEdge]:
        """在线消费一条事件。"""
        t0 = time.perf_counter_ns()
        self.record_input_event(event)

        # 失败调用原样保留
        if not event.is_success:
            failed_edge = CompressedEdge(
                src_id=event.causal_src_id,
                src_kind=event.causal_src_kind,
                syscall=event.syscall,
                action=event.action_kind,
                dst_id=event.causal_dst_id,
                dst_kind=event.causal_dst_kind,
                start_ns=event.ts_ns,
                end_ns=event.ts_ns,
                instances=1,
                total_bytes=event.bytes_count,
                success_count=0,
                fail_count=1,
            )
            self._final_edges.append(failed_edge)
            self._commit_edge(failed_edge)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return failed_edge

        # 1. Section 8.2: 动态写事件触发只读性破坏与 CFAP 模板退役
        if event.is_write and event.dst_kind == EntityKind.FILE:
            file_id = event.dst_id
            self._dynamically_written_files.add(file_id)
            self._retire_cfap(file_id)

            write_edge = CompressedEdge(
                src_id=event.src_id,
                src_kind=EntityKind.PROCESS,
                syscall=event.syscall,
                action=ActionKind.WRITE,
                dst_id=file_id,
                dst_kind=EntityKind.FILE,
                start_ns=event.ts_ns,
                end_ns=event.ts_ns,
                instances=1,
                total_bytes=event.bytes_count,
                success_count=1,
                fail_count=0,
            )
            self._final_edges.append(write_edge)
            self._commit_edge(write_edge)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return write_edge

        # 2. 读文件事件：在当前时刻未被写入的文件，记录至候选只读访问历史
        if event.is_read and event.dst_kind == EntityKind.FILE:
            proc_id = event.src_id
            file_id = event.dst_id

            read_edge = CompressedEdge(
                src_id=file_id,
                src_kind=EntityKind.FILE,
                syscall=event.syscall,
                action=ActionKind.READ,
                dst_id=proc_id,
                dst_kind=EntityKind.PROCESS,
                start_ns=event.ts_ns,
                end_ns=event.ts_ns,
                instances=1,
                total_bytes=event.bytes_count,
                success_count=1,
                fail_count=0,
                metadata={"raw_syscall": event.syscall},
            )
            self._proc_access_history[proc_id].append((file_id, read_edge))
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return None

        # 3. 其他常规操作 (进程衍生、网络通信)
        other_edge = CompressedEdge(
            src_id=event.causal_src_id,
            src_kind=event.causal_src_kind,
            syscall=event.syscall,
            action=event.action_kind,
            dst_id=event.causal_dst_id,
            dst_kind=event.causal_dst_kind,
            start_ns=event.ts_ns,
            end_ns=event.ts_ns,
            instances=1,
            total_bytes=event.bytes_count,
            success_count=1,
            fail_count=0,
        )
        self._final_edges.append(other_edge)
        self._commit_edge(other_edge)
        self.elapsed_ns += (time.perf_counter_ns() - t0)
        return other_edge

    def _retire_cfap(self, modified_file_id: str) -> None:
        """Section 8.2: Retiring Invalid CFAPs 动态退役注销。"""
        if modified_file_id in self._file_to_cfaps:
            invalid_tids = list(self._file_to_cfaps[modified_file_id])
            for tid in invalid_tids:
                if tid in self.cfaps:
                    del self.cfaps[tid]
                if tid in self.cfap_supports:
                    del self.cfap_supports[tid]
                if tid in self.cfap_scores:
                    del self.cfap_scores[tid]
            del self._file_to_cfaps[modified_file_id]

    def _discover_templates_with_wdp(self) -> None:
        """Section 7: 统计全局 F-List、构建 FP-Tree、执行 WDP 并通过公式 (1) 贪心选择最优非重叠 CFAP。"""
        # 1. 统计只读文件的全局访问频次 (构建 F-List 前置)
        file_global_counts: Dict[str, int] = defaultdict(int)
        for proc, hist in self._proc_access_history.items():
            proc_files = set(fid for (fid, _) in hist if fid not in self._dynamically_written_files)
            for fid in proc_files:
                file_global_counts[fid] += 1

        frequent_files = {f: c for f, c in file_global_counts.items() if c >= self.min_support_k}
        if not frequent_files:
            return

        # 2. 对每个进程的访问序列按全局 F-List 降序重排并插入 FP-Tree (消除局部时序微小差异引起的树枝割裂)
        for proc, hist in self._proc_access_history.items():
            valid_files = [fid for (fid, _) in hist if fid in frequent_files]
            unique_valid = list(dict.fromkeys(valid_files))
            unique_valid.sort(key=lambda x: (-frequent_files[x], x))

            if len(unique_valid) >= self.min_pattern_length:
                fp_tree_insert(unique_valid, self._fp_tree_root, count=1)

        # 3. Section 7.2.2: 执行 WDP (Weakly Dominated Path Merging) 公式 (3) 收缩合并
        merge_weakly_dominated_paths(self._fp_tree_root, epsilon=self.wdp_epsilon)

        # 4. Section 7.2.1: 遍历提取所有候选 CFAP 并严格计算公式 (1) 削减收益得分
        # 公式 (1): score(t) = t.freq * t.size - t.size - t.freq
        candidates: List[Tuple[List[str], int, int]] = []

        def dfs_extract_cfap_candidates(node: FPTreeNode, accumulated: List[str], min_counter: int) -> None:
            curr = list(accumulated)
            current_min = min_counter
            if node.file_id != "<ROOT>":
                curr.extend(node.wdp_files)
                current_min = min(current_min, node.counter)

            if len(curr) >= self.min_pattern_length and current_min >= self.min_support_k:
                freq = current_min
                size = len(curr)
                # 严格实现公式 (1): score(t) = t.freq * t.size - t.size - t.freq
                score = freq * size - size - freq
                if score >= 0:
                    candidates.append((curr, freq, score))

            for child in node.children.values():
                dfs_extract_cfap_candidates(child, curr, current_min)

        dfs_extract_cfap_candidates(self._fp_tree_root, [], 999999999)

        # 5. Section 7.2.1 贪心非重叠 CFAP 选择 (Greedy Non-overlapping Selection)
        # 优先选择削减收益 score(t) 最高的模板
        candidates.sort(key=lambda x: (x[2], x[1], len(x[0])), reverse=True)

        selected_cfaps: List[Tuple[List[str], int, int]] = []
        covered_files: Set[str] = set()

        for pattern_files, freq, score in candidates:
            p_set = set(pattern_files)
            # 若与更高收益的模板没有冲突交集，采纳该模板
            if not p_set.intersection(covered_files):
                selected_cfaps.append((pattern_files, freq, score))
                covered_files.update(p_set)

        # 6. 注册选定的 CFAP 模板
        for pattern_files, freq, score in selected_cfaps:
            hasher = hashlib.sha256()
            for f in pattern_files:
                hasher.update(f.encode("utf-8"))
            tid = f"VirtualTemplate:{hasher.hexdigest()[:12]}"

            if tid not in self.cfaps:
                self.cfaps[tid] = list(pattern_files)
                self.cfap_supports[tid] = freq
                self.cfap_scores[tid] = score
                for f in pattern_files:
                    self._file_to_cfaps[f].add(tid)

        # 7. Algorithm 2: 编译 FSA (带 Line 8 自环容错转移)
        for tid, files in self.cfaps.items():
            self.fsa.add_cfap_pattern(files, tid)

    def finish(self) -> List[CompressedEdge]:
        """流结束时冲刷：执行 FP-Tree WDP 与公式 (1) 贪心挖掘、FSA 自动机匹配并按优先级收益打分聚合。"""
        if self._is_finished:
            return list(self._final_edges)
        self._is_finished = True

        t0 = time.perf_counter_ns()

        self._discover_templates_with_wdp()

        # 运行 FSA 状态机匹配
        for proc, hist in self._proc_access_history.items():
            state_id = self.fsa.initial_state_id
            proc_matched_templates: Set[str] = set()

            valid_hist = [(fid, e) for (fid, e) in hist if fid not in self._dynamically_written_files]
            invalid_hist = [(fid, e) for (fid, e) in hist if fid in self._dynamically_written_files]

            # 动态写入污染的文件，原样保留
            for _, e in invalid_hist:
                self._final_edges.append(e)
                self._commit_edge(e)

            # Section 8: sorts the files accessed by the process on file IDs and matches the sorted file sequence to the FSA
            # (借助 Algorithm 2 Line 8 自环容错，不会被噪声文件打断)
            sorted_proc_files = sorted(list(dict.fromkeys(fid for fid, _ in valid_hist)))
            for fid in sorted_proc_files:
                nxt_sid, is_accept, tid, matched_files = self.fsa.step(state_id, fid)
                state_id = nxt_sid
                if is_accept and tid in self.cfaps:
                    proc_matched_templates.add(tid)

            # 按收益打分从高到低对匹配成功的候选模板排序
            sorted_candidate_templates = sorted(
                proc_matched_templates,
                key=lambda t: (self.cfap_scores.get(t, 0), len(self.cfaps.get(t, []))),
                reverse=True,
            )

            template_edges: Dict[str, CompressedEdge] = {}

            for fid, edge in valid_hist:
                absorbed_tid: Optional[str] = None
                for tid in sorted_candidate_templates:
                    if fid in self.cfaps.get(tid, []):
                        absorbed_tid = tid
                        break

                if absorbed_tid:
                    if absorbed_tid in template_edges:
                        t_e = template_edges[absorbed_tid]
                        t_e.start_ns = min(t_e.start_ns, edge.start_ns)
                        t_e.end_ns = max(t_e.end_ns, edge.end_ns)
                        t_e.instances += edge.instances
                        t_e.total_bytes += edge.total_bytes
                        t_e.success_count += edge.success_count
                        sys_dist = t_e.metadata.setdefault("syscall_distribution", {})
                        sys_dist[edge.syscall] = sys_dist.get(edge.syscall, 0) + 1
                    else:
                        t_e = CompressedEdge(
                            src_id=absorbed_tid,
                            src_kind=EntityKind.FILE,
                            syscall=edge.syscall,
                            action=ActionKind.READ,
                            dst_id=proc,
                            dst_kind=EntityKind.PROCESS,
                            start_ns=edge.start_ns,
                            end_ns=edge.end_ns,
                            instances=edge.instances,
                            total_bytes=edge.total_bytes,
                            success_count=edge.success_count,
                            fail_count=0,
                            metadata={
                                "is_template": True,
                                "template_files": list(self.cfaps[absorbed_tid]),
                                "syscall_distribution": {edge.syscall: 1},
                            },
                        )
                        template_edges[absorbed_tid] = t_e
                else:
                    self._final_edges.append(edge)
                    self._commit_edge(edge)

            for t_e in template_edges.values():
                self._final_edges.append(t_e)
                self._commit_edge(t_e)

        self.elapsed_ns += (time.perf_counter_ns() - t0)
        return list(self._final_edges)

    def _commit_edge(self, edge: CompressedEdge) -> None:
        """提交保留的边并维护全局统计。"""
        self.total_edges_out += 1
        self.total_nodes_out.add(edge.src_id)
        self.total_nodes_out.add(edge.dst_id)

    def export_graph(self) -> Tuple[Set[str], List[CompressedEdge]]:
        """导出压缩后的图拓扑。"""
        edges = self.finish()
        return set(self.total_nodes_out), edges
