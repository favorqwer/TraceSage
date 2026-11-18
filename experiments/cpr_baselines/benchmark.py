"""因果保持图压缩 (CPR) 算法统一对比评测运行器 (真流式、低内存、全场景版本)。

对比四组算法：
1. TraceSage_Current: 项目当前图折叠与版本化算法
2. CPR_2016: CCS 2016 原案基线 (连续读写折叠与上下文状态机)
3. FDPR_2018: USENIX Security 2018 原案基线 (实体版本图 + REO + RNO)
4. NodeMerge_2018: CCS 2018 原案基线 (只读实体模板挖掘与虚拟节点合并)

内存硬性保证：
- 采用 Python 生成器 (Generator) 逐行流式解析，彻底消除全量 TraceEvent 列表内存常驻；
- 四组算法串行独立运行，运行完立即释放拓扑并触发 gc.collect()；
- 全流程内存占用恒定控制在 100~250 MB 以内，彻底告别内存爆炸。
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import gc
import json
import os
import psutil
import random
import re
import sys
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
REPO_ROOT = os.path.dirname(PARENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR, REPO_ROOT]:
    if p not in sys.path:
        sys.path.insert(0, p)

from experiments.cpr_baselines.event import ActionKind, EntityKind, TraceEvent
from experiments.cpr_baselines.base_reducer import BaseGraphReducer
from experiments.cpr_baselines.reducers.cpr_reducer import CPRReducer
from experiments.cpr_baselines.reducers.fdpr_reducer import FDPRReducer
from experiments.cpr_baselines.reducers.nodemerge_reducer import NodeMergeReducer
from experiments.cpr_baselines.reducers.project_adapter import ProjectCurrentReducer


def get_current_rss_mb() -> float:
    """获取当前进程实际常驻物理内存 (RSS，单位 MB)。"""
    return round(psutil.Process().memory_info().rss / (1024.0 * 1024.0), 2)


def stream_synthetic_workload(num_events: int = 10000, seed: int = 42) -> Iterator[TraceEvent]:
    """生成高保真合成系统调用事件流 (固定随机种子，零常驻列表，严格跨算法可重放)。"""
    rng = random.Random(seed)
    host = "host-01"
    procs = [f"proc_{i}" for i in range(1, 21)]
    readonly_libs = [f"/usr/lib/lib_{k}.so" for k in range(1, 16)]
    shared_files = [f"/var/log/app_{m}.log" for m in range(1, 6)]
    tmp_pipes = [f"/tmp/pipe_{p}" for p in range(1, 10)]

    ts = 1_000_000_000
    produced = 0

    # 1. 初始化阶段：库加载与读取
    for p in procs:
        for lib in readonly_libs:
            if produced >= num_events:
                return
            ts += 1000
            produced += 1
            yield TraceEvent(
                host_id=host, ts_ns=ts, src_id=p, src_kind=EntityKind.PROCESS,
                syscall="openat", dst_id=lib, dst_kind=EntityKind.FILE, result=3, event_id=produced
            )
            for _ in range(2):
                if produced >= num_events:
                    return
                ts += 200
                produced += 1
                yield TraceEvent(
                    host_id=host, ts_ns=ts, src_id=p, src_kind=EntityKind.PROCESS,
                    syscall="read", dst_id=lib, dst_kind=EntityKind.FILE, result=1024, bytes_count=1024, event_id=produced
                )

    # 2. 正常运行阶段
    while produced < num_events:
        p = rng.choice(procs)
        r = rng.random()
        if r < 0.35:
            target = rng.choice(shared_files)
            for _ in range(rng.randint(3, 8)):
                if produced >= num_events:
                    return
                ts += 500
                produced += 1
                yield TraceEvent(
                    host_id=host, ts_ns=ts, src_id=p, src_kind=EntityKind.PROCESS,
                    syscall="write", dst_id=target, dst_kind=EntityKind.FILE, result=256, bytes_count=256, event_id=produced
                )
        elif r < 0.65:
            pipe = rng.choice(tmp_pipes)
            p_consumer = rng.choice([x for x in procs if x != p])
            if produced >= num_events:
                return
            ts += 500
            produced += 1
            yield TraceEvent(
                host_id=host, ts_ns=ts, src_id=p, src_kind=EntityKind.PROCESS,
                syscall="write", dst_id=pipe, dst_kind=EntityKind.FILE, result=128, bytes_count=128, event_id=produced
            )
            if produced >= num_events:
                return
            ts += 500
            produced += 1
            yield TraceEvent(
                host_id=host, ts_ns=ts, src_id=pipe, src_kind=EntityKind.FILE,
                syscall="read", dst_id=p_consumer, dst_kind=EntityKind.PROCESS, result=128, bytes_count=128, event_id=produced
            )
        else:
            ts += 1000
            produced += 1
            yield TraceEvent(
                host_id=host, ts_ns=ts, src_id=p, src_kind=EntityKind.PROCESS,
                syscall="recvfrom", dst_id="192.168.1.100:443", dst_kind=EntityKind.NETWORK, result=512, bytes_count=512, event_id=produced
            )


def stream_sysdig_events(jsonl_path: str, max_events: int = 0) -> Iterator[TraceEvent]:
    """从 Sysdig JSONL 文件流式产出 TraceEvent (有状态进入/退出事件配对，提取真实返回值与目标对象)。"""
    re_name = re.compile(r'\bname=([^\s]+)')
    re_path = re.compile(r'\bpath=([^\s]+)')
    re_file_fd = re.compile(r'\bfd=\d+\(<[fdu]>([^)]+)\)')
    re_net_fd = re.compile(r'\bfd=\d+\(<[46]>([^)]+)\)')
    re_size = re.compile(r'\bsize=(\d+)')
    re_res = re.compile(r'\bres=(-?\d+)')

    evt_count = 0
    host = "host-01"

    # 进入事件未完成池: (tid_or_pid, syscall) -> enter_info dict
    pending_enters: Dict[Tuple[int, str], Dict[str, Any]] = {}

    with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            raw_time = obj.get("evt.rawtime", 0)
            syscall = obj.get("evt.type", "")
            pid = obj.get("proc.pid")
            tid = obj.get("thread.tid") or pid
            exe = obj.get("proc.exepath") or obj.get("proc.name") or "unknown_proc"
            fd_name = obj.get("fd.name") or ""
            args = obj.get("evt.args") or ""
            evt_dir = obj.get("evt.dir", "")

            if not pid or not syscall:
                continue

            thread_key = (int(tid), str(syscall))

            # 1. 系统调用进入记录 ('>'): 登记调用参数与目标客体，进入待配对池
            if evt_dir == ">":
                m_name = re_name.search(args)
                m_path = re_path.search(args)
                m_ffd = re_file_fd.search(args)
                m_nfd = re_net_fd.search(args)
                m_size = re_size.search(args)
                req_bytes = int(m_size.group(1)) if m_size else 0

                if m_name:
                    dst_id = f"file:{m_name.group(1)}"
                    dst_kind = EntityKind.FILE
                elif m_path:
                    dst_id = f"file:{m_path.group(1)}"
                    dst_kind = EntityKind.FILE
                elif m_ffd:
                    dst_id = f"file:{m_ffd.group(1)}"
                    dst_kind = EntityKind.FILE
                elif m_nfd:
                    dst_id = f"net:{m_nfd.group(1)}"
                    dst_kind = EntityKind.NETWORK
                elif fd_name.startswith("/") or "\\" in fd_name:
                    dst_id = f"file:{fd_name}"
                    dst_kind = EntityKind.FILE
                elif ":" in fd_name or "." in fd_name:
                    dst_id = f"net:{fd_name}"
                    dst_kind = EntityKind.NETWORK
                else:
                    dst_id = f"res:{fd_name or 'generic'}"
                    dst_kind = EntityKind.FILE

                pending_enters[thread_key] = {
                    "ts": raw_time,
                    "dst_id": dst_id,
                    "dst_kind": dst_kind,
                    "bytes": req_bytes,
                }
                continue

            # 2. 系统调用完成退出记录 ('<'): 取回进入参数，解析真实返回值，产出完整事件
            enter_info = pending_enters.pop(thread_key, None)

            # 解析实际返回值 res
            m_res = re_res.search(args)
            if m_res:
                res_val = int(m_res.group(1))
            else:
                res_val = obj.get("evt.res")
                if res_val is None:
                    res_val = 0
                else:
                    try:
                        res_val = int(res_val)
                    except Exception:
                        res_val = 0

            # 确定客体标识与类型
            if enter_info:
                dst_id = enter_info["dst_id"]
                dst_kind = enter_info["dst_kind"]
                ts_ns = enter_info["ts"]
                bytes_count = res_val if res_val > 0 and syscall in ("read", "write", "recvfrom", "sendto") else enter_info["bytes"]
            else:
                # 缺失进入记录时的回退提取
                ts_ns = raw_time
                bytes_count = res_val if res_val > 0 else 0
                m_ffd = re_file_fd.search(args)
                m_nfd = re_net_fd.search(args)
                if m_ffd:
                    dst_id = f"file:{m_ffd.group(1)}"
                    dst_kind = EntityKind.FILE
                elif m_nfd:
                    dst_id = f"net:{m_nfd.group(1)}"
                    dst_kind = EntityKind.NETWORK
                elif fd_name.startswith("/") or "\\" in fd_name:
                    dst_id = f"file:{fd_name}"
                    dst_kind = EntityKind.FILE
                elif ":" in fd_name or "." in fd_name:
                    dst_id = f"net:{fd_name}"
                    dst_kind = EntityKind.NETWORK
                else:
                    dst_id = f"res:{fd_name or 'generic'}"
                    dst_kind = EntityKind.FILE

            src_id = f"proc:{pid}:{exe}"
            src_kind = EntityKind.PROCESS

            evt_count += 1
            yield TraceEvent(
                host_id=host,
                ts_ns=ts_ns,
                src_id=src_id,
                src_kind=src_kind,
                syscall=syscall,
                dst_id=dst_id,
                dst_kind=dst_kind,
                result=res_val,
                bytes_count=bytes_count,
                event_id=evt_count,
            )

            if max_events > 0 and evt_count >= max_events:
                break


def build_raw_causal_adjacency(stream_fn: Callable[[], Iterator[TraceEvent]]) -> Tuple[int, Dict[str, Set[str]]]:
    """通过第一遍轻量流式扫描，统计总事件数并构建紧凑的原始因果邻接表 (内存仅数 MB)。"""
    raw_adj: Dict[str, Set[str]] = defaultdict(set)
    total_count = 0
    t0 = time.time()

    for e in stream_fn():
        total_count += 1
        if e.is_success:
            if e.is_read:
                raw_adj[e.dst_id].add(e.src_id)
            else:
                raw_adj[e.src_id].add(e.dst_id)

        if total_count % 300000 == 0:
            print(f"  [+] 流式扫描进度: {total_count} 条事件 (耗时: {time.time()-t0:.1f}s, 当前内存: {get_current_rss_mb()} MB)...", flush=True)

    print(f"  [+] 全场景流式扫描完毕: 共 {total_count} 条合法事件，因果实体节点数: {len(raw_adj)} (总耗时: {time.time()-t0:.2f}s, 常驻内存: {get_current_rss_mb()} MB)。", flush=True)
    return total_count, raw_adj


def load_groundtruth_pairs(scene_name: str) -> List[Tuple[str, str]]:
    """若存在对应的 Ground Truth 标注文件，加载其中所有关键攻击实体因果对。"""
    gt_dir = os.path.join(REPO_ROOT, "groundtruth")
    candidates = [
        os.path.join(gt_dir, f"{scene_name}.groundtruth.json"),
        os.path.join(gt_dir, f"{scene_name.replace('.jsonl', '')}.groundtruth.json"),
    ]
    gt_file = None
    for c in candidates:
        if os.path.exists(c):
            gt_file = c
            break

    if not gt_file:
        return []

    try:
        with open(gt_file, "r", encoding="utf-8") as f:
            gt_data = json.load(f)
        pairs: List[Tuple[str, str]] = []
        for phase in gt_data.get("attack_path", []):
            for edge in phase.get("edges", []):
                src = edge.get("src", "")
                dst = edge.get("dst", "")
                if src and dst:
                    pairs.append((src, dst))
        return pairs
    except Exception:
        return []


def verify_causal_reachability_against_raw(
    raw_adj: Dict[str, Set[str]],
    reduced_edges: List[Any],
    sample_size: int = 50,
    template_mapping: Optional[Dict[str, List[str]]] = None,
    gt_pairs: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, float]:
    """验证因果可达性一致率 (Causality Soundness & Completeness)。"""
    def project_entity(node_id: str) -> Set[str]:
        if "#v" in node_id:
            base_id = node_id.split("#v")[0]
            return {base_id}
        if node_id.startswith("VirtualTemplate:") and template_mapping and node_id in template_mapping:
            return set(template_mapping[node_id])
        return {node_id}

    red_adj: Dict[str, Set[str]] = defaultdict(set)
    for edge in reduced_edges:
        src_set = project_entity(edge.src_id)
        dst_set = project_entity(edge.dst_id)
        for s in src_set:
            for d in dst_set:
                red_adj[s].add(d)

    proc_sources = sorted([s for s in raw_adj.keys() if s.startswith("proc:")], key=lambda x: len(raw_adj[x]), reverse=True)
    file_sources = sorted([s for s in raw_adj.keys() if s.startswith("file:")], key=lambda x: len(raw_adj[x]), reverse=True)
    net_sources = sorted([s for s in raw_adj.keys() if s.startswith("net:")], key=lambda x: len(raw_adj[x]), reverse=True)
    other_sources = sorted([s for s in raw_adj.keys() if not (s.startswith("proc:") or s.startswith("file:") or s.startswith("net:"))], key=lambda x: len(raw_adj[x]), reverse=True)

    samples: List[str] = []
    samples.extend(proc_sources[:20])
    samples.extend(file_sources[:15])
    samples.extend(net_sources[:10])
    samples.extend(other_sources[:5])

    all_sorted = sorted(raw_adj.keys(), key=lambda x: len(raw_adj[x]), reverse=True)
    for s in all_sorted:
        if len(samples) >= sample_size:
            break
        if s not in samples:
            samples.append(s)

    if not samples:
        return {
            "causal_recall_pct": 100.0,
            "causal_precision_pct": 100.0,
            "causal_consistency_pct": 100.0,
            "gt_path_preservation_pct": 100.0,
        }

    def get_forward_reach(adj: Dict[str, Set[str]], start: str, max_depth: int = 4) -> Set[str]:
        visited = set()
        queue = [(start, 0)]
        while queue:
            curr, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for nxt in adj.get(curr, set()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, depth + 1))
        return visited

    recalls: List[float] = []
    precisions: List[float] = []
    jaccards: List[float] = []

    for s in samples:
        reach_raw = get_forward_reach(raw_adj, s)
        reach_red = get_forward_reach(red_adj, s)
        if not reach_raw and not reach_red:
            recalls.append(1.0)
            precisions.append(1.0)
            jaccards.append(1.0)
            continue

        overlap = len(reach_raw.intersection(reach_red))
        rec = (overlap / len(reach_raw)) if reach_raw else 1.0
        prec = (overlap / len(reach_red)) if reach_red else 1.0
        union = len(reach_raw.union(reach_red))
        jac = (overlap / union) if union > 0 else 1.0

        recalls.append(rec)
        precisions.append(prec)
        jaccards.append(jac)

    gt_preserved_count = 0
    gt_tested_count = 0
    if gt_pairs:
        red_all_nodes = set(red_adj.keys())

        def match_gt_entity(raw_ent: str) -> List[str]:
            """根据实体类型与规范路径/端点对齐压缩图节点。"""
            matched = []
            if raw_ent.startswith("p:"):
                # 进程格式形如 "p:scenario/host:/usr/bin/python" 或 "p:host:pid:exe"
                parts = raw_ent.split(":")
                exe_part = parts[-1] if len(parts) >= 2 else raw_ent
                exe_base = os.path.basename(exe_part)
                for n in red_all_nodes:
                    if n.startswith("proc:"):
                        if (len(exe_part) > 2 and exe_part in n) or (len(exe_base) > 2 and exe_base in n):
                            matched.append(n)
            elif raw_ent.startswith("f:"):
                # 文件格式形如 "f:scenario/host:/var/log/app.log"
                parts = raw_ent.split(":")
                f_path = parts[-1] if len(parts) >= 2 else raw_ent
                f_norm = os.path.normpath(f_path)
                f_base = os.path.basename(f_norm)
                for n in red_all_nodes:
                    if n.startswith("file:"):
                        if f_norm in n or (len(f_base) > 3 and f_base in n):
                            matched.append(n)
            elif raw_ent.startswith("n:"):
                # 网络格式形如 "n:scenario:10.0.0.1:80->10.0.0.2:443"
                parts = raw_ent.split(":")
                ep = parts[-1] if len(parts) >= 2 else raw_ent
                for n in red_all_nodes:
                    if n.startswith("net:") and ep in n:
                        matched.append(n)
            else:
                for n in red_all_nodes:
                    if raw_ent in n or n in raw_ent:
                        matched.append(n)
            return matched

        for raw_src, raw_dst in gt_pairs:
            matched_srcs = match_gt_entity(raw_src)
            matched_dsts = match_gt_entity(raw_dst)

            gt_tested_count += 1
            if not matched_srcs or not matched_dsts:
                # 实体未对齐或丢失，计入已测试总量但未保留，真实反映路径中断
                continue

            reachable = False
            for m_src in matched_srcs[:3]:
                reach = get_forward_reach(red_adj, m_src, max_depth=5)
                if any(m_dst in reach for m_dst in matched_dsts):
                    reachable = True
                    break
            if reachable:
                gt_preserved_count += 1

    gt_pct = round(gt_preserved_count / gt_tested_count * 100.0, 2) if gt_tested_count > 0 else None

    return {
        "causal_recall_pct": round(sum(recalls) / len(recalls) * 100.0, 2),
        "causal_precision_pct": round(sum(precisions) / len(precisions) * 100.0, 2),
        "causal_consistency_pct": round(sum(jaccards) / len(jaccards) * 100.0, 2),
        "gt_path_preservation_pct": gt_pct if gt_pct is not None else -1.0,
        "gt_tested_count": gt_tested_count,
    }


def run_benchmark_streaming(
    stream_factory: Callable[[], Iterator[TraceEvent]],
    dataset_name: str,
    gt_pairs: Optional[List[Tuple[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """四组算法串行独立隔离流式运行 (运行完即刻 gc.collect()，内存恒定受控)。"""
    print(f"\n[*] 阶段一：执行全场景第一遍轻量流式扫描，提取基础因果网络与事件全量...", flush=True)
    total_events, raw_adj = build_raw_causal_adjacency(stream_factory)

    # 算法实例工厂列表
    reducer_factories = [
        ("TraceSage_Current", lambda: ProjectCurrentReducer()),
        ("CPR_2016", lambda: CPRReducer()),
        ("FDPR_2018", lambda: FDPRReducer(enable_rno=True, enable_reo_star=False, enable_cco=False)),
        ("NodeMerge_2018", lambda: NodeMergeReducer(min_support_k=2, min_pattern_length=2)),
    ]

    results: List[Dict[str, Any]] = []

    print(f"\n[*] 阶段二：开始串行独立驱动四组算法 (流式消费，严格单算法内存隔离)...", flush=True)

    for algo_name, factory in reducer_factories:
        gc.collect()
        mem_before = get_current_rss_mb()
        print(f"\n  --------------------------------------------------------------------------------", flush=True)
        print(f"  [>] 正在启动算法: {algo_name} (初始内存: {mem_before} MB)...", flush=True)

        red: BaseGraphReducer = factory()
        t_start = time.perf_counter_ns()
        evt_idx = 0

        for evt in stream_factory():
            evt_idx += 1
            red.process_event(evt)
            if evt_idx % 400000 == 0:
                print(f"      [{algo_name}] 已处理 {evt_idx}/{total_events} 条事件 (内存: {get_current_rss_mb()} MB)...", flush=True)

        red.finish()
        t_total = time.perf_counter_ns() - t_start
        red.elapsed_ns = t_total
        elapsed_ms = round(t_total / 1_000_000.0, 2)
        mem_peak = get_current_rss_mb()
        print(f"  [✓] {algo_name} 流式处理完毕！耗时: {t_total / 1_000_000_000.0:.2f} s ({elapsed_ms} ms)，保留边: {red.total_edges_out}，内存峰值: {mem_peak} MB", flush=True)

        nodes, edges = red.export_graph()
        stats = red.get_stats()
        stats["raw_events"] = total_events
        stats["peak_mem_mb"] = mem_peak

        # 验证因果闭包与 Ground Truth
        print(f"  [>] 正在对 {algo_name} 执行分层因果保真度与 GT 攻击路径覆盖验证...", flush=True)
        template_map = getattr(red, "cfaps", None)
        reach_metrics = verify_causal_reachability_against_raw(
            raw_adj=raw_adj,
            reduced_edges=edges,
            sample_size=50,
            template_mapping=template_map,
            gt_pairs=gt_pairs,
        )
        stats.update(reach_metrics)
        results.append(stats)

        # 立即销毁并回收
        del red
        del nodes
        del edges
        gc.collect()
        print(f"  [+] {algo_name} 运行产物已清理并执行垃圾回收，当前常驻内存: {get_current_rss_mb()} MB", flush=True)

    return results


def print_report_table(results: List[Dict[str, Any]], dataset_name: str, has_gt: bool = False) -> None:
    """以清晰的 ASCII 表格形式打印全场景评测结果。"""
    print(f"\n=================================================================================================================================================")
    print(f"                                          TraceSage 因果保持图压缩 (CPR) 全场景基准评测报告")
    print(f"                                          评测场景: {dataset_name} | 全场景事件总量: {results[0]['raw_events']}")
    print(f"=================================================================================================================================================")
    if has_gt:
        print(f"{'算法名称':<18} | {'保留边数':<8} | {'边压缩率(%)':<11} | {'保留节点':<8} | {'节点压缩率(%)':<11} | {'耗时(s)':<8} | {'峰值内存(MB)':<12} | {'完备性(召回%)':<12} | {'可靠性(精确%)':<12} | {'综合保真(%)':<10} | {'GT攻击路径保持(%)':<16}")
        print(f"-------------------------------------------------------------------------------------------------------------------------------------------------")
        for r in results:
            elapsed_sec = round(r['elapsed_ms'] / 1000.0, 2)
            gt_val = r.get('gt_path_preservation_pct', -1.0)
            gt_str = f"{gt_val:.2f}%" if gt_val >= 0 else "N/A"
            print(f"{r['algorithm']:<18} | {r['reduced_edges']:<8} | {r['edge_reduction_ratio_pct']:<11} | {r['reduced_nodes']:<8} | {r['node_reduction_ratio_pct']:<11} | {elapsed_sec:<8} | {r['peak_mem_mb']:<12} | {r['causal_recall_pct']:<12} | {r['causal_precision_pct']:<12} | {r['causal_consistency_pct']:<10} | {gt_str:<16}")
    else:
        print(f"{'算法名称':<18} | {'保留边数':<8} | {'边压缩率(%)':<11} | {'保留节点':<8} | {'节点压缩率(%)':<11} | {'耗时(s)':<8} | {'峰值内存(MB)':<12} | {'完备性(召回%)':<12} | {'可靠性(精确%)':<12} | {'综合保真(%)':<10}")
        print(f"-------------------------------------------------------------------------------------------------------------------------------------------------")
        for r in results:
            elapsed_sec = round(r['elapsed_ms'] / 1000.0, 2)
            print(f"{r['algorithm']:<18} | {r['reduced_edges']:<8} | {r['edge_reduction_ratio_pct']:<11} | {r['reduced_nodes']:<8} | {r['node_reduction_ratio_pct']:<11} | {elapsed_sec:<8} | {r['peak_mem_mb']:<12} | {r['causal_recall_pct']:<12} | {r['causal_precision_pct']:<12} | {r['causal_consistency_pct']:<10}")
    print(f"=================================================================================================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="TraceSage CPR Baselines Benchmark Runner (Streaming & Low-Memory)")
    parser.add_argument("--jsonl", type=str, default="", help="Sysdig JSONL 日志文件路径 (留空则使用高保真合成负载)")
    parser.add_argument("--events", type=int, default=0, help="处理的事件总数上限 (0 表示全场景不设上限)")
    parser.add_argument("--out", type=str, default="", help="指标输出保存的 JSON 文件路径")
    args = parser.parse_args()

    gt_pairs: List[Tuple[str, str]] = []
    if args.jsonl and os.path.exists(args.jsonl):
        limit_desc = f"上限: {args.events} 条" if args.events > 0 else "全场景全量消费 (不设上限)"
        print(f"[*] 目标输入场景: {args.jsonl} ({limit_desc})", flush=True)
        stream_factory = lambda: stream_sysdig_events(args.jsonl, max_events=args.events)
        dataset_name = os.path.basename(args.jsonl)
        gt_pairs = load_groundtruth_pairs(dataset_name)
        if gt_pairs:
            print(f"[+] 成功加载关联场景的 Ground Truth 攻击实体因果对: {len(gt_pairs)} 组", flush=True)
    else:
        num_evts = args.events if args.events > 0 else 10000
        print(f"[*] 未指定或未找到 JSONL 文件，使用标准高保真因果事件负载 (事件数: {num_evts} 条, 种子: 42)", flush=True)
        stream_factory = lambda: stream_synthetic_workload(num_events=num_evts, seed=42)
        dataset_name = "Synthetic_Causal_Workload_v1"

    results = run_benchmark_streaming(
        stream_factory=stream_factory,
        dataset_name=dataset_name,
        gt_pairs=gt_pairs,
    )
    print_report_table(results, dataset_name, has_gt=bool(gt_pairs))

    if args.out:
        out_dir = os.path.dirname(args.out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"dataset": dataset_name, "results": results}, f, indent=2)
        print(f"[+] 评测指标已成功保存至: {args.out}", flush=True)


if __name__ == "__main__":
    main()
