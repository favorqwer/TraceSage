#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TraceSage 核心机制细粒度支撑指标自动化评测与统计工具 (measure_mechanism_metrics.py)
对 10 个标准场景执行深度物理度量，提取并汇总 7 项支撑指标：
  - 机制 A (行为抽象与前置剪枝)：宏观去噪压缩比、内部候选过滤比、闸门剪枝量、连通主干占比
  - 机制 B (规则知识检索)：微观因果基模库规模、基模命中率
  - 机制 C (后验状态机与安全降级)：四值判决分布、安全降级与保守兜底量、零虚假跳链校验
"""

import argparse
import json
from pathlib import Path
import networkx as nx
from typing import Dict, Any, List
from rules_match import SCORING_PROTOCOL


def analyze_scenario(report_path: str, summary_entry: Dict[str, Any], baseline_edges: int) -> Dict[str, Any]:
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    sc_name = data["scenario"]
    
    edges = data.get("edges", [])
    excluded = data.get("excluded", [])
    unexcluded = data.get("unexcluded", [])
    stats = data.get("stats", {})
    rules_lib = data.get("rules_library", {})
    
    confirmed_count = (
        int(stats["confirmed_count"])
        if "confirmed_count" in stats
        else sum(1 for e in edges if e.get("origin", "confirmed") == "confirmed")
    )
    reported_triples = summary_entry["reported_triples"]
    
    # 机制 A.1: 宏观去噪压缩率 (对比经典基线输出边数)
    macro_compression = ((baseline_edges - reported_triples) / baseline_edges * 100.0) if baseline_edges > 0 else 0.0
    
    # 机制 A.2: 内部候选事件流降维过滤率
    pruned_noise = stats.get("pruned_noise_count", 0)
    excluded_count = len(excluded)
    unexcluded_count = int(stats["unexcluded_count"]) if "unexcluded_count" in stats else len(unexcluded)
    candidate_total = confirmed_count + excluded_count + unexcluded_count + pruned_noise
    internal_filtering_rate = ((candidate_total - confirmed_count) / candidate_total * 100.0) if candidate_total > 0 else 0.0
    
    # 机制 A.3: 拓扑弱连通分量与主干集中度
    G = nx.DiGraph()
    for e in edges:
        s = str(e.get("src", ""))
        t = str(e.get("dst", ""))
        if s and t:
            G.add_edge(s, t)
            
    num_nodes = G.number_of_nodes()
    num_edges = G.number_of_edges()
    wcc = list(nx.weakly_connected_components(G))
    num_wcc = len(wcc) if num_nodes > 0 else 0
    main_component_nodes = max([len(c) for c in wcc]) if wcc else 0
    main_component_ratio = (main_component_nodes / num_nodes * 100.0) if num_nodes > 0 else 0.0
    
    # 机制 B.4: 微观因果基模覆盖
    n_candidates = rules_lib.get("n_candidates", 0)
    n_selected = rules_lib.get("n_selected", 0)
    rules_hit = summary_entry.get("rules_hit")
    rules_total = summary_entry.get("rules_total")
    if rules_hit is None or rules_total is None:
        val_path = Path(report_path).with_name("validation.json")
        if val_path.is_file():
            val_metrics = json.loads(val_path.read_text(encoding="utf-8")).get("metrics") or {}
            rules_hit = val_metrics.get("rule_hits", [])
            rules_total = val_metrics.get("rules_total", 0)
        else:
            rules_hit, rules_total = [], 0
    rule_hit_coverage = (len(rules_hit) / rules_total * 100.0) if rules_total > 0 else 100.0
    
    
    # 机制 C.5: 四值判决分布统计
    v_counts = {"all": 0, "none": 0, "degraded_safe": 0, "other": 0}
    seen_triples = {(e.get("src"), e.get("syscall"), e.get("dst")) for e in edges}
    all_items = list(edges) + list(excluded) + [
        e for e in unexcluded if (e.get("src"), e.get("syscall"), e.get("dst")) not in seen_triples
    ]
    for item in all_items:
        v = item.get("verdict")
        if v == "all":
            v_counts["all"] += 1
        elif v == "none":
            v_counts["none"] += 1
        elif v in ["cap_kept", "vacuous_kept"]:
            v_counts["degraded_safe"] += 1
        else:
            r = item.get("reason", "")
            if "无关" in r or "排除" in r:
                v_counts["none"] += 1
            elif "确认" in r or item.get("origin") == "confirmed":
                v_counts["all"] += 1
            else:
                v_counts["other"] += 1
                
    # 机制 C.6: 状态机降级与保守兜底频次
    # 当判定缺乏确定性引用校验时，触发安全兜底保留
    degradation_frequency = v_counts["degraded_safe"]
    
    # 机制 C.7: 零虚假跳链物理校验 (Zero False Hops)
    false_hops = 0
    for e in edges:
        e_ids = e.get("event_ids", [])
        inst = e.get("instances", 0)
        if not e_ids and inst == 0:
            false_hops += 1
            
    return {
        "scenario": sc_name,
        "baseline_edges": baseline_edges,
        "reported_triples": reported_triples,
        "candidate_total": candidate_total,
        "confirmed_count": confirmed_count,
        "macro_compression": macro_compression,
        "pruned_noise": pruned_noise,
        "internal_filtering_rate": internal_filtering_rate,
        "nodes": num_nodes,
        "edges": num_edges,
        "num_wcc": num_wcc,
        "main_component_ratio": main_component_ratio,
        "n_candidates": n_candidates,
        "n_selected": n_selected,
        "rules_hit": rules_hit,
        "rules_total": rules_total,
        "rule_hit_coverage": rule_hit_coverage,
        "llm_calls": stats.get("llm_calls", 0),
        "verdict_all": v_counts["all"],
        "verdict_none": v_counts["none"],
        "degraded_safe": v_counts["degraded_safe"],
        "degradation_frequency": degradation_frequency,
        "false_hops": false_hops,
        "zero_false_hops_verified": (false_hops == 0)
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    with args.summary.open(encoding="utf-8") as f:
        summary_data = json.load(f)
    if summary_data.get("scoring_protocol") != SCORING_PROTOCOL:
        raise SystemExit("需要三元组重建汇总")
    systems = summary_data["systems"]
    engine_counts = {row["scenario"]: row["reported_triples"] for row in systems["engine"]["results"]}
    results = [
        analyze_scenario(row["report"]["path"], row, engine_counts[row["scenario"]])
        for row in systems["attack_graph"]["results"]
    ]
        
    print(f"\n{'='*120}")
    print(f"TraceSage 三大核心机制细粒度物理支撑数据测试报告 (10 个真实攻击场景)")
    print(f"{'='*120}")
    
    print(f"{'场景编号与名称':<35} | {'基线边数':<8} | {'输出边数':<8} | {'闸门剪枝':<8} | {'主干连通':<8} | {'基模命中':<8} | {'LLM判决(确/排/降)':<16} | {'虚假跳链':<8}")
    print(f"{'-'*120}")
    
    tot_base = sum(r["baseline_edges"] for r in results)
    tot_out = sum(r["reported_triples"] for r in results)
    tot_pruned = sum(r["pruned_noise"] for r in results)
    tot_all = sum(r["verdict_all"] for r in results)
    tot_none = sum(r["verdict_none"] for r in results)
    tot_safe = sum(r["degraded_safe"] for r in results)
    tot_false = sum(r["false_hops"] for r in results)
    
    for r in results:
        v_str = f"{r['verdict_all']}/{r['verdict_none']}/{r['degraded_safe']}"
        rule_str = f"{len(r['rules_hit'])}/{r['rules_total']}" if r['rules_total'] > 0 else "N/A"
        print(f"{r['scenario'][:33]:<35} | {r['baseline_edges']:<8} | {r['reported_triples']:<8} | {r['pruned_noise']:<8} | {r['main_component_ratio']:>6.1f}% | {rule_str:<8} | {v_str:<16} | {r['false_hops']:<8}")
        
    print(f"{'-'*120}")
    print(f"{'全场景合并统计 (Overall Total)':<35} | {tot_base:<8} | {tot_out:<8} | {tot_pruned:<8} | {'逐场景':<8} | {'逐场景':<8} | {f'{tot_all}/{tot_none}/{tot_safe}':<16} | {tot_false:<8}")
    print(f"{'='*120}\n")
    
    with args.json_out.open("x", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[*] 完整测试度量数据已落盘至: {args.json_out}")

if __name__ == "__main__":
    main()
