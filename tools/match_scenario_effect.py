#!/usr/bin/env python3
"""
match_scenario_effect.py
TraceSage 良性基模库实战场景效果评估脚本 (优化版)
严格遵循 TraceSage 图模型契约，基于 nodes.csv 精准回表与 ppid 谱系溯源
实装安全红线断言核验与锚点收敛 R1/R2 匹配
"""

import os
import sys
import csv
import json
import time
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Any

from role_classifier import RoleClassifier
from benign_matcher import BenignMotifMatcher

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def run_scenario_evaluation(scenario_edges_csv: str, scenario_nodes_csv: str, gt_json: str, kg_path: str):
    log("=== 1. 初始化检索器与加载数据集 ===")
    matcher = BenignMotifMatcher(kg_path)

    # 1. 预加载 nodes.csv 建立实体元数据索引表 (含 ppid)
    log(f"加载节点元数据索引: {scenario_nodes_csv}")
    proc_lookup = {}
    pid_to_proc = {}
    file_lookup = {}
    with open(scenario_nodes_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "")
            cid = row.get("container_id", "host") or "host"
            if lbl == "Process":
                pid = row.get("pid", "")
                st = row.get("start_ns", "")
                ppid = row.get("ppid", "")
                proc_info = (
                    row.get("exe_path", ""),
                    row.get("cmdline", ""),
                    row.get("uid", "0"),
                    row.get("euid", "0"),
                    ppid
                )
                proc_lookup[(cid, pid, st)] = proc_info
                pid_to_proc[(cid, pid)] = proc_info
            elif lbl == "File":
                path = row.get("path", "")
                file_lookup[(cid, path)] = row.get("file_type", "file")
    log(f"节点元数据索引构建完成: 进程节点 {len(proc_lookup)} 个, 文件节点 {len(file_lookup)} 个")

    # 2. 加载标注攻击边集合
    with open(gt_json, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    attack_edge_keys = set()
    attack_edges_list = []
    for phase in gt_data.get("attack_path", []):
        for e in phase.get("edges", []):
            ek = e.get("edge_key") # 形如 "ProcessToFile:12345:write"
            if ek:
                attack_edge_keys.add(ek)
            attack_edges_list.append(e)

    log(f"已加载 Groundtruth 标注攻击边: {len(attack_edges_list)} 条 (唯一边键: {len(attack_edge_keys)} 个)")

    # 3. 流式扫描场景全量边，区分良性背景边与攻击边
    log(f"=== 2. 流式扫描场景全量图并匹配良性基模 ({scenario_edges_csv}) ===")
    total_edges = 0
    bg_edges_count = 0
    attack_in_graph_count = 0

    bg_r2_count = 0
    bg_r1_count = 0
    bg_none_count = 0
    bg_sec_violations = 0

    attack_r2_edges = []
    attack_r1_edges = []
    attack_sec_violations = []
    attack_rejected_edges = []

    # 统计良性背景命中的基模大类分布
    bg_motif_hits = Counter()
    bg_sample_hits = []

    with open(scenario_edges_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_edges += 1
            if total_edges % 100000 == 0:
                log(f"已处理 {total_edges} 条边...")

            eclass = row.get("edge_class", "")
            eid = row.get("event_id", "")
            action = row.get("action", "")
            edge_key = f"{eclass}:{eid}:{action}"

            src_lbl = row.get("src_label", "")
            src_path = row.get("src_path", "")
            src_cid = row.get("src_container", "host") or "host"
            src_pid = row.get("src_pid", "")
            src_st = row.get("src_start_ns", "")
            
            dst_lbl = row.get("dst_label", "")
            dst_path = row.get("dst_path", "")
            dst_cid = row.get("dst_container", "host") or "host"
            dst_pid = row.get("dst_pid", "")
            dst_st = row.get("dst_start_ns", "")

            # 真实角色分类与 ppid 谱系提取
            context = {}
            if src_lbl == "Network":
                src_role = RoleClassifier.classify_network(src_path)
                src_desc = src_path
            elif src_lbl == "File":
                ft = file_lookup.get((src_cid, src_path), "file")
                src_role = RoleClassifier.classify_file(src_path, ft, action)
                src_desc = src_path
            else:
                exe, cmd, uid, euid, ppid = proc_lookup.get((src_cid, src_pid, src_st), ("", "", "0", "0", ""))
                src_role = RoleClassifier.classify_process(exe, cmd, uid, euid, src_cid)
                src_desc = f"{exe} (pid={src_pid})"
                
                # 追溯父进程角色
                parent_proc = pid_to_proc.get((src_cid, ppid))
                if parent_proc:
                    p_exe, p_cmd, p_uid, p_euid, _ = parent_proc
                    context["parent_role"] = RoleClassifier.classify_process(p_exe, p_cmd, p_uid, p_euid, src_cid)
                    context["parent_exe"] = p_exe

            if dst_lbl == "Network":
                dst_role = RoleClassifier.classify_network(dst_path)
                dst_desc = dst_path
            elif dst_lbl == "File":
                ft = file_lookup.get((dst_cid, dst_path), "file")
                dst_role = RoleClassifier.classify_file(dst_path, ft, action)
                dst_desc = dst_path
            else:
                exe, cmd, uid, euid, ppid = proc_lookup.get((dst_cid, dst_pid, dst_st), ("", "", "0", "0", ""))
                dst_role = RoleClassifier.classify_process(exe, cmd, uid, euid, dst_cid)
                dst_desc = f"{exe} (pid={dst_pid})"

            # 检索基模并进行安全红线与父进程谱系核验
            res = matcher.match_single_edge(src_role, action, dst_role, context)
            m_level = res["match_level"]

            is_attack = edge_key in attack_edge_keys

            if is_attack:
                attack_in_graph_count += 1
                edge_info = {
                    "edge_key": edge_key,
                    "action": action,
                    "src_role": src_role,
                    "src_desc": src_desc,
                    "dst_role": dst_role,
                    "dst_desc": dst_desc,
                    "hop": f"{src_role} -({action})-> {dst_role}",
                    "match_level": m_level
                }
                if m_level == "R2_EXACT":
                    edge_info["matched_motif"] = res["motifs"][0]["title"]
                    edge_info["security_boundary"] = res["motifs"][0]["security_boundary"]
                    attack_r2_edges.append(edge_info)
                elif m_level == "R1_PARTIAL":
                    edge_info["matched_motif"] = res["motifs"][0]["title"]
                    edge_info["aligned_hop"] = res["motifs"][0].get("aligned_hop", "")
                    edge_info["security_boundary"] = res["motifs"][0]["security_boundary"]
                    attack_r1_edges.append(edge_info)
                elif m_level == "SECURITY_VIOLATION":
                    edge_info["reason"] = res.get("reason", "触碰安全红线")
                    attack_sec_violations.append(edge_info)
                else:
                    edge_info["reason"] = "拓扑与动作失配 (未登记于任何良性范式中)"
                    attack_rejected_edges.append(edge_info)
            else:
                bg_edges_count += 1
                if m_level == "R2_EXACT":
                    bg_r2_count += 1
                    motif_name = res["motifs"][0]["title"]
                    bg_motif_hits[motif_name] += 1
                    if len(bg_sample_hits) < 5:
                        bg_sample_hits.append({
                            "action": action,
                            "src_desc": src_desc,
                            "dst_desc": dst_desc,
                            "roles": f"{src_role} -({action})-> {dst_role}",
                            "matched_motif": motif_name
                        })
                elif m_level == "R1_PARTIAL":
                    bg_r1_count += 1
                elif m_level == "SECURITY_VIOLATION":
                    bg_sec_violations += 1
                else:
                    bg_none_count += 1

    log(f"全图扫描完成: 总边数 {total_edges}，良性背景边 {bg_edges_count}，GT标注攻击边 {attack_in_graph_count}")

    # 3. 输出量化评估
    bg_cov_pct = round((bg_r2_count + bg_r1_count) / bg_edges_count * 100, 2) if bg_edges_count else 0
    bg_r2_pct = round(bg_r2_count / bg_edges_count * 100, 2) if bg_edges_count else 0
    
    attack_r2_count = len(attack_r2_edges)
    attack_r1_count = len(attack_r1_edges)
    attack_sec_count = len(attack_sec_violations)
    attack_rejected_count = len(attack_rejected_edges)
    total_blocked = attack_sec_count + attack_rejected_count

    attack_fp_pct = round(attack_r2_count / attack_in_graph_count * 100, 2) if attack_in_graph_count else 0
    attack_r1_pct = round(attack_r1_count / attack_in_graph_count * 100, 2) if attack_in_graph_count else 0
    attack_block_pct = round(total_blocked / attack_in_graph_count * 100, 2) if attack_in_graph_count else 0

    result_summary = {
        "scenario": "2_SSH_Spray_Lateral_Exfiltration",
        "total_graph_edges": total_edges,
        "background_edges": {
            "total": bg_edges_count,
            "r2_exact_matches": bg_r2_count,
            "r2_rate_pct": bg_r2_pct,
            "r1_partial_matches": bg_r1_count,
            "r1_rate_pct": round(bg_r1_count / bg_edges_count * 100, 2) if bg_edges_count else 0,
            "unmatched_count": bg_none_count,
            "security_violations": bg_sec_violations,
            "overall_benign_coverage_pct": bg_cov_pct,
            "top_matched_canonical_motifs": bg_motif_hits.most_common(8),
            "sample_matched_operations": bg_sample_hits
        },
        "attack_edges": {
            "total_gt_attack_edges": len(attack_edges_list),
            "matched_in_graph_attack_edges": attack_in_graph_count,
            "r2_false_positive_matches": {
                "count": attack_r2_count,
                "pct": attack_fp_pct,
                "edges": attack_r2_edges
            },
            "r1_partial_matches": {
                "count": attack_r1_count,
                "pct": attack_r1_pct,
                "edges": attack_r1_edges
            },
            "security_boundary_violations": {
                "count": attack_sec_count,
                "pct": round(attack_sec_count / attack_in_graph_count * 100, 2) if attack_in_graph_count else 0,
                "edges": attack_sec_violations
            },
            "clean_rejected_edges": {
                "count": attack_rejected_count,
                "pct": round(attack_rejected_count / attack_in_graph_count * 100, 2) if attack_in_graph_count else 0,
                "edges": attack_rejected_edges
            },
            "total_defended_and_isolated": {
                "count": total_blocked,
                "pct": attack_block_pct
            }
        }
    }

    out_file = "output/rule-kg/SCENARIO_2_MATCH_EFFECT.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result_summary, f, indent=2, ensure_ascii=False)
    log(f"实战效果评估报告已保存 -> {out_file}")

    return result_summary

if __name__ == "__main__":
    edges_csv = "output/parser-v2/2_SSH_Spray_Lateral_Exfiltration-r3/edges.csv"
    nodes_csv = "output/parser-v2/2_SSH_Spray_Lateral_Exfiltration-r3/nodes.csv"
    gt_json = "groundtruth/2_SSH_Spray_Lateral_Exfiltration.groundtruth.json"
    kg_path = "output/rule-kg/canonical_benign_kg.json"
    run_scenario_evaluation(edges_csv, nodes_csv, gt_json, kg_path)
