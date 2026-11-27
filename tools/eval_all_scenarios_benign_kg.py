#!/usr/bin/env python3
"""
eval_all_scenarios_benign_kg.py
TraceSage 10 个标准攻击场景全量离线评测脚本
评估良性基模知识库 (canonical_benign_kg.json) 在多场景下的背景降噪能力与抗误判能力
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

SCENARIOS = [
    {
        "id": 1,
        "name": "1_Web_Exploit_Ransomware",
        "dir": "output/parser-v2/1_Web_Exploit_Ransomware-r3",
        "gt": "groundtruth/1_Web_Exploit_Ransomware.groundtruth.json",
        "desc": "Web 漏洞渗透与勒索文件加密"
    },
    {
        "id": 2,
        "name": "2_SSH_Spray_Lateral_Exfiltration",
        "dir": "output/parser-v2/2_SSH_Spray_Lateral_Exfiltration-r3",
        "gt": "groundtruth/2_SSH_Spray_Lateral_Exfiltration.groundtruth.json",
        "desc": "SSH 弱口令喷洒与凭证横向外传"
    },
    {
        "id": 3,
        "name": "3_Phishing_Beacon_Cryptomining",
        "dir": "output/parser-v2/3_Phishing_Beacon_Cryptomining-r3",
        "gt": "groundtruth/3_Phishing_Beacon_Cryptomining.groundtruth.json",
        "desc": "钓鱼载荷执行、C2 通联与挖矿木马"
    },
    {
        "id": 4,
        "name": "4_Repo_Poisoning_Backdoor",
        "dir": "output/parser-v2/4_Repo_Poisoning_Backdoor-r3",
        "gt": "groundtruth/4_Repo_Poisoning_Backdoor.groundtruth.json",
        "desc": "代码仓库投毒与编译构建后门"
    },
    {
        "id": 5,
        "name": "5_Exposed_Service_Pivot",
        "dir": "output/parser-v2/5_Exposed_Service_Pivot-r3",
        "gt": "groundtruth/5_Exposed_Service_Pivot.groundtruth.json",
        "desc": "暴露服务提权与内网穿透枢纽"
    },
    {
        "id": 6,
        "name": "6_Web_SQLi_Data_Exfiltration",
        "dir": "output/parser-v2/6_Web_SQLi_Data_Exfiltration-r3",
        "gt": "groundtruth/6_Web_SQLi_Data_Exfiltration.groundtruth.json",
        "desc": "Web SQL 注入与数据库核心表外传"
    },
    {
        "id": 7,
        "name": "7_DB_BruteForce_DataWipe",
        "dir": "output/parser-v2/7_DB_BruteForce_DataWipe-r3",
        "gt": "groundtruth/7_DB_Bruteforce_Datawipe.groundtruth.json",
        "desc": "数据库暴力破解与恶意删库破坏"
    },
    {
        "id": 8,
        "name": "8_FTP_WeakCreds_WebShell_Exfiltration",
        "dir": "output/parser-v2/8_FTP_WeakCreds_WebShell_Exfiltration-r3",
        "gt": "groundtruth/8_FTP_WeakCreds_WebShell_Exfiltration.groundtruth.json",
        "desc": "FTP 弱口令 WebShell 投递与核心数据打包"
    },
    {
        "id": 9,
        "name": "9_Site_Defacement",
        "dir": "output/parser-v2/9_Site_Defacement",
        "gt": "groundtruth/9_Site_Defacement.groundtruth.json",
        "desc": "Web 站点篡改与文件替换"
    },
    {
        "id": 10,
        "name": "10_Tomcat_Weakcreds_DNS_Exfiltration",
        "dir": "output/parser-v2/10_Tomcat_Weakcreds_DNS_Exfiltration-r3",
        "gt": "groundtruth/10_Tomcat_Weakcreds_DNS_Exfiltration.groundtruth.json",
        "desc": "Tomcat 弱口令部署与 DNS 隧道隐蔽外传"
    }
]

def eval_single_scenario(sc: Dict[str, Any], matcher: BenignMotifMatcher) -> Dict[str, Any]:
    name = sc["name"]
    edges_csv = os.path.join(sc["dir"], "edges.csv")
    nodes_csv = os.path.join(sc["dir"], "nodes.csv")
    gt_json = sc["gt"]

    t0 = time.time()
    log(f"============================================================")
    log(f"开始评测场景 [{sc['id']}/10]: {name} ({sc['desc']})")
    
    if not os.path.exists(edges_csv) or not os.path.exists(nodes_csv):
        log(f"[ERROR] 找不到数据文件: {edges_csv} 或 {nodes_csv}")
        return {"error": "file_not_found"}

    # 1. 预加载 nodes.csv 建立实体元数据索引表
    proc_lookup = {}
    pid_to_proc = {}
    file_lookup = {}
    with open(nodes_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "")
            cid = row.get("container_id", "host") or "host"
            if lbl == "Process":
                pid = row.get("pid", "")
                st = row.get("start_ns", "")
                ppid = row.get("ppid", "")
                info = (row.get("exe_path", ""), row.get("cmdline", ""), row.get("uid", "0"), row.get("euid", "0"), ppid)
                proc_lookup[(cid, pid, st)] = info
                pid_to_proc[(cid, pid)] = info
            elif lbl == "File":
                path = row.get("path", "")
                file_lookup[(cid, path)] = row.get("file_type", "file")

    # 2. 加载 Groundtruth 标注攻击边与 POI
    attack_edge_keys = set()
    poi_key = None
    if os.path.exists(gt_json):
        with open(gt_json, "r", encoding="utf-8") as f:
            gt_data = json.load(f)
        for phase in gt_data.get("attack_path", []):
            for e in phase.get("edges", []):
                ek = e.get("edge_key")
                if ek:
                    attack_edge_keys.add(ek)
        poi_key = gt_data.get("poi", {}).get("edge_key")

    # 3. 流式读取 edges.csv 并进行匹配
    total_edges = 0
    bg_total = 0
    bg_r2 = 0
    bg_r1 = 0
    bg_sec_violation = 0
    bg_none = 0

    attack_in_graph = 0
    attack_r2_list = []
    attack_r1_list = []
    attack_sec_list = []
    attack_none_list = []

    poi_result = None

    with open(edges_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_edges += 1
            if total_edges % 500000 == 0:
                log(f"  [{name}] 已处理 {total_edges} 条边...")

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
                parent_proc = pid_to_proc.get((src_cid, ppid))
                if parent_proc:
                    p_exe, p_cmd, p_uid, p_euid, _ = parent_proc
                    context["parent_role"] = RoleClassifier.classify_process(p_exe, p_cmd, p_uid, p_euid, src_cid)

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

            # 检索基模
            res = matcher.match_single_edge(src_role, action, dst_role, context)
            m_level = res["match_level"]

            is_attack = edge_key in attack_edge_keys

            if is_attack:
                attack_in_graph += 1
                edge_item = {
                    "edge_key": edge_key,
                    "action": action,
                    "src_role": src_role,
                    "dst_role": dst_role,
                    "match_level": m_level
                }
                if m_level == "R2_EXACT":
                    edge_item["matched_motif"] = res["motifs"][0]["title"]
                    attack_r2_list.append(edge_item)
                elif m_level == "R1_PARTIAL":
                    attack_r1_list.append(edge_item)
                elif m_level == "SECURITY_VIOLATION":
                    edge_item["reason"] = res.get("reason", "")
                    attack_sec_list.append(edge_item)
                else:
                    attack_none_list.append(edge_item)

            else:
                bg_total += 1
                if m_level == "R2_EXACT":
                    bg_r2 += 1
                elif m_level == "R1_PARTIAL":
                    bg_r1 += 1
                elif m_level == "SECURITY_VIOLATION":
                    bg_sec_violation += 1
                else:
                    bg_none += 1

            if edge_key == poi_key:
                poi_result = {
                    "poi_key": poi_key,
                    "action": action,
                    "src_role": src_role,
                    "dst_role": dst_role,
                    "match_level": m_level,
                    "defended": m_level in ("NONE", "SECURITY_VIOLATION")
                }

    elapsed = round(time.time() - t0, 2)
    bg_cov_pct = round((bg_r2 + bg_r1) / bg_total * 100, 2) if bg_total else 0.0
    bg_r2_pct = round(bg_r2 / bg_total * 100, 2) if bg_total else 0.0
    
    atk_fp_count = len(attack_r2_list)
    atk_fp_pct = round(atk_fp_count / attack_in_graph * 100, 2) if attack_in_graph else 0.0
    
    atk_isolated = len(attack_sec_list) + len(attack_none_list)
    atk_def_pct = round(atk_isolated / attack_in_graph * 100, 2) if attack_in_graph else 0.0

    log(f"[{name}] 评测完成 (耗时 {elapsed}s):")
    log(f"  - 总边数: {total_edges} (良性: {bg_total}, 攻击标注: {attack_in_graph})")
    log(f"  - 良性背景覆盖率: {bg_cov_pct}% (R2: {bg_r2_pct}%, R1: {round(bg_r1/bg_total*100, 2)}%)")
    log(f"  - 攻击边 R2 假阳性率: {atk_fp_pct}% ({atk_fp_count}/{attack_in_graph})")
    log(f"  - 攻击边直接隔离阻断率: {atk_def_pct}% ({atk_isolated}/{attack_in_graph}) [红线: {len(attack_sec_list)}, 失配: {len(attack_none_list)}]")
    log(f"  - POI 核心破坏动作判定: {'成功阻断拒止' if poi_result and poi_result.get('defended') else '未完全阻断'}")

    return {
        "id": sc["id"],
        "name": name,
        "description": sc["desc"],
        "elapsed_seconds": elapsed,
        "total_edges": total_edges,
        "background": {
            "total": bg_total,
            "r2_count": bg_r2,
            "r2_pct": bg_r2_pct,
            "r1_count": bg_r1,
            "r1_pct": round(bg_r1 / bg_total * 100, 2) if bg_total else 0.0,
            "sec_violation_count": bg_sec_violation,
            "none_count": bg_none,
            "coverage_pct": bg_cov_pct
        },
        "attack": {
            "total_in_graph": attack_in_graph,
            "r2_fp_count": atk_fp_count,
            "r2_fp_pct": atk_fp_pct,
            "r1_count": len(attack_r1_list),
            "r1_pct": round(len(attack_r1_list) / attack_in_graph * 100, 2) if attack_in_graph else 0.0,
            "sec_violation_count": len(attack_sec_list),
            "none_count": len(attack_none_list),
            "isolated_count": atk_isolated,
            "defense_isolation_pct": atk_def_pct,
            "sample_fp_edges": attack_r2_list[:3]
        },
        "poi": poi_result
    }

def main():
    log("=== TraceSage 10 个标准场景良性基模知识库全量评估开始 ===")
    kg_path = "output/rule-kg/canonical_benign_kg.json"
    matcher = BenignMotifMatcher(kg_path)

    results = []
    total_start = time.time()

    for sc in SCENARIOS:
        res = eval_single_scenario(sc, matcher)
        if "error" not in res:
            results.append(res)

    total_elapsed = round(time.time() - total_start, 2)
    log(f"=== 全部 10 个场景评测执行完毕，总耗时 {total_elapsed} 秒 ===")

    # 计算 Macro-Average 与 Micro-Average
    n_sc = len(results)
    macro_bg_cov = round(sum(r["background"]["coverage_pct"] for r in results) / n_sc, 2) if n_sc else 0
    macro_bg_r2 = round(sum(r["background"]["r2_pct"] for r in results) / n_sc, 2) if n_sc else 0
    macro_atk_fp = round(sum(r["attack"]["r2_fp_pct"] for r in results) / n_sc, 2) if n_sc else 0
    macro_atk_def = round(sum(r["attack"]["defense_isolation_pct"] for r in results) / n_sc, 2) if n_sc else 0

    total_bg_edges = sum(r["background"]["total"] for r in results)
    total_bg_hits = sum(r["background"]["r2_count"] + r["background"]["r1_count"] for r in results)
    micro_bg_cov = round(total_bg_hits / total_bg_edges * 100, 2) if total_bg_edges else 0

    total_atk_edges = sum(r["attack"]["total_in_graph"] for r in results)
    total_atk_fp = sum(r["attack"]["r2_fp_count"] for r in results)
    micro_atk_fp = round(total_atk_fp / total_atk_edges * 100, 2) if total_atk_edges else 0

    total_atk_def = sum(r["attack"]["isolated_count"] for r in results)
    micro_atk_def = round(total_atk_def / total_atk_edges * 100, 2) if total_atk_edges else 0

    poi_defended_count = sum(1 for r in results if r["poi"] and r["poi"].get("defended"))

    summary = {
        "metadata": {
            "evaluation_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_scenarios_evaluated": n_sc,
            "total_elapsed_seconds": total_elapsed,
            "knowledge_base_evaluated": kg_path
        },
        "aggregate_metrics": {
            "macro_average": {
                "background_coverage_pct": macro_bg_cov,
                "background_r2_exact_pct": macro_bg_r2,
                "attack_r2_false_positive_pct": macro_atk_fp,
                "attack_defense_isolation_pct": macro_atk_def
            },
            "micro_average": {
                "total_background_edges": total_bg_edges,
                "background_coverage_pct": micro_bg_cov,
                "total_attack_edges": total_atk_edges,
                "attack_r2_false_positive_pct": micro_atk_fp,
                "attack_defense_isolation_pct": micro_atk_def
            },
            "poi_defense_summary": {
                "total_poi_evaluated": n_sc,
                "poi_successfully_isolated": poi_defended_count,
                "poi_isolation_rate_pct": round(poi_defended_count / n_sc * 100, 2) if n_sc else 0
            }
        },
        "scenario_details": results
    }

    # 落盘 JSON
    out_json = "output/rule-kg/TEN_SCENARIOS_BENIGN_KG_EVAL.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    log(f"结构化评测结果已落盘 -> {out_json}")

    # 落盘 Markdown 矩阵报告
    out_md = "output/rule-kg/TEN_SCENARIOS_BENIGN_KG_EVAL.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# TraceSage 良性基模知识库 10 大攻击场景全量评测报告\n\n")
        f.write(f"- **评测时间**：`{summary['metadata']['evaluation_time']}`\n")
        f.write(f"- **基模库版本**：`canonical_benign_kg.json` (12 大经典业务范式)\n")
        f.write(f"- **总图边数**：`{total_bg_edges + total_atk_edges:,}` 条\n")
        f.write(f"- **总耗时**：`{total_elapsed}` 秒\n\n")
        
        f.write("## 1. 全量场景综合指标矩阵\n\n")
        f.write("| 编号 | 场景名称 | 场景业务/攻击简述 | 总边数 | 良性背景覆盖率 | 攻击边 R2 假阳性率 | 攻击边直接阻断率 | POI 核心破坏动作判定 |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in results:
            poi_str = "阻断拒止" if r["poi"] and r["poi"].get("defended") else "未阻断"
            f.write(f"| {r['id']} | `{r['name']}` | {r['description']} | {r['total_edges']:,} | {r['background']['coverage_pct']}% | {r['attack']['r2_fp_pct']}% ({r['attack']['r2_fp_count']}/{r['attack']['total_in_graph']}) | {r['attack']['defense_isolation_pct']}% ({r['attack']['isolated_count']}/{r['attack']['total_in_graph']}) | {poi_str} |\n")
        
        f.write(f"\n**汇总统计**：\n")
        f.write(f"- **宏平均 (Macro-Average)**：良性背景覆盖率 **{macro_bg_cov}%**，攻击边 R2 假阳性率 **{macro_atk_fp}%**，攻击边直接阻断率 **{macro_atk_def}%**\n")
        f.write(f"- **微平均 (Micro-Average)**：良性背景覆盖率 **{micro_bg_cov}%**，攻击边 R2 假阳性率 **{micro_atk_fp}%**，攻击边直接阻断率 **{micro_atk_def}%**\n")
        f.write(f"- **POI 核心破坏动作阻断率**：**{poi_defended_count} / {n_sc} ({round(poi_defended_count / n_sc * 100, 2)}%)**\n\n")

    log(f"Markdown 评估矩阵报告已落盘 -> {out_md}")

if __name__ == "__main__":
    main()
