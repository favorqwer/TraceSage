"""
全量 10 场景自动化评测脚本 (v4 方案：符号规则语义下沉 + 全链路因果闭包与纯化)
严格遵循：
1. 留一交叉原则 (LOO)：测试场景 k 时，规则库由对应的 distill/fold-libraries/{k}.json 读取
2. 绝对零硬编码，所有算子均基于 Linux 进程模型与图因果公理
3. 产物严格隔离在 tmp/rule_context_runs/，绝不污染主干或基线目录
4. 评测口径 100% 采用 tools/score_report_product.py 官方口径
"""
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "provenance"))
sys.path.insert(0, str(REPO_ROOT / "tmp"))
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import settings as cfg
cfg.load_dotenv()

from domain.edge import edge_key
from domain.pool import CandidatePool
from closure import extract_raw_closure
from rules.library import load_library_file, _role_cuts
from rules.online import MatchIndex
from routing.prepare import PreFilter
from routing.filters import DebrisPrune
from routing.report import build_report_from_outcome, save_report
from llm.client import LlmBudget, set_trace_raw
from llm.judge import LlmChannel, set_trace_sink
from navigator.decoder import decode_motif
import score_report_product as scorer

def _key(e: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return edge_key(e)

# A/B 对照开关：只控制提示词里是否出现「离线攻击基模参考证据」这一段；
# 上游执行环境提示、图公理、束划分、模型参数全部保持不变。
USE_MOTIF_EVIDENCE = True
VARIANT = "v4_motif_evidence"
# 解码开关：True = B1 真 2 跳；False = B0 旧解码（2 跳只读顶层角色，得到空角色标签）
REAL_2HOP = True
# RAG 判定器复用同一场景的 MatchIndex 与场景名；由 run_single_scenario 运行时写入。
CURRENT_MATCHER = None
CURRENT_SCENARIO = ""
CURRENT_PARENT_MAP = {}
# 渲染钩子：None 时走 B0/B1 原逻辑；RAG 实验传入自己的 render。
RENDER_HOOK = None
# B2：内容绑定。提示词里显示“覆盖率 + 命中成员”，并对“有证据但覆盖率很低却判 all”的束降级。
CONTENT_BINDING = False
COVERAGE_MIN = 0.5
# 主方案：按基模拆束。命中基模的边单独判（带证据），没命中的边单独判（无标签）。
SPLIT_EVIDENCE = False
# A：高精度符号通道直确认。当前只实现“与 POI 攻击者主机对一致且进程属于锚点进程”的网络边。
ANCHOR_PAIR_CONFIRM = False
# C：基模锚定子图，在命中基模的子束后追加 1 跳邻域边。
SUBGRAPH_EVIDENCE = False
# D：结构化输出，要求判 all 时必须在理由里写成员边编号；没有编号的 all 降级。
STRUCTURED_OUTPUT = False

PASSIVE_RUNTIME_PREFIXES = (
    "/etc/ld.so.",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/usr/lib/locale/",
)

PASSIVE_SYSCALLS = ("mmap", "access", "stat", "fstat")

def is_passive_kernel_runtime_edge(edge: Dict[str, Any]) -> bool:
    """通用判定：是否属于 Linux 程序启动时内核与 ld-linux.so 强制执行的只读被动加载伴随边。"""
    sc = str(edge.get("syscall") or "")
    if sc not in PASSIVE_SYSCALLS:
        return False
        
    src = str(edge.get("src") or "")
    dst = str(edge.get("dst") or "")
    
    for path in (src, dst):
        if any(path.startswith(p) for p in PASSIVE_RUNTIME_PREFIXES):
            return True
        if (path.startswith("/lib/") or path.startswith("/usr/lib/")) and (".so" in path):
            return True
    return False

def run_single_scenario(scenario_name: str, fold_lib_path: str, out_json: str) -> Dict[str, Any]:
    global USE_MOTIF_EVIDENCE
    t0 = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] >>> 开始执行场景: {scenario_name}")
    
    # 1. 读留一折库
    patterns, audit = load_library_file(fold_lib_path)
    admitted = audit.get("selected")
    role_cuts = _role_cuts(audit)
    
    # 2. 闭包抽取
    raw_edges, closure_stats, deps = extract_raw_closure(scenario_name, return_deps=True, log=lambda s: None)
    anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]
    
    # 3. 锚点事实确认
    anchor_keys = {tuple(t) for t in anchor_triples}
    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for e in raw_edges:
        k = _key(e)
        if k in anchor_keys:
            rec = dict(e)
            rec["origin"] = "confirmed"
            rec["class"] = "anchor"
            rec["reason"] = "告警事实锚点 (POI)"
            final_confirmed[k] = rec
            
    # 4. 静态初筛
    pool = CandidatePool(raw_edges)
    tf = pool.facts
    channel_input = [e for e in raw_edges if _key(e) not in anchor_keys]
    clean_unexcluded, pruned_background = PreFilter(tf).apply(channel_input)
    
    # 5. 符号基模匹配（规则不直接确诊，全部解码为自然语言证据）
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, tf, role_cuts=role_cuts)
    global CURRENT_MATCHER, CURRENT_SCENARIO
    CURRENT_MATCHER = matcher
    CURRENT_SCENARIO = scenario_name
    matched = matcher.match(patterns or [], admitted=admitted, seed_edges=final_confirmed)
    
    motif_by_id = {str(m["id"]): m for m in audit["motifs"]}
    rule_evidence_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for k, pat in matched.items():
        mid = pat.get("id")
        full_m = motif_by_id.get(mid, pat)
        rule_evidence_map[k] = {
            "motif_id": mid,
            "motif_name": pat.get("name", ""),
            "decoded_desc": decode_motif(full_m, real_2hop=REAL_2HOP),
            "support_scenarios": full_m.get("support_scenarios_list", []),
        }

    # 6. 通用进程血缘拓扑表构建
    parent_map: Dict[str, str] = {}
    for e in raw_edges:
        if e.get("syscall") in ("execve", "clone"):
            p_src = str(e.get("src", ""))
            p_dst = str(e.get("dst", ""))
            if p_src and p_dst and p_src != p_dst:
                parent_map[p_dst] = p_src
    global CURRENT_PARENT_MAP
    CURRENT_PARENT_MAP = parent_map

    ambiguous_candidates = [e for e in clean_unexcluded if _key(e) not in final_confirmed]
    
    # 6.5 高精度符号通道：与 POI 攻击者主机对一致、且进程属于锚点进程的网络边直接确认。
    if ANCHOR_PAIR_CONFIRM:
        import llm.judge as judge_mod
        anchor_info = judge_mod.anchor_facts(deps.record.poi_rows)
        anchor_pairs = anchor_info.get("pairs") or set()
        anchor_procs = anchor_info.get("procs") or set()
        remaining = []
        for e in ambiguous_candidates:
            obj, label = judge_mod.object_side(
                e["src"], e["syscall"], e["dst"],
                str(e.get("src_label") or ""), str(e.get("dst_label") or ""))
            pair = judge_mod.dir_class(str(obj), label) if label == "Network" else ""
            procs = {str(m) for m in (e.get("member_processes") or ())}
            if e.get("process_id"):
                procs.add(str(e["process_id"]))
            if (label == "Network" and pair in anchor_pairs
                    and (not anchor_procs or (procs & anchor_procs))):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["reason"] = "高精度符号通道：与 POI 攻击者主机对一致"
                rec["evidence_kind"] = "anchor_pair"
                final_confirmed[_key(e)] = rec
            else:
                remaining.append(e)
        ambiguous_candidates = remaining
    
    # 7. 通用血缘感知与规则线索注入渲染
    import llm.judge as judge_mod
    original_render = judge_mod.render
    
    def custom_render_v4(items, records, ref_t, **kwargs):
        for item in items:
            matched_evidences = []
            seen_mids = set()
            for triple in item.get("members", []):
                ev = rule_evidence_map.get(triple)
                if ev and ev["motif_id"] not in seen_mids:
                    seen_mids.add(ev["motif_id"])
                    matched_evidences.append(ev)
            item["_matched_evidences"] = matched_evidences
            
            parents = set()
            for prog in item.get("programs", []):
                if prog in parent_map:
                    parents.add(parent_map[prog])
            item["_parent_programs"] = list(parents)
            
        base_text = original_render(items, records, ref_t, **kwargs)
        lines = base_text.split("\n")
        new_lines = []
        for line in lines:
            new_lines.append(line)
            for item in items:
                if line.startswith(f"{item['id']}｜"):
                    if USE_MOTIF_EVIDENCE and item.get("_matched_evidences"):
                        evs = item["_matched_evidences"]
                        size = max(1, int(item.get("size") or 0))
                        motif_members = {}
                        for t in item.get("members", []):
                            ev = rule_evidence_map.get(t)
                            if ev:
                                motif_members.setdefault(ev["motif_id"], []).append(t)
                        ranked = sorted(evs, key=lambda ev: len(motif_members.get(ev["motif_id"], [])), reverse=True)
                        shown = ranked[:2] if CONTENT_BINDING else evs[:2]
                        new_lines.append(f"    【离线攻击基模参考证据】(本束成员 {size} 条，命中 {len(evs)} 个攻击基模):")
                        for ev in shown:
                            mid = ev["motif_id"]
                            matched = motif_members.get(mid, [])
                            cov = len(matched) / size
                            new_lines.append(f"    - 基模 {mid}: {ev['decoded_desc']}")
                            if CONTENT_BINDING:
                                new_lines.append(f"      覆盖率：本束 {size} 条边中命中 {len(matched)} 条（{cov:.1%}）")
                                if matched:
                                    samples = "；".join(f"{s} --{sc}--> {d}" for s, sc, d in matched[:5])
                                    new_lines.append(f"      命中样例：{samples}")
                        if CONTENT_BINDING:
                            item["_motif_coverage"] = {mid: len(v) / size for mid, v in motif_members.items()}
                            new_lines.append("    【判定要求】只确认上面列出的命中边；本束其他边不要因为命中基模就判 all；命中边占比很低时应判 mixed。")
                        if SUBGRAPH_EVIDENCE and item.get("members") and all(t in rule_evidence_map for t in item["members"]):
                            for t in item["members"][:2]:
                                neigh = []
                                for e in raw_edges:
                                    if _key(e) == t:
                                        continue
                                    if e.get("src") in (t[0], t[2]) or e.get("dst") in (t[0], t[2]):
                                        neigh.append(e)
                                for e in neigh[:2]:
                                    new_lines.append(f"      邻域边：{e.get('src')} --{e.get('syscall')}--> {e.get('dst')}")
                    
                    parents = item.get("_parent_programs", [])
                    has_shell_parent = any("bash" in p or "sh" in p or "java" in p or "python" in p or "sshd" in p or "cron" in p for p in parents)
                    if has_shell_parent:
                        new_lines.append(f"    【上游执行环境】该批动作由交互式会话或网络应用进程派生（父进程: {', '.join(parents)}）")
                        new_lines.append("    【通用审核要求】通用命令行工具（如 id, uname, hostname, ls, du, tar, gzip, mkdir, chmod, nc, curl, wget）：若属于上游交互式会话下发的指令或临时目录配置，请判 all，不得因程序本身是常见 Linux 命令而误判为 none。")
                    if STRUCTURED_OUTPUT:
                        new_lines.append("    【输出要求】判 all 时必须在理由中写出你确认的成员边编号（如 M1、M2）；没有编号的 all 会被系统降级为 mixed。")
        return "\n".join(new_lines)

    judge_mod.render = RENDER_HOOK if RENDER_HOOK is not None else custom_render_v4

    # 7.5 逐批观测：每个场景一份 trace.jsonl，记录束元数据、完整提示词、原始结论。
    trace_path = Path(out_json).with_suffix(".trace.jsonl")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_lock = threading.Lock()
    code_version = "b1-frozen-9c11503"

    def _trace_sink(payload: Dict[str, Any]) -> None:
        items = []
        for item in payload.get("items", []):
            rec = dict(item)
            rec["evidence_ids"] = sorted({
                str(rule_evidence_map[tuple(t)].get("motif_id"))
                for t in item.get("members", [])
                if tuple(t) in rule_evidence_map
            })
            rec["rag_rule_ids"] = list(item.get("rag_rule_ids")
                                       or item.get("_rag_rule_ids") or [])
            items.append(rec)
        record = {
            "scenario": scenario_name,
            "code_version": code_version,
            "ts": time.time(),
            "level_name": payload.get("level_name"),
            "items": items,
            "listing": payload.get("listing", ""),
            "result": payload.get("result", {}),
        }
        with trace_lock:
            with trace_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    set_trace_sink(_trace_sink)
    set_trace_raw(True)
    trace_details: List[Dict[str, Any]] = []

    deps.budget = LlmBudget()
    llm_channel = LlmChannel(deps=deps)
    if SPLIT_EVIDENCE:
        motif_candidates = [e for e in ambiguous_candidates if _key(e) in rule_evidence_map]
        residual_candidates = [e for e in ambiguous_candidates if _key(e) not in rule_evidence_map]
        orig_use = USE_MOTIF_EVIDENCE
        USE_MOTIF_EVIDENCE = True
        motif_res = llm_channel.judge(motif_candidates, tf)
        USE_MOTIF_EVIDENCE = False
        residual_res = llm_channel.judge(residual_candidates, tf)
        USE_MOTIF_EVIDENCE = orig_use
        llm_confirmed = (motif_res.get("confirmed") or []) + (residual_res.get("confirmed") or [])
        excluded_edges = (motif_res.get("excluded") or []) + (residual_res.get("excluded") or [])
        remaining_ambiguous = (motif_res.get("kept") or []) + (residual_res.get("kept") or [])
        trace_details.extend(motif_res.get("detail") or [])
        trace_details.extend(residual_res.get("detail") or [])
    else:
        motif_candidates = ambiguous_candidates
        residual_candidates = []
        llm_results = llm_channel.judge(ambiguous_candidates, tf)
        llm_confirmed = llm_results.get("confirmed", [])
        excluded_edges = llm_results.get("excluded", [])
        remaining_ambiguous = llm_results.get("kept", [])
        trace_details.extend(llm_results.get("detail") or [])

    set_trace_sink(None)
    set_trace_raw(False)
    with trace_lock:
        with trace_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "scenario": scenario_name, "code_version": code_version,
                "kind": "detail", "detail": trace_details,
            }, ensure_ascii=False, default=str) + "\n")

    judge_mod.render = original_render
    
    # 8. 通用因果纯化与全链路闭包
    # 8.1 初始确诊边过滤：隔离未知执行体（<NA>）粗粒度泛化
    for e in llm_confirmed:
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        if (src == "<NA>" or dst == "<NA>") and sc in ("execve", "clone"):
            continue
        final_confirmed[_key(e)] = e

    # 8.2 提取确诊恶意进程实例集合与已写入文件集合
    confirmed_procs: Set[str] = set()
    written_files: Set[str] = set()
    
    for e in final_confirmed.values():
        for m in (e.get("member_processes") or ()):
            confirmed_procs.add(str(m))
        for item in (e.get("src_identities") or []) + (e.get("dst_identities") or []):
            if isinstance(item, list) and len(item) > 1:
                confirmed_procs.add(str(item[1]))
        p_id = e.get("process_id")
        if p_id:
            confirmed_procs.add(str(p_id))
            
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        if sc in ("write", "open", "creat", "rename") and dst.startswith("/"):
            written_files.add(dst)

    # 8.3 通用单向因果树与临时空间派生拉直 (基于 src_identities 发起者判定)
    pool_candidates = list(clean_unexcluded) + [e for e in excluded_edges if e.get("syscall") in ("mkdir", "chmod", "execve", "clone", "write")]
    promoted_keys = set(final_confirmed.keys())
    
    for iteration in range(3):
        promoted_this_round = 0
        for e in pool_candidates:
            k = _key(e)
            if k in promoted_keys:
                continue
                
            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            sc = str(e.get("syscall") or "")
            
            src_ids = {str(item[1]) for item in (e.get("src_identities") or []) if isinstance(item, list) and len(item) > 1}
            has_confirmed_caller = bool(src_ids & confirmed_procs)
            
            # 公理 A：失陷进程树发起的子命令派生 (execve / clone)
            if has_confirmed_caller and sc in ("execve", "clone") and (dst.startswith("/") or dst.startswith(".")):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["reason"] = "通用因果闭包：失陷进程树发起的子命令派生"
                final_confirmed[k] = rec
                promoted_keys.add(k)
                promoted_this_round += 1
                for m in (e.get("member_processes") or ()):
                    confirmed_procs.add(str(m))
                for item in (e.get("dst_identities") or []):
                    if isinstance(item, list) and len(item) > 1:
                        confirmed_procs.add(str(item[1]))
                if e.get("process_id"):
                    confirmed_procs.add(str(e.get("process_id")))
                continue
                
            # 公理 B：失陷进程对临时可写空间的载荷落地与配置修改
            if has_confirmed_caller and sc in ("mkdir", "chmod", "write", "open") and any(dst.startswith(p) for p in ("/tmp/", "/var/tmp/", "/dev/shm/")):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["reason"] = "通用因果闭包：失陷进程临时空间载荷与环境配置"
                final_confirmed[k] = rec
                promoted_keys.add(k)
                promoted_this_round += 1
                dst_f = str(e.get("dst") or "")
                if dst_f.startswith("/"):
                    written_files.add(dst_f)
                continue
                
        if promoted_this_round == 0:
            break

    # 8.4 写后读 (RAW) 污染装载公理
    for e in clean_unexcluded:
        k = _key(e)
        if k in promoted_keys:
            continue
        src = str(e.get("src") or "")
        sc = str(e.get("syscall") or "")
        if sc in ("read", "open", "mmap") and src in written_files:
            rec = dict(e)
            rec["origin"] = "confirmed"
            rec["class"] = "story"
            rec["reason"] = "通用因果公理：前序失陷会话落盘载荷的读取与装载 (RAW)"
            final_confirmed[k] = rec
            promoted_keys.add(k)

    # 8.5 通用匿名管道双端对齐映射与闭环判定
    pipe_writers: Dict[str, Set[str]] = {}
    pipe_readers: Dict[str, Set[str]] = {}

    all_candidate_edges = list(clean_unexcluded) + list(final_confirmed.values())
    for e in all_candidate_edges:
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        
        if "pipe:" in dst and sc in ("write", "sendto", "sendmsg", "ioctl"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in (e.get("src_identities") or []):
                if isinstance(item, list) and len(item) > 1:
                    caller_procs.add(str(item[1]))
            if e.get("process_id"):
                caller_procs.add(str(e.get("process_id")))
            pipe_writers.setdefault(dst, set()).update(caller_procs)
            
        if "pipe:" in src and sc in ("read", "recvfrom", "recvmsg", "ioctl"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in (e.get("dst_identities") or []):
                if isinstance(item, list) and len(item) > 1:
                    caller_procs.add(str(item[1]))
            if e.get("process_id"):
                caller_procs.add(str(e.get("process_id")))
            pipe_readers.setdefault(src, set()).update(caller_procs)

    valid_pipes = set()
    for pipe in set(pipe_writers.keys()) & set(pipe_readers.keys()):
        has_writer = bool(pipe_writers[pipe] & confirmed_procs)
        has_reader = bool(pipe_readers[pipe] & confirmed_procs)
        if has_writer and has_reader:
            valid_pipes.add(pipe)

    # 确诊子进程向有效双端管道的回传写入纳入确认
    for e in clean_unexcluded:
        k = _key(e)
        if k in promoted_keys:
            continue
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        if dst in valid_pipes and sc in ("write", "sendto", "sendmsg"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in (e.get("src_identities") or []):
                if isinstance(item, list) and len(item) > 1:
                    caller_procs.add(str(item[1]))
            if e.get("process_id"):
                caller_procs.add(str(e.get("process_id")))
            if bool(caller_procs & confirmed_procs):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["reason"] = "通用因果公理：失陷命令向有效管道回传输出"
                final_confirmed[k] = rec
                promoted_keys.add(k)

    # 8.6 通用伴随边纯化与单端悬空管道剥离
    purified_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    unpromoted_ambiguous = []

    for k, e in final_confirmed.items():
        if k in anchor_keys:
            purified_confirmed[k] = e
            continue
            
        # 纯化 1：被动动态链接与系统只读配置
        if is_passive_kernel_runtime_edge(e):
            rec = dict(e)
            rec["origin"] = "kept"
            unpromoted_ambiguous.append(rec)
            continue
            
        # 纯化 2：单端悬空或未闭环匿名管道
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        if "pipe:" in src or "pipe:" in dst:
            p_obj = src if "pipe:" in src else dst
            if p_obj not in valid_pipes:
                rec = dict(e)
                rec["origin"] = "kept"
                unpromoted_ambiguous.append(rec)
                continue
                
        # 纯化 3：完全无关的系统级独立后台维护任务
        if any(token in src or token in dst for token in ("unit-root", "dpkg", "apt", "systemd-timedated", "fstrim", "update-notifier", "motd", "fwupdmgr", "system-generators")):
            rec = dict(e)
            rec["origin"] = "kept"
            unpromoted_ambiguous.append(rec)
            continue

        purified_confirmed[k] = e

    # 9. 后置剪枝
    final_confirmed_map, debris_pruned = DebrisPrune(anchor_triples).apply(
        purified_confirmed, candidate_pool=pool.raw
    )
    if CONTENT_BINDING or SPLIT_EVIDENCE:
        for k, e in final_confirmed_map.items():
            ev = rule_evidence_map.get(k)
            if ev:
                e["evidence_motif_id"] = ev["motif_id"]
    final_unexcluded = list(unpromoted_ambiguous) + list(pruned_background) + list(debris_pruned) + [e for e in remaining_ambiguous if _key(e) not in final_confirmed_map]
    
    from routing.route import RouteOutcome
    outcome = RouteOutcome(
        confirmed=final_confirmed_map,
        unexcluded=final_unexcluded,
        excluded=[e for e in excluded_edges if _key(e) not in final_confirmed_map],
        audit={
            "mode": "hybrid-rule-context-v4",
            "pruned_count": len(pruned_background),
            "ambiguous_count": len(ambiguous_candidates),
            "llm_confirmed_count": len(llm_confirmed),
            "anchor_confirmed_count": len(anchor_keys),
            "debris_pruned_count": len(debris_pruned),
        }
    )
    
    # 10. 生成报告
    elapsed = time.time() - t0
    report = build_report_from_outcome(
        outcome, scenario_name,
        elapsed_seconds=elapsed,
        llm_calls=deps.budget.calls,
        llm_enabled=True,
        library={
            "path": audit.get("path"),
            "mode": "hybrid-rule-context-v4",
            "n_selected": len(admitted),
            "n_candidates": len(audit["motifs"]),
            "fold_library": True,
            "test_scenario": scenario_name,
            "variant": VARIANT,
            "motif_evidence": USE_MOTIF_EVIDENCE,
            "real_2hop": REAL_2HOP,
            "content_binding": CONTENT_BINDING,
            "split_evidence": SPLIT_EVIDENCE,
            "motif_candidates": len(motif_candidates),
            "residual_candidates": len(residual_candidates),
            "anchor_pair_confirm": ANCHOR_PAIR_CONFIRM,
            "subgraph_evidence": SUBGRAPH_EVIDENCE,
            "structured_output": STRUCTURED_OUTPUT,
        }
    )
    
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    save_report(report, out_json)
    
    # 11. 官方评分
    gt_path = str(REPO_ROOT / f"groundtruth/{scenario_name}.groundtruth.json")
    ev = scorer.evaluate(out_json, gt_path, scenario=scenario_name)
    
    recall_pct = ev["recall"] * 100
    precision_pct = ev["precision"] * 100
    print(f"[{time.strftime('%H:%M:%S')}] <<< 完成场景: {scenario_name} | 召回: {recall_pct:.1f}% ({ev['steps_hit']}/{ev['steps_total']}) | 查准: {precision_pct:.1f}% ({ev['correct_edges']}/{ev['reported_triples']}) | 确认边数: {len(final_confirmed_map)} | 耗时: {elapsed:.1f}s | LLM调用: {deps.budget.calls}次")
    
    return {
        "scenario": scenario_name,
        "recall": ev["recall"],
        "steps_hit": ev["steps_hit"],
        "steps_total": ev["steps_total"],
        "must_hit": ev["must_hits"],
        "must_total": ev["gt_edges"],
        "rules_hit": ev["rule_hits"],
        "rules_total": ev["rules_total"],
        "precision": ev["precision"],
        "correct_edges": ev["correct_edges"],
        "reported_triples": ev["reported_triples"],
        "confirmed_edges": len(final_confirmed_map),
        "llm_calls": deps.budget.calls,
        "elapsed": elapsed,
        "report_file": out_json,
    }

def main():
    # 场景清单以 config/scenarios.json 为唯一来源；按场景名前缀数字排序，保持历史执行顺序。
    scenarios = sorted(
        cfg.available_scenarios(),
        key=lambda s: int(s.split("_", 1)[0]) if s.split("_", 1)[0].isdigit() else 10**9,
    )
    
    print("=" * 80)
    print("开始全量 10 场景自动化评测 (v4 方案)")
    print(f"评测场景数: {len(scenarios)}")
    print(f"开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    total_t0 = time.time()
    results = []
    
    for idx, sc in enumerate(scenarios, 1):
        fold_lib = str(REPO_ROOT / f"output/navigator-baseline/distill/fold-libraries/{sc}.json")
        out_json = str(REPO_ROOT / f"tmp/rule_context_runs/{sc}_v4.json")
        try:
            res = run_single_scenario(sc, fold_lib, out_json)
            results.append(res)
        except Exception as err:
            import traceback
            print(f"场景 {sc} 执行异常: {err}")
            traceback.print_exc()
            results.append({
                "scenario": sc,
                "error": str(err),
            })
            
    total_elapsed = time.time() - total_t0
    
    # 汇总微平均
    sum_hit = sum(r.get("steps_hit", 0) for r in results)
    sum_total_steps = sum(r.get("steps_total", 0) for r in results)
    sum_correct = sum(r.get("correct_edges", 0) for r in results)
    sum_reported = sum(r.get("reported_triples", 0) for r in results)
    sum_calls = sum(r.get("llm_calls", 0) for r in results)
    
    micro_recall = sum_hit / sum_total_steps if sum_total_steps else 0.0
    micro_precision = sum_correct / sum_reported if sum_reported else 0.0
    
    summary = {
        "mode": "hybrid-rule-context-v4",
        "total_elapsed": total_elapsed,
        "scenarios_count": len(scenarios),
        "micro": {
            "hit": sum_hit,
            "total": sum_total_steps,
            "recall": micro_recall,
            "correct": sum_correct,
            "reported": sum_reported,
            "precision": micro_precision,
            "calls": sum_calls,
            "elapsed": total_elapsed,
        },
        "results": results,
    }
    
    summary_path = str(REPO_ROOT / "tmp/rule_context_runs/summary_v4.json")
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        
    print("\n" + "=" * 80)
    print(f"全量 10 场景评测完成！总耗时: {total_elapsed:.1f} 秒 | 汇总已保存至: {summary_path}")
    print(f"微平均召回率: {micro_recall * 100:.2f}% ({sum_hit}/{sum_total_steps})")
    print(f"微平均查准率: {micro_precision * 100:.2f}% ({sum_correct}/{sum_reported})")
    print(f"大模型总调用: {sum_calls} 次")
    print("=" * 80)

if __name__ == "__main__":
    main()
