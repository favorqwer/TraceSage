"""阶段 5：因果公理链路补全与伴随边纯化。"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from core.axioms import heal_and_purify_causal_closure

# POSIX / Linux 标准系统调用：无物理数据载荷的纯只读元数据与目录探测
PROBE_SYSCALLS = {
    "stat", "lstat", "fstat", "access", "faccessat",
    "readlink", "getdents", "getdents64"
}


def run(
    llm_confirmed: List[Dict[str, Any]],
    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    clean_unexcluded: List[Dict[str, Any]],
    excluded_edges: List[Dict[str, Any]],
    anchor_keys: Set[Tuple[Any, Any, Any]],
) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
    """对 LLM 确认边执行通用因果变异检验、只读探测降噪与因果闭包补全纯化。"""
    # 1. 汇总全量候选边以提取物理突变进程与写入文件
    mutating_procs: Set[str] = set()
    written_files: Set[str] = set()
    all_candidate_edges = (
        list(clean_unexcluded)
        + list(final_confirmed.values())
        + list(llm_confirmed)
    )

    for e in all_candidate_edges:
        sc = str(e.get("syscall") or "")
        rels = set(e.get("rels") or ())
        d = str(e.get("dst") or "")

        pids = (
            [str(e.get("process_id") or "")]
            + [str(m) for m in (e.get("member_processes") or ())]
            + [
                str(item[1])
                for item in (e.get("src_identities") or [])
                if isinstance(item, list) and len(item) > 1
            ]
            + [
                str(item[1])
                for item in (e.get("dst_identities") or [])
                if isinstance(item, list) and len(item) > 1
            ]
        )

        is_mut = False
        if sc in ("execve", "clone", "fork") or (rels & {"spawn"}):
            is_mut = True
        elif sc in ("connect", "sendto", "sendmsg") or (rels & {"p2n"}):
            if not any(loop in d for loop in ("127.0.0.1", "::1", "localhost")):
                is_mut = True
        elif sc in ("write", "creat", "truncate", "rename", "unlink", "chmod") or (rels & {"p2f"}):
            if d.startswith("/") and not any(p in d for p in ("/dev/", "pipe:")):
                is_mut = True
                written_files.add(d)

        if is_mut:
            for p in pids:
                if p:
                    mutating_procs.add(p)

    # 2. 按聚合原因进行分组以度量束的多样性基数
    bundle_groups = defaultdict(list)
    for e in llm_confirmed:
        vr = e.get("verdict_reason") or e.get("reason") or "default"
        bundle_groups[vr].append(e)

    # 3. 初始确认集合初始化（保留已有锚点并使用复合键区分多进程实例）
    initial_confirmed: Dict[Any, Dict[str, Any]] = {}
    for k, e in final_confirmed.items():
        comp_k = (e.get("src"), e.get("syscall"), e.get("dst"), str(e.get("process_id") or ""))
        initial_confirmed[comp_k] = e

    unpromoted_llm: List[Dict[str, Any]] = []

    for vr, edges in bundle_groups.items():
        distinct_objs = len(set(e.get("dst") for e in edges) | set(e.get("src") for e in edges))

        for e in edges:
            k = edge_key(e)
            if k in anchor_keys or e.get("class") == "anchor":
                comp_k = (e.get("src"), e.get("syscall"), e.get("dst"), str(e.get("process_id") or ""))
                initial_confirmed[comp_k] = e
                continue

            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            sc = str(e.get("syscall") or "")

            # 方法三准则 1：无物理载荷的纯只读元数据探测过滤（POSIX 规范）
            if sc in PROBE_SYSCALLS:
                rec = dict(e)
                rec["origin"] = "kept"
                rec["reason"] = "通用因果验证：无物理数据载荷的只读元数据探测系统调用，降噪归入未排除"
                unpromoted_llm.append(rec)
                continue

            # 方法三准则 2：Linux XDG 标准临时缓存且无前序写入的边过滤
            is_xdg_cache = "/.cache/" in dst or "/.cache/" in src
            if is_xdg_cache and (dst not in written_files and src not in written_files):
                rec = dict(e)
                rec["origin"] = "kept"
                rec["reason"] = "通用因果验证：Linux XDG标准临时缓存访问且无前序写入突变，降噪归入未排除"
                unpromoted_llm.append(rec)
                continue

            # 方法一准则 3：高基数集合突变检验（大聚合束非全同态准入）
            if distinct_objs >= 10:
                pids = (
                    [str(e.get("process_id") or "")]
                    + [str(m) for m in (e.get("member_processes") or ())]
                    + [
                        str(item[1])
                        for item in (e.get("src_identities") or [])
                        if isinstance(item, list) and len(item) > 1
                    ]
                    + [
                        str(item[1])
                        for item in (e.get("dst_identities") or [])
                        if isinstance(item, list) and len(item) > 1
                    ]
                )
                has_mutation = any(p in mutating_procs for p in pids if p)
                if not has_mutation:
                    rec = dict(e)
                    rec["origin"] = "kept"
                    rec["reason"] = "通用因果验证：高基数聚合束成员缺乏下游物理状态突变，降级归入未排除"
                    unpromoted_llm.append(rec)
                    continue

            comp_k = (e.get("src"), e.get("syscall"), e.get("dst"), str(e.get("process_id") or ""))
            initial_confirmed[comp_k] = e

    # 4. 执行因果公理全链路补全与纯化
    purified_confirmed, unpromoted_ambiguous = heal_and_purify_causal_closure(
        initial_confirmed=initial_confirmed,
        clean_unexcluded=clean_unexcluded,
        excluded_edges=excluded_edges,
        anchor_keys=anchor_keys,
    )

    # 5. 归一化键为主干标准 3 元组键 (src, syscall, dst)，并将未晋升的边汇入 unpromoted_ambiguous
    final_confirmed_3tuple: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {
        edge_key(e): e for e in purified_confirmed.values()
    }
    all_unpromoted = list(unpromoted_ambiguous) + unpromoted_llm

    return final_confirmed_3tuple, all_unpromoted
