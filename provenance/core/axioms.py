"""通用因果公理推导与伴随边纯化规则集。

定义操作系统执行级因果公理：
- 进程树派生传播 (execve / clone)
- 临时空间载荷与配置文件落地 (/tmp, /var/tmp, /dev/shm)
- 写后读 (RAW) 污染装载闭环
- 匿名管道双端对齐闭合
- 被动动态加载、悬空管道与后台系统任务纯化
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set, Tuple

from domain.edge import edge_key

PASSIVE_RUNTIME_PREFIXES = (
    "/etc/ld.so.",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/usr/lib/locale/",
)

PASSIVE_SYSCALLS = ("mmap", "access", "stat", "fstat")

BACKGROUND_SERVICE_TOKENS = (
    "unit-root",
    "dpkg",
    "apt",
    "systemd-timedated",
    "fstrim",
    "update-notifier",
    "motd",
    "fwupdmgr",
    "system-generators",
)


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


def extract_confirmed_entities(
    edges: Iterable[Dict[str, Any]],
) -> Tuple[Set[str], Set[str]]:
    """从已确认边集合中提取失陷进程 ID 集合与已写入文件集合。"""
    confirmed_procs: Set[str] = set()
    written_files: Set[str] = set()

    for e in edges:
        for m in e.get("member_processes") or ():
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

    return confirmed_procs, written_files


def heal_and_purify_causal_closure(
    initial_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    clean_unexcluded: List[Dict[str, Any]],
    excluded_edges: List[Dict[str, Any]],
    anchor_keys: Set[Tuple[Any, Any, Any]],
) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
    """执行基于因果公理的全链路补全与伴随边过滤。

    返回:
        (purified_confirmed, unpromoted_ambiguous)
    """
    final_confirmed = dict(initial_confirmed)
    confirmed_procs, written_files = extract_confirmed_entities(final_confirmed.values())

    # 1. 通用单向因果树与临时空间派生拉直 (基于 src_identities 发起者判定)
    pool_candidates = list(clean_unexcluded) + [
        e for e in excluded_edges
        if e.get("syscall") in ("mkdir", "chmod", "execve", "clone", "write")
    ]
    promoted_keys = set(final_confirmed.keys())

    for _ in range(3):
        promoted_this_round = 0
        for e in pool_candidates:
            k = edge_key(e)
            if k in promoted_keys:
                continue

            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            sc = str(e.get("syscall") or "")

            src_ids = {
                str(item[1]) for item in (e.get("src_identities") or [])
                if isinstance(item, list) and len(item) > 1
            }
            has_confirmed_caller = bool(src_ids & confirmed_procs)

            # 公理 A：失陷进程树发起的子命令派生 (execve / clone)
            if (
                has_confirmed_caller
                and sc in ("execve", "clone")
                and (dst.startswith("/") or dst.startswith("."))
            ):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["reason"] = "通用因果闭包：失陷进程树发起的子命令派生"
                final_confirmed[k] = rec
                promoted_keys.add(k)
                promoted_this_round += 1
                for m in e.get("member_processes") or ():
                    confirmed_procs.add(str(m))
                for item in e.get("dst_identities") or []:
                    if isinstance(item, list) and len(item) > 1:
                        confirmed_procs.add(str(item[1]))
                if e.get("process_id"):
                    confirmed_procs.add(str(e.get("process_id")))
                continue

            # 公理 B：失陷进程对临时可写空间的载荷落地与配置修改
            if (
                has_confirmed_caller
                and sc in ("mkdir", "chmod", "write", "open")
                and any(dst.startswith(p) for p in ("/tmp/", "/var/tmp/", "/dev/shm/"))
            ):
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

    # 2. 写后读 (RAW) 污染装载公理
    for e in clean_unexcluded:
        k = edge_key(e)
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

    # 3. 通用匿名管道双端对齐映射与闭环判定
    pipe_writers: Dict[str, Set[str]] = {}
    pipe_readers: Dict[str, Set[str]] = {}

    all_candidate_edges = list(clean_unexcluded) + list(final_confirmed.values())
    for e in all_candidate_edges:
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")

        if "pipe:" in dst and sc in ("write", "sendto", "sendmsg", "ioctl"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in e.get("src_identities") or []:
                if isinstance(item, list) and len(item) > 1:
                    caller_procs.add(str(item[1]))
            if e.get("process_id"):
                caller_procs.add(str(e.get("process_id")))
            pipe_writers.setdefault(dst, set()).update(caller_procs)

        if "pipe:" in src and sc in ("read", "recvfrom", "recvmsg", "ioctl"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in e.get("dst_identities") or []:
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
        k = edge_key(e)
        if k in promoted_keys:
            continue
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        if dst in valid_pipes and sc in ("write", "sendto", "sendmsg"):
            caller_procs = {str(m) for m in (e.get("member_processes") or ())}
            for item in e.get("src_identities") or []:
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

    # 4. 通用伴随边纯化与单端悬空管道剥离
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
        if any(token in src or token in dst for token in BACKGROUND_SERVICE_TOKENS):
            rec = dict(e)
            rec["origin"] = "kept"
            unpromoted_ambiguous.append(rec)
            continue

        purified_confirmed[k] = e

    return purified_confirmed, unpromoted_ambiguous
