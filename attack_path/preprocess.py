"""研究点二第一阶段前置处理：无效事件清洗、路径规约、外网拆向与 poi 反向线性裁剪。

全部计算均基于研究点一导出的事件明细（ScenarioEvents）在内存中完成，零 Neo4j 依赖。
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
import importlib
import posixpath
from typing import Any, Callable, Optional

from attack_path._bridge import ensure_attack_graph_on_path
from attack_path.loader import EntityAttr, RawEvent, ScenarioEvents

_READ_ACTIONS = frozenset({"read", "recv"})
_TERMINATION_ACTIONS = frozenset({"exit", "wait"})
_NON_PRODUCER_FILE_ACTIONS = frozenset({"unlink", "chroot", "umount"})
_RECREATE_FILE_ACTIONS = frozenset({"create", "write", "mmap_write", "rename", "link"})
_SPECIAL_FILE_PREFIXES = ("pipe:", "unix:", "memfd:", "socket:")
# Linux 非阻塞 TCP 套接字调用 connect() 时返回 -EINPROGRESS (-115) 表示后台握手已正常发起，不是连接失败。
_NONBLOCK_CONNECT_INPROGRESS = -115


def _load_attack_graph_helpers() -> tuple[frozenset[str], Callable[[Any], bool], Callable[[Any], tuple[str, str]]]:
    """复用研究点一既有的无状态公共枢纽清单与网络端点解析函数。"""
    ensure_attack_graph_on_path()
    tp = importlib.import_module("core.stages.temporal_pruning")
    net = importlib.import_module("domain.network")
    stateless_hubs = frozenset(getattr(tp, "_STATELESS_HUBS", ()))
    is_dns = getattr(net, "is_loopback_dns_resolver")
    parse_ep = getattr(net, "parse_endpoint")
    return stateless_hubs, is_dns, parse_ep


STATELESS_HUBS, is_loopback_dns_resolver, parse_endpoint = _load_attack_graph_helpers()


@dataclass(frozen=True)
class PreprocessConfig:
    """第一阶段清洗与反向裁剪配置项。"""

    drop_failed_calls: bool = True
    drop_zero_byte_reads: bool = True
    drop_termination_actions: bool = True
    drop_missing_timestamps: bool = True
    normalize_file_paths: bool = True
    resolve_chroot_aliases: bool = True
    split_external_network: bool = True
    block_stateless_hubs: bool = True
    truncate_recreated_unlinked_files: bool = True
    prune_backward_from_poi: bool = True


@dataclass(frozen=True)
class PreprocessStats:
    """清洗与反向裁剪全流程可审计统计项。"""

    input_events: int
    cleaned_events: int
    pruned_events: int
    poi_events_count: int
    dropped_failed: int = 0
    dropped_zero_read: int = 0
    dropped_termination: int = 0
    dropped_missing_ts: int = 0
    normalized_file_refs: int = 0
    chroot_aliases_resolved: int = 0
    external_net_in_events: int = 0
    external_net_out_events: int = 0
    loopback_net_events: int = 0
    stateless_hub_blocked_entities: int = 0
    unlink_truncations: int = 0
    dropped_unreachable_from_poi: int = 0
    input_confirmed_events: int = 0
    pruned_confirmed_events: int = 0
    input_unexcluded_events: int = 0
    pruned_unexcluded_events: int = 0

    @property
    def overall_reduction_ratio(self) -> float:
        if self.input_events <= 0:
            return 0.0
        return 1.0 - (self.pruned_events / self.input_events)


@dataclass(frozen=True)
class PreprocessedScenario:
    """经过清洗、路径规约、外网拆向与 poi 反向裁剪后的场景事件集。"""

    scenario: str
    database: str
    poi_events: tuple[str, ...]
    cleaned_events: tuple[RawEvent, ...]
    events: tuple[RawEvent, ...]
    entities: dict[str, EntityAttr]
    blocked_hub_entity_ids: frozenset[str]
    stats: PreprocessStats
    alias_rewrites: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)


def _split_container_path(file_key: str) -> tuple[str, str]:
    """拆出容器文件键可能携带的 `<container_id>|` 前缀，保留容器隔离边界。"""
    if "|" in file_key:
        prefix, _, rest = file_key.partition("|")
        if rest.startswith("/") or rest.startswith(".") or "/" in rest:
            return prefix, rest
    return "", file_key


def _join_container_path(container_prefix: str, path: str) -> str:
    return f"{container_prefix}|{path}" if container_prefix else path


def canonicalize_file_key(file_key: str) -> str:
    """对 File 键执行确定性 POSIX 规范化，保留特殊对象前缀与容器前缀。"""
    if not file_key:
        return file_key
    container_prefix, path = _split_container_path(file_key)
    if path.startswith(_SPECIAL_FILE_PREFIXES):
        return file_key
    if "/" not in path and path not in (".", ".."):
        return file_key
    norm = posixpath.normpath(path)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return _join_container_path(container_prefix, norm)


def _extract_ip(endpoint_part: str) -> str:
    part = endpoint_part.strip()
    if not part:
        return ""
    if part.startswith("["):
        end = part.find("]")
        return part[1:end] if end != -1 else part
    if part.count(":") == 1:
        return part.split(":", 1)[0]
    return part


def is_loopback_network_key(net_key: str) -> bool:
    """判定网络连接端点两端是否均位于本机回环地址（127.0.0.0/8、::1、localhost）。"""
    left, right = parse_endpoint(net_key)
    if not left or not right:
        return False
    ips = (_extract_ip(left), _extract_ip(right))
    if not all(ips):
        return False
    return all(ip == "localhost" or ip == "::1" or ip.startswith("127.") for ip in ips)


def _is_stateless_hub_entity(kind: str, key: str) -> bool:
    if kind == "File":
        _, path = _split_container_path(key)
        return path in STATELESS_HUBS
    if kind in ("Network", "NetworkIn", "NetworkOut"):
        return bool(is_loopback_dns_resolver(key))
    return False


def _collect_chroot_roots(events: list[RawEvent]) -> dict[str, list[tuple[int, str]]]:
    """收集每个进程实例成功执行的 chroot 记录（按时间排序）。"""
    roots: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for ev in events:
        if ev.rel != "p2f" or ev.action != "chroot":
            continue
        if ev.result is not None and ev.result < 0:
            continue
        if ev.start_ns is None:
            continue
        _, root_path = _split_container_path(ev.dst_key)
        root_norm = posixpath.normpath(root_path)
        if not root_norm.startswith("/") or root_norm == "/":
            continue
        roots[ev.src_key].append((ev.start_ns, root_norm))
    for items in roots.values():
        items.sort(key=lambda item: item[0])
    return roots


def _active_chroot_root(proc_roots: list[tuple[int, str]], ts: int) -> Optional[str]:
    active: Optional[str] = None
    for chroot_ts, root in proc_roots:
        if chroot_ts <= ts:
            active = root
        else:
            break
    return active


def _maybe_resolve_chroot_key(
    file_key: str,
    host_id: str,
    chroot_root: str,
    known_host_file_keys: set[tuple[str, str]],
) -> Optional[str]:
    """仅当 chroot 后的路径为相对路径、或拼接后确实命中同主机同容器已有文件时才改写。"""
    container_prefix, path = _split_container_path(file_key)
    if path.startswith(_SPECIAL_FILE_PREFIXES):
        return None
    if path == chroot_root or path.startswith(chroot_root + "/"):
        return None

    if not path.startswith("/"):
        joined = posixpath.normpath(posixpath.join(chroot_root, path))
        return _join_container_path(container_prefix, joined)

    candidate_path = posixpath.normpath(chroot_root + path)
    candidate_key = _join_container_path(container_prefix, candidate_path)
    if (host_id, candidate_key) in known_host_file_keys:
        return candidate_key
    return None


def _ensure_entity(
    entities: dict[str, EntityAttr],
    kind: str,
    key: str,
    *,
    template: Optional[EntityAttr] = None,
    host_id: str = "",
    file_type: Optional[str] = None,
) -> None:
    eid = f"{kind}:{key}"
    if eid in entities:
        return
    if template is not None:
        entities[eid] = replace(template, entity_id=eid, kind=kind, key=key, content=key)
    else:
        entities[eid] = EntityAttr(
            entity_id=eid,
            kind=kind,
            key=key,
            content=key,
            host_id=host_id,
            file_type=file_type,
        )


def _compute_file_epoch_starts(candidates: list[RawEvent]) -> list[int]:
    """单遍前向计算文件入边每个位置所属的“删除-重建”有效分代起点索引。

    若文件被 unlink 删除后又出现 create/write/rename/mmap_write/link 重建，
    则重建之后的读事件只追溯到本次 unlink 之后的写入；若 unlink 后未重建，
    保留对删除前已打开文件句柄的历史写入追溯能力。
    """
    epoch_starts: list[int] = [0] * len(candidates)
    cur_epoch_start = 0
    last_unlink_idx = -1
    for i, ev in enumerate(candidates):
        if ev.action == "unlink":
            last_unlink_idx = i
        elif ev.action in _RECREATE_FILE_ACTIONS and last_unlink_idx >= cur_epoch_start:
            cur_epoch_start = last_unlink_idx + 1
        epoch_starts[i] = cur_epoch_start
    return epoch_starts


def _backward_prune_from_poi(
    events: list[RawEvent],
    poi_ids: set[str],
    blocked_hubs: set[str],
    *,
    truncate_recreated_unlinked: bool,
) -> tuple[list[RawEvent], int]:
    """从告警终点 poi 沿实体时间线做单遍线性反向时序可达裁剪（零平方边展开）。"""
    by_id = {ev.id: ev for ev in events}
    missing = [pid for pid in sorted(poi_ids) if pid not in by_id]
    if missing:
        raise ValueError(f"反向裁剪前缺失告警终点事件：{missing}")

    incoming: dict[str, list[RawEvent]] = defaultdict(list)
    for ev in events:
        if ev.start_ns is None:
            continue
        if ev.src_entity_id in blocked_hubs or ev.dst_entity_id in blocked_hubs:
            continue
        # unlink / chroot / umount 本身不向文件提供可供后续读取的内容载荷，
        # 但文件实体上的 unlink 仍需记录，用于识别“删除后重新创建”的版本边界。
        incoming[ev.dst_entity_id].append(ev)

    file_epoch_starts: dict[str, list[int]] = {}
    for eid, ev_list in incoming.items():
        ev_list.sort(key=lambda e: (e.start_ns if e.start_ns is not None else -1, e.event_id))
        if truncate_recreated_unlinked and eid.startswith("File:"):
            file_epoch_starts[eid] = _compute_file_epoch_starts(ev_list)

    visited: set[str] = set(poi_ids)
    pending: deque[RawEvent] = deque(by_id[pid] for pid in sorted(poi_ids))
    # 全部实体按 (实体或文件分代起点) 维护单调递增游标，确保每条入边至多扫描一次（严格线性复杂度）。
    non_file_cursors: dict[str, int] = {}
    file_epoch_cursors: dict[tuple[str, int], int] = {}
    truncated_epochs_seen: set[tuple[str, int]] = set()
    unlink_truncations = 0

    while pending:
        current = pending.popleft()
        src_eid = current.src_entity_id
        if src_eid in blocked_hubs:
            continue
        if not current.src_host:
            continue
        cur_end = current.end_ns if current.end_ns is not None else current.start_ns
        if cur_end is None:
            continue

        candidates = incoming.get(src_eid)
        if not candidates:
            continue

        if current.src_kind == "File" and truncate_recreated_unlinked:
            # 二分定位 start_ns <= cur_end 的最右位置 top，再仅在所属分代区间 [ep_start, top] 推进游标。
            lo, hi = 0, len(candidates)
            while lo < hi:
                mid = (lo + hi) // 2
                ts = candidates[mid].start_ns
                if ts is not None and ts <= cur_end:
                    lo = mid + 1
                else:
                    hi = mid
            top = lo - 1
            if top < 0:
                continue
            ep_start = file_epoch_starts[src_eid][top]
            if ep_start > 0 and (src_eid, ep_start) not in truncated_epochs_seen:
                truncated_epochs_seen.add((src_eid, ep_start))
                unlink_truncations += 1
            cursor_key = (src_eid, ep_start)
            cursor = file_epoch_cursors.get(cursor_key, ep_start)
            while cursor <= top:
                prev = candidates[cursor]
                if prev.dst_host == current.src_host and prev.action not in _NON_PRODUCER_FILE_ACTIONS:
                    if prev.id not in visited:
                        visited.add(prev.id)
                        pending.append(prev)
                cursor += 1
            if cursor > file_epoch_cursors.get(cursor_key, ep_start):
                file_epoch_cursors[cursor_key] = cursor
        else:
            cursor = non_file_cursors.get(src_eid, 0)
            while cursor < len(candidates):
                prev = candidates[cursor]
                if prev.start_ns is not None and prev.start_ns > cur_end:
                    break
                if prev.dst_host == current.src_host and prev.action not in _NON_PRODUCER_FILE_ACTIONS:
                    if prev.id not in visited:
                        visited.add(prev.id)
                        pending.append(prev)
                cursor += 1
            non_file_cursors[src_eid] = cursor

    kept = [ev for ev in events if ev.id in visited]
    return kept, unlink_truncations


def preprocess_scenario(
    scenario_events: ScenarioEvents,
    *,
    config: Optional[PreprocessConfig] = None,
) -> PreprocessedScenario:
    """对单个场景的事件明细执行第 1 步清洗规约与第 2 步 poi 反向线性裁剪。"""
    cfg = config or PreprocessConfig()
    poi_set = set(scenario_events.poi_events)
    if not poi_set:
        raise ValueError(f"场景 {scenario_events.scenario} 缺少 poi_events 告警终点")

    input_events = list(scenario_events.events)
    input_confirmed = sum(1 for e in input_events if e.report_status == "confirmed")
    input_unexcluded = sum(1 for e in input_events if e.report_status != "confirmed")

    # 1. 过滤无效事件（强保护 poi_events，绝不静默丢弃告警终点）
    dropped_failed = 0
    dropped_zero_read = 0
    dropped_termination = 0
    dropped_missing_ts = 0
    filtered: list[RawEvent] = []

    for ev in input_events:
        is_poi = ev.id in poi_set
        if ev.start_ns is None:
            if is_poi:
                raise ValueError(f"场景 {scenario_events.scenario} 的告警终点事件 {ev.id} 缺失 start_ns")
            if cfg.drop_missing_timestamps:
                dropped_missing_ts += 1
                continue
        if not is_poi:
            if cfg.drop_failed_calls and ev.result is not None and ev.result < 0:
                if not (ev.action == "connect" and ev.result == _NONBLOCK_CONNECT_INPROGRESS):
                    dropped_failed += 1
                    continue
            if cfg.drop_zero_byte_reads and ev.action in _READ_ACTIONS and ev.result == 0:
                dropped_zero_read += 1
                continue
            if cfg.drop_termination_actions and ev.action in _TERMINATION_ACTIONS:
                dropped_termination += 1
                continue
        filtered.append(ev)

    entities: dict[str, EntityAttr] = dict(scenario_events.entities)

    # 2. POSIX 路径规范化（保留容器前缀与特殊文件类型）
    normalized_file_refs = 0
    if cfg.normalize_file_paths:
        norm_events: list[RawEvent] = []
        for ev in filtered:
            new_src_key = ev.src_key
            new_dst_key = ev.dst_key
            changed = False
            if ev.src_kind == "File":
                cand = canonicalize_file_key(ev.src_key)
                if cand != ev.src_key:
                    old_ent = entities.get(ev.src_entity_id)
                    new_src_key = cand
                    _ensure_entity(entities, "File", cand, template=old_ent, host_id=ev.src_host, file_type=ev.src_file_type)
                    normalized_file_refs += 1
                    changed = True
            if ev.dst_kind == "File":
                cand = canonicalize_file_key(ev.dst_key)
                if cand != ev.dst_key:
                    old_ent = entities.get(ev.dst_entity_id)
                    new_dst_key = cand
                    _ensure_entity(entities, "File", cand, template=old_ent, host_id=ev.dst_host, file_type=ev.dst_file_type)
                    normalized_file_refs += 1
                    changed = True
            norm_events.append(replace(ev, src_key=new_src_key, dst_key=new_dst_key) if changed else ev)
        filtered = norm_events

    # 3. 安全 chroot 路径别名还原（仅基于事件中客观观测到的 chroot 记录）
    chroot_aliases_resolved = 0
    alias_rewrites: list[tuple[str, str, str]] = []
    if cfg.resolve_chroot_aliases:
        chroot_roots = _collect_chroot_roots(filtered)
        if chroot_roots:
            known_host_file_keys: set[tuple[str, str]] = set()
            for ev in filtered:
                if ev.src_kind == "File":
                    known_host_file_keys.add((ev.src_host, ev.src_key))
                if ev.dst_kind == "File":
                    known_host_file_keys.add((ev.dst_host, ev.dst_key))

            resolved_events: list[RawEvent] = []
            for ev in filtered:
                if ev.start_ns is None or ev.action == "chroot":
                    resolved_events.append(ev)
                    continue
                if ev.rel == "p2f" and ev.src_key in chroot_roots:
                    root = _active_chroot_root(chroot_roots[ev.src_key], ev.start_ns)
                    if root:
                        new_key = _maybe_resolve_chroot_key(ev.dst_key, ev.dst_host, root, known_host_file_keys)
                        if new_key and new_key != ev.dst_key:
                            old_ent = entities.get(ev.dst_entity_id)
                            _ensure_entity(entities, "File", new_key, template=old_ent, host_id=ev.dst_host, file_type=ev.dst_file_type)
                            alias_rewrites.append((ev.id, ev.dst_key, new_key))
                            chroot_aliases_resolved += 1
                            resolved_events.append(replace(ev, dst_key=new_key))
                            continue
                elif ev.rel == "f2p" and ev.dst_key in chroot_roots:
                    root = _active_chroot_root(chroot_roots[ev.dst_key], ev.start_ns)
                    if root:
                        new_key = _maybe_resolve_chroot_key(ev.src_key, ev.src_host, root, known_host_file_keys)
                        if new_key and new_key != ev.src_key:
                            old_ent = entities.get(ev.src_entity_id)
                            _ensure_entity(entities, "File", new_key, template=old_ent, host_id=ev.src_host, file_type=ev.src_file_type)
                            alias_rewrites.append((ev.id, ev.src_key, new_key))
                            chroot_aliases_resolved += 1
                            resolved_events.append(replace(ev, src_key=new_key))
                            continue
                resolved_events.append(ev)
            filtered = resolved_events

    # 4. 外部网络按方向拆分为 NetworkIn / NetworkOut（本机回环保留为 Network）
    external_net_in = 0
    external_net_out = 0
    loopback_net = 0
    if cfg.split_external_network:
        split_events: list[RawEvent] = []
        for ev in filtered:
            if ev.src_kind == "Network":
                if is_loopback_network_key(ev.src_key):
                    loopback_net += 1
                    split_events.append(ev)
                else:
                    old_ent = entities.get(ev.src_entity_id)
                    _ensure_entity(entities, "NetworkIn", ev.src_key, template=old_ent, host_id=ev.src_host)
                    external_net_in += 1
                    split_events.append(replace(ev, src_kind="NetworkIn"))
            elif ev.dst_kind == "Network":
                if is_loopback_network_key(ev.dst_key):
                    loopback_net += 1
                    split_events.append(ev)
                else:
                    old_ent = entities.get(ev.dst_entity_id)
                    _ensure_entity(entities, "NetworkOut", ev.dst_key, template=old_ent, host_id=ev.dst_host)
                    external_net_out += 1
                    split_events.append(replace(ev, dst_kind="NetworkOut"))
            else:
                split_events.append(ev)
        filtered = split_events

    # 5. 收集无状态公共枢纽实体集合
    blocked_hubs: set[str] = set()
    if cfg.block_stateless_hubs:
        for ev in filtered:
            if _is_stateless_hub_entity(ev.src_kind, ev.src_key):
                blocked_hubs.add(ev.src_entity_id)
            if _is_stateless_hub_entity(ev.dst_kind, ev.dst_key):
                blocked_hubs.add(ev.dst_entity_id)

    cleaned_events = tuple(filtered)

    # 6. 从 poi 反向线性时序裁剪
    unlink_truncations = 0
    if cfg.prune_backward_from_poi:
        pruned_list, unlink_truncations = _backward_prune_from_poi(
            filtered,
            poi_set,
            blocked_hubs,
            truncate_recreated_unlinked=cfg.truncate_recreated_unlinked_files,
        )
    else:
        pruned_list = list(filtered)

    # 裁剪 entities 字典仅保留在 cleaned_events 中出现过的实体（兼顾后续断链诊断需要）
    used_eids = {ev.src_entity_id for ev in cleaned_events} | {ev.dst_entity_id for ev in cleaned_events}
    pruned_entities = {eid: ent for eid, ent in entities.items() if eid in used_eids}

    pruned_confirmed = sum(1 for e in pruned_list if e.report_status == "confirmed")
    pruned_unexcluded = sum(1 for e in pruned_list if e.report_status != "confirmed")

    stats = PreprocessStats(
        input_events=len(input_events),
        cleaned_events=len(cleaned_events),
        pruned_events=len(pruned_list),
        poi_events_count=len(poi_set),
        dropped_failed=dropped_failed,
        dropped_zero_read=dropped_zero_read,
        dropped_termination=dropped_termination,
        dropped_missing_ts=dropped_missing_ts,
        normalized_file_refs=normalized_file_refs,
        chroot_aliases_resolved=chroot_aliases_resolved,
        external_net_in_events=external_net_in,
        external_net_out_events=external_net_out,
        loopback_net_events=loopback_net,
        stateless_hub_blocked_entities=len(blocked_hubs),
        unlink_truncations=unlink_truncations,
        dropped_unreachable_from_poi=len(cleaned_events) - len(pruned_list),
        input_confirmed_events=input_confirmed,
        pruned_confirmed_events=pruned_confirmed,
        input_unexcluded_events=input_unexcluded,
        pruned_unexcluded_events=pruned_unexcluded,
    )

    return PreprocessedScenario(
        scenario=scenario_events.scenario,
        database=scenario_events.database,
        poi_events=scenario_events.poi_events,
        cleaned_events=cleaned_events,
        events=tuple(pruned_list),
        entities=pruned_entities,
        blocked_hub_entity_ids=frozenset(blocked_hubs),
        stats=stats,
        alias_rewrites=tuple(alias_rewrites),
    )
