"""Enter/exit record pairing.

Sysdig JSONL interleaves syscall enter (>) and exit (<) records; edges are
built from the *pair*.  This module buffers unmatched enter records under
two indexes and, on each exit record, returns the matching enter record —
exact by (start_ns, tid, event), then a latency-tolerance fallback that
never consumes a wrong partner (a missing edge is preferred over a wrong
edge), and finally a synthetic dummy start so the event still flows.
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from ..jsonl.record import record_latency_ns, record_start_ns


@dataclass(frozen=True, slots=True)
class _EventKey:
    """Primary key for pairing enter/exit records: (start_ns, tid, event)."""

    start_ns: int
    tid: str
    event: str


@dataclass(frozen=True, slots=True)
class _ThreadEventKey:
    """Secondary key for pairing: (tid, event) without timestamp."""

    tid: str
    event: str


@dataclass(frozen=True, slots=True, eq=False)
class _PendingStart:
    """A buffered enter (>) record awaiting its matching exit record."""

    key: _EventKey
    thread_event_key: _ThreadEventKey
    entry: Dict[str, str]

    @property
    def start_ns(self) -> int:
        return self.key.start_ns


class PairingBuffer:
    """Buffers enter records and resolves each exit record to its start record."""

    def __init__(self, tolerance_ns: int) -> None:
        self._tolerance_ns = tolerance_ns
        self._incomplete_events: Dict[_EventKey, Deque[_PendingStart]] = {}
        self._incomplete_events_by_thread: Dict[_ThreadEventKey, Deque[_PendingStart]] = {}
        # --- pairing counters ---
        self._pairing_start_records = 0
        self._pairing_end_records = 0
        self._pairing_exact_matches = 0
        self._pairing_fallback_matched = 0
        self._pairing_fallback_rejected = 0
        self._pairing_fallback_no_partner = 0
        self._pairing_dummy_starts = 0
        self._pairing_dummy_by_event: Dict[str, int] = {}
        self._pairing_start_key_collisions = 0
        self._pairing_ambiguous_fallbacks = 0

    @property
    def tolerance_ns(self) -> int:
        return self._tolerance_ns

    def add_start(self, record: Dict[str, str]) -> None:
        """Buffer an enter (>) record under both pairing indexes."""
        self._pairing_start_records += 1
        start_ns = record_start_ns(record)
        tid = record.get("pid", "0")
        event = record.get("event", "")

        event_key = _EventKey(start_ns, tid, event)
        thread_key = _ThreadEventKey(tid, event)

        pending = _PendingStart(event_key, thread_key, record)

        if event_key in self._incomplete_events:
            self._pairing_start_key_collisions += 1
        self._incomplete_events.setdefault(event_key, deque()).append(pending)
        self._incomplete_events_by_thread.setdefault(thread_key, deque()).append(pending)

    def take_start_record(self, record: Dict[str, str]) -> Dict[str, str]:
        """Resolve an exit (<) record to its start record (real or dummy)."""
        self._pairing_end_records += 1
        end_ns = record_start_ns(record)
        latency_ns = record_latency_ns(record)
        expected_start_ns = end_ns - latency_ns
        tid = record.get("pid", "0")
        event = record.get("event", "")

        # Step 1: exact match by EventKey
        event_key = _EventKey(expected_start_ns, tid, event)
        pending = self._pop_pending_start(event_key)
        if pending is not None:
            self._pairing_exact_matches += 1
        else:
            # Step 2: merged tolerance fallback (time-checked, ambiguity-aware).
            # Replaces the former two-step fallback: the blind FIFO pop (which
            # paired exits with time-inconsistent pendings) and the unreachable
            # dict-scan tolerance level. A wrong partner is never consumed:
            # a missing edge is preferred over a wrong edge.
            pending = self._pair_by_latency_tolerance(end_ns, latency_ns, tid, event)

        if pending is None:
            # Step 3: dummy start
            # 直接构造一个最小化的合成进入记录(args=!dummy!,无 fd 上下文)。
            # 以退出记录为模板复制后仅改 4 个键；退出记录上已缓存的 args
            # 派生值（_fs/_size/_res）对 "!dummy!" 无效，必须全部清除
            # （_ns/_latency_ns 与退出记录同值，保留）。
            self._pairing_dummy_starts += 1
            self._pairing_dummy_by_event[event] = (
                self._pairing_dummy_by_event.get(event, 0) + 1
            )
            # event_key 即上方的精确匹配键（expected_start_ns/tid/event）
            dummy_record = dict(record)
            dummy_record["eventno"] = "0"
            dummy_record["direction"] = ">"
            dummy_record["args"] = "!dummy!"
            dummy_record.pop("_size", None)
            dummy_record.pop("_fs", None)
            dummy_record.pop("_res", None)
            pending = _PendingStart(event_key, _ThreadEventKey(tid, event), dummy_record)

        return pending.entry

    def _pair_by_latency_tolerance(
        self, end_ns: int, latency_ns: int, tid: str, event: str
    ) -> Optional[_PendingStart]:
        """Single fallback layer: time-checked pairing with ambiguity rejection.

        Sysdig computes evt.latency from the very two records of a pair, so the
        true partner always satisfies
        |observed_latency - declared_latency| <= tolerance.  Candidates that
        fail this check are wrong partners (their own exit was lost) and are
        deliberately left unconsumed so their real exit can still pair later.

        - 0 candidates  -> no pairing (caller falls back to a dummy start)
        - 1 candidate   -> pair
        - >1 candidates -> pair the best only if strictly better than the
          runner-up; otherwise ambiguous, nothing is consumed.
        """
        thread_dq = self._incomplete_events_by_thread.get(_ThreadEventKey(tid, event))
        if not thread_dq:
            self._pairing_fallback_no_partner += 1
            return None

        candidates: List[Tuple[_PendingStart, int]] = []
        for pending in thread_dq:
            if pending.start_ns > end_ns:
                continue
            delta = abs((end_ns - pending.start_ns) - latency_ns)
            if delta <= self._tolerance_ns:
                candidates.append((pending, delta))

        if not candidates:
            self._pairing_fallback_rejected += 1
            return None
        if len(candidates) == 1:
            self._pairing_fallback_matched += 1
            return self._pop_pending_start(candidates[0][0].key)
        candidates.sort(key=lambda x: x[1])
        if candidates[0][1] < candidates[1][1]:
            self._pairing_fallback_matched += 1
            return self._pop_pending_start(candidates[0][0].key)
        self._pairing_ambiguous_fallbacks += 1
        return None

    def _pop_pending_start(self, key: _EventKey) -> Optional[_PendingStart]:
        dq = self._incomplete_events.get(key)
        if dq is None:
            return None
        pending = dq.popleft()
        if not dq:
            del self._incomplete_events[key]
        # Also remove from thread index. _PendingStart 为 eq=False 的
        # dataclass（identity 相等），deque.remove 即按身份移除，等价于
        # 原先的 Python 级重建循环。
        thread_key = pending.thread_event_key
        thread_dq = self._incomplete_events_by_thread.get(thread_key)
        if thread_dq:
            try:
                thread_dq.remove(pending)
            except ValueError:
                pass
            if thread_dq:
                self._incomplete_events_by_thread[thread_key] = thread_dq
            else:
                del self._incomplete_events_by_thread[thread_key]
        return pending

    def print_summary(self) -> None:
        print(
            f"pairing: startRecords={self._pairing_start_records} "
            f"endRecords={self._pairing_end_records} "
            f"exactMatches={self._pairing_exact_matches} "
            f"tolerancePaired={self._pairing_fallback_matched} "
            f"toleranceRejected={self._pairing_fallback_rejected} "
            f"noPendingPartner={self._pairing_fallback_no_partner} "
            f"dummyStarts={self._pairing_dummy_starts} "
            f"startKeyCollisions={self._pairing_start_key_collisions} "
            f"ambiguousFallbacks={self._pairing_ambiguous_fallbacks}"
        )
        if self._pairing_dummy_by_event:
            top = sorted(self._pairing_dummy_by_event.items(), key=lambda x: -x[1])[:10]
            breakdown = ", ".join(f"{name}={count}" for name, count in top)
            print(f"dummy starts by syscall (top {len(top)}): {breakdown}")
