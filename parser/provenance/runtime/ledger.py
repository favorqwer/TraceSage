"""行级账本（§6-1）：每行恰好结算一次，12 个桶互斥且穷尽。

用 evt.num 做结算位图；重复结算直接抛异常。对账等式在这里检查。
"""

from __future__ import annotations

from ..core.events import EventRow
from ..core.kinds import Bucket
from ..core.snapshots import LedgerSnapshot


class Ledger:
    def __init__(self) -> None:
        self.ingested = 0
        self.abnormal = 0
        self.settled = 0
        self.counts: dict[Bucket, int] = {b: 0 for b in Bucket}
        self.reasons: dict[str, int] = {}

        self._flags = bytearray()
        self._prev_num = 0
        self.max_num = 0
        self.gap_numbers = 0
        self.gap_segments = 0
        self.max_gap = 0

    # -- 接入 ----------------------------------------------------------
    def ingest(self, row: EventRow) -> None:
        num = row.num
        if self._prev_num and num <= self._prev_num:
            raise ValueError(f"事件号回退：{num} <= {self._prev_num}（捕获损坏或拼接错误）")
        if self._prev_num:
            gap = num - self._prev_num - 1
            if gap > 0:
                self.gap_numbers += gap
                self.gap_segments += 1
                self.max_gap = max(self.max_gap, gap)
        self._prev_num = num
        self.max_num = max(self.max_num, num)
        self.ingested += 1

    def ingest_bad(self, reason: str) -> None:
        self.ingested += 1
        self.abnormal += 1
        self._add(Bucket.ABNORMAL, reason)

    # -- 结算 ----------------------------------------------------------
    def settle(self, num: int, bucket: Bucket, reason: str = "") -> None:
        if num >= len(self._flags):
            self._flags.extend(b"\x00" * (num + 1 - len(self._flags)))
        if self._flags[num]:
            raise RuntimeError(f"事件 {num} 被重复结算（账本必须互斥）")
        self._flags[num] = 1
        self.settled += 1
        self._add(bucket, reason)

    def settle_call(self, call, bucket: Bucket, reason: str = "") -> None:
        for num in call.rows:
            self.settle(num, bucket, reason)

    def _add(self, bucket: Bucket, reason: str) -> None:
        self.counts[bucket] += 1
        if reason:
            key = f"{bucket.value}:{reason}"
            self.reasons[key] = self.reasons.get(key, 0) + 1

    # -- 对账 ----------------------------------------------------------
    def check(self, pending: int) -> None:
        total = self.settled + self.abnormal + pending
        if total != self.ingested:
            raise RuntimeError(
                f"账本不平：ingested={self.ingested} 已结算={self.settled} "
                f"异常={self.abnormal} 待定={pending} 差额={self.ingested - total}"
            )

    def final(self) -> None:
        self.check(0)

    # -- 报告 ----------------------------------------------------------
    def bucket_rows(self) -> dict[str, int]:
        return {b.value: n for b, n in self.counts.items() if n}

    def top_reasons(self, limit: int = 40) -> list[tuple[str, int]]:
        return sorted(self.reasons.items(), key=lambda kv: -kv[1])[:limit]

    def gap_stats(self) -> dict[str, int]:
        return {
            "ingested_rows": self.ingested,
            "max_event_num": self.max_num,
            "missing_numbers": max(0, self.max_num - self.ingested),
            "gap_numbers": self.gap_numbers,
            "gap_segments": self.gap_segments,
            "max_gap": self.max_gap,
        }

    def snapshot(self) -> LedgerSnapshot:
        return LedgerSnapshot(
            buckets=self.bucket_rows(),
            equation={
                "ingested": self.ingested,
                "settled": self.settled,
                "abnormal": self.abnormal,
                "pending": 0,
                "balanced": self.ingested == self.settled + self.abnormal,
            },
            top_reasons=self.top_reasons(60),
            gaps=self.gap_stats(),
            ingested=self.ingested,
            settled=self.settled,
            abnormal=self.abnormal,
        )
