"""审计值对象：由采集适配器产出，报告消费。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Audit:
    total_rows: int
    total_by_type: dict[str, int]
    pid_rows: int
    pid_by_type: dict[str, int]
    max_num: int

    def dropped_by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for name, total in self.total_by_type.items():
            diff = total - self.pid_by_type.get(name, 0)
            if diff > 0:
                out[name] = diff
        return out
