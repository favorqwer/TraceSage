"""解析器需要维护的活状态。除这一层外，所有模块都是纯函数。"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.snapshots import StateSnapshot
from .containers import ContainerState
from .fds import FdTable
from .proc import ProcState


@dataclass(slots=True)
class State:
    host_id: str
    proc: ProcState
    fds: FdTable
    containers: ContainerState

    @classmethod
    def build(cls, host_id: str, fd_cap: int = 4096) -> "State":
        return cls(
            host_id=host_id,
            proc=ProcState(host_id),
            fds=FdTable(cap=fd_cap),
            containers=ContainerState(),
        )

    def snapshot(self) -> StateSnapshot:
        containers = [
            {
                "id": c.id,
                "name": c.name,
                "image": c.image,
                "container_privileged": c.privileged,
                "container_host_root_rw": c.host_root_rw,
                "observations": c.observations,
                "backfills": c.backfills,
            }
            for c in self.containers.listing()
        ]
        return StateSnapshot(
            proc=self.proc.stats(),
            fds=self.fds.stats(),
            containers=containers,
        )
