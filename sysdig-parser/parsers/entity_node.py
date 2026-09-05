from typing import Optional

from .file_entity import FileEntity
from .network_entity import NetworkEntity
from .process import Process


class EntityNode:
    """Wrapper that holds exactly one of {FileEntity, NetworkEntity, Process}
    and is used as a source/sink in an EventEdge."""

    def __init__(self, entity: object) -> None:
        if isinstance(entity, FileEntity):
            self._f: Optional[FileEntity] = entity
            self._n: Optional[NetworkEntity] = None
            self._p: Optional[Process] = None
        elif isinstance(entity, Process):
            self._f = None
            self._n = None
            self._p = entity
        elif isinstance(entity, NetworkEntity):
            self._f = None
            self._n = entity
            self._p = None
        else:
            raise TypeError(f"Unsupported entity type: {type(entity)}")

    @property
    def f(self) -> Optional[FileEntity]:
        return self._f

    @property
    def n(self) -> Optional[NetworkEntity]:
        return self._n

    @property
    def p(self) -> Optional[Process]:
        return self._p

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityNode):
            return NotImplemented
        return self._f == other._f and self._n == other._n and self._p == other._p

    def __hash__(self) -> int:
        return hash((self._f, self._n, self._p))

    def __repr__(self) -> str:
        if self._f is not None:
            return f"File({self._f.path})"
        if self._n is not None:
            return f"Network({self._n.src_and_dst_ip})"
        if self._p is not None:
            return f"Process({self._p.pid_and_name})"
        return "EntityNode(<empty>)"
