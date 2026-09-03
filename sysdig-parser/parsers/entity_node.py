from typing import Optional
from .file_entity import FileEntity
from .network_entity import NetworkEntity
from .process import Process


class EntityNode:
    """Wrapper that holds exactly one of {FileEntity, NetworkEntity, Process}
    and is used as a source/sink in an EventEdge."""

    def __init__(
        self,
        entity: object,
    ) -> None:
        if isinstance(entity, FileEntity):
            self._f: Optional[FileEntity] = entity
            self._n: Optional[NetworkEntity] = None
            self._p: Optional[Process] = None
            self._id = entity.uniq_id
            self._signature = entity.path
        elif isinstance(entity, Process):
            self._f = None
            self._n = None
            self._p = entity
            self._id = entity.uniq_id
            self._signature = entity.pid_and_name
        elif isinstance(entity, NetworkEntity):
            self._f = None
            self._n = entity
            self._p = None
            self._id = entity.uniq_id
            self._signature = entity.src_and_dst_ip
        else:
            raise TypeError(f"Unsupported entity type: {type(entity)}")

    @property
    def id(self) -> int:
        return self._id

    @property
    def f(self) -> Optional[FileEntity]:
        return self._f

    @property
    def n(self) -> Optional[NetworkEntity]:
        return self._n

    @property
    def p(self) -> Optional[Process]:
        return self._p

    @property
    def signature(self) -> str:
        return self._signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityNode):
            return NotImplemented
        return (
            self._id == other._id
            and self._f == other._f
            and self._n == other._n
            and self._p == other._p
            and self._signature == other._signature
        )

    def __hash__(self) -> int:
        return hash((self._id, self._f, self._n, self._p, self._signature))

    def __repr__(self) -> str:
        return f"{self._id} {self._signature}"
