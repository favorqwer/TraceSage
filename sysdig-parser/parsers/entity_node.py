from typing import Optional

from .file_entity import FileEntity
from .network_entity import NetworkEntity
from .process import Process


class EntityNode:
    """Wrapper that holds exactly one of {FileEntity, NetworkEntity, Process}
    and is used as a source/sink in an EventEdge."""

    def __init__(self, entity: object) -> None:
        if isinstance(entity, FileEntity):
            self._file: Optional[FileEntity] = entity
            self._network: Optional[NetworkEntity] = None
            self._process: Optional[Process] = None
        elif isinstance(entity, Process):
            self._file = None
            self._network = None
            self._process = entity
        elif isinstance(entity, NetworkEntity):
            self._file = None
            self._network = entity
            self._process = None
        else:
            raise TypeError(f"Unsupported entity type: {type(entity)}")

    @property
    def file(self) -> Optional[FileEntity]:
        return self._file

    @property
    def network(self) -> Optional[NetworkEntity]:
        return self._network

    @property
    def process(self) -> Optional[Process]:
        return self._process

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityNode):
            return NotImplemented
        return (
            self._file == other._file
            and self._network == other._network
            and self._process == other._process
        )

    def __hash__(self) -> int:
        return hash((self._file, self._network, self._process))

    def __repr__(self) -> str:
        if self._file is not None:
            return f"File({self._file.path})"
        if self._network is not None:
            return f"Network({self._network.src_and_dst_ip})"
        if self._process is not None:
            return f"Process({self._process.pid_and_name})"
        return "EntityNode(<empty>)"
