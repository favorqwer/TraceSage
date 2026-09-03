from typing import Optional
from .entity_node import EntityNode


class EventEdge:
    """Directed edge in the provenance graph between two EntityNodes."""

    def __init__(
        self,
        source: EntityNode,
        sink: EntityNode,
        edge_id: int,
        optype: str,
        size: int,
        start_ns: int,
        end_ns: int,
        event_no: int,
    ) -> None:
        self._source = source
        self._sink = sink
        self._id = edge_id
        self._event = optype
        self._size = size
        self._start_ns = start_ns
        self._end_ns = end_ns
        self._event_no = event_no
        self._synthetic_reverse: Optional[bool] = None
        self._host: Optional[str] = None

    @property
    def id(self) -> int:
        return self._id

    @property
    def source(self) -> EntityNode:
        return self._source

    @property
    def sink(self) -> EntityNode:
        return self._sink

    @property
    def start_ns(self) -> int:
        return self._start_ns

    @start_ns.setter
    def start_ns(self, value: int) -> None:
        self._start_ns = value

    @property
    def end_ns(self) -> int:
        return self._end_ns

    @end_ns.setter
    def end_ns(self, value: int) -> None:
        self._end_ns = value

    @property
    def event_no(self) -> int:
        return self._event_no

    @property
    def synthetic_reverse(self) -> Optional[bool]:
        return self._synthetic_reverse

    @synthetic_reverse.setter
    def synthetic_reverse(self, value: Optional[bool]) -> None:
        self._synthetic_reverse = value

    @property
    def event(self) -> str:
        return self._event

    @property
    def size(self) -> int:
        return self._size

    @property
    def host(self) -> Optional[str]:
        return self._host

    @host.setter
    def host(self, value: Optional[str]) -> None:
        self._host = value
