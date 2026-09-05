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
    ) -> None:
        self._source = source
        self._sink = sink
        self._id = edge_id
        self._event = optype
        self._size = size
        self._start_ns = start_ns
        self._end_ns = end_ns

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
    def event(self) -> str:
        return self._event

    @property
    def size(self) -> int:
        return self._size
