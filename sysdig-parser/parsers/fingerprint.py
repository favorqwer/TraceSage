from typing import Optional, Type
from .entity import Entity


class Fingerprint:
    """Composite key: (event_name, start_entity_type, end_entity_type)
    used to look up the matching SystemCall handler."""

    def __init__(
        self,
        event: str,
        c1: Optional[Type[Entity]],
        c2: Optional[Type[Entity]],
    ) -> None:
        s1 = c1.__name__ if c1 is not None else "null"
        s2 = c2.__name__ if c2 is not None else "null"
        self._fingerprint_string = f"{event}{s1}{s2}"

    @classmethod
    def to_fingerprint(
        cls,
        begin_event: str,
        begin_entity: Optional[Entity],
        end_entity: Optional[Entity],
    ) -> "Fingerprint":
        c1 = type(begin_entity) if begin_entity is not None else None
        c2 = type(end_entity) if end_entity is not None else None
        return cls(begin_event, c1, c2)

    @property
    def fingerprint_string(self) -> str:
        return self._fingerprint_string

    def __hash__(self) -> int:
        return hash(self._fingerprint_string)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fingerprint):
            return NotImplemented
        return self._fingerprint_string == other._fingerprint_string

    def __repr__(self) -> str:
        return self._fingerprint_string
