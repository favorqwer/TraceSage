"""System call dispatch: Fingerprint lookup key, SystemCall handler, action
type, and the factory that binds a shared action set to many syscall names."""

from typing import Callable, Dict, List, Optional, Type

from ..model.entities import Entity

# An action receives the paired (start, end) records and the entities
# extracted from each: (start_rec, end_rec, start_entities, end_entities).
Action = Callable[
    [Dict[str, str], Dict[str, str], List[Optional[Entity]], List[Optional[Entity]]],
    None,
]


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
        # 事件名单独存一份：指纹字符串的事件名与实体类名后缀**没有分隔符**
        # （`sendtoFileEntitynull`），从字符串反推事件名会歧义——
        # 用宽松后缀正则会误把 `send`/`recv` 这类已注册名的真前缀当成已建模
        # （tools/coverage_gap.py 曾据此错报）。消费者一律读 fp.event。
        self.event = event
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


class SystemCall:
    """Handler for a single system call event, with a list of actions to execute on match."""

    def __init__(self, fingerprint: Fingerprint) -> None:
        self.fingerprint = fingerprint
        self.on_match: List[Action] = []

    def add_action(self, action: Action) -> "SystemCall":
        self.on_match.append(action)
        return self

    def react(
        self,
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        for action in self.on_match:
            action(start_rec, end_rec, start_entities, end_entities)


class SystemCallFactory:
    """Factory that creates SystemCall instances for a given direction type,
    sharing a common set of actions."""

    def __init__(
        self,
        c1: Optional[Type[Entity]],
        c2: Optional[Type[Entity]],
    ) -> None:
        self._on_match: List[Action] = []
        self._c1 = c1
        self._c2 = c2

    def add_action(self, action: Action) -> "SystemCallFactory":
        self._on_match.append(action)
        return self

    def get_system_call(self, event: str) -> SystemCall:
        system_call = SystemCall(Fingerprint(event, self._c1, self._c2))
        for action in self._on_match:
            system_call.add_action(action)
        return system_call
