from typing import List, Optional, Type
from .entity import Entity
from .fingerprint import Fingerprint
from .system_call import SystemCall
from .action import Action

_factory_id_counter: int = 0


def _next_factory_id() -> int:
    global _factory_id_counter
    _factory_id_counter += 1
    return _factory_id_counter


class SystemCallFactory:
    """Factory that creates SystemCall instances for a given direction type,
    sharing a common set of actions."""

    def __init__(
        self,
        type_: str,
        c1: Optional[Type[Entity]],
        c2: Optional[Type[Entity]],
    ) -> None:
        self._type = type_
        self._on_match: List[Action] = []
        self._c1 = c1
        self._c2 = c2

    def add_action(self, action: Action) -> "SystemCallFactory":
        self._on_match.append(action)
        return self

    def get_system_call(self, event: str) -> SystemCall:
        instance = SystemCall(
            str(_next_factory_id()),
            self._type,
            Fingerprint(event, self._c1, self._c2),
        )
        for action in self._on_match:
            instance = instance.add_action(action)
        return instance
