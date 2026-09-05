from typing import List, Optional, Type
from .entity import Entity
from .fingerprint import Fingerprint
from .system_call import SystemCall
from .action import Action


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
