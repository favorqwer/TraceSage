from typing import Dict, List, Optional
from .entity import Entity
from .fingerprint import Fingerprint
from .action import Action


class SystemCall:
    """Handler for a single system call event, with a list of actions to execute on match."""

    def __init__(
        self,
        name: str,
        type_: str,
        finger_print: Fingerprint,
    ) -> None:
        self.name = name
        self.type = type_
        self.finger_print = finger_print
        self.on_match: List[Action] = []

    def add_action(self, action: Action) -> "SystemCall":
        self.on_match.append(action)
        return self

    def react(
        self,
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        for action in self.on_match:
            action(m_start, m_end, e_start, e_end)
