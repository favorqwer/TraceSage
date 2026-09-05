from typing import Dict, List, Optional
from .entity import Entity
from .fingerprint import Fingerprint
from .action import Action


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
