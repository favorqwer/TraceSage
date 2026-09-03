from typing import Optional
from .entity import Entity


class Process(Entity):
    def __init__(
        self,
        reputation: float,
        pid: str,
        uid: Optional[str],
        group_id: Optional[str],
        name: str,
        uniq_id: int,
        exe_path: Optional[str],
    ) -> None:
        super().__init__(reputation, uniq_id)
        self._pid = pid
        self._uid = uid
        self._group_id = group_id
        self._name = name
        self._exe_path = exe_path

    @property
    def pid(self) -> str:
        return self._pid

    @property
    def uid(self) -> Optional[str]:
        return self._uid

    @property
    def group_id(self) -> Optional[str]:
        return self._group_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def exe_path(self) -> Optional[str]:
        return self._exe_path

    @exe_path.setter
    def exe_path(self, value: Optional[str]) -> None:
        self._exe_path = value

    @property
    def pid_and_name(self) -> str:
        return self._pid + self._name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Process):
            return NotImplemented
        return (
            self._pid == other._pid
            and self._uid == other._uid
            and self._name == other._name
        )

    def __hash__(self) -> int:
        return hash((self._pid, self._uid, self._name))
