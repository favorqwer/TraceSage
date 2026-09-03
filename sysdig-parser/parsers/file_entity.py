from typing import Optional
from .entity import Entity


class FileEntity(Entity):
    def __init__(
        self,
        reputation: float,
        user_id: Optional[str],
        group_id: Optional[str],
        path: str,
        uniq_id: int,
    ) -> None:
        super().__init__(reputation, uniq_id)
        self._user_id = user_id
        self._group_id = group_id
        self._path = path

    @property
    def user_id(self) -> Optional[str]:
        return self._user_id

    @property
    def group_id(self) -> Optional[str]:
        return self._group_id

    @property
    def path(self) -> str:
        return self._path

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FileEntity):
            return NotImplemented
        return (
            self._user_id == other._user_id
            and self._group_id == other._group_id
            and self._path == other._path
        )

    def __hash__(self) -> int:
        return hash((self._user_id, self._group_id, self._path))
