from .entity import Entity


class FileEntity(Entity):
    def __init__(self, path: str) -> None:
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FileEntity):
            return NotImplemented
        return self._path == other._path

    def __hash__(self) -> int:
        return hash(self._path)
