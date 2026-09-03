from typing import Optional


class Entity:
    """Base class for all graph vertex entities (Process, FileEntity, NetworkEntity)."""

    def __init__(self, reputation: float, uniq_id: int) -> None:
        self._reputation = reputation
        self._uniq_id = uniq_id
        self._host: Optional[str] = None

    @property
    def reputation(self) -> float:
        return self._reputation

    @property
    def uniq_id(self) -> int:
        return self._uniq_id

    @property
    def host(self) -> Optional[str]:
        return self._host

    @host.setter
    def host(self, value: Optional[str]) -> None:
        self._host = value
