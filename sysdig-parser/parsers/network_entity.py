from typing import Optional
from .entity import Entity


class NetworkEntity(Entity):
    def __init__(
        self,
        reputation: float,
        src_address: Optional[str],
        dst_address: Optional[str],
        src_port: str,
        dst_port: str,
        uniq_id: int,
    ) -> None:
        super().__init__(reputation, uniq_id)
        self._src_address = src_address
        self._dst_address = dst_address
        self._src_port = src_port
        self._dst_port = dst_port

    @property
    def src_address(self) -> Optional[str]:
        return self._src_address

    @property
    def dst_address(self) -> Optional[str]:
        return self._dst_address

    @property
    def src_port(self) -> str:
        return self._src_port

    @property
    def dst_port(self) -> str:
        return self._dst_port

    @property
    def src_and_dst_ip(self) -> str:
        return f"{self._src_address}:{self._src_port}->{self._dst_address}:{self._dst_port}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkEntity):
            return NotImplemented
        return self._uniq_id == other._uniq_id

    def __hash__(self) -> int:
        return hash(self._uniq_id)
