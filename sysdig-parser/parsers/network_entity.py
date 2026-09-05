from typing import Optional

from .entity import Entity


class NetworkEntity(Entity):
    """Network vertex (a connection 4-tuple).

    Identity/equality is the 4-tuple only; protocol is a descriptive
    attribute carried as a vertex property in the graph store and must not
    participate in __eq__/__hash__.
    """

    def __init__(
        self,
        src_address: Optional[str],
        dst_address: Optional[str],
        src_port: str,
        dst_port: str,
        protocol: Optional[str] = None,
    ) -> None:
        self._src_address = src_address
        self._dst_address = dst_address
        self._src_port = src_port
        self._dst_port = dst_port
        self._protocol = protocol

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
    def protocol(self) -> Optional[str]:
        """L4 protocol (fd.l4proto, e.g. 'tcp'/'udp'); None when never seen
        with a valid value in the log ('<NA>' / null count as not parseable)."""
        return self._protocol

    @protocol.setter
    def protocol(self, value: Optional[str]) -> None:
        self._protocol = value

    @property
    def src_and_dst_ip(self) -> str:
        return f"{self._src_address}:{self._src_port}->{self._dst_address}:{self._dst_port}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkEntity):
            return NotImplemented
        return self.src_and_dst_ip == other.src_and_dst_ip

    def __hash__(self) -> int:
        return hash(self.src_and_dst_ip)
