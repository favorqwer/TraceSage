"""Graph vertex model: the Entity marker and the three vertex types
(Process / FileEntity / NetworkEntity).

Identity/equality of each vertex type is its MERGE key only; descriptive
attributes (args, cwd, exe_path, protocol) must not participate in
__eq__/__hash__.
"""

from typing import Optional


class Entity:
    """Base class for all graph vertex entities (Process, FileEntity, NetworkEntity)."""


class Process(Entity):
    """Process vertex.

    Identity/equality is (pid, name) only; args / cwd / exe_path are
    descriptive attributes carried as vertex properties in the graph store
    and must not participate in __eq__/__hash__.
    """

    def __init__(
        self,
        pid: str,
        name: str,
        exe_path: Optional[str],
        args: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> None:
        self._pid = pid
        self._name = name
        self._exe_path = exe_path
        self._args = args
        self._cwd = cwd

    @property
    def pid(self) -> str:
        return self._pid

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
    def args(self) -> Optional[str]:
        """Command line (proc.args); None when never seen non-empty in the log."""
        return self._args

    @args.setter
    def args(self, value: Optional[str]) -> None:
        self._args = value

    @property
    def cwd(self) -> Optional[str]:
        """Working directory (proc.cwd); None when never seen non-empty in the log."""
        return self._cwd

    @cwd.setter
    def cwd(self, value: Optional[str]) -> None:
        self._cwd = value

    @property
    def pid_and_name(self) -> str:
        return self._pid + self._name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Process):
            return NotImplemented
        return self._pid == other._pid and self._name == other._name

    def __hash__(self) -> int:
        return hash((self._pid, self._name))


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
