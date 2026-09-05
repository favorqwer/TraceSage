from typing import Optional

from .entity import Entity


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
