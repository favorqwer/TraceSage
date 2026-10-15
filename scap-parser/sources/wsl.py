"""WSL2 bridging SCAP streaming source for Windows."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterator, Optional, Union

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource, stream_process_batches


import tempfile


class WslScapSource(ScapSource):
    """Streams sysdig execution inside Windows Subsystem for Linux (WSL2)."""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
        distribution: Optional[str] = None,
    ) -> None:
        super().__init__(scap_path, format_string, max_events)
        self.distribution = distribution
        self._proc: Optional[subprocess.Popen] = None
        self._stderr_file: Optional[object] = None

    @classmethod
    def is_available(cls, distribution: Optional[str] = None) -> bool:
        """Check if wsl executable exists and sysdig is installed inside WSL."""
        if shutil.which("wsl") is None:
            return False
        cmd = ["wsl"]
        if distribution:
            cmd.extend(["-d", distribution])
        cmd.extend(["sysdig", "--version"])
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
            return r.returncode == 0 and b"sysdig version" in r.stdout
        except Exception:
            return False

    @staticmethod
    def to_wsl_path(win_path: Union[str, Path]) -> str:
        """Convert Windows path (e.g. E:\\Work\\file.scap) to WSL path (/mnt/e/Work/file.scap)."""
        p = Path(win_path).resolve()
        drive = p.drive.rstrip(":").lower()
        if drive:
            rest = p.as_posix()[len(p.drive):].lstrip("/")
            return f"/mnt/{drive}/{rest}"
        return p.as_posix()

    def stream_lines(self) -> Iterator[Union[str, bytes]]:
        resolved_path = Path(self.scap_path).resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Local SCAP file not found: {resolved_path}")

        wsl_file = self.to_wsl_path(resolved_path)

        cmd = ["wsl"]
        if self.distribution:
            cmd.extend(["-d", self.distribution])
        cmd.extend(["sysdig", "-r", wsl_file, "-j", f"-p{self.format_string}"])

        if self.max_events is not None and self.max_events > 0:
            cmd.extend(["-n", str(self.max_events)])

        self._stderr_file = tempfile.TemporaryFile()
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            bufsize=2 * 1024 * 1024,
        )

        try:
            yield from stream_process_batches(
                self._proc,
                queue_size=100,
                batch_size=1000,
                stderr_file=self._stderr_file,
            )
        finally:
            self.close()

    def close(self) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._proc = None
        if getattr(self, "_stderr_file", None) is not None:
            try:
                self._stderr_file.close()
            except Exception:
                pass
            self._stderr_file = None
        self._closed = True

