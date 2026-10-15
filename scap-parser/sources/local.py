"""Local native Linux SCAP streaming source."""

import shutil
import subprocess
from pathlib import Path
from typing import Iterator, Optional, Union

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource, stream_process_batches


class LocalScapSource(ScapSource):
    """Streams sysdig output from local system execution (Linux servers)."""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
        sysdig_bin: str = "sysdig",
    ) -> None:
        super().__init__(scap_path, format_string, max_events)
        self.sysdig_bin = sysdig_bin
        self._proc: Optional[subprocess.Popen] = None

    @classmethod
    def is_available(cls, sysdig_bin: str = "sysdig") -> bool:
        """Check if local sysdig executable is installed and runnable."""
        return shutil.which(sysdig_bin) is not None

    def stream_lines(self) -> Iterator[Union[str, bytes]]:
        resolved_path = Path(self.scap_path).resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Local SCAP file not found: {resolved_path}")

        cmd = [self.sysdig_bin, "-r", str(resolved_path), "-j", f"-p{self.format_string}"]
        if self.max_events is not None and self.max_events > 0:
            cmd.extend(["-n", str(self.max_events)])

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=2 * 1024 * 1024,
        )

        try:
            yield from stream_process_batches(self._proc, queue_size=100, batch_size=1000)
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
        self._closed = True
