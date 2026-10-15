"""Docker container SCAP streaming source."""

import shutil
import subprocess
from pathlib import Path
from typing import Iterator, Optional, Union

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource, stream_process_batches

DEFAULT_DOCKER_IMAGE = "sysdig/sysdig:latest"


class DockerScapSource(ScapSource):
    """Streams sysdig execution using a Docker container (sysdig/sysdig)."""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
        image: str = DEFAULT_DOCKER_IMAGE,
    ) -> None:
        super().__init__(scap_path, format_string, max_events)
        self.image = image
        self._proc: Optional[subprocess.Popen] = None

    @classmethod
    def is_available(cls) -> bool:
        """Check if docker CLI is available and docker daemon is running."""
        if shutil.which("docker") is None:
            return False
        try:
            r = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=4,
            )
            return r.returncode == 0
        except Exception:
            return False

    def stream_lines(self) -> Iterator[Union[str, bytes]]:
        resolved_path = Path(self.scap_path).resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Local SCAP file not found: {resolved_path}")

        parent_dir = resolved_path.parent
        file_name = resolved_path.name

        cmd = [
            "docker", "run", "--rm", "-i",
            "-v", f"{parent_dir.as_posix()}:/data:ro",
            self.image,
            "sysdig", "-r", f"/data/{file_name}",
            "-j", f"-p{self.format_string}",
        ]

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
