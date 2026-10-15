"""SSH remote streaming SCAP source.

Connects to a remote Linux capture/victim machine (e.g. 物理机A 的 ubuntu)
and streams sysdig output across the SSH stdout pipe into local memory.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterator, Optional, Union

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource, stream_process_batches

DEFAULT_SSH_HOST = "100.86.108.4"
DEFAULT_SSH_USER = "ubuntu"
DEFAULT_SSH_PORT = 22


class SshScapSource(ScapSource):
    """Streams sysdig execution over an SSH remote pipe."""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
        host: str = DEFAULT_SSH_HOST,
        user: str = DEFAULT_SSH_USER,
        port: int = DEFAULT_SSH_PORT,
        remote_cache_dir: str = "/tmp/scap_cache",
        auto_sync: bool = True,
    ) -> None:
        super().__init__(scap_path, format_string, max_events)
        self.host = host
        self.user = user
        self.port = port
        self.remote_cache_dir = remote_cache_dir
        self.auto_sync = auto_sync
        self._proc: Optional[subprocess.Popen] = None

    @classmethod
    def is_available(cls, host: str = DEFAULT_SSH_HOST, user: str = DEFAULT_SSH_USER, timeout: int = 2) -> bool:
        """Check if ssh command exists and target remote host is reachable without password."""
        if shutil.which("ssh") is None:
            return False
        cmd = [
            "ssh",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            f"{user}@{host}",
            "sysdig --version",
        ]
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
            return r.returncode == 0 and b"sysdig version" in r.stdout
        except Exception:
            return False

    def _ensure_remote_scap(self) -> str:
        """Return the remote path to the .scap file, syncing if local."""
        local_p = Path(self.scap_path)
        if not local_p.exists() and (self.scap_path.startswith("/") or self.scap_path.startswith("~")):
            return self.scap_path

        if not local_p.exists():
            raise FileNotFoundError(f"Local SCAP file not found: {self.scap_path}")

        if not self.auto_sync:
            raise ValueError(f"Local SCAP specified but auto_sync is False: {self.scap_path}")

        # Ensure remote cache directory exists
        mkdir_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            f"{self.user}@{self.host}",
            f"mkdir -p {self.remote_cache_dir}",
        ]
        subprocess.run(mkdir_cmd, check=True)

        # Distinguish scenario directories by prefixing parent folder name if available
        prefix = f"{local_p.parent.name}_" if local_p.parent.name else ""
        remote_filename = f"{prefix}{local_p.name}"
        remote_path = f"{self.remote_cache_dir}/{remote_filename}"

        # Check if remote already has file with exact same size
        stat_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            f"{self.user}@{self.host}",
            f"stat -c %s {remote_path} 2>/dev/null || echo -1",
        ]
        r = subprocess.run(stat_cmd, stdout=subprocess.PIPE, text=True)
        remote_size = int(r.stdout.strip() or -1)
        local_size = local_p.stat().st_size

        if remote_size != local_size:
            print(f"[SSH Backend] Syncing {local_p} ({local_size / (1024*1024):.2f} MB) to {self.user}@{self.host}:{remote_path}...")
            scp_cmd = [
                "scp",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
                str(local_p.resolve()),
                f"{self.user}@{self.host}:{remote_path}",
            ]
            subprocess.run(scp_cmd, check=True)
            print(f"[SSH Backend] Sync completed.")
        else:
            print(f"[SSH Backend] Reusing cached remote SCAP: {remote_path}")

        return remote_path

    def stream_lines(self) -> Iterator[Union[str, bytes]]:
        remote_scap = self._ensure_remote_scap()

        max_arg = f"-n {self.max_events}" if (self.max_events and self.max_events > 0) else ""
        remote_cmd = f"sysdig -r {remote_scap} -j {max_arg} -p '{self.format_string}'"

        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            f"{self.user}@{self.host}",
            remote_cmd,
        ]

        self._proc = subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=2 * 1024 * 1024,
        )

        try:
            # Optimization 3: Threaded producer-consumer reader queue
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
