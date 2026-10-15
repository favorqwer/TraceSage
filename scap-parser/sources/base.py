"""Abstract base class for streaming SCAP data sources."""

import queue
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Iterator, Optional, Union

# Format string strictly compatible with existing sysdig-parser 12 canonical JSONL keys:
# evt.num, evt.rawtime, proc.pid, proc.exepath, proc.name, proc.args, proc.cwd,
# fd.l4proto, evt.dir, evt.type, evt.args, evt.latency
DEFAULT_SYSDIG_FORMAT = (
    "*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args "
    "%proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency"
)


def stream_process_batches(
    proc: subprocess.Popen,
    queue_size: int = 100,
    batch_size: int = 1000,
    stderr_file: Optional[object] = None,
) -> Iterator[Union[str, bytes]]:
    """Producer-consumer reader queue for high-throughput pipe streaming (Optimization 3).
    
    Reads lines from proc.stdout in a background I/O thread in batches of `batch_size`,
    feeding a bounded queue to decouple I/O transmission from CPU parsing.
    Validates process exit code on completion to fail-fast on pipe errors.
    """
    q: queue.Queue = queue.Queue(maxsize=queue_size)
    sentinel = object()
    reader_exc = []

    def reader():
        batch = []
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if not line:
                    continue
                batch.append(line)
                if len(batch) >= batch_size:
                    q.put(batch)
                    batch = []
            if batch:
                q.put(batch)
        except Exception as e:
            reader_exc.append(e)
        finally:
            q.put(sentinel)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    while True:
        item = q.get()
        if item is sentinel:
            break
        for line in item:
            yield line

    if reader_exc:
        raise reader_exc[0]

    rc = proc.poll()
    if rc is None:
        try:
            rc = proc.wait(timeout=5)
        except Exception:
            rc = proc.poll()
    if rc is not None and rc != 0:
        err_msg = ""
        if stderr_file is not None and hasattr(stderr_file, "seek") and hasattr(stderr_file, "read"):
            try:
                stderr_file.seek(0)
                raw_err = stderr_file.read()
                if isinstance(raw_err, bytes):
                    err_msg = raw_err.decode("utf-8", "replace").strip()
                else:
                    err_msg = str(raw_err).strip()
            except Exception:
                pass
        raise RuntimeError(f"Streaming process exited with non-zero exit code {rc}: {err_msg}")



class ScapSource(ABC):
    """Abstract provider of streaming JSON events from a .scap binary file."""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
    ) -> None:
        self.scap_path = scap_path
        self.format_string = format_string
        self.max_events = max_events
        self._closed = False

    @abstractmethod
    def stream_lines(self) -> Iterator[Union[str, bytes]]:
        """Stream raw JSON lines from backend execution."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Terminate underlying process or cleanup resources."""
        pass

    def __enter__(self) -> "ScapSource":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
