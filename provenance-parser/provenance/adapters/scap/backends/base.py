"""SCAP 读取层抽象：把"怎么拿到 sysdig 输出"与"怎么解析输出"分开。

这一层从 scap-parser/sources 融合而来，保留其多后端、真实可用性探测、
SSH 同步、生产者-消费者批处理等能力；同时补齐 provenance-parser 原有的
失败可见性：所有后端都捕获 stderr，并在退出码非零时把原因带进异常。

与 scap-parser 的差异只有两处，都是为 provenance-parser 服务：
1. ``json_output`` 可关闭：provenance-parser 使用制表符模板而不是 ``-j``；
2. ``expression`` 可为容器元数据扫描追加 sysdig 过滤表达式。
"""

from __future__ import annotations

import subprocess
import tempfile
from abc import ABC, abstractmethod
from typing import Iterator, Optional

# 与 scap-parser 保持一致的 12 个规范 JSON 字段。
# provenance-parser 默认关闭 JSON，只把它当作"不指定模板时的兼容默认值"。
DEFAULT_SYSDIG_FORMAT = (
    "*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args "
    "%proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency"
)

QUEUE_BLOCKS = 100
BATCH_LINES = 1000
PIPE_BUFFER = 2 * 1024 * 1024
# 主线程分块读管道：一次 read 1 MiB，再在 C 层 split(b"\n")。
# 旧的“读线程 + 有界队列 + 逐行 readline”在 1290 万行上实测每行多花 ~7 µs。
CHUNK_BYTES = 1 << 20
# 13 = SIGPIPE，141 = 128+13；下游提前结束时不当作读取失败。
OK_EXIT_CODES = frozenset({0, 13, 141, -13})


def _stderr_text(stderr_file: Optional[object]) -> str:
    if stderr_file is None or not hasattr(stderr_file, "seek"):
        return ""
    try:
        stderr_file.seek(0)
        raw = stderr_file.read()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", "replace").strip()
        return str(raw).strip()
    except Exception:
        return ""


def _finish_process(proc: subprocess.Popen, stderr_file: Optional[object]) -> None:
    rc = proc.poll()
    if rc is None:
        try:
            rc = proc.wait(timeout=5)
        except Exception:
            rc = proc.poll()
    if rc is not None and rc not in OK_EXIT_CODES:
        reason = _stderr_text(stderr_file)
        raise RuntimeError(f"sysdig 读取失败（exit={rc}）：{reason}")


def stream_process_chunks(
    proc: subprocess.Popen,
    chunk_size: int = CHUNK_BYTES,
    stderr_file: Optional[object] = None,
) -> Iterator[list[bytes]]:
    """主线程分块读管道，按块（list[bytes]）交出整行。

    与旧实现的行为差异只有实现方式：不再起读线程、不再经有界队列逐行搬运，
    改成 1 MiB 一次 ``read`` + ``split(b"\\n")``，退出码/stderr 的失败可见性不变。
    """
    stdout = proc.stdout
    assert stdout is not None
    tail = b""
    try:
        while True:
            chunk = stdout.read(chunk_size)
            if not chunk:
                break
            data = tail + chunk if tail else chunk
            lines = data.split(b"\n")
            tail = lines.pop()
            if lines:
                yield lines
        if tail:
            yield [tail]
    finally:
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass
    _finish_process(proc, stderr_file)


def stream_process_batches(
    proc: subprocess.Popen,
    queue_size: int = QUEUE_BLOCKS,
    batch_size: int = BATCH_LINES,
    stderr_file: Optional[object] = None,
) -> Iterator[bytes]:
    """逐行接口（兼容旧调用方）：实现已换成主线程分块读。"""
    for chunk in stream_process_chunks(proc, stderr_file=stderr_file):
        yield from chunk


class ScapSource(ABC):
    """统一的 SCAP 流式读取接口。"""

    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: Optional[int] = None,
        json_output: bool = True,
        expression: Optional[str] = None,
        sysdig_bin: str = "sysdig",
        base64_buffer: bool = False,
    ) -> None:
        self.scap_path = scap_path
        self.format_string = format_string
        self.max_events = max_events
        self.json_output = json_output
        self.expression = expression
        self.sysdig_bin = sysdig_bin
        self.base64_buffer = base64_buffer
        self._proc: Optional[subprocess.Popen] = None
        self._closed = False

    # -- 子类实现：命令构造 ------------------------------------------------
    @abstractmethod
    def _build_command(self) -> list[str]:
        """返回可直接交给 subprocess.Popen 的 argv。"""

    def command(self) -> list[str]:
        """公开只读的命令视图，供测试和报告核对。"""
        return self._build_command()

    # -- 公共 sysdig 参数 --------------------------------------------------
    def _sysdig_args(self, binary: str, input_path: str) -> list[str]:
        args = [binary, "-r", input_path]
        if self.expression:
            args.append(self.expression)
        if self.json_output:
            args.append("-j")
        if self.base64_buffer:
            args.append("-b")
        args += ["-p", self.format_string]
        if self.max_events is not None and self.max_events > 0:
            args += ["-n", str(self.max_events)]
        return args

    # -- 统一的启动/收尾 ---------------------------------------------------
    def stream_chunks(self) -> Iterator[list[bytes]]:
        """按块交出整行（热路径入口）。"""
        cmd = self._build_command()
        stderr_file = tempfile.TemporaryFile()
        self._closed = False
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                bufsize=PIPE_BUFFER,
            )
        except Exception:
            stderr_file.close()
            raise
        try:
            yield from stream_process_chunks(self._proc, stderr_file=stderr_file)
        finally:
            self.close()
            try:
                stderr_file.close()
            except Exception:
                pass

    def stream_lines(self) -> Iterator[bytes]:
        for chunk in self.stream_chunks():
            yield from chunk

    def close(self) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    try:
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            self._proc = None
        self._closed = True

    def __enter__(self) -> "ScapSource":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
