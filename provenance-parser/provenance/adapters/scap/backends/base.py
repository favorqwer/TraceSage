"""SCAP 读取层抽象：把"怎么拿到 sysdig 输出"与"怎么解析输出"分开。

这一层从 scap-parser/sources 融合而来，保留其多后端、真实可用性探测、
SSH 同步、生产者-消费者批处理等能力；同时补齐 provenance-parser 原有的
失败可见性：所有后端都捕获 stderr，并在退出码非零时把原因带进异常。

与 scap-parser 的差异只有两处，都是为 provenance-parser 服务：
1. ``json_output`` 可关闭：provenance-parser 使用制表符模板而不是 ``-j``；
2. ``expression`` 可为容器元数据扫描追加 sysdig 过滤表达式。
"""

from __future__ import annotations

import queue
import subprocess
import tempfile
import threading
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


def stream_process_batches(
    proc: subprocess.Popen,
    queue_size: int = QUEUE_BLOCKS,
    batch_size: int = BATCH_LINES,
    stderr_file: Optional[object] = None,
) -> Iterator[bytes]:
    """后台线程读管道，有界队列交给主线程，避免 sysdig 被 64KB 管道反压。

    队列按"块"计数而不是按字节计数：最多 ``queue_size * batch_size`` 行。
    这是有界内存结构，不是全量缓存。
    """
    q: "queue.Queue[object]" = queue.Queue(maxsize=queue_size)
    sentinel = object()
    reader_exc: list[BaseException] = []

    def reader() -> None:
        batch: list[bytes] = []
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
        except BaseException as exc:  # noqa: BLE001 - 原样抛给主线程
            reader_exc.append(exc)
        finally:
            q.put(sentinel)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    try:
        while True:
            item = q.get()
            if item is sentinel:
                break
            for line in item:  # type: ignore[union-attr]
                yield line
    finally:
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass

    if reader_exc:
        raise reader_exc[0]

    rc = proc.poll()
    if rc is None:
        try:
            rc = proc.wait(timeout=5)
        except Exception:
            rc = proc.poll()
    if rc is not None and rc not in OK_EXIT_CODES:
        reason = _stderr_text(stderr_file)
        raise RuntimeError(f"sysdig 读取失败（exit={rc}）：{reason}")


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
    ) -> None:
        self.scap_path = scap_path
        self.format_string = format_string
        self.max_events = max_events
        self.json_output = json_output
        self.expression = expression
        self.sysdig_bin = sysdig_bin
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
        args += ["-p", self.format_string]
        if self.max_events is not None and self.max_events > 0:
            args += ["-n", str(self.max_events)]
        return args

    # -- 统一的启动/收尾 ---------------------------------------------------
    def stream_lines(self) -> Iterator[bytes]:
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
            yield from stream_process_batches(
                self._proc,
                queue_size=QUEUE_BLOCKS,
                batch_size=BATCH_LINES,
                stderr_file=stderr_file,
            )
        finally:
            self.close()
            try:
                stderr_file.close()
            except Exception:
                pass

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
