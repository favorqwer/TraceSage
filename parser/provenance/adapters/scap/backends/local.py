"""本地 Linux 后端：直接调用本机 sysdig。"""

from __future__ import annotations

import shutil
from pathlib import Path

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource


class LocalScapSource(ScapSource):
    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: int | None = None,
        json_output: bool = True,
        expression: str | None = None,
        sysdig_bin: str = "sysdig",
        base64_buffer: bool = False,
    ) -> None:
        super().__init__(
            scap_path, format_string, max_events, json_output, expression,
            sysdig_bin, base64_buffer,
        )

    @classmethod
    def is_available(cls, sysdig_bin: str = "sysdig") -> bool:
        return shutil.which(sysdig_bin) is not None

    def _build_command(self) -> list[str]:
        resolved = Path(self.scap_path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"本地捕获文件不存在：{resolved}")
        return self._sysdig_args(self.sysdig_bin, str(resolved))
