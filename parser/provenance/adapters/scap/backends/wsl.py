"""WSL2 后端：Windows 开发机调用 WSL 内的 sysdig。"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Union

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource


class WslScapSource(ScapSource):
    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: int | None = None,
        json_output: bool = True,
        expression: str | None = None,
        sysdig_bin: str = "sysdig",
        distribution: str | None = None,
        base64_buffer: bool = False,
    ) -> None:
        super().__init__(
            scap_path, format_string, max_events, json_output, expression,
            sysdig_bin, base64_buffer,
        )
        self.distribution = distribution

    @classmethod
    def is_available(
        cls, distribution: str | None = None, sysdig_bin: str = "sysdig"
    ) -> bool:
        if shutil.which("wsl") is None:
            return False
        cmd = ["wsl"]
        if distribution:
            cmd += ["-d", distribution]
        cmd += [sysdig_bin, "--version"]
        try:
            # 首次冷启动 WSL 可能要数秒；4 秒会把可用环境误判为不可用。
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15
            )
            return result.returncode == 0 and b"sysdig version" in result.stdout
        except Exception:
            return False

    @staticmethod
    def to_wsl_path(win_path: Union[str, Path]) -> str:
        path = Path(win_path).resolve()
        drive = path.drive.rstrip(":").lower()
        if drive:
            rest = path.as_posix()[len(path.drive):].lstrip("/")
            return f"/mnt/{drive}/{rest}"
        return path.as_posix()

    def _build_command(self) -> list[str]:
        # 已经是 WSL/Linux 绝对路径时不要再用 Windows Path.resolve 改写；
        # 旧实现显式保留了这种用法。
        if self.scap_path.startswith("/"):
            wsl_path = self.scap_path
        else:
            resolved = Path(self.scap_path).resolve()
            if not resolved.exists():
                raise FileNotFoundError(f"本地捕获文件不存在：{resolved}")
            wsl_path = self.to_wsl_path(resolved)
        cmd = ["wsl"]
        if self.distribution:
            cmd += ["-d", self.distribution]
        cmd += ["-e"] + self._sysdig_args(self.sysdig_bin, wsl_path)
        return cmd
