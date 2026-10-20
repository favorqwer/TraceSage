"""Docker 后端：在 sysdig 官方镜像里读取挂载进来的 .scap。"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource

DEFAULT_DOCKER_IMAGE = "sysdig/sysdig:latest"


class DockerScapSource(ScapSource):
    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: int | None = None,
        json_output: bool = True,
        expression: str | None = None,
        sysdig_bin: str = "sysdig",
        image: str = DEFAULT_DOCKER_IMAGE,
    ) -> None:
        super().__init__(
            scap_path, format_string, max_events, json_output, expression, sysdig_bin
        )
        self.image = image

    @classmethod
    def is_available(cls) -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            result = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _build_command(self) -> list[str]:
        resolved = Path(self.scap_path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"本地捕获文件不存在：{resolved}")
        parent = resolved.parent
        cmd = [
            "docker", "run", "--rm", "-i",
            "-v", f"{parent.as_posix()}:/data:ro",
            self.image,
        ]
        # 容器内固定用镜像自带的 sysdig；宿主机的 --sysdig-bin 不适用。
        cmd += self._sysdig_args("sysdig", f"/data/{resolved.name}")
        return cmd
