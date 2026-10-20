"""SSH 后端：远端 Linux 上执行 sysdig，stdout 通过 SSH 管道流回本地。

融合 scap-parser 的远端缓存策略：本地有文件时自动 scp 到远端缓存目录，
远端已有同尺寸文件则复用；``scap_path`` 本身就是远端绝对路径时直接使用。
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource

DEFAULT_SSH_PORT = 22
DEFAULT_REMOTE_CACHE_DIR = "/tmp/scap_cache"


class SshScapSource(ScapSource):
    def __init__(
        self,
        scap_path: str,
        format_string: str = DEFAULT_SYSDIG_FORMAT,
        max_events: int | None = None,
        json_output: bool = True,
        expression: str | None = None,
        sysdig_bin: str = "sysdig",
        host: str = "",
        user: str = "",
        port: int = DEFAULT_SSH_PORT,
        remote_cache_dir: str = DEFAULT_REMOTE_CACHE_DIR,
        auto_sync: bool = True,
    ) -> None:
        super().__init__(
            scap_path, format_string, max_events, json_output, expression, sysdig_bin
        )
        self.host = host
        self.user = user
        self.port = port
        self.remote_cache_dir = remote_cache_dir
        self.auto_sync = auto_sync

    # -- 可用性 ------------------------------------------------------------
    @classmethod
    def is_available(
        cls,
        host: str = "",
        user: str = "",
        port: int = DEFAULT_SSH_PORT,
        sysdig_bin: str = "sysdig",
        timeout: int = 2,
    ) -> bool:
        if not host or shutil.which("ssh") is None:
            return False
        target = f"{user}@{host}" if user else host
        cmd = [
            "ssh",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
        ]
        if port:
            cmd += ["-p", str(port)]
        cmd += [target, f"{sysdig_bin} --version"]
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2
            )
            return result.returncode == 0 and b"sysdig version" in result.stdout
        except Exception:
            return False

    # -- 远端文件准备 ------------------------------------------------------
    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    @staticmethod
    def _remote_path(value: str) -> str:
        # 允许 ~/ 由远端 shell 展开；其余路径按字面量引用。
        if value.startswith("~"):
            return value
        return shlex.quote(value)

    def _ssh_argv(self, remote_command: str) -> list[str]:
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
        ]
        if self.port:
            cmd += ["-p", str(self.port)]
        cmd += [self.target, remote_command]
        return cmd

    def _ensure_remote_scap(self) -> str:
        local_path = Path(self.scap_path)
        if not local_path.exists() and (
            self.scap_path.startswith("/") or self.scap_path.startswith("~")
        ):
            return self.scap_path

        if not local_path.exists():
            raise FileNotFoundError(f"本地捕获文件不存在：{self.scap_path}")
        if not self.auto_sync:
            raise ValueError(
                f"本地文件需要上传但 auto_sync=False：{self.scap_path}"
            )

        mkdir_cmd = self._ssh_argv(
            f"mkdir -p {self._remote_path(self.remote_cache_dir)}"
        )
        subprocess.run(mkdir_cmd, check=True)

        prefix = f"{local_path.parent.name}_" if local_path.parent.name else ""
        remote_path = f"{self.remote_cache_dir}/{prefix}{local_path.name}"

        stat_cmd = self._ssh_argv(
            f"stat -c %s {self._remote_path(remote_path)} 2>/dev/null || echo -1"
        )
        result = subprocess.run(stat_cmd, stdout=subprocess.PIPE, text=True)
        remote_size = int(result.stdout.strip() or -1)
        local_size = local_path.stat().st_size

        if remote_size != local_size:
            print(
                f"[SSH Backend] 上传 {local_path} "
                f"({local_size / (1024 * 1024):.2f} MB) -> "
                f"{self.target}:{remote_path} ...",
                flush=True,
            )
            scp_cmd = [
                "scp",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
            ]
            if self.port:
                scp_cmd += ["-P", str(self.port)]
            scp_cmd += [
                str(local_path.resolve()),
                f"{self.target}:{self._remote_path(remote_path)}",
            ]
            subprocess.run(scp_cmd, check=True)
            print("[SSH Backend] 上传完成。", flush=True)
        else:
            print(
                f"[SSH Backend] 复用远端缓存：{remote_path}",
                flush=True,
            )
        return remote_path

    # -- 命令 --------------------------------------------------------------
    @staticmethod
    def _remote_arg(value: str) -> str:
        # ~/ 交给远端 shell 展开；其余按字面量引用。
        if value.startswith("~"):
            return value
        return shlex.quote(value)

    def _build_command(self) -> list[str]:
        if not self.host:
            raise ValueError("ssh 后端需要 host（--ssh-host 或 PARSER_SSH_HOST）")
        remote_path = self._ensure_remote_scap()
        remote_args = self._sysdig_args(self.sysdig_bin, remote_path)
        remote_command = " ".join(self._remote_arg(arg) for arg in remote_args)
        return self._ssh_argv(remote_command)
