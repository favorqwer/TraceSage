"""后端探测与工厂：把配置解析成具体 ScapSource。"""

from __future__ import annotations

import os
from typing import Dict, Optional

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource
from .docker import DEFAULT_DOCKER_IMAGE, DockerScapSource
from .local import LocalScapSource
from .ssh import DEFAULT_REMOTE_CACHE_DIR, DEFAULT_SSH_PORT, SshScapSource
from .wsl import WslScapSource

BACKENDS = ("auto", "local", "wsl", "ssh", "docker")


def detect_available_backends(
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_port: int = DEFAULT_SSH_PORT,
    sysdig_bin: str = "sysdig",
    wsl_distribution: Optional[str] = None,
) -> Dict[str, bool]:
    """实际探测每个后端，而不是只看配置是否非空。"""
    return {
        "local": LocalScapSource.is_available(sysdig_bin),
        "wsl": WslScapSource.is_available(wsl_distribution, sysdig_bin),
        "ssh": bool(ssh_host)
        and SshScapSource.is_available(
            host=ssh_host,
            user=ssh_user,
            port=ssh_port,
            sysdig_bin=sysdig_bin,
        ),
        "docker": DockerScapSource.is_available(),
    }


def choose_backend(
    readiness: Dict[str, bool], os_name: Optional[str] = None
) -> str:
    """按 scap-parser 的优先级选择后端。

    Windows 上即使本机装了 sysdig 也优先 WSL，因为 Windows 原生 sysdig
    通常不能直接读 Linux 采集的 .scap。
    """
    name = os_name if os_name is not None else os.name
    if readiness.get("local") and name != "nt":
        return "local"
    if readiness.get("wsl"):
        return "wsl"
    if readiness.get("ssh"):
        return "ssh"
    if readiness.get("docker"):
        return "docker"
    if readiness.get("local"):
        return "local"
    raise RuntimeError(
        "找不到任何可用读取后端：本机无 sysdig、无可用 WSL、"
        "SSH 不可达、Docker 不可用。"
    )


def create_scap_source(
    scap_path: str,
    backend: str = "auto",
    format_string: str = DEFAULT_SYSDIG_FORMAT,
    max_events: Optional[int] = None,
    json_output: bool = True,
    expression: Optional[str] = None,
    sysdig_bin: str = "sysdig",
    base64_buffer: bool = False,
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_port: int = DEFAULT_SSH_PORT,
    ssh_cache_dir: str = DEFAULT_REMOTE_CACHE_DIR,
    ssh_auto_sync: bool = True,
    wsl_distribution: Optional[str] = None,
    docker_image: str = DEFAULT_DOCKER_IMAGE,
) -> ScapSource:
    selected = (backend or "auto").lower().strip()
    if selected not in BACKENDS:
        raise ValueError(
            f"未知后端：{backend!r}，可选 {', '.join(BACKENDS)}"
        )

    if selected == "auto":
        readiness = detect_available_backends(
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            sysdig_bin=sysdig_bin,
            wsl_distribution=wsl_distribution,
        )
        selected = choose_backend(readiness)

    common = dict(
        scap_path=scap_path,
        format_string=format_string,
        max_events=max_events,
        json_output=json_output,
        expression=expression,
        sysdig_bin=sysdig_bin,
        base64_buffer=base64_buffer,
    )
    if selected == "local":
        return LocalScapSource(**common)
    if selected == "wsl":
        return WslScapSource(**common, distribution=wsl_distribution)
    if selected == "ssh":
        if not ssh_host:
            raise ValueError("ssh 后端需要 host（--ssh-host 或 PARSER_SSH_HOST）")
        return SshScapSource(
            **common,
            host=ssh_host,
            user=ssh_user,
            port=ssh_port,
            remote_cache_dir=ssh_cache_dir,
            auto_sync=ssh_auto_sync,
        )
    if selected == "docker":
        return DockerScapSource(**common, image=docker_image)
    raise AssertionError(f"未处理的后端：{selected}")
