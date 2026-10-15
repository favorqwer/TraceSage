"""Factory and detection for SCAP streaming sources."""

import os
from typing import Dict, List, Optional

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource
from .docker import DockerScapSource
from .local import LocalScapSource
from .ssh import DEFAULT_SSH_HOST, DEFAULT_SSH_USER, SshScapSource
from .wsl import WslScapSource


def detect_available_backends(
    ssh_host: str = DEFAULT_SSH_HOST,
    ssh_user: str = DEFAULT_SSH_USER,
) -> Dict[str, bool]:
    """Probe system environment and return readiness of each backend."""
    return {
        "local": LocalScapSource.is_available(),
        "wsl": WslScapSource.is_available(),
        "ssh": SshScapSource.is_available(host=ssh_host, user=ssh_user),
        "docker": DockerScapSource.is_available(),
    }


def create_scap_source(
    scap_path: str,
    backend: str = "auto",
    format_string: str = DEFAULT_SYSDIG_FORMAT,
    max_events: Optional[int] = None,
    ssh_host: str = DEFAULT_SSH_HOST,
    ssh_user: str = DEFAULT_SSH_USER,
    wsl_distribution: Optional[str] = None,
    docker_image: str = "sysdig/sysdig:latest",
) -> ScapSource:
    """Create a configured ScapSource instance based on requested backend or auto detection."""
    selected_backend = backend.lower().strip()

    if selected_backend == "auto":
        # Auto detection priority:
        # 1. Native local (if running on Linux server with sysdig)
        # 2. WSL2 (if running on Windows with WSL sysdig, fast local execution without network)
        # 3. SSH remote (if victim/capture machine is reachable)
        # 4. Docker (if container engine is running)
        readiness = detect_available_backends(ssh_host=ssh_host, ssh_user=ssh_user)
        print(f"[SCAP Parser] Probing execution backends: {readiness}")

        if readiness["local"] and os.name != "nt":
            selected_backend = "local"
        elif readiness["wsl"]:
            selected_backend = "wsl"
        elif readiness["ssh"]:
            selected_backend = "ssh"
        elif readiness["docker"]:
            selected_backend = "docker"
        elif readiness["local"]:
            selected_backend = "local"
        else:
            raise RuntimeError(
                "No runnable SCAP execution backend detected! "
                "Ensure one of the following is available: "
                "1) Local Linux system with sysdig installed; "
                "2) WSL2 with sysdig installed; "
                f"3) SSH connection to {ssh_user}@{ssh_host} with sysdig installed; "
                "4) Running Docker daemon with sysdig/sysdig image."
            )

    print(f"[SCAP Parser] Using streaming backend: '{selected_backend}'")

    if selected_backend == "local":
        return LocalScapSource(
            scap_path=scap_path,
            format_string=format_string,
            max_events=max_events,
        )
    elif selected_backend == "ssh":
        return SshScapSource(
            scap_path=scap_path,
            format_string=format_string,
            max_events=max_events,
            host=ssh_host,
            user=ssh_user,
        )
    elif selected_backend == "wsl":
        return WslScapSource(
            scap_path=scap_path,
            format_string=format_string,
            max_events=max_events,
            distribution=wsl_distribution,
        )
    elif selected_backend == "docker":
        return DockerScapSource(
            scap_path=scap_path,
            format_string=format_string,
            max_events=max_events,
            image=docker_image,
        )
    else:
        raise ValueError(
            f"Unknown backend '{backend}'. Supported backends: 'auto', 'ssh', 'local', 'wsl', 'docker'."
        )
