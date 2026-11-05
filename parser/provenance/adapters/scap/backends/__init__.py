"""SCAP 读取层：多后端、真实探测、SSH 同步、有界批处理。"""

from .base import DEFAULT_SYSDIG_FORMAT, ScapSource
from .docker import DEFAULT_DOCKER_IMAGE, DockerScapSource
from .factory import (
    BACKENDS,
    choose_backend,
    create_scap_source,
    detect_available_backends,
)
from .local import LocalScapSource
from .ssh import DEFAULT_REMOTE_CACHE_DIR, DEFAULT_SSH_PORT, SshScapSource
from .wsl import WslScapSource

__all__ = [
    "BACKENDS",
    "DEFAULT_DOCKER_IMAGE",
    "DEFAULT_REMOTE_CACHE_DIR",
    "DEFAULT_SSH_PORT",
    "DEFAULT_SYSDIG_FORMAT",
    "DockerScapSource",
    "LocalScapSource",
    "ScapSource",
    "SshScapSource",
    "WslScapSource",
    "choose_backend",
    "create_scap_source",
    "detect_available_backends",
]
