"""Streaming SCAP data sources for scap-parser.

Provides pluggable streaming execution backends to parse .scap binary capture files
directly into json event streams without intermediate .jsonl physical files.
"""

from .base import ScapSource, DEFAULT_SYSDIG_FORMAT
from .factory import create_scap_source, detect_available_backends

__all__ = [
    "ScapSource",
    "DEFAULT_SYSDIG_FORMAT",
    "create_scap_source",
    "detect_available_backends",
]
