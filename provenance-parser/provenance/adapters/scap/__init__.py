"""SCAP 适配器：后端、模板、审计与采集。"""

from .backends import detect_available_backends
from .capture import ScapCapture

__all__ = ["ScapCapture", "detect_available_backends"]
