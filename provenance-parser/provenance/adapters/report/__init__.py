"""报告适配器：采集器与落盘器。"""

from .collector import ReportCollector
from .writer import ReportWriter

__all__ = ["ReportCollector", "ReportWriter"]
