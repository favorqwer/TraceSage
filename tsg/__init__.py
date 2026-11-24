"""TraceSage Graph (.tsg) 单文件全属性溯源图索引引擎。"""
from __future__ import annotations

from .format import (
    EDGE_RECORD,
    HEADER_STRUCT,
    MAGIC,
    REL_BY_CODE,
    REL_CODES,
    TSG_VERSION,
    TSGEdge,
    TSGReader,
    TSGWriter,
)

__all__ = [
    "EDGE_RECORD",
    "HEADER_STRUCT",
    "MAGIC",
    "REL_BY_CODE",
    "REL_CODES",
    "TSG_VERSION",
    "TSGEdge",
    "TSGReader",
    "TSGWriter",
]
