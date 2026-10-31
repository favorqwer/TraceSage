"""CDM18（DARPA Transparent Computing Engagement 3）数据源适配器。

数据形态：``tar.gz`` 里每行一条 Avro-JSON 记录（Host / Principal / Subject /
FileObject / NetFlowObject / MemoryObject / SrcSinkObject / Event / TimeMarker …），
不是 sysdig ``.scap``。

分工：
    archive.py  流式读归档，按成员数字后缀排序
    decode.py   Avro-JSON 的 union / map / UUID 解包
    objects.py  uuid -> Subject / File / Net 的精简索引
    mapping.py  事件映射表（data/cdm_events.toml）的加载与校验
    emit.py     一条 Event -> Node / Edge / Outcome
    run.py      管线编排与账本
    report.py   report.json / report.md / edges.csv / nodes.csv / events.csv
"""

from __future__ import annotations

from . import archive, decode, emit, mapping, objects, report, run

__all__ = ["archive", "decode", "emit", "mapping", "objects", "report", "run"]
