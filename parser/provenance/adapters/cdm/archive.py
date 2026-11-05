"""CDM18 JSONL 归档的流式读取。

两条硬规则，都由实测得出：

1. **逐行读，不整体解压、不缓存整行**。实测解压吞吐 199 MB/s（单核），
   与磁盘顺序读 205 MB/s 相同，因此流式读没有额外代价；解压到盘上只会多占
   68.64 GB 并多一次全量写盘。

2. **时间顺序不一定等于 tar 顺序**。THEIA 归档
   （ta1-theia-e3-official-6r.json.tar.gz）的 tar 成员顺序是
   ``.json, .1, .10, .11, .12, .2, .3 …``，按时间应当是
   ``.json, .1, .2 … .12``（实测 ``.10`` 起点 2018-04-12 23:20Z，``.2`` 起点
   2018-04-10 22:25Z）。

   默认走 tar 顺序（单趟流式，48 GB 归档 228 s）；需要严格时间顺序时用
   ``sort_members=True``，代价是 tar.gz 不支持随机定位：先整包建索引再按序号
   取成员，向后跳的成员会把 gzip 流回绕到起点重新解压（THEIA 实测约多 3 分钟）。
   两条路径产出的行内事件都不丢，差别只在处理顺序，而处理顺序不影响图
   （边的端点与时间戳都在记录里）。
"""

from __future__ import annotations

import tarfile
from typing import Iterator


def member_index(name: str) -> int:
    """成员名 -> 逻辑序号：``x.json`` 记 0，``x.json.7`` 记 7。"""
    tail = name.rsplit(".", 1)[-1]
    if tail == "json":
        return 0
    if tail.isdigit():
        return int(tail)
    return 1 << 30


def list_members(path: str, sort: bool = True) -> list[tuple[int, str, int]]:
    """列出全部成员 ``(逻辑序号, 名字, 解压后字节数)``。

    需要把整个归档流式过一遍（tar.gz 不能随机定位），实测 TRACE 16 s、THEIA 26 s。
    """
    found: list[tuple[int, str, int]] = []
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            if member.isfile():
                found.append((member_index(member.name), member.name, member.size))
    if sort:
        found.sort()
    return found


def iter_lines(
    path: str,
    member_from: int = 0,
    member_to: int | None = None,
    sort_members: bool = False,
) -> Iterator[tuple[int, str, int, bytes]]:
    """逐行产出 ``(成员逻辑序号, 成员名, 行号, 原始行)``。

    ``member_from`` / ``member_to`` 按逻辑序号（含两端）过滤。被过滤掉的成员
    仍会被 gzip 解压（tar.gz 无随机定位），但不会产生 Python 对象。

    ``sort_members=False``（默认）：单趟流式，按 tar 内的物理顺序产出。
    ``sort_members=True``：按逻辑序号升序产出，代价见模块文档。

    注意：``member_from`` 大于 0 时，窗口之前发布的 Subject / FileObject /
    NetFlowObject 不在索引里，引用它们的事件会落 ``subject_unseen`` 桶。
    """
    if sort_members:
        yield from _iter_sorted(path, member_from, member_to)
        return
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            index = member_index(member.name)
            if index < member_from:
                continue
            if member_to is not None and index > member_to:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            yield from _lines(index, member.name, handle)


def _iter_sorted(
    path: str, member_from: int, member_to: int | None
) -> Iterator[tuple[int, str, int, bytes]]:
    with tarfile.open(path, "r:gz") as archive:
        members = [
            (member_index(member.name), member)
            for member in archive.getmembers()
            if member.isfile()
        ]
        members.sort(key=lambda item: item[0])
        for index, member in members:
            if index < member_from:
                continue
            if member_to is not None and index > member_to:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            yield from _lines(index, member.name, handle)


def _lines(index: int, name: str, handle) -> Iterator[tuple[int, str, int, bytes]]:
    line_no = 0
    for raw in handle:
        line_no += 1
        if not raw.strip():
            continue
        yield index, name, line_no, raw
