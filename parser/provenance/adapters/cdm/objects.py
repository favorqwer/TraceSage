"""CDM 的对象索引：uuid -> 精简对象记录。

为什么必须有这一层：CDM 的 Event 只带 uuid 引用，名字（路径、命令行、端点）
全在对象记录里，而且对象记录与事件记录在同一条流里交错发布。事件到达时必须
能查到它引用的对象，否则建不出顶点。

只索引三类能建顶点的对象（项目图模型只有 Process / File / Network）：
    Subject       -> Process
    FileObject    -> File
    NetFlowObject -> Network

下列记录类型**不进索引**（按项目公理 R3：无名的对象不建顶点）：
    SrcSinkObject / MemoryObject / UnnamedPipeObject / PacketSocketObject /
    RegistryKeyObject。它们仍被计数，报告里按类型列出条数，用来解释
    「为什么事件数远大于边数」——实测 TRACE 的事件有 72.3% 客体是 SrcSinkObject，
    THEIA 有 60.8% 是 MemoryObject。
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.kinds import FileKind
from . import decode as D

#: FileObject.type -> 项目 File.file_type 枚举值。
#:
#: 枚举只有 file / directory / pipe / unix / memfd / unknown 六个值，因此设备节点
#: （BLOCK / CHAR）、PE 头对象（PEFILE）落 unknown：把它们写成 "file" 是没有证据的
#: 结论。memfd 在 CDM 里没有独立类型（MemfdObject 记录不存在），U+ 不臆造。
FILE_TYPE_MAP: dict[str, FileKind] = {
    "FILE_OBJECT_FILE": FileKind.FILE,
    "FILE_OBJECT_DIR": FileKind.DIRECTORY,
    "FILE_OBJECT_NAMED_PIPE": FileKind.PIPE,
    "FILE_OBJECT_UNIX_SOCKET": FileKind.UNIX,
    "FILE_OBJECT_LINK": FileKind.FILE,
    "FILE_OBJECT_BLOCK": FileKind.UNKNOWN,
    "FILE_OBJECT_CHAR": FileKind.UNKNOWN,
    "FILE_OBJECT_PEFILE": FileKind.UNKNOWN,
}

#: ipProtocol 数值 -> proto 字符串（sysdig 侧写的是 tcp / udp 这类名字）。
IP_PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

#: 不建顶点但需要按类别解释的对象（写进报告，不写进图）。
UNNAMED_KINDS = ("memory", "srcsink", "pipe", "packet", "registry")
_UNNAMED_CODE = {name: index + 1 for index, name in enumerate(UNNAMED_KINDS)}
_UNNAMED_NAME = {code: name for name, code in _UNNAMED_CODE.items()}


@dataclass(slots=True)
class SubjectRec:
    uuid: str = ""
    host_id: str = ""
    pid: int = 0          # 取自 Subject.cid（实测 THEIA/TRACE 的 cid 就是 pid/tgid）
    start_ns: int = 0     # 0 = 出生时刻未知（模型定义）
    path: str = ""        # 可执行文件绝对路径（THEIA 有；TRACE 只有 name）
    name: str = ""        # 进程名（不是路径，不得当作 exe_path）
    cmdline: str = ""
    ppid: int = 0
    parent: str = ""      # parentSubject 的 uuid
    principal: str = ""   # localPrincipal 的 uuid
    cwd: str = ""
    stype: str = ""       # SUBJECT_PROCESS / SUBJECT_UNIT / ...（只用于统计）


@dataclass(slots=True)
class FileRec:
    uuid: str = ""
    host_id: str = ""
    path: str = ""
    ftype: str = ""       # FileObject.type 原值
    filename: str = ""    # properties.map.filename（THEIA 用这个键装路径）


@dataclass(slots=True)
class NetRec:
    uuid: str = ""
    host_id: str = ""
    endpoints: str = ""   # lip:lport->rip:rport
    proto: str = ""

    @property
    def named(self) -> bool:
        return bool(self.endpoints)


def _merge(existing, new):
    """同一 uuid 重复发布时按字段合并：新值非空就覆盖，空值不覆盖已有值。

    实测两套数据都会重复发布同一对象（例如 SrcSinkObject 每条事件前都可能重发一次），
    后到的记录往往字段更少，因此不能整体替换。
    """
    for field_name in new.__slots__:
        value = getattr(new, field_name)
        if value in ("", 0, None):
            continue
        setattr(existing, field_name, value)
    return existing


def parse_subject(body: dict) -> SubjectRec:
    props = D.mapping(body.get("properties"))
    return SubjectRec(
        uuid=D.text(body.get("uuid")),
        host_id=D.text(body.get("hostId")),
        pid=D.number(body.get("cid")) or 0,
        start_ns=D.number(body.get("startTimestampNanos")) or 0,
        path=D.text(props.get("path")),
        name=D.text(props.get("name")),
        cmdline=D.text(body.get("cmdLine")),
        ppid=D.number(props.get("ppid")) or 0,
        parent=D.uuid(body.get("parentSubject")),
        principal=D.uuid(body.get("localPrincipal")),
        cwd=D.text(props.get("cwd")),
        stype=D.text(body.get("type")),
    )


def parse_file(body: dict) -> FileRec:
    base = body.get("baseObject") or {}
    base_props = D.mapping(base.get("properties") if isinstance(base, dict) else None)
    return FileRec(
        uuid=D.text(body.get("uuid")),
        host_id=D.text(base.get("hostId")) if isinstance(base, dict) else "",
        path=D.text(base_props.get("path")),
        ftype=D.text(body.get("type")),
        filename=D.text(base_props.get("filename")),
    )


def parse_netflow(body: dict) -> NetRec:
    base = body.get("baseObject") or {}
    local_addr = D.text(body.get("localAddress"))
    local_port = D.number(body.get("localPort"))
    remote_addr = D.text(body.get("remoteAddress"))
    remote_port = D.number(body.get("remotePort"))
    endpoints = ""
    if local_addr or remote_addr:
        endpoints = (
            f"{local_addr}:{local_port if local_port is not None else ''}"
            f"->{remote_addr}:{remote_port if remote_port is not None else ''}"
        )
    proto_code = D.number(body.get("ipProtocol"))
    proto = IP_PROTO_MAP.get(proto_code, "" if proto_code is None else str(proto_code))
    return NetRec(
        uuid=D.text(body.get("uuid")),
        host_id=D.text(base.get("hostId")) if isinstance(base, dict) else "",
        endpoints=endpoints,
        proto=proto,
    )


class ObjectIndex:
    """uuid -> 对象记录的索引；同时保存 Principal（uid/euid 的来源）。"""

    def __init__(self) -> None:
        self.subjects: dict[str, SubjectRec] = {}
        self.files: dict[str, FileRec] = {}
        self.nets: dict[str, NetRec] = {}
        self.principals: dict[str, tuple[str, str]] = {}
        # uuid 的 64 位截断 -> 类别码。只为把「客体查不到」拆成
        # 「无名对象（memory/srcsink/pipe）」与「真的索引里没有」，
        # 不参与建图。64 位对千万级条目的碰撞概率约 1e-6，只影响报告计数。
        self.unnamed: dict[int, int] = {}

    # -- 写入 ----------------------------------------------------------
    def add_subject(self, rec: SubjectRec) -> None:
        if not rec.uuid:
            return
        existing = self.subjects.get(rec.uuid)
        self.subjects[rec.uuid] = rec if existing is None else _merge(existing, rec)

    def add_file(self, rec: FileRec) -> None:
        if not rec.uuid:
            return
        existing = self.files.get(rec.uuid)
        if existing is None:
            self.files[rec.uuid] = rec
            return
        merged = _merge(existing, rec)
        # 路径不是"后到覆盖"语义：先到的 path/filename 任一非空就不要再被另一种键覆盖。
        if existing.path and rec.filename:
            merged.path = existing.path
        self.files[rec.uuid] = merged

    def add_netflow(self, rec: NetRec) -> None:
        if not rec.uuid:
            return
        existing = self.nets.get(rec.uuid)
        self.nets[rec.uuid] = rec if existing is None else _merge(existing, rec)

    def add_principal(self, body: dict) -> None:
        pid = D.text(body.get("uuid"))
        if not pid:
            return
        props = D.mapping(body.get("properties"))
        self.principals[pid] = (D.text(body.get("userId")), props.get("euid", ""))

    def add_unnamed(self, kind: str, uuid_value: str) -> None:
        code = _UNNAMED_CODE.get(kind)
        if not code or not uuid_value:
            return
        key = int(uuid_value.replace("-", "")[:16], 16) if _is_hex(uuid_value) else 0
        if key:
            self.unnamed[key] = code

    def unnamed_kind(self, uuid_value: str) -> str:
        if not uuid_value or not _is_hex(uuid_value):
            return ""
        return _UNNAMED_NAME.get(self.unnamed.get(int(uuid_value.replace("-", "")[:16], 16), 0), "")

    # -- 读取 ----------------------------------------------------------
    def get(self, uuid_value: str):
        """返回 ``("subject"|"file"|"net", 记录)``；查不到返回 None。"""
        if not uuid_value:
            return None
        found = self.subjects.get(uuid_value)
        if found is not None:
            return "subject", found
        found = self.files.get(uuid_value)
        if found is not None:
            return "file", found
        found = self.nets.get(uuid_value)
        if found is not None:
            return "net", found
        return None

    def principal_of(self, subject: SubjectRec) -> tuple[str, str]:
        if not subject.principal:
            return "", ""
        return self.principals.get(subject.principal, ("", ""))

    # -- 统计 ----------------------------------------------------------
    def counts(self) -> dict[str, int]:
        return {
            "subjects": len(self.subjects),
            "files": len(self.files),
            "nets": len(self.nets),
            "principals": len(self.principals),
            "unnamed": len(self.unnamed),
        }


def _is_hex(value: str) -> bool:
    head = value.replace("-", "")[:16]
    if len(head) < 16:
        return False
    try:
        int(head, 16)
    except ValueError:
        return False
    return True


def file_path_of(rec: FileRec) -> str:
    """File 的路径：``baseObject.properties.map.path`` 优先，其次 ``filename``。

    实测覆盖率：TRACE 873/873 用 ``path``，THEIA 1,968/1,983 用 ``filename``。
    """
    return rec.path or rec.filename
