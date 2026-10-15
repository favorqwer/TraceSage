"""Sysdig args-string field extraction (fd=..., res=..., filename=...).

Pure string-level helpers over the evt.args text; they raise ValueError on
malformed socket endpoints, which the pipeline counts as skipped lines.
"""

import posixpath
import re
from typing import Dict, Optional, Tuple

_FILE_DESCRIPTOR_PATTERN = re.compile(r"^fd=\S*\(<f>(?P<path>.*)\)$")
_PIPE_DESCRIPTOR_PATTERN = re.compile(r"^fd=\S*\(<p>(?P<name>.*)\)$")
# fd token 起点：字段边界上的 fd=（避免命中 dirfd=/oldfd= 等字段名内部）。
# 必须用环视而不消费空格：match.start() 要正好落在 "fd=" 的 f 上——
# _extract_fd_token 从这里 +3 跳过 "fd="。此前写成消费空格的 (?:^| )，
# 非行首的 fd=（如 mmap 的 "flags=... fd=3(<f>/...)"）切出的 token 带前导
# 空格，所有 ^fd= 锚定的类型模式全部失配，fd 解析静默失败。
_FD_TOKEN_START_PATTERN = re.compile(r"(?:^|(?<= ))fd=")
# fd 编号："fd=16(<p>)" -> "16"。管道身份解析（fd 表查找，见
# pipeline/fd_table.py）需要裸 fd 号本身，类型括号内的名字对裸管道为空。
_FD_NUMBER_PATTERN = re.compile(r"^fd=(\d+)")
# 尖括号内的原始类型符（不限于 f/p/4/6/u）：`fd=3(<n>)` -> 'n'、`fd=1(<d>/x)` -> 'd'。
# 与 fd_type 的区别：fd_type 只在识别为 f/p/4/6/u 时才存在，本键只要带
# `<X>` 标记就有，供审计分类（netlink/eventfd/目录等）使用。
_FD_TYPE_RAW_PATTERN = re.compile(r"^fd=\S*?<(?P<t>[^>]*)>")
# 按字段名取 fd token 的起点（fd= / in_fd= / out_fd= …）。
# 必须用环视而不消费空格：match.start() 要正好落在 "<key>=" 的首字符上。
_FD_TOKEN_PATTERNS: Dict[str, "re.Pattern[str]"] = {}


def _fd_token_pattern(key: str) -> "re.Pattern[str]":
    pattern = _FD_TOKEN_PATTERNS.get(key)
    if pattern is None:
        pattern = re.compile(r"(?:^|(?<= ))" + re.escape(key) + "=")
        _FD_TOKEN_PATTERNS[key] = pattern
    return pattern


# ---------------------------------------------------------------------------
# unix socket 文件系统路径提取（**唯一实现**，供 fields / pipeline.fd_table /
# dispatch.handlers 共用；历史上同一语义在三处各写了一份，容易漂移）。
#
# 路径形态统一为：可选的内核地址前缀（以空格分隔，如 'ffff890c..->ffff890c..' 或
# '0->ffff8b..'）+ 以 '/' 开头、到空格或右括号为止的路径。
#   抽象命名空间 '@/tmp/.X11-unix/X0' 与裸注记 '' 均不匹配。
#   内核地址对无路径（'ffff..->ffff..' 后无空格+路径）也不匹配。
_UNIX_PATH_TAIL = r"(?:[^)]*? )?(?P<path>/[^\s)]+)"
# 1) fd 注记括号内的端点内容（整串匹配）：'ffff..->ffff.. /dev/log'、'/run/user/1000/bus'
UNIX_PATH_IN_ENDPOINT_RE = re.compile(r"^" + _UNIX_PATH_TAIL + r"$")
# 2) args 里的 fd 注记：'fd=7(<u>ffff..->ffff.. /dev/log)'。
#    字段名含裸 fd= 以及双 fd 系统调用的 in_fd= / out_fd=（sendfile）。
UNIX_PATH_IN_FD_NOTE_RE = re.compile(
    r"(?<![a-zA-Z0-9_])(?:fd|in_fd|out_fd)=(\d+)\(<u>" + _UNIX_PATH_TAIL + r"\)"
)
# 3) connect 退出记录：'tuple=<addr>-><addr> /path'（fd 编号在进入记录里）
UNIX_PATH_IN_CONNECT_TUPLE_RE = re.compile(r"(?:^| )tuple=\S+ " + _UNIX_PATH_TAIL)
# 4) bind 退出记录：'addr=/path'（netlink 为 addr=NULL，不匹配）
UNIX_PATH_IN_BIND_ADDR_RE = re.compile(r"(?:^| )addr=" + _UNIX_PATH_TAIL)


def unix_path_from_endpoint(endpoint: str) -> Optional[str]:
    """fd 注记括号内的端点内容 -> 文件系统路径（无路径/抽象命名空间返回 None）。"""
    ep = endpoint.strip()
    if not ep or ep.startswith("@"):
        return None
    m = UNIX_PATH_IN_ENDPOINT_RE.match(ep)
    return m.group("path") if m else None
# 内核对“已打开但已删除”文件的标准注记后缀（/proc/<pid>/fd readlink 结果）
_DELETED_SUFFIX = " (deleted)"


# 内核相对路径注记：'原始参数(解析后的绝对路径)'，如
#   filename=.(/srv/progql-web/releases/release_20260531-211727)
#   path=./assets(/srv/.../release_20260531-211727/assets)
# 判定只看第一对括号：括号内以 / 开头才剥壳，否则括号视为文件名的普通
# 字符（'/tmp/a (copy).txt'、'/var/log/(deleted)' 保持原样）。此前仅
# mkdir/unlink/rename 通道做了此归一，filename= 通道未做，导致边挂到带括号
# 注记的孤立顶点上（docs/graph-defects-20260913.md G3）。
# 合成顶点键（管道/socket/netlink 等）不是文件系统路径，不得交给
# posixpath.normpath（它会把 'pipe:[123]' 当相对路径改写）。
# 例外：unix:[<绝对路径>] 的括号内是**真文件系统路径**，必须词法归一——
# 否则同一 socket 会因 '..'/'./'/'//' 写法不同裂成多个顶点
# （实测 unix:[/run/user/1000/snap.firefox/../pulse/native] 与
#  unix:[/run/user/1000/pulse/native] 分裂）。只归一内部路径，合成前缀本身
# 不进 normpath（见 normalize_file_path）。
_SYNTHETIC_VERTEX_PREFIXES = ("pipe:[", "socket:[", "netlink:[")
_UNIX_VERTEX_PREFIX = "unix:["
_UNIX_VERTEX_SUFFIX = "]"


def strip_path_annotation(value: Optional[str]) -> Optional[str]:
    """'rel(/abs/resolved)' -> '/abs/resolved'；其余形态只去首尾空白。

    判据与旧的 _normalize_exit_path / _normalize_rename_path 逐字一致，
    保证 mkdir/unlink/rmdir/symlink/rename 通道零行为变化；同时允许
    括号内再带括号（如 '/x (y)(/abs (y))'）。
    """
    if not value:
        return value
    normalized = value.strip()
    if normalized.endswith(")") and "(" in normalized:
        inner = normalized[normalized.index("(") + 1 : -1].strip()
        if inner.startswith("/"):
            return inner
    return normalized


def normalize_file_path(value: Optional[str]) -> Optional[str]:
    """File 顶点键的统一归一：剥内核括号注记 + 词法归一。

    词法归一（posixpath.normpath）折叠 '/./' 段、内部 '//' 与尾斜杠，
    使同一目录/文件不再裂成两个顶点（docs/graph-defects-20260913.md G4）。
    POSIX 保留行首恰好两个斜杠（'//usr/share/fonts' 原样不动），因此
    snap-confine 在 chroot 下的 // 开头顶点不会被误并进真实系统路径。
    空串/None 原样返回，不交给 normpath（normpath('') 会变成 '.'）。

    unix 合成顶点（unix:[<绝对路径>]）只把**括号内的路径**交给 normpath：
    前缀本身是合成命名空间、路径是真实文件系统身份，两者都保真才既不误并
    pipe:[...] 也不漏并同一 socket 的其他写法。
    """
    stripped = strip_path_annotation(value)
    if not stripped:
        return stripped
    if stripped.startswith(_UNIX_VERTEX_PREFIX) and stripped.endswith(_UNIX_VERTEX_SUFFIX):
        inner = stripped[len(_UNIX_VERTEX_PREFIX) : -len(_UNIX_VERTEX_SUFFIX)]
        if inner.startswith("/"):
            inner = posixpath.normpath(inner)
        return _UNIX_VERTEX_PREFIX + inner + _UNIX_VERTEX_SUFFIX
    if stripped.startswith(_SYNTHETIC_VERTEX_PREFIXES):
        return stripped
    return posixpath.normpath(stripped)


def _extract_fd_token(s: str, start: int, key: str = "fd") -> str:
    """取完整 fd token：<key>=<num>(<type>...)。

    括号内可含空格与嵌套括号（如内核对已删除文件的
    "fd=124(<f>/memfd:mozilla-ipc (deleted))"），以括号配平为准；
    无括号形态（fd=8 / fd=AT_FDCWD）以空格为界。此前按第一个空格截断，
    含空格的注记路径会被拦腰切断导致整条 fd 解析失败。"""
    i = start + len(key) + 1  # 跳过 "<key>="
    depth = 0
    for j in range(i, len(s)):
        c = s[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[start : j + 1]
        elif c == " " and depth == 0:
            return s[start:j]
    return s[start:]
_SOCKET_DESCRIPTOR_PATTERN = re.compile(
    r"^fd=\S*\(<(?P<family>[46u])(?P<transport>[tu])?>(?P<endpoint>.*)\)$"
)
_ENDPOINT_PATTERN = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def extract_size(s: str) -> int:
    """Extract the return value from 'res=...' in the args string.
    Returns -1 if the result is negative, missing, or unparseable.

    部分系统调用（fcntl/dup/clone/eventfd...）的返回值带括号说明
    （res=0(<f>/dev/null)、res=20982(gjs)），只取括号前的数字部分。

    注意：本函数把“字段缺失”与“返回值为负”合并成同一个 -1，因此**不能**用作
    “调用是否失败”的判据（那会被 extract_res / record_failed 取代）；它适用于
    “把 res 当字节量”的数据流边（read/write/sendto/recvfrom）——那里拿不到
    res 就没有可用的 bytes。
    """
    if "res=" in s:
        size_str = s[s.index("res=") + 4 :].split(" ")[0]
        if not size_str.startswith("-"):
            if "(" in size_str:
                size_str = size_str[: size_str.index("(")]
            try:
                return int(size_str)
            except ValueError:
                return -1
    return -1


def extract_res(s: str) -> Optional[int]:
    """'res=...' 的原始返回值；**只有在字段缺失时才返回 None**。

    与 extract_size() 的差别就是这一项：本函数能区分
      字段缺失（None，导出格式没给 res）与
      调用失败（负数）与
      字段存在但不可解析（归为 -1，与 extract_size 口径一致，保守当失败）。

    背景：本采集导出（-p '... %evt.args ...'）下 accept 的退出记录形如
    `fd=5(<4t>192.168.122.128:43064->192.168.122.129:22) tuple=... queuepct=0 ...`，
    不带 `res=`（实测场景 3 的 12,208 条 accept 退出记录中带 res= 的为 0 条）。
    只看 extract_size()==-1 会把“所有 accept”当成失败而无差别丢弃。
    """
    if "res=" not in s:
        return None
    res_str = s[s.index("res=") + 4 :].split(" ")[0]
    if "(" in res_str:
        res_str = res_str[: res_str.index("(")]
    try:
        return int(res_str)
    except ValueError:
        return -1


def extract_file_and_socket(s: str, key: str = "fd") -> Dict[str, str]:
    """Extract file path or socket endpoint info from the '<key>=...' field.

    key 默认为裸 `fd=`；sendfile 这类双 fd 系统调用用 key="in_fd"/"out_fd"
    分别取两个端点（`in_fd=` 里的 `fd=` 前面是下划线，裸 `fd=` 的环视
    模式匹配不到它，所以必须显式指定字段名）。

    Returns a dict with keys among: path / sip,sport,dip,dport / pipe / socket
    / fd_type / fd_type_raw / unix_path / unix_abstract。
    - `<f>path`          -> {'path': path, 'fd_type': 'f'}
    - `<p>pipe:[N]`      -> {'pipe': 'pipe:[N]', 'fd_type': 'p'}  (非文件，但可表示)
    - `<u>...` / `<4t>...`
      - 若含 `lip:lport->rip:rport` -> {'sip',...,'dport'} + 'socket'
      - 否则（内核 fd 地址如 ffff...->ffff...，或空）-> {'socket': '<u>...'}
      - unix（`<u>`）注记里带文件系统路径时额外给 'unix_path'
        （'<u>ffff..->ffff.. /dev/log' 与 '<u>/run/user/1000/bus' 两种形态）；
        抽象命名空间给 'unix_abstract'
      - 均附带 'fd_type'（尖括号内原始类型符，如 'u' / '4t' / '6u'）
    - `fd=N` 无 `(<...>)` 标记（如 `fd=8`）或标记不在
      f/p/4/6/u 之列（如目录 `<d>`）-> 结果不含 'fd_type'；
      'fd_type_raw' 不受此限（只要带 `<X>` 就有，如 '<d>' -> 'd'、'<n>' -> 'n'）

    'fd_type' 是尖括号内的原始类型符（fd.typechar），仅当 fd 带括号标记且能
    识别时才存在。当前解析器未把它写入顶点属性（File.type 已移除：值域仅
    'file'，与 :File 标签冗余），保留提取作为将来目录顶点（<d>）方案的
    基础能力与调试信息。
    """
    path: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[str] = None
    socket: Optional[str] = None
    pipe: Optional[str] = None
    fd_type: Optional[str] = None
    result: Dict[str, str] = {}

    fd_token_match = _fd_token_pattern(key).search(s)
    if fd_token_match:
        raw_token = _extract_fd_token(s, fd_token_match.start(), key)
        body = raw_token[len(key) + 1:] if raw_token.startswith(key + "=") else raw_token
        fd = "fd=" + body          # 复用下面 ^fd= 锚定的各类型模式
        raw_type_match = _FD_TYPE_RAW_PATTERN.match(fd)
        if raw_type_match:
            result["fd_type_raw"] = raw_type_match.group("t")
        num_match = _FD_NUMBER_PATTERN.match(fd)
        if num_match:
            result["fd_num"] = num_match.group(1)
        file_match = _FILE_DESCRIPTOR_PATTERN.match(fd)
        if file_match:
            path = _normalize_descriptor_path(file_match.group("path"))
            fd_type = "f"
        else:
            pipe_match = _PIPE_DESCRIPTOR_PATTERN.match(fd)
            if pipe_match:
                pipe = pipe_match.group("name")
                fd_type = "p"
            else:
                socket_match = _SOCKET_DESCRIPTOR_PATTERN.match(fd)
                if socket_match:
                    fd_type = socket_match.group("family") + (
                        socket_match.group("transport") or ""
                    )
                    socket_ep = socket_match.group("endpoint")
                    socket = fd[socket_match.start() :]
                    if fd_type is not None and fd_type[0] == "u":
                        unix_path = unix_path_from_endpoint(socket_ep)
                        if unix_path:
                            result["unix_path"] = unix_path
                        elif socket_ep.strip().startswith("@"):
                            result["unix_abstract"] = "1"
                    if socket_ep and "->" in socket_ep and "ffff" not in socket_ep:
                        try:
                            ports_and_ip = _get_ip_and_ports(socket_ep)
                            src_ip = ports_and_ip[0]
                            src_port = ports_and_ip[1]
                            dest_ip = ports_and_ip[2]
                            dest_port = ports_and_ip[3]
                        except ValueError:
                            # 内核 fd 地址解析不到真实 IP -> 保留 socket 名
                            src_ip = None
                            src_port = None
                            dest_ip = None
                            dest_port = None

    if path is not None:
        result["path"] = path
    elif pipe is not None:
        result["pipe"] = pipe
    if src_ip is not None:
        result["sip"] = src_ip
    if src_port is not None:
        result["sport"] = src_port
    if dest_ip is not None:
        result["dip"] = dest_ip
    if dest_port is not None:
        result["dport"] = dest_port
    if socket is not None and socket:
        result["socket"] = socket
    if fd_type is not None:
        result["fd_type"] = fd_type
    return result


def extract_process_file(s: str) -> Optional[str]:
    """Extract filename from 'filename=...' in args（execve 进入记录）。

    此处不做归一：括号剥壳与词法归一统一收到 File 顶点键生成处
    （pipeline/entity_registry.get_or_create_file 调 normalize_file_path），
    避免多个通道各自实现而漏归一。本函数只按空格切出字面 token：
    内核的 " (deleted)" 注记由空格分词自然落在 token 之外；而无条件
    剥括号会把 "x (deleted)" 之类路径撕碎。"""
    if "filename=" in s:
        path = s[s.index("filename=") + 9 :].split(" ")[0]
        return path or None
    return None


def _get_ip_and_ports(endpoint_str: str) -> Tuple[str, str, str, str]:
    parts = endpoint_str.split("->", 1)
    src = _parse_endpoint(parts[0])
    if len(parts) < 2:
        return (src[0], src[1], "0.0.0.0", "0")
    dest = _parse_endpoint(parts[1])
    return (src[0], src[1], dest[0], dest[1])


def _normalize_descriptor_path(path: str) -> str:
    """fd 注记路径归一：只剥内核对已删除文件的标准后缀 " (deleted)"
    （来自 /proc/<pid>/fd 的 readlink 结果），其余括号一律视为路径本身
    的字符（如 "a (copy).txt"）——此前无条件剥括号会把
    "/memfd:mozilla-ipc (deleted)" 错误归一成 "deleted"，使所有已删除
    文件共享一个垃圾顶点。"""
    if path.endswith(_DELETED_SUFFIX):
        return path[: -len(_DELETED_SUFFIX)]
    return path


def _parse_endpoint(endpoint: str) -> Tuple[str, str]:
    matcher = _ENDPOINT_PATTERN.match(endpoint.strip())
    if not matcher:
        raise ValueError(f"Malformed socket endpoint: {endpoint}")
    host = matcher.group("host")
    port = matcher.group("port")
    if not port or not port.isdigit():
        raise ValueError(f"Non-numeric socket port '{port}' in {endpoint}")
    return (host, port)
