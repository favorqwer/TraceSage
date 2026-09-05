"""Sysdig args-string field extraction (fd=..., res=..., filename=...).

Pure string-level helpers over the evt.args text; they raise ValueError on
malformed socket endpoints, which the pipeline counts as skipped lines.
"""

import re
from typing import Dict, Optional, Tuple

_FILE_DESCRIPTOR_PATTERN = re.compile(r"^fd=\S*\(<f>(?P<path>.*)\)$")
_PIPE_DESCRIPTOR_PATTERN = re.compile(r"^fd=\S*\(<p>(?P<name>.*)\)$")
_SOCKET_DESCRIPTOR_PATTERN = re.compile(
    r"^fd=\S*\(<(?P<family>[46u])(?P<transport>[tu])?>(?P<endpoint>.*)\)$"
)
_ENDPOINT_PATTERN = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def extract_size(s: str) -> int:
    """Extract the return value from 'res=...' in the args string.
    Returns -1 if the result is negative or missing."""
    if "res=" in s:
        size_str = s[s.index("res=") + 4 :].split(" ")[0]
        if not size_str.startswith("-"):
            return int(size_str)
    return -1


def extract_file_and_socket(s: str) -> Dict[str, str]:
    """Extract file path or socket endpoint info from the 'fd=...' field.

    Returns a dict with keys among: path / sip,sport,dip,dport / pipe / socket
    / fd_type。
    - `<f>path`          -> {'path': path, 'fd_type': 'f'}
    - `<p>pipe:[N]`      -> {'pipe': 'pipe:[N]', 'fd_type': 'p'}  (非文件，但可表示)
    - `<u>...` / `<4t>...`
      - 若含 `lip:lport->rip:rport` -> {'sip',...,'dport'} + 'socket'
      - 否则（内核 fd 地址如 ffff...->ffff...，或空）-> {'socket': '<u>...'}
      - 均附带 'fd_type'（尖括号内原始类型符，如 'u' / '4t' / '6u'）
    - `fd=N` 无 `(<...>)` 标记（如 `fd=8`）或标记不在
      f/p/4/6/u 之列（如目录 `<d>`）-> 结果不含 'fd_type'

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

    if "fd=" in s:
        fd = s[s.index("fd=") :].split(" ")[0]
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
    """Extract filename from 'filename=...' in args."""
    if "filename=" in s:
        path = s[s.index("filename=") + 9 :].split(" ")[0]
        if "(" in path:
            path = path[path.index("(") + 1 : -1]
        return path
    return None


def _get_ip_and_ports(endpoint_str: str) -> Tuple[str, str, str, str]:
    parts = endpoint_str.split("->", 1)
    src = _parse_endpoint(parts[0])
    if len(parts) < 2:
        return (src[0], src[1], "0.0.0.0", "0")
    dest = _parse_endpoint(parts[1])
    return (src[0], src[1], dest[0], dest[1])


def _normalize_descriptor_path(path: str) -> str:
    if "(" in path:
        return path[path.index("(") + 1 : -1]
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
