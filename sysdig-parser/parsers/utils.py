import re
from typing import Dict, List, Optional, Tuple

_FILE_DESCRIPTOR_PATTERN = re.compile(r"^fd=\S*\(<f>(?P<path>.*)\)$")
_SOCKET_DESCRIPTOR_PATTERN = re.compile(
    r"^fd=\S*\(<(?P<family>[46])(?P<transport>[tu])?>(?P<endpoint>.*)\)$"
)
_ENDPOINT_PATTERN = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")
_PID_TOKEN_PATTERN = re.compile(r"^\(\d+\)$")


class Utils:
    """Utility methods for parsing Sysdig log lines and extracting fields."""

    @staticmethod
    def parse_entry(entry: str) -> Optional[Dict[str, str]]:
        """Parse a single Sysdig JSONL line into a field map."""
        try:
            fields = entry.split(" ")
            pid_index = -1
            for i, f in enumerate(fields):
                if _PID_TOKEN_PATTERN.match(f):
                    pid_index = i
                    break
            if pid_index == -1:
                return None

            process_arr = fields[3:pid_index]
            process_str = " ".join(process_arr)
            res: Dict[str, str] = {}
            res["raw"] = entry
            res["eventno"] = fields[0]
            res["timestamp"] = fields[1]
            res["cpu"] = fields[2]
            res["process"] = process_str
            res["pid"] = fields[pid_index][1:-1]
            res["direction"] = fields[pid_index + 1]
            res["event"] = fields[pid_index + 2]
            res["cwd"] = fields[pid_index + 3][4:]

            if fields[-1] == "(deleted)":
                res["latency"] = fields[-3][8:]
                res["exepath"] = fields[-2][8:]
                res["args"] = " ".join(fields[pid_index + 4 : -3])
            else:
                res["latency"] = fields[-2][8:]
                res["exepath"] = fields[-1][8:]
                res["args"] = " ".join(fields[pid_index + 4 : -2])
            return res
        except Exception:
            return None

    @staticmethod
    def extract_size(s: str) -> int:
        """Extract the return value from 'res=...' in the args string.
        Returns -1 if the result is negative or missing."""
        if "res=" in s:
            size_str = s[s.index("res=") + 4 :].split(" ")[0]
            if not size_str.startswith("-"):
                return int(size_str)
        return -1

    @staticmethod
    def extract_file_and_socket(s: str) -> Dict[str, str]:
        """Extract file path or socket endpoint info from the 'fd=...' field."""
        path: Optional[str] = None
        src_ip: Optional[str] = None
        src_port: Optional[str] = None
        dest_ip: Optional[str] = None
        dest_port: Optional[str] = None
        socket: Optional[str] = None
        res: Dict[str, str] = {}

        if "fd=" in s:
            fd = s[s.index("fd=") :].split(" ")[0]
            file_match = _FILE_DESCRIPTOR_PATTERN.match(fd)
            if file_match:
                path = Utils._normalize_descriptor_path(file_match.group("path"))
            else:
                socket_match = _SOCKET_DESCRIPTOR_PATTERN.match(fd)
                if socket_match:
                    socket = socket_match.group("endpoint")
                    if socket:
                        ports_and_ip = Utils._get_ip_and_ports(socket)
                        src_ip = ports_and_ip[0]
                        src_port = ports_and_ip[1]
                        dest_ip = ports_and_ip[2]
                        dest_port = ports_and_ip[3]

        if path is not None:
            res["path"] = path
        if src_ip is not None:
            res["sip"] = src_ip
        if src_port is not None:
            res["sport"] = src_port
        if dest_ip is not None:
            res["dip"] = dest_ip
        if dest_port is not None:
            res["dport"] = dest_port
        if socket is not None and socket:
            res["socket"] = socket
        return res

    @staticmethod
    def extract_process_file(s: str) -> Optional[str]:
        """Extract filename from 'filename=...' in args."""
        if "filename=" in s:
            path = s[s.index("filename=") + 9 :].split(" ")[0]
            if "(" in path:
                path = path[path.index("(") + 1 : -1]
            return path
        return None

    @staticmethod
    def _get_ip_and_ports(endpoint_str: str) -> Tuple[str, str, str, str]:
        parts = endpoint_str.split("->", 1)
        src = Utils._parse_endpoint(parts[0])
        if len(parts) < 2:
            return (src[0], src[1], "0.0.0.0", "0")
        dest = Utils._parse_endpoint(parts[1])
        return (src[0], src[1], dest[0], dest[1])

    @staticmethod
    def _normalize_descriptor_path(path: str) -> str:
        if "(" in path:
            return path[path.index("(") + 1 : -1]
        return path

    @staticmethod
    def _parse_endpoint(endpoint: str) -> Tuple[str, str]:
        matcher = _ENDPOINT_PATTERN.match(endpoint.strip())
        if not matcher:
            raise ValueError(f"Malformed socket endpoint: {endpoint}")
        host = matcher.group("host")
        port = matcher.group("port")
        if not port or not port.isdigit():
            raise ValueError(f"Non-numeric socket port '{port}' in {endpoint}")
        return (host, port)
