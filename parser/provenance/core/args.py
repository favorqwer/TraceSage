"""evt.args 解码。

为什么所有客体信息都从这里取：实测（见 README「实测依据」）把条件字段
（fd.name / fd.type / evt.rawres）放进 sysdig 的 -p 模板会成行丢失——
`%fd.name` 只剩 34.7%，`%evt.rawres` 只剩 26.1%，`%proc.duration` 直接 0 行。
`evt.args` 是唯一 100% 可打印且自带 fd 类型/名字/返回值/载荷的载体。

本模块是纯函数，不 import 任何其它模块。
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_FD_RE = re.compile(r"^(-?\d+)\((.*)\)$", re.S)
_KEY_RE = re.compile(r"\s(?:[a-zA-Z_][a-zA-Z0-9_]*=)")

_KIND_BY_CODE = {
    "f": "file",
    "d": "directory",
    "u": "unix",
    "p": "pipe",
    "e": "event",
    "t": "timerfd",
    "i": "inotify",
    "s": "signalfd",
    "n": "netlink",
    "P": "eventpoll",
    "b": "bpf",
    "m": "memfd",
    "X": "other",
}


@dataclass(frozen=True, slots=True)
class Fd:
    """从一个 fd token 解出来的全部信息。"""

    num: int
    code: str          # 单字符类型码或空
    kind: str          # file / directory / ipv4 / ipv6 / unix / pipe / other ...
    name: str          # 路径、元组、pipe:[inode] 等
    proto: str = ""    # tcp / udp / ""

    @property
    def is_socket(self) -> bool:
        return self.kind in ("ipv4", "ipv6")

    @property
    def is_file_like(self) -> bool:
        return self.kind in ("file", "directory")


def split_tokens(text: str) -> list[str]:
    """按空格切分，但括号内的空格不切（unix 套接字名字里有空格）。"""
    tokens: list[str] = []
    start = 0
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == " " and depth == 0:
            if i > start:
                tokens.append(text[start:i])
            start = i + 1
    if start < len(text):
        tail = text[start:]
        if tail:
            tokens.append(tail)
    return tokens


def _extract_payload(text: str) -> tuple[str, str]:
    """把 data=... 摘出来单独返回，避免载荷里的空格把后续键切碎。

    sysdig 把载荷渲染成可打印字符（不可打印字节变成 '.'），所以这里
    拿到的是一段安全文本，不是二进制。
    """
    m = re.search(r"(?:^|\s)data=", text)
    if not m:
        return text, ""
    start = m.end()
    nxt = _KEY_RE.search(text, start)
    end = nxt.start() if nxt else len(text)  # search(pos) 返回的是绝对下标
    payload = text[start:end]
    return text[: m.start()] + text[end:], payload


def parse(text: str) -> dict[str, str]:
    """evt.args 原文 -> {键: 原样值}。

    键不存在时调用方拿不到值；值一律保持数据源原生形态（R3）。
    """
    if not text:
        return {}
    rest, payload = _extract_payload(text)
    out: dict[str, str] = {}
    for token in split_tokens(rest):
        eq = token.find("=")
        if eq <= 0:
            continue  # 位置参数（如 execve 的命令行碎片）没有消费者
        out[token[:eq]] = token[eq + 1 :]
    if payload:
        out["data"] = payload
    return out


def annotation(value: str) -> str:
    """`fd=8(<f>/run/x)` / `res=-2(ENOENT)` / `mode=0644(S_IWUSR|...)` -> 括号内文本。"""
    if not value.endswith(")"):
        return ""
    idx = value.rfind("(")
    return value[idx + 1 : -1] if idx >= 0 else ""


def int_of(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    head = value.split("(", 1)[0].strip()
    if head == "":
        return None
    try:
        return int(head, 10)
    except ValueError:
        try:
            return int(head, 16)  # mmap 的 result 是十六进制地址
        except ValueError:
            return None


def flags_of(value: str | None) -> set[str]:
    if not value:
        return set()
    inner = annotation(value)
    if not inner:
        return set()
    return {part for part in inner.split("|") if part}


def fd_of(value: str | None) -> Fd | None:
    """`5(<f>/etc/passwd)` -> Fd(5, 'f', 'file', '/etc/passwd')。"""
    if not value:
        return None
    m = _FD_RE.match(value.strip())
    if not m:
        return None
    num = int(m.group(1))
    inner = m.group(2)
    code = ""
    name = inner
    if inner.startswith("<"):
        close = inner.find(">")
        if close > 0:
            code = inner[1:close]
            name = inner[close + 1 :]
    if code.startswith(("4", "6")):
        kind = "ipv4" if code[0] == "4" else "ipv6"
        proto = {"t": "tcp", "u": "udp"}.get(code[1:2], "")
    else:
        kind = _KIND_BY_CODE.get(code[:1], "other")
        proto = ""
    return Fd(num=num, code=code, kind=kind, name=name, proto=proto)


def tuple_of(name: str) -> tuple[str, int, str, int] | None:
    """`1.2.3.4:5->6.7.8.9:10` -> (sip, sport, dip, dport)。IPv6 用 rsplit 兜住。"""
    text = name.strip()
    if "->" not in text:
        return None
    left, right = text.split("->", 1)
    left = left.strip()
    right = right.strip()
    if ":" not in left or ":" not in right:
        return None
    sip, sport_s = left.rsplit(":", 1)
    dip, dport_s = right.rsplit(":", 1)
    sport = int_of(sport_s)
    dport = int_of(dport_s)
    if sport is None or dport is None:
        return None
    return sip.strip(), sport, dip.strip(), dport


def is_wildcard(ip: str) -> bool:
    return ip in ("", "0.0.0.0", "::", "*")


def tuple_usable(name: str, session: bool) -> bool:
    """§2.3 良构判据：会话两端端口>0且无通配；端点允许通配但端口>0。"""
    parsed = tuple_of(name)
    if parsed is None:
        return False
    sip, sport, dip, dport = parsed
    if sport <= 0 or dport <= 0:
        return False
    if session:
        return not (is_wildcard(sip) or is_wildcard(dip))
    return True


def endpoint_usable(name: str) -> bool:
    """`0.0.0.0:8443` 形态（bind/listen）。"""
    text = name.strip()
    if ":" not in text or "->" in text:
        return False
    ip, port_s = text.rsplit(":", 1)
    port = int_of(port_s)
    return port is not None and port > 0


def unix_path(name: str) -> str:
    """从 unix 套接字的原生名字里取路径。

    实测两种形态：
      `<u>/run/user/1000/bus`            -> 直接就是路径
      `0->ffff8bdb2a89d400 /var/run/nscd/socket` -> 空格后才是路径
    抽象命名空间（`public/qmgr`）不是路径，返回空串（R3：不能当身份）。
    """
    text = (name or "").strip()
    if text.startswith("/"):
        return text
    idx = text.rfind(" ")
    if idx >= 0:
        tail = text[idx + 1 :].strip()
        if tail.startswith("/"):
            return tail
    return ""


def is_unknown_name(name: str) -> bool:
    """`<UNKNOWN><3>`、`<unknown>`、空串、`<e>` 这类类型代号都不能当身份（R3）。"""
    text = name.strip()
    if not text:
        return True
    if text.startswith("<"):
        return True
    return False


def payload_head(args: dict[str, str], limit: int) -> str | None:
    data = args.get("data")
    if not data:
        return None
    return data[:limit] if limit > 0 else None


def payload_head_b64(value: str, limit: int) -> str | None:
    """%evt.buffer -b 的 base64 -> 前 limit 字节的 base64。"""
    if not value or limit <= 0:
        return None
    try:
        raw = base64.b64decode(value, validate=False)
    except Exception:
        return None
    return base64.b64encode(raw[:limit]).decode("ascii")
