"""统一角色判定：离线蒸馏与在线匹配共用同一套编码。

设计要点：
  1. 角色由「结构属性」拼成，不用单一标签，取消 GENERIC 垃圾桶。
  2. 每个属性都有客观判据：网络方向、派生形态、实例数、写入者数、对端数。
     不引入新的路径常量（只保留"认证文件 / /etc 配置"这一层 POSIX 常识）。
  3. 数值档位（实例数、写入者数、对端数）的分界由建库时从训练数据算出，
     写进规则库；在线按同一组分界映射，保证两端角色一致。

角色编码：
  Process : P.<dir>.<spawn>.<inst>.<priv>
            dir   = in | out | both | none
            spawn = multi | exec | clone | leaf
            inst  = single | few | many
            priv  = chg | -
  File    : F.<bits>.<writers>.<sens>.<place>
            bits    = w/x/r/d 的任意组合，无为 "-"
            writers = multi | single | none
            sens    = auth | cfg | -
            place   = sys（/usr /lib /bin /sbin /etc 等）| usr（其余）
  Network : N.<dir>.<peers>
            dir   = listen | dial | both
            peers = multi | single
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from domain.keys import path_part, split_container, split_process_id

# ---- 只保留这一层路径常识（POSIX/FHS 通用） ----

AUTH_PATH_MARKERS = (
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers",
    "authorized_keys", "/.ssh/", "/etc/ssh/ssh_host",
)
CONFIG_PREFIX = "/etc/"
SYSTEM_PATH_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/boot/", "/opt/", "/etc/", "/var/lib/")
WRITE_SYSCALLS = ("write", "create", "rename", "symlink", "mkdir", "truncate", "unlink", "chmod", "chown")
EXEC_SYSCALLS = ("execve",)
READ_SYSCALLS = ("read", "open", "stat", "mmap_read", "sendfile")
PRIV_SYSCALLS = ("chmod", "chown")
NET_OUT_SYSCALLS = ("connect", "sendto", "send")


@dataclass
class RoleCuts:
    """数值档位分界。建库时从训练数据算出，写进规则库，在线复用。"""

    inst: Tuple[float, float] = (2.0, 5.0)       # (single/few, few/many)
    writers: Tuple[float, float] = (2.0, 3.0)
    peers: float = 2.0                            # (single/multi)

    def to_dict(self) -> Dict[str, Any]:
        return {"inst": list(self.inst), "writers": list(self.writers), "peers": self.peers}

    @classmethod
    def from_dict(cls, node: Optional[Dict[str, Any]]) -> "RoleCuts":
        if not node:
            return cls()
        return cls(
            inst=tuple(float(x) for x in (node.get("inst") or cls.inst))[:2],
            writers=tuple(float(x) for x in (node.get("writers") or cls.writers))[:2],
            peers=float(node.get("peers", cls.peers)),
        )

    @staticmethod
    def _band(value: float, cut: Tuple[float, float], names: Tuple[str, str, str]) -> str:
        """按 [0,lo) / [lo,hi) / [hi,∞) 三段映射到 names。

        严格小于：写入者数为 0 才落 none，1 落 single。
        """
        lo, hi = cut
        if value < lo:
            return names[0]
        if value < hi:
            return names[1]
        return names[2]


@dataclass
class RoleContext:
    """一个候选池的结构统计。"""

    proc_instances: Dict[str, int] = field(default_factory=dict)   # 程序标识 → 不同 (pid,start_ns) 数
    file_writers: Dict[str, int] = field(default_factory=dict)     # 文件路径 → 写入者实例数
    net_peers: Dict[str, int] = field(default_factory=dict)        # 网络端点 → 不同对端数
    in_edges: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    out_edges: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)           # 端点 → 顶点类型

    def to_cuts(self) -> RoleCuts:
        """按本池的分布算档位分界（中位数 / 95 分位）。"""
        def pick(values: Sequence[int]) -> Tuple[float, float]:
            if not values:
                return (2.0, 5.0)
            vals = sorted(values)
            n = len(vals)
            med = float(vals[n // 2])
            p95 = float(vals[min(n - 1, max(0, int(n * 0.95) - 1))])
            if p95 <= med:
                p95 = med + 1.0
            return (med, p95)

        i1, i2 = pick([v for v in self.proc_instances.values() if v > 0])
        w1, w2 = pick([v for v in self.file_writers.values() if v > 0])
        peers = [v for v in self.net_peers.values() if v > 0]
        p_cut = float(sorted(peers)[len(peers) // 2]) if peers else 2.0
        # 至少 2：对端数为 1 是单通道，>=2 才可能是服务端口
        p_cut = max(2.0, p_cut)
        return RoleCuts(inst=(i1, i2), writers=(w1, w2), peers=p_cut)


# ---------- 构建上下文 ----------

def _proc_key(endpoint: str) -> str:
    """程序标识：去掉 pid/start_ns，只留 host|container|可执行内容。"""
    host, container = split_process_id(endpoint)
    content = endpoint
    if host:
        parts = endpoint.split("|", 3)
        if len(parts) == 4:
            content = parts[3]
    return f"{host}|{container}|{content}"


def _peer_of(endpoint: str) -> Optional[str]:
    """网络端点 → 对端 IP。"""
    if "->" not in endpoint:
        return None
    left, right = endpoint.split("->", 1)
    for side in (left, right):
        ip = side.rsplit(":", 1)[0]
        if ip:
            return ip
    return None


_KIND_BY_PREFIX = {"p": "Process", "f": "File", "n": "Network"}


def _kind_of(endpoint: str, hint: str = "") -> str:
    if hint in ("Process", "File", "Network"):
        return hint
    if len(endpoint) >= 2 and endpoint[1] == ":":
        return _KIND_BY_PREFIX.get(endpoint[0], "")
    if "->" in endpoint:
        return "Network"
    return ""


def build_context(edges: Sequence[Dict[str, Any]]) -> RoleContext:
    """从一个候选池算出角色判定需要的统计量。"""
    ctx = RoleContext()
    seen_proc: Dict[str, set] = {}
    writers: Dict[str, set] = {}
    peers: Dict[str, set] = {}
    pool = list(edges)

    for e in pool:
        sc = str(e.get("syscall") or "")
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        pid = str(e.get("process_id") or "")
        sl = str(e.get("src_label") or "")
        dl = str(e.get("dst_label") or "")
        if src:
            ctx.labels.setdefault(src, _kind_of(src, sl))
            ctx.out_edges.setdefault(src, []).append(e)
        if dst:
            ctx.labels.setdefault(dst, _kind_of(dst, dl))
            ctx.in_edges.setdefault(dst, []).append(e)

        # 进程实例：以 process_id（含 pid+start_ns）为单位
        for endpoint, label in ((src, sl), (dst, dl)):
            if _kind_of(endpoint, label) == "Process":
                key = _proc_key(endpoint)
                bucket = seen_proc.setdefault(key, set())
                ident = pid if (pid and endpoint == src) else endpoint
                bucket.add(ident)

        # 文件写入者：写到该路径的不同进程实例
        if sc in WRITE_SYSCALLS and dst:
            writers.setdefault(dst, set()).add(pid or f"{src}@{e.get('start_ns')}")
        if sc in ("rename", "symlink") and src:
            writers.setdefault(src, set()).add(pid or f"{dst}@{e.get('start_ns')}")

        # 网络对端
        for endpoint in (src, dst):
            if "->" in endpoint:
                peer = _peer_of(endpoint)
                if peer:
                    peers.setdefault(endpoint, set()).add(peer)

    ctx.proc_instances = {k: len(v) for k, v in seen_proc.items()}
    ctx.file_writers = {k: len(v) for k, v in writers.items()}
    ctx.net_peers = {k: len(v) for k, v in peers.items()}
    return ctx


# ---------- 角色判定 ----------

def _path_of(endpoint: str) -> str:
    """从端点字符串里取出纯路径。

    兼容两种写法：标准答案的 `f:主机/容器:内容`，以及图侧原始内容（可能带容器前缀）。
    """
    s = str(endpoint)
    if len(s) >= 2 and s[1] == ":" and s[0] in "pfn" and s.count(":") >= 2:
        s = s.split(":", 2)[2]
    return split_container(s)[1]


def _place_of(path: str) -> str:
    """系统路径 vs 用户路径。只看是否落在系统目录，不看具体发行版布局。"""
    return "sys" if path.startswith(SYSTEM_PATH_PREFIXES) else "usr"


def _sens_of(path: str) -> str:
    if any(marker in path for marker in AUTH_PATH_MARKERS):
        return "auth"
    if path.startswith(CONFIG_PREFIX):
        return "cfg"
    return "-"


def _proc_role(s: str, ctx: RoleContext, cuts: RoleCuts) -> str:
    out = [e.get("syscall") for e in ctx.out_edges.get(s, [])]
    inn = [e.get("syscall") for e in ctx.in_edges.get(s, [])]
    in_net = any(x == "accept" for x in inn)
    out_net = any(x in NET_OUT_SYSCALLS for x in out)
    direction = "both" if (in_net and out_net) else "in" if in_net else "out" if out_net else "none"

    has_clone = "clone" in out
    has_exec = "execve" in out
    spawn = ("multi" if (has_clone and has_exec) else "exec" if has_exec
             else "clone" if has_clone else "leaf")

    inst = RoleCuts._band(ctx.proc_instances.get(_proc_key(s), 1),
                          cuts.inst, ("single", "few", "many"))
    priv = "chg" if any(x in PRIV_SYSCALLS for x in out) else "-"
    return f"P.{direction}.{spawn}.{inst}.{priv}"


def _file_role(s: str, ctx: RoleContext, cuts: RoleCuts) -> str:
    p = _path_of(s)
    bits = []
    ins = ctx.in_edges.get(s, [])
    outs = ctx.out_edges.get(s, [])
    if any(e.get("syscall") in WRITE_SYSCALLS for e in ins):
        bits.append("w")
    if any(e.get("syscall") in EXEC_SYSCALLS for e in ins):
        bits.append("x")
    if any(e.get("syscall") in READ_SYSCALLS for e in ins):
        bits.append("r")
    if any(e.get("syscall") == "unlink" for e in outs + ins):
        bits.append("d")
    bit_s = "".join(bits) or "-"
    writers = RoleCuts._band(int(ctx.file_writers.get(s, 0)),
                             cuts.writers, ("none", "single", "multi"))
    return f"F.{bit_s}.{writers}.{_sens_of(p)}.{_place_of(p)}"


def _net_role(s: str, ctx: RoleContext, cuts: RoleCuts) -> str:
    """网络端点的方向：accept 以连接为源（NetworkToProcess），connect 以连接为目标。

    所以「入站」看它作为 src 的 accept 边，「出站」看它作为 dst 的 connect/send 边。
    """
    outs = ctx.out_edges.get(s, [])
    inn = ctx.in_edges.get(s, [])
    listened = any(e.get("syscall") == "accept" for e in outs)
    dialed = any(e.get("syscall") in NET_OUT_SYSCALLS for e in inn)
    direction = "both" if (listened and dialed) else "listen" if listened else "dial"
    peers = RoleCuts._band(int(ctx.net_peers.get(s, 0)), (cuts.peers, cuts.peers * 10),
                           ("single", "single", "multi"))
    return f"N.{direction}.{peers}"


def profile_role(endpoint: str, ctx: RoleContext, cuts: RoleCuts,
                 kind_hint: str = "") -> str:
    """一个端点的多维角色编码。"""
    s = str(endpoint)
    kind = _kind_of(s, kind_hint) or ctx.labels.get(s, "")
    if kind == "Network" or "->" in s:
        return _net_role(s, ctx, cuts)
    if kind == "File":
        return _file_role(s, ctx, cuts)
    if kind == "Process":
        return _proc_role(s, ctx, cuts)
    # 类型未知时按结构猜：有出边就按进程，否则按文件
    return _proc_role(s, ctx, cuts) if ctx.out_edges.get(s) else _file_role(s, ctx, cuts)


def merge_contexts(contexts: Iterable[RoleContext]) -> RoleContext:
    """合并多个场景的统计（同名 key 取最大值，代表最"共享"的那次观测）。"""
    out = RoleContext()
    for ctx in contexts:
        for attr in ("proc_instances", "file_writers", "net_peers"):
            src = getattr(ctx, attr)
            dst = getattr(out, attr)
            for k, v in src.items():
                if v > dst.get(k, 0):
                    dst[k] = v
    return out


def role_map(ctx: RoleContext, cuts: RoleCuts) -> Dict[str, str]:
    """全部已出现端点的角色，供形态挖掘与在线匹配共用。"""
    return {ep: profile_role(ep, ctx, cuts, ctx.labels.get(ep, "")) for ep in ctx.labels}
