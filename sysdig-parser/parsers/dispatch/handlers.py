"""System call handler registration: the four special syscalls (execve /
accept / fcntl / rename), the MetaConfig-driven generic directions
(f2p / p2f / n2p / p2n), and three exit-record-based families added for
attack-provenance coverage:

- open family   (openat / openat2 / creat / fchmod / fchmodat):
  进入记录 args 为空，文件实体只能从退出记录提取（fd=<f> 或 filename=）。
  openat 按 flags 决定方向（写标志 -> p2f，否则 f2p）；creat/fchmod* 恒为 p2f。
  退出记录带 res= 时（fchmod*），res<0 的失败操作不建边；openat/creat
  的成败编码在 fd=（失败 fd=-N(errno) 提不出实体，自然跳过）。
- lifecycle family (unlink / unlinkat / mkdir / mkdirat / rmdir / symlink):
  路径在退出记录的字段中（非 at 变体 path=，*at 变体 name= 并附括号内
  解析路径，symlink 为 linkpath=），建 p2f 边（进程对文件生命周期
  的写类操作）；res<0 的失败操作不建边。
- connect: 进入记录 fd 不带端点（fd=N(<4>)），四元组只能从退出记录的
  tuple= 字段解析，建 p2n 边；unix/内核地址 tuple 无法成顶点，不建边。
- renameat/renameat2：与 rename 同语义的 *at 变体，共用 _rename_action。
- 进程创建家族（clone/vfork/fork）：每次创建有父侧（res=子pid(名字)）与
  子侧（res=0）两类退出记录，只在父侧建 p2p 边；CLONE_THREAD 线程克隆
  跳过（与父共享进程顶点，建边即自环）。
- bind：监听端点 p2n 边，端点取退出记录 addr= 字段（本采集全为 netlink
  socket 的 addr=NULL，不建边）。

边的 syscall 属性写家族基本名（canonical_syscall，见 meta_config.py）：
pread/preadv/preadv2 -> read、sendmsg/sendmmsg -> sendto、
openat/creat -> open、fchmod/fchmodat -> chmod 等；事件分发与 enter/exit
配对仍使用 evt.type 原始名。

ftruncate / utimensat / chown / setxattr 在当前采集里 enter/exit args
均为空，无路径可提取，不注册（加入后只会变成 unmatched 跳过）。

Actions need to emit graph elements, so they take a ``ParserContext``
(the pipeline parser) that provides id generation, edge queueing, and the
entity registry.  Registration order is load-bearing: same-named syscalls
across direction tables overwrite each other in dict order (see the
generic-directions comment below), so keep the sequence unchanged.
"""

import re
from typing import Dict, List, Optional, Protocol

from ..jsonl.fields import extract_size
from ..jsonl.record import parse_timestamp_ns
from ..model.entities import Entity, FileEntity, NetworkEntity
from ..model.entity_node import EntityNode
from ..model.event_edge import EventEdge
from .meta_config import MetaConfig, canonical_syscall
from .system_call import Fingerprint, SystemCall, SystemCallFactory

# oldpath 用与 _extract_named_field 相同的 key= 前瞻收口：renameat2 在
# oldpath 与 newpath 之间还有 newdirfd= 字段，若只以 " newpath=" 定界，
# old 捕获组会把 newdirfd 一起吞入（再经括号剥离后变成 "AT_FDCWD"）。
_RENAME_PATHS = re.compile(
    r"oldpath=(?P<old>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=)"
    r".*?newpath=(?P<new>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)"
)
_PARENT_PATTERN = re.compile(r"ptid=(?P<parentPID>\d+)\((?P<parent>.+?)\)")

# flags=13377(O_DIRECTORY|O_RDONLY|...)：括号内的标志名列表。
# open 家族据此判断打开方向；clone 家族据此过滤 CLONE_THREAD 线程克隆。
_FLAGS_VALUE_PATTERN = re.compile(r"flags=\d*(?:\((?P<names>[^)]*)\))?")

# openat 的写意图标志：命中任一按写类（p2f）建边，否则按读类（f2p）。
# 不含 O_TMPFILE：本采集的 sysdig 会把 O_DIRECTORY 打开的符号 flags 展开
# 出 O_TMPFILE（208/208 均伴随 O_DIRECTORY），纯读的目录打开会被误判为
# 写；而真正的 O_TMPFILE 打开没有可解析路径，不会成顶点建边。
_OPEN_WRITE_FLAGS = frozenset({
    "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND",
})

# clone/vfork 父侧退出记录：res=<子pid>(<子名>)（子侧记录 res=0，无括号）。
_SPAWN_RES_PATTERN = re.compile(r"^res=(?P<cpid>\d+)\((?P<cname>[^)]*)\)")

# bind 退出记录的绑定地址：addr=127.0.0.1:53（netlink 等为 addr=NULL）。
_BIND_ADDR_PATTERN = re.compile(r"addr=(?P<addr>\S+)")

# 退出记录中 “key=value（到下一个 key= 或串尾）” 的字段提取，
# 覆盖 path=/linkpath=（unlink/mkdir/symlink 家族）与 tuple=（connect）。
def _extract_named_field(args: str, field: str) -> Optional[str]:
    match = re.search(
        rf"(?:^| ){re.escape(field)}=(?P<value>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
        args,
    )
    if match is None:
        return None
    value = match.group("value").strip()
    return value or None

# connect 退出记录 tuple=127.0.0.1:41135->127.0.0.53:53；
# unix/内核地址 tuple（如 tuple=0->ffff890c...）无端口，解析失败返回 None。
_CONNECT_TUPLE_PATTERN = re.compile(r"tuple=(?P<src>\S+)->(?P<dst>\S+)")
_ENDPOINT_VALUE_PATTERN = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def _flag_names(args: str) -> set:
    """提取 flags=N(A|B|...) 的标志名集合；无 flags 字段返回空集。"""
    match = _FLAGS_VALUE_PATTERN.search(args)
    if match is None or match.group("names") is None:
        return set()
    return set(match.group("names").split("|"))


def _open_is_write(args: str) -> bool:
    return bool(_flag_names(args) & _OPEN_WRITE_FLAGS)


def _parse_connect_tuple(args: str):
    match = _CONNECT_TUPLE_PATTERN.search(args)
    if match is None:
        return None
    endpoints = []
    for part in (match.group("src"), match.group("dst")):
        ep = _ENDPOINT_VALUE_PATTERN.match(part)
        if ep is None:
            return None
        endpoints.append((ep.group("host"), ep.group("port")))
    return (*endpoints[0], *endpoints[1])


class ParserContext(Protocol):
    """Pipeline facilities the syscall actions need (implemented by
    SysdigLogParser)."""

    def next_event_id(self) -> int: ...

    def queue_edge(self, rel: str, edge: EventEdge) -> None: ...

    def get_or_create_process(
        self, process_key: str, pid: str, process_name: str, exe_path: str
    ) -> object: ...

    def get_or_create_file(self, file_key: str, path: str) -> object: ...

    def get_or_create_network(
        self, sip: str, sport: str, dip: str, dport: str, protocol: str = ""
    ) -> object: ...

    def register_forward_flow(self, key: str, edge: EventEdge) -> None: ...

    def extend_forward_flow(self, key: str, end_ns: int) -> None: ...

    def note_incomplete_network(self) -> None: ...


def _normalize_rename_path(path: Optional[str]) -> str:
    if path is None:
        return ""
    normalized = path.strip()
    if normalized.endswith(")") and "(" in normalized:
        normalized = normalized[normalized.index("(") + 1:-1].strip()
    return normalized


# MetaConfig 驱动的四类通用方向：
#   rel -> (工厂实体类型, 系统调用名集合, start_entities 中作为边源/汇的下标)
# 这四类系统调用的两端实体都取自进入记录
# （start_entities[0]=Process，[1]=File/Network），方向由下标决定。
# 顺序须与旧版逐段注册一致（ftop -> ptof -> ntop -> pton），
# 保证同名系统调用（如 rename 同时在 ftop/ptof 中）的覆盖结果不变。
_GENERIC_SYSCALL_DIRECTIONS = (
    ("f2p", FileEntity, MetaConfig.ftop_system_calls, 1, 0),
    ("p2f", FileEntity, MetaConfig.ptof_system_calls, 0, 1),
    ("n2p", NetworkEntity, MetaConfig.ntop_system_calls, 1, 0),
    ("p2n", NetworkEntity, MetaConfig.pton_system_calls, 0, 1),
)


def _update_p2p_links(
    ctx: ParserContext,
    start_rec: Dict[str, str],
    end_rec: Dict[str, str],
    start_entities: List[Optional[Entity]],
    end_entities: List[Optional[Entity]],
) -> None:
    """Extend the end time of the execve p2p edge keyed by the acting process.

    execve registers its parent->child edge under the parent's key (ptid);
    this lookup by the acting process's pid+name therefore only ever matches
    when the acting process is that parent — the child's own events never
    extend the edge.
    """
    end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
    key = end_rec.get("pid", "") + end_rec.get("process", "")
    ctx.extend_forward_flow(key, end_ns)


def _make_edge_action(
    ctx: ParserContext, rel: str, src_idx: int, dst_idx: int
):
    """Build the edge action shared by the four MetaConfig-driven directions.

    两端实体都取自进入记录（start_entities[0]=Process，[1]=File/Network），
    (src_idx, dst_idx) 决定边方向；size 取自退出记录 args 的 res=，
    res 缺失或为负（size == -1）时不建边。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        first_node = EntityNode(start_entities[0])
        second_node = EntityNode(start_entities[1])
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        size = extract_size(end_rec.get("args", ""))
        if size != -1:
            edge = EventEdge(
                first_node if src_idx == 0 else second_node,
                first_node if dst_idx == 0 else second_node,
                ctx.next_event_id(),
                canonical_syscall(start_rec.get("event", "")),
                size,
                start_ns,
                end_ns,
            )
            ctx.queue_edge(rel, edge)

    return action


def _make_open_family_action(ctx: ParserContext, event: str, always_write: bool):
    """open 家族：文件实体来自退出记录（进入记录 args 为空）。

    openat/openat2 按 flags 判断方向；creat/fchmod/fchmodat 语义上恒为
    写类（always_write=True）。size 恒为 0：openat/creat 的 res 是 fd 号、
    chmod 的 res 是状态码，都不是字节量。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)
        args = end_rec.get("args", "")
        # openat/creat 的成败编码在 fd=（失败 fd=-N(errno)，提取不出实体，
        # 自然跳过，且退出记录没有 res= 字段）；fchmod/fchmodat 的退出记录
        # 带 res=，res<0（失败操作）不建边。因此仅在 res= 存在时检查。
        if "res=" in args and extract_size(args) == -1:
            return
        f = end_entities[1]  # FileEntity（退出记录 fd=<f> 或 filename=）
        if f is None:
            return
        p = end_entities[0]  # Process（取自退出记录，dummy start 时仍可靠）
        p_node = EntityNode(p)
        f_node = EntityNode(f)
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        if always_write or _open_is_write(args):
            edge = EventEdge(
                p_node, f_node, ctx.next_event_id(),
                canonical_syscall(event), 0, start_ns, end_ns,
            )
            ctx.queue_edge("p2f", edge)
        else:
            edge = EventEdge(
                f_node, p_node, ctx.next_event_id(),
                canonical_syscall(event), 0, start_ns, end_ns,
            )
            ctx.queue_edge("f2p", edge)

    return action


def _normalize_exit_path(value: Optional[str]) -> str:
    """*at 变体 name= 值的两种形态归一：普通绝对路径原样返回；
    相对名(解析后的绝对路径)取括号内的绝对路径。

    仅当括号内以 / 开头才剥离，避免误伤本身以括号结尾的真实路径
    （如 /tmp/foo (bar)）。
    """
    if value is None:
        return ""
    normalized = value.strip()
    if normalized.endswith(")") and "(" in normalized:
        inner = normalized[normalized.index("(") + 1 : -1].strip()
        if inner.startswith("/"):
            return inner
    return normalized


def _make_exit_path_action(ctx: ParserContext, event: str, fields):
    """unlink/mkdir/symlink 家族：路径在退出记录的字段中。

    fields 为按序尝试的候选字段名：非 at 变体（unlink/mkdir/rmdir）用
    path=，*at 变体（unlinkat/mkdirat）用 name=（sysdig 对相对名附加
    括号内的解析路径），symlink 用 linkpath=。

    建 p2f 边（进程 -> 被创建/删除的文件，写类生命周期操作）；
    res<0（如 mkdir EEXIST）或无路径字段时不建边。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        args = end_rec.get("args", "")
        if extract_size(args) == -1:
            return
        path = None
        for field in fields:
            raw = _extract_named_field(args, field)
            if raw is not None:
                path = _normalize_exit_path(raw)
                break
        if not path:
            return
        p = end_entities[0]  # Process
        file = ctx.get_or_create_file(path, path)
        p_node = EntityNode(p)
        f_node = EntityNode(file)
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        edge = EventEdge(
            p_node, f_node, ctx.next_event_id(),
            canonical_syscall(event), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2f", edge)

    return action


def _make_connect_action(ctx: ParserContext):
    """connect：四元组在退出记录 tuple= 字段（进入记录 fd 不带端点）。

    建 p2n 边（进程 -> 目标连接）；res<0（连接失败）或 tuple 解析不出
    （unix/内核地址）时不建边。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        args = end_rec.get("args", "")
        if extract_size(args) == -1:
            return
        endpoints = _parse_connect_tuple(args)
        if endpoints is None:
            return
        sip, sport, dip, dport = endpoints
        p = end_entities[0]  # Process
        n = ctx.get_or_create_network(
            sip, sport, dip, dport, protocol=end_rec.get("l4proto", "")
        )
        p_node = EntityNode(p)
        n_node = EntityNode(n)
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        edge = EventEdge(
            p_node, n_node, ctx.next_event_id(),
            "connect", 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2n", edge)

    return action


def _make_spawn_action(ctx: ParserContext, event: str):
    """进程创建家族（clone / vfork / fork）：父 -> 子 p2p 边。

    每次创建产生两类退出记录：父侧（记录进程=父，res=<子pid>(<子名>)，
    与进入记录真实配对）与子侧（记录进程=子，res=0，走 dummy start）。
    只在父侧建边，子侧 res=0 解析不出子 pid，自然跳过。CLONE_THREAD
    线程克隆与父进程共享同一进程顶点，建边会成自环，必须跳过。子顶点
    的描述属性由子侧记录与子进程后续事件回填，这里只带 pid+name。
    边注册在父进程键下。注意 forward-flow 每键只存一条边（后注册覆盖
    先注册）：子进程随后 execve 时，execve 边会以同一父键接管延长，本边
    的 endtime 停在出生时刻 —— 出生是瞬时事件，execve 边承载后续的
    父子关系活跃期，语义可接受；子进程不 execve 时（纯 fork）本边照常
    被父进程后续事件延长。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)
        args = end_rec.get("args", "")
        if "CLONE_THREAD" in _flag_names(args):
            return
        match = _SPAWN_RES_PATTERN.match(args.strip())
        if match is None:
            return
        child_pid = match.group("cpid")
        child_name = match.group("cname")
        p = end_entities[0]  # 记录进程 = 父进程
        child = ctx.get_or_create_process(
            child_pid + child_name, child_pid, child_name, ""
        )
        p_node = EntityNode(p)
        c_node = EntityNode(child)
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        edge = EventEdge(
            p_node, c_node, ctx.next_event_id(),
            canonical_syscall(event), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2p", edge)
        ctx.register_forward_flow(
            end_rec.get("pid", "") + end_rec.get("process", ""), edge
        )

    return action


def _make_bind_action(ctx: ParserContext):
    """bind：监听端点，p2n 边（进程 -> 本地服务端点）。

    端点取退出记录 addr=<host:port>；远端未知记 0.0.0.0:0。本采集的
    bind 全部是 netlink socket（addr=NULL），不建边；addr 解析不出
    （NULL/非 host:port）时静默跳过。res<0（绑定失败）不建边。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        args = end_rec.get("args", "")
        if extract_size(args) == -1:
            return
        match = _BIND_ADDR_PATTERN.search(args)
        if match is None:
            return
        endpoint = _ENDPOINT_VALUE_PATTERN.match(match.group("addr"))
        if endpoint is None:
            return
        p = end_entities[0]  # Process
        n = ctx.get_or_create_network(
            endpoint.group("host"), endpoint.group("port"),
            "0.0.0.0", "0", protocol=end_rec.get("l4proto", ""),
        )
        p_node = EntityNode(p)
        n_node = EntityNode(n)
        start_ns = parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
        end_ns = parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
        edge = EventEdge(
            p_node, n_node, ctx.next_event_id(),
            canonical_syscall("bind"), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2n", edge)

    return action


# open 家族：文件实体在退出记录 -> 指纹 (None, FileEntity)。
_OPEN_FAMILY = (
    # (事件名, 是否恒为写类)
    ("openat", False),
    ("openat2", False),
    ("creat", True),
    ("fchmod", True),
    ("fchmodat", True),
)

# 文件生命周期家族：路径字段在退出记录 -> 指纹 (None, None)。
# 额外注册 (FileEntity, None) 兜底：个别采集进入记录可能带 fd。
_EXIT_PATH_FAMILY = (
    # (事件名, 候选路径字段，按序尝试)。本采集实测：unlink/mkdir 用
    # path=，unlinkat 用 name=（sysdig 对 *at 变体的参数名），symlink 用
    # linkpath=；候选列表同时兼容其他采集形态。
    ("unlink", ("path", "name")),
    ("unlinkat", ("name", "path")),
    ("rmdir", ("path", "name")),
    ("mkdir", ("path", "name")),
    ("mkdirat", ("name", "path")),
    ("symlink", ("linkpath",)),
)


def build_handlers(ctx: ParserContext) -> Dict[Fingerprint, SystemCall]:
    """Build the full fingerprint -> SystemCall handler table."""
    handlers: Dict[Fingerprint, SystemCall] = {}

    # --- 通用方向（MetaConfig 驱动：f2p / p2f / n2p / p2n）---
    for rel, entity_cls, syscall_names, src_idx, dst_idx in _GENERIC_SYSCALL_DIRECTIONS:
        factory = SystemCallFactory(entity_cls, None)
        factory.add_action(_make_update_p2p_links_action(ctx))
        factory.add_action(_make_edge_action(ctx, rel, src_idx, dst_idx))
        for sc_name in syscall_names:
            sc = factory.get_system_call(sc_name)
            handlers[sc.fingerprint] = sc

    # --- execve (special: PtoP + file edge) ---
    def _execve_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        p_end = end_entities[0]  # Process
        p_end_node = EntityNode(p_end)
        f = start_entities[1]  # FileEntity (executable)
        file_node = EntityNode(f)
        exe_path = start_rec.get("exepath", "")
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        args = end_rec.get("args", "")

        if "res=0" in args:
            if f.path != "<NA>":
                edge = EventEdge(
                    file_node, p_end_node, ctx.next_event_id(),
                    "execve", 0, start_ns, end_ns,
                )
                ctx.queue_edge("f2p", edge)

            parent_match = _PARENT_PATTERN.search(args)
            if parent_match:
                pid_parent = parent_match.group("parentPID")
                name_parent = parent_match.group("parent")
                key_parent = pid_parent + name_parent
                parent = ctx.get_or_create_process(
                    key_parent, pid_parent, name_parent, exe_path
                )
                parent_node = EntityNode(parent)
                forward_edge = EventEdge(
                    parent_node, p_end_node, ctx.next_event_id(),
                    "execve", 0, start_ns, end_ns,
                )
                ctx.queue_edge("p2p", forward_edge)
                ctx.register_forward_flow(key_parent, forward_edge)

    execve_sc = SystemCall(
        Fingerprint("execve", FileEntity, None),
    ).add_action(_execve_action)
    handlers[execve_sc.fingerprint] = execve_sc

    # --- accept (special: NtoP) ---
    def _accept_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        p = end_entities[0]  # Process
        p_node = EntityNode(p)
        n = end_entities[1]  # NetworkEntity
        if n is None:
            # 无完整五元组的 accept（如内核 fd 地址）-> 不建边，可审计
            ctx.note_incomplete_network()
            return
        n_node = EntityNode(n)
        ts_end = end_rec.get("timestamp", "0.0")
        end_ns = parse_timestamp_ns(ts_end)

        edge = EventEdge(
            n_node, p_node, ctx.next_event_id(),
            "accept", 0, end_ns, end_ns,
        )
        ctx.queue_edge("n2p", edge)

    accept_sc = SystemCall(
        Fingerprint("accept", None, NetworkEntity),
    ).add_action(_accept_action)
    handlers[accept_sc.fingerprint] = accept_sc

    # --- fcntl (special: NtoP) ---
    def _fcntl_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        p = end_entities[0]  # Process
        p_node = EntityNode(p)
        n = end_entities[1]  # NetworkEntity
        if n is None:
            ctx.note_incomplete_network()
            return
        n_node = EntityNode(n)

        edge = EventEdge(
            n_node, p_node, ctx.next_event_id(),
            "fcntl", 0, start_ns, end_ns,
        )
        ctx.queue_edge("n2p", edge)

    fcntl_sc = SystemCall(
        Fingerprint("fcntl", None, NetworkEntity),
    ).add_action(_fcntl_action)
    handlers[fcntl_sc.fingerprint] = fcntl_sc

    # --- rename (special: PtoF + FtoP) ---
    def _rename_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        ts_start = start_rec.get("timestamp", "0.0")
        ts_end = end_rec.get("timestamp", "0.0")
        start_ns = parse_timestamp_ns(ts_start)
        end_ns = parse_timestamp_ns(ts_end)
        args = end_rec.get("args", "")
        rename_match = _RENAME_PATHS.search(args)
        if not rename_match:
            return

        old_path = _normalize_rename_path(rename_match.group("old"))
        new_path = _normalize_rename_path(rename_match.group("new"))

        p = start_entities[0]  # Process
        p_node = EntityNode(p)

        old_file = ctx.get_or_create_file(old_path, old_path)
        old_f_node = EntityNode(old_file)
        f2p_edge = EventEdge(
            old_f_node, p_node, ctx.next_event_id(),
            "rename", 0, start_ns, end_ns,
        )
        ctx.queue_edge("f2p", f2p_edge)

        new_file = ctx.get_or_create_file(new_path, new_path)
        new_f_node = EntityNode(new_file)
        p2f_edge = EventEdge(
            p_node, new_f_node, ctx.next_event_id(),
            "rename", 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2f", p2f_edge)

    rename_sc = SystemCall(
        Fingerprint("rename", None, None),
    ).add_action(_rename_action)
    handlers[rename_sc.fingerprint] = rename_sc

    # renameat/renameat2 与 rename 同语义（*at 变体，退出记录同样带
    # oldpath/newpath），共用 _rename_action；边属性固定为 "rename"。
    for rename_variant in ("renameat", "renameat2"):
        sc = SystemCall(
            Fingerprint(rename_variant, None, None),
        ).add_action(_rename_action)
        handlers[sc.fingerprint] = sc

    # --- open 家族（openat / creat / fchmod*：文件实体在退出记录）---
    for event, always_write in _OPEN_FAMILY:
        sc = SystemCall(
            Fingerprint(event, None, FileEntity),
        ).add_action(_make_open_family_action(ctx, event, always_write))
        handlers[sc.fingerprint] = sc

    # --- 文件生命周期家族（unlink / mkdir / symlink：路径在退出记录）---
    for event, fields in _EXIT_PATH_FAMILY:
        sc = SystemCall(
            Fingerprint(event, None, None),
        ).add_action(_make_exit_path_action(ctx, event, fields))
        handlers[sc.fingerprint] = sc
        # 兜底：进入记录带 fd 的采集形态（当前采集不会命中）
        sc_fb = SystemCall(
            Fingerprint(event, FileEntity, None),
        ).add_action(_make_exit_path_action(ctx, event, fields))
        handlers[sc_fb.fingerprint] = sc_fb

    # --- connect（四元组在退出记录 tuple=）---
    # 进入记录 fd 有两种形态：裸 <4>/<6>（无端点 -> 指纹 (None, None)）与
    # 带端点的 <4t>/<4u>/...（实体提取出 NetworkEntity -> 指纹
    # (NetworkEntity, None)）。两种都必须注册；边统一由退出记录 tuple= 构造
    # （进入记录的远端端口多为 0，不可靠）。
    connect_action = _make_connect_action(ctx)
    for c1 in (None, NetworkEntity):
        connect_sc = SystemCall(
            Fingerprint("connect", c1, None),
        ).add_action(connect_action)
        handlers[connect_sc.fingerprint] = connect_sc

    # --- 进程创建家族（clone / vfork / fork：父 -> 子 p2p）---
    # 进入记录 args 为空、退出记录无 fd -> 指纹 (None, None)。
    for spawn_event in ("clone", "vfork", "fork"):
        sc = SystemCall(
            Fingerprint(spawn_event, None, None),
        ).add_action(_make_spawn_action(ctx, spawn_event))
        handlers[sc.fingerprint] = sc

    # --- bind（监听端点，p2n）---
    # 端点在退出记录 addr= 字段；进入记录 fd 形态同 connect，两种指纹都注册。
    bind_action = _make_bind_action(ctx)
    for c1 in (None, NetworkEntity):
        bind_sc = SystemCall(
            Fingerprint("bind", c1, None),
        ).add_action(bind_action)
        handlers[bind_sc.fingerprint] = bind_sc

    return handlers


def _make_update_p2p_links_action(ctx: ParserContext):
    """Bind _update_p2p_links to the context so it fits the Action signature."""

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)

    return action
