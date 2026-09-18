"""System call handler registration: the four special syscalls (execve /
accept / fcntl / rename), the MetaConfig-driven generic directions
(f2p / p2f / n2p / p2n), and two exit-record-based families:
- fchmod / fchmodat (chmod)：进入记录 args 为空，文件实体只能从退出记录
  提取（fd=<f>）；退出记录带 res= 时，res<0 的失败操作不建边。
- lifecycle family (unlink / unlinkat / mkdir / mkdirat / rmdir / symlink):
  路径在退出记录的字段中（非 at 变体 path=，*at 变体 name= 并附括号内
  解析路径，symlink 为 linkpath=），建 p2f 边（进程对文件生命周期
  的写类操作）；res<0 的失败操作不建边。
- openat / openat2 / creat：不产出溯源边——读意图 open 的信息被 read
  家族覆盖（同对 read 边），写意图 open 被 write 家族覆盖，仅存的独特
  场景（O_TRUNC 截断且零写入）按调查目标放弃。指纹仍注册以免计入
  unmatched，事件继续参与 execve/clone p2p 边 endtime 的延长（进程
  活跃期语义不变）。
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
from typing import Dict, List, Optional, Protocol, Tuple

from ..jsonl.fields import (
    UNIX_PATH_IN_CONNECT_TUPLE_RE,
    extract_file_and_socket,
    strip_path_annotation,
)
from ..jsonl.record import (
    record_connect_failed,
    record_failed,
    record_in_progress,
    record_res,
    record_size,
    record_start_ns,
)
from ..model.entities import Entity, FileEntity, NetworkEntity
from ..model.entity_node import EntityNode
from ..model.event_edge import EventEdge
from .meta_config import (
    CANONICAL_SYSCALL_MAP,
    MetaConfig,
    canonical_syscall,
)
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
# clone 家族据此过滤 CLONE_THREAD 线程克隆。
_FLAGS_VALUE_PATTERN = re.compile(r"flags=\d*(?:\((?P<names>[^)]*)\))?")

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
# unix socket 的 tuple：无端口，但有文件系统路径尾巴
#   tuple=ffff8939144a3c00->ffff893810fa2c00 /dev/log
# 抽象命名空间（tuple=... @/tmp/.X11-unix/X0）不匹配。
# 正则本体在 jsonl/fields.py（与 fd_table / fields 共用，避免三份实现漂移）。


def _flag_names(args: str) -> set:
    """提取 flags=N(A|B|...) 的标志名集合；无 flags 字段返回空集。"""
    match = _FLAGS_VALUE_PATTERN.search(args)
    if match is None or match.group("names") is None:
        return set()
    return set(match.group("names").split("|"))


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

    def entity_from_descriptor(self, record, file_socket) -> object: ...

    def get_or_create_network(
        self, sip: str, sport: str, dip: str, dport: str, protocol: str = ""
    ) -> object: ...

    def register_forward_flow(self, key: str, edge: EventEdge) -> None: ...

    def extend_forward_flow(self, key: str, end_ns: int) -> None: ...

    def note_incomplete_network(self) -> None: ...

    def note_connect_in_progress(self) -> None: ...


def _normalize_rename_path(path: Optional[str]) -> str:
    """rename 家族路径归一（旧的独立实现已收敛到 fields.strip_path_annotation，
    规则同一：仅括号内以 / 开头才剥壳）；词法归一由 File 键生成处统一做。"""
    if path is None:
        return ""
    return strip_path_annotation(path) or ""


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
    # send/recv 家族在 unix socket（合成 File 顶点，G1 类①）上的方向：
    # 端点是 File 而非 Network，必须落到 f2p/p2f（关系名决定端点标签），
    # 不能沿用 n2p/p2n。指纹 (recvmsg, FileEntity, None) / (sendmsg, FileEntity, None)
    # 此前未注册（send/recv 家族原先只在 NetworkEntity 方向注册），不覆盖
    # 任何既有条目，所以追加到末尾是安全的。
    ("f2p", FileEntity, MetaConfig.recv_system_calls, 1, 0),
    ("p2f", FileEntity, MetaConfig.send_system_calls, 0, 1),
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
    end_ns = record_start_ns(end_rec)
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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        size = record_size(end_rec)
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


def _make_chmod_action(ctx: ParserContext, event: str):
    """fchmod/fchmodat（chmod）：文件实体来自退出记录（进入记录 args 为空）。

    退出记录带 res= 时，res<0 的失败操作不建边。size 恒为 0：chmod 的
    res 是状态码，不是字节量。边 syscall 为归一名 chmod。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)
        if record_failed(end_rec):
            return
        f = end_entities[1]  # FileEntity（退出记录 fd=<f>）
        if f is None:
            return
        p = end_entities[0]  # Process（取自退出记录，dummy start 时仍可靠）
        p_node = EntityNode(p)
        f_node = EntityNode(f)
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        edge = EventEdge(
            p_node, f_node, ctx.next_event_id(),
            canonical_syscall(event), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2f", edge)

    return action


def _make_open_link_extension_action(ctx: ParserContext):
    """openat / openat2 / creat：不产出溯源边，只延长 p2p 边活跃期。

    读意图 open 的信息被同对的 read 边覆盖，写意图 open 被 write 边覆盖；
    仅存的独特场景（O_TRUNC 截断且零写入）按调查目标放弃。指纹仍注册，
    事件不计入 unmatched，且继续参与 execve/clone p2p 边 endtime 的延长，
    进程活跃期语义与建边时代保持一致。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        _update_p2p_links(ctx, start_rec, end_rec, start_entities, end_entities)

    return action


def _normalize_exit_path(value: Optional[str]) -> str:
    """生命周期家族（unlink/mkdir/rmdir/symlink 及 *at 变体）退出记录里的
    路径归一。实现已收敛到 fields.strip_path_annotation（与 rename 共用一套
    规则，避免再出现“某条通道忘了归一”）；词法归一由 File 键生成处统一做。
    """
    if value is None:
        return ""
    return strip_path_annotation(value) or ""


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
        if record_failed(end_rec):
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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        edge = EventEdge(
            p_node, f_node, ctx.next_event_id(),
            canonical_syscall(event), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2f", edge)

    return action


def _make_connect_action(ctx: ParserContext):
    """connect：四元组在退出记录 tuple= 字段（进入记录 fd 不带端点）。

    建 p2n 边（进程 -> 目标连接）；tuple 解析不出（unix/内核地址）时不建边。
    失败判据用 record_connect_failed：res<0 视为失败，但 EINPROGRESS(-115)
    （非阻塞 connect 已发起、四元组已由内核分配）不算失败，照常建边并计数。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        args = end_rec.get("args", "")
        if record_connect_failed(end_rec):
            return
        endpoints = _parse_connect_tuple(args)
        if endpoints is None:
            # unix socket 的 tuple 没有端口：类①（文件系统路径）建
            #   Process --connect--> unix:[/run/user/1000/systemd/private]
            # （G1 §2.3 期望形态）。抽象命名空间与内核地址对不成顶点，不建边。
            m = UNIX_PATH_IN_CONNECT_TUPLE_RE.search(args)
            if m is None:
                return
            unix_path = m.group("path")
            p = end_entities[0]  # Process
            if p is None:
                return
            unix = f"unix:[{unix_path}]"
            file_entity = ctx.get_or_create_file(unix, unix)
            ctx.queue_edge("p2f", EventEdge(
                EntityNode(p), EntityNode(file_entity), ctx.next_event_id(),
                "connect", 0, record_start_ns(start_rec), record_start_ns(end_rec),
            ))
            return
        if record_in_progress(end_rec):
            # 计数放在端点解析之后：该计数严格等于“EINPROGRESS 且实际建了边”的次数，
            # 于是 Δ(p2n 边数) == connect_in_progress 可直接当作改写正确性的断言。
            ctx.note_connect_in_progress()
        sip, sport, dip, dport = endpoints
        p = end_entities[0]  # Process
        n = ctx.get_or_create_network(
            sip, sport, dip, dport, protocol=end_rec.get("l4proto", "")
        )
        p_node = EntityNode(p)
        n_node = EntityNode(n)
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
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
        if record_failed(end_rec):
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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        edge = EventEdge(
            p_node, n_node, ctx.next_event_id(),
            canonical_syscall("bind"), 0, start_ns, end_ns,
        )
        ctx.queue_edge("p2n", edge)

    return action


# openat / openat2 / creat / open：指纹仍注册（避免 unmatched），但动作只延长
# p2p，不建边——见 _make_open_link_extension_action。
# open 是 open(2) 的事件名（同 send/recv 一样，glibc 会转成 openat，所以六场景
# 日志里只有 openat/creat）；登记它使这类主机上不再计入 unmatched、且 p2p 活跃期
# 语义与 openat 一致。
_OPEN_NO_EDGE_EVENTS = ("open", "openat", "openat2", "creat")


def _family(*canonical_names: str) -> Tuple[str, ...]:
    """按 canonical 名反查同一语义家族的**全部**事件名（含 canonical 名本身）。

    手写事件名名单曾导致整族丢边：`CANONICAL_SYSCALL_MAP` 已把裸 `chmod`、
    `symlinkat` 归到 `chmod`/`symlink`，但注册表没跟上，于是这些记录落入
    `Unmatched fingerprint`、边整类丢失（实测场景 3/4/5/6 共 5,138 条 p2f）。
    改为从归一表反查后，家族变体只要进 map 就自动注册（例如内核 6.5+ /
    glibc 2.39 起 `fchmodat()` 改走 `fchmodat2`，只靠 map 一项即可覆盖）。
    """
    wanted = set(canonical_names)
    variants = {n for n, c in CANONICAL_SYSCALL_MAP.items() if c in wanted}
    return tuple(sorted(wanted | variants))


# chmod 家族：文件实体在退出/进入记录的 filename= 或 fd 注记 -> 指纹
# (None, FileEntity)，恒为 p2f。
_CHMOD_FAMILY = _family("chmod")

# rename 家族（f2p + p2f 双边）：rename / renameat / renameat2
_RENAME_FAMILY = _family("rename")

# 进程创建家族：父 -> 子 p2p 边
_SPAWN_FAMILY = _family("clone")

# 文件生命周期家族：路径字段在退出记录 -> 指纹 (None, None)。
# 额外注册 (FileEntity, None) 兜底：个别采集进入记录可能带 fd。
# 字段名随变体不同（mkdir 用 path=、mkdirat 用 name=），所以按 canonical
# 家族给基准字段、*at 变体单独覆盖，再由 _family() 补齐该家族的全部变体。
_LIFECYCLE_BASE_FIELDS = {
    # (canonical 家族名, 候选路径字段，按序尝试)。本采集实测：unlink/mkdir
    # 用 path=，*at 变体用 name=，symlink 用 linkpath=；候选列表同时兼容
    # 其他采集形态。
    "unlink": ("path", "name"),
    "mkdir": ("path", "name"),
    "rmdir": ("path", "name"),
    "symlink": ("linkpath",),
}
_LIFECYCLE_FIELD_OVERRIDES = {
    "unlinkat": ("name", "path"),
    "mkdirat": ("name", "path"),
}


def _lifecycle_family() -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
    out = []
    for canonical, fields in _LIFECYCLE_BASE_FIELDS.items():
        for event in _family(canonical):
            out.append((event, _LIFECYCLE_FIELD_OVERRIDES.get(event, fields)))
    return tuple(sorted(out))


_EXIT_PATH_FAMILY = _lifecycle_family()


def _make_sendfile_action(ctx: ParserContext):
    """sendfile(in_fd, out_fd, offset, size)：零拷贝，两端点都在**进入**记录里。

    每次调用建 2 条边（G2）：
        File(in_fd)  --f2p--> Process
        Process      --p2n--> Network(out_fd)      # out_fd 为普通文件时落 p2f
    bytes 取退出记录的 res=（= 实际传输字节）；res 缺失或 <0 不建边。
    失败/字节判据必须用 record_res / record_failed，不能用 record_size——
    后者把“字段缺失”与“res<0”合并成 -1（AGENTS §4 的教训）。

    指纹是 (sendfile, None, None)：`in_fd=`/`out_fd=` 里的 `fd=` 前面是下划线，
    通用抽取（裸 `fd=` 环视模式）取不到端点，因此 start_entities[1] 恒为 None；
    端点由本 action 按字段名抽取后交给 entity_from_descriptor（与 extract_entities
    共用同一个“描述符->实体”映射点，不复制第二份实现）。
    """

    def action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        if record_failed(end_rec):
            return
        res = record_res(end_rec)
        if res is None or res < 0:
            return
        p = start_entities[0]  # Process
        if p is None:
            return
        start_args = start_rec.get("args", "")
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        p_node = EntityNode(p)

        in_fs = extract_file_and_socket(start_args, "in_fd")
        src = ctx.entity_from_descriptor(start_rec, in_fs) if in_fs else None
        if type(src) is FileEntity:
            ctx.queue_edge("f2p", EventEdge(
                EntityNode(src), p_node, ctx.next_event_id(),
                "sendfile", res, start_ns, end_ns,
            ))

        out_fs = extract_file_and_socket(start_args, "out_fd")
        dst = ctx.entity_from_descriptor(start_rec, out_fs) if out_fs else None
        if type(dst) is NetworkEntity:
            ctx.queue_edge("p2n", EventEdge(
                p_node, EntityNode(dst), ctx.next_event_id(),
                "sendfile", res, start_ns, end_ns,
            ))
        elif type(dst) is FileEntity:
            ctx.queue_edge("p2f", EventEdge(
                p_node, EntityNode(dst), ctx.next_event_id(),
                "sendfile", res, start_ns, end_ns,
            ))

    return action


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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        args = end_rec.get("args", "")

        # 精确判断成功：execve 成功当且仅当 res=0；此前用 "res=0" in args
        # 子串判断，args 字段内容含 "res=0" 字样时会误判
        if record_size(end_rec) == 0:
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
        # 失败的 accept（res<0）不建边，也不计入不完整网络审计——那是
        # “成功但解析不出端点”的口径。判失败必须用 record_failed 而不是
        # record_size == -1：本导出格式下 accept 的退出记录只给 fd+tuple 注记、
        # 不带 res=（场景 3 的 12,208 条退出记录全无 res=），按后者会把
        # 成功的 accept 一并当成失败，整类 n2p accept 边丢光。
        if record_failed(end_rec):
            return
        p = end_entities[0]  # Process
        p_node = EntityNode(p)
        n = end_entities[1]  # NetworkEntity
        if n is None:
            # 无完整五元组的 accept（如内核 fd 地址）-> 不建边，可审计
            ctx.note_incomplete_network()
            return
        n_node = EntityNode(n)
        end_ns = record_start_ns(end_rec)

        edge = EventEdge(
            n_node, p_node, ctx.next_event_id(),
            "accept", 0, end_ns, end_ns,
        )
        ctx.queue_edge("n2p", edge)

    accept_sc = SystemCall(
        Fingerprint("accept", None, NetworkEntity),
    ).add_action(_accept_action)
    handlers[accept_sc.fingerprint] = accept_sc

    # --- fcntl（注册但不建边：已决策不进图）---
    def _fcntl_action(
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        """fcntl 不进图（口径见 tools/coverage_spec.json 的 declared_no_edge_events）。

        fcntl 是 fd 记账调用（查状态 / 加锁 / 复制 fd），不搬数据、无 bytes，
        边模型分不出 F_GETFL 与 F_SETLK，画出来全是噪声；实测六场景建边上限
        ≈1.5 万条且新增加通性为 0，故已决策不建边。

        handler 仍保留注册：① 事件不落入 `Unmatched fingerprint` 统计；
        ② fd 表记账（dup/clone 传播、close 失效）走 pipeline/fd_table.py 的
        observe_start/observe_end 钩子，与本 handler 无关，不受影响；
        ③ 保留“socket 注记但无完整四元组”的审计计数（与 accept 同一口径：
        只用 record_failed 判失败，不把“无 res= 字段”当失败）。
        此前这里留着一条 n2p 建边分支，与口径声明不一致（本采集里该分支
        从未命中，六库 0 条 fcntl 边），已删除。
        """
        if record_failed(end_rec):
            return
        if end_entities[1] is None:
            ctx.note_incomplete_network()

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
        start_ns = record_start_ns(start_rec)
        end_ns = record_start_ns(end_rec)
        args = end_rec.get("args", "")
        # res<0（rename 失败）不建边——与 chmod/lifecycle/connect 家族
        # 同一口径；失败时 sysdig 照样打印 oldpath/newpath，不挡会产出幽灵边。
        # 只用 record_failed：无 res= 字段不等于失败。
        if record_failed(end_rec):
            return
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
    for rename_variant in (e for e in _RENAME_FAMILY if e != "rename"):
        sc = SystemCall(
            Fingerprint(rename_variant, None, None),
        ).add_action(_rename_action)
        handlers[sc.fingerprint] = sc

    # --- openat / openat2 / creat（只延长 p2p，不建边）---
    for event in _OPEN_NO_EDGE_EVENTS:
        sc = SystemCall(
            Fingerprint(event, None, FileEntity),
        ).add_action(_make_open_link_extension_action(ctx))
        handlers[sc.fingerprint] = sc

    # --- chmod 家族（chmod/fchmod/fchmodat/fchmodat2：文件实体在记录里，p2f 边）---
    for event in _CHMOD_FAMILY:
        sc = SystemCall(
            Fingerprint(event, None, FileEntity),
        ).add_action(_make_chmod_action(ctx, event))
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
    for spawn_event in _SPAWN_FAMILY:
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

    # --- sendfile（G2：零拷贝，in_fd + out_fd 双端点）---
    # 指纹 (None, None)：端点由 action 自己按 in_fd=/out_fd= 抽取（见
    # _make_sendfile_action 注释）。
    sendfile_sc = SystemCall(
        Fingerprint("sendfile", None, None),
    ).add_action(_make_sendfile_action(ctx))
    handlers[sendfile_sc.fingerprint] = sendfile_sc

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
