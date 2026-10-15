"""System call family config: direction lists and canonical naming.

两个职责：

1. 方向名单：数据流类读写系统调用（fd 携带实体，进入记录可提取实体），
   按语义家族定义后拼接。文件生命周期类（open/unlink/mkdir/...）与
   connect 的路径/四元组在退出记录中，进入记录为空，走 handlers.py 的
   专用 handler，不在此名单。
2. 通用名称（canonical syscall name）：同一语义家族的变体系统调用
   （pread/preadv/preadv2 等）在边的 syscall 属性上统一为家族基本名
   （read）。事件分发与 enter/exit 配对仍使用 evt.type 原始名，
   归一只发生在 handlers.py 构造 EventEdge 时。
"""

# 同一语义家族的变体系统调用 -> 家族基本名。
# 仅收录已注册 handler 的名字；未注册的名字写进来也不会产生边。
CANONICAL_SYSCALL_MAP = {
    # 读家族
    "readv": "read",
    "pread": "read",
    "preadv": "read",
    "preadv2": "read",
    # 写家族
    "writev": "write",
    "pwrite": "write",
    "pwritev": "write",
    "pwritev2": "write",
    # 发送/接收家族
    # send/recv 是 send(2)/recv(2) 的事件名（glibc 通常把 send()/recv() 转成
    # sendto/recvfrom 系统调用，所以日志里常见带后缀的变体；但静态链接/直接走
    # 系统调用的程序会出现裸名）。归一成家族基本名是必须的：边模型与 Java 侧
    # 消费方（LlmEdgePrefilter / LlmRepairCandidateScorer 等）都按 sendto/recvfrom 匹配。
    "send": "sendto",
    "recv": "recvfrom",
    "sendmsg": "sendto",
    "sendmmsg": "sendto",
    "recvmsg": "recvfrom",
    "recvmmsg": "recvfrom",
    # 打开家族（creat 等价 open(O_CREAT|O_WRONLY|O_TRUNC)）
    "openat": "open",
    "openat2": "open",
    "creat": "open",
    # 重命名/删除/建目录/链接/改权限家族
    "renameat": "rename",
    "renameat2": "rename",
    "unlinkat": "unlink",
    "mkdirat": "mkdir",
    "symlinkat": "symlink",
    "fchmod": "chmod",
    "fchmodat": "chmod",
    # 内核 6.5 新增 fchmodat2；glibc 2.39 起 fchmodat() 在可用时改走它。
    # 不进本表的话，那类主机上 chmod 整族会静默丢失。
    "fchmodat2": "chmod",
    # 进程创建家族（现代内核 fork/vfork 经由 clone(2) 实现）
    "vfork": "clone",
    "fork": "clone",
    # 零拷贝发送（G2）。本导出里没有 sendfile64，但多个架构的 glibc 会用它，
    # 成本为零，防将来在其他主机上重现"整族未归一"的缺口。
    "sendfile64": "sendfile",
}


def canonical_syscall(event: str) -> str:
    """evt.type 原始事件名 -> 边 syscall 属性用的家族基本名。"""
    return CANONICAL_SYSCALL_MAP.get(event, event)


class MetaConfig:
    # 数据流家族（read/write 同时出现在文件与网络两个方向：
    # 由进入记录 fd 的实体类型决定落点）。
    _READ_FAMILY = ("read", "readv", "pread", "preadv", "preadv2")
    _WRITE_FAMILY = ("write", "writev", "pwrite", "pwritev", "pwritev2")
    _SEND_FAMILY = ("send", "sendto", "sendmsg", "sendmmsg")
    _RECV_FAMILY = ("recv", "recvfrom", "recvmsg", "recvmmsg")

    # 公开别名：handlers 需要把 send/recv 家族也注册到 FileEntity 方向，
    # 以覆盖 unix socket（合成 File 顶点）上的收发（G1）。
    send_system_calls = _SEND_FAMILY
    recv_system_calls = _RECV_FAMILY

    ptof_system_calls = _WRITE_FAMILY + ("rename",)
    ftop_system_calls = _READ_FAMILY + ("rename",)
    pton_system_calls = _SEND_FAMILY + _WRITE_FAMILY
    ntop_system_calls = _RECV_FAMILY + _READ_FAMILY
