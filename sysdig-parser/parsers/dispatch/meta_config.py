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
}


def canonical_syscall(event: str) -> str:
    """evt.type 原始事件名 -> 边 syscall 属性用的家族基本名。"""
    return CANONICAL_SYSCALL_MAP.get(event, event)


class MetaConfig:
    # 数据流家族（read/write 同时出现在文件与网络两个方向：
    # 由进入记录 fd 的实体类型决定落点）。
    _READ_FAMILY = ("read", "readv", "pread", "preadv", "preadv2")
    _WRITE_FAMILY = ("write", "writev", "pwrite", "pwritev", "pwritev2")
    _SEND_FAMILY = ("sendto", "sendmsg", "sendmmsg")
    _RECV_FAMILY = ("recvfrom", "recvmsg", "recvmmsg")

    ptof_system_calls = _WRITE_FAMILY + ("rename",)
    ftop_system_calls = _READ_FAMILY + ("rename",)
    pton_system_calls = _SEND_FAMILY + _WRITE_FAMILY
    ntop_system_calls = _RECV_FAMILY + _READ_FAMILY
