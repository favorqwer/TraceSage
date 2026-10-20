"""结果语义规范化：决定一次调用的返回值以什么形态落到边的 ``res`` 上。

为什么单独一层（而不是让每个 handler 自己决定传 None 还是传值）：
数据源给的 ``%evt.rawres`` 是**内核原始返回值**，不同调用族语义完全不同——

  openat  成功 -> 文件描述符（进程内局部编号，跨事件无意义）
  mmap    成功 -> 虚拟地址
  write   成功 -> 写入字节数
  connect 失败 -> 负错误码

如果原样落到 ``res``，「字节数 / 负错误码 / 零字节」这条单轨语义就会被
fd 号和内存地址污染（查询里 ``r.res > 0`` 会把地址算成外泄字节）。
所以所有边一律经过本函数，由调用族决定是否保留。

本模块是纯函数，不 import 任何其它模块。
"""

from __future__ import annotations

# 成功时返回地址的调用：按 §3.2 例外，成功不写、失败写负错误码。
_ADDRESS_RETURNS = frozenset({"mmap", "mmap2", "shmat"})

# 成功时返回 fd 号（或新套接字）的调用：成功值不是结果，必须挡掉。
_FD_RETURNS = frozenset(
    {
        "open", "openat", "openat2", "open64", "openat64", "creat",
        "accept", "accept4",
    }
)

# 单向事件：数据源本来就不给返回值，写进去只会是占位。
_NO_RESULT_ACTIONS = frozenset({"exit"})


def norm_res(action: str, call_name: str, res: int | None) -> int | None:
    """边上的 ``res`` 唯一出口。

    - ``None``  -> ``None``（未观测，写库时属性不出现）
    - 成功且返回 fd/地址 -> ``None``（不能当结果）
    - 其余原样（字节数 / 0 / 负错误码 / clone 的子 pid）
    """
    if res is None:
        return None
    if action in _NO_RESULT_ACTIONS:
        return None
    if res >= 0 and call_name in _ADDRESS_RETURNS:
        return None
    if res >= 0 and call_name in _FD_RETURNS:
        return None
    return res


# ------------------------------------------------------------------ 报告口径
# 只用于报告里声明"这个 action 的 res 是什么语义"，不影响图。

_SIZE_ACTIONS = frozenset({"read", "write", "send", "recv"})
_PID_ACTIONS = frozenset({"clone"})
_ERRNO_ONLY_ACTIONS = frozenset({"mmap"})
_ERRNO_ACTIONS = frozenset(
    {
        "unlink", "truncate", "chmod", "mount", "chroot", "ns", "ioctl",
        "probe", "connect", "signal", "wait", "ptrace", "mem_read",
        "mem_write", "pidfd_getfd",
    }
)
_SUCCESS_ACTIONS = frozenset(
    {"create", "link", "rename", "bind", "listen", "accept", "exec", "load_image"}
)

#: 报告用词表：action -> res 语义
RES_SEMANTICS: dict[str, str] = {name: "size" for name in _SIZE_ACTIONS}
RES_SEMANTICS.update({name: "pid" for name in _PID_ACTIONS})
RES_SEMANTICS.update({name: "errno_only" for name in _ERRNO_ONLY_ACTIONS})
RES_SEMANTICS.update({name: "errno_or_zero" for name in _ERRNO_ACTIONS})
RES_SEMANTICS.update({name: "zero_on_success" for name in _SUCCESS_ACTIONS})
RES_SEMANTICS.update({name: "none" for name in _NO_RESULT_ACTIONS})


def res_semantic(action: str) -> str:
    """报告里与每个 action 并列输出的 res 语义标签。"""
    return RES_SEMANTICS.get(action, "unknown")
