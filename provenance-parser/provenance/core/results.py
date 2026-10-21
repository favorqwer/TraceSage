"""结果语义规范化：决定一次调用的返回值以什么形态落到边的 ``result`` 上。

为什么单独一层（而不是让每个 handler 自己决定传 None 还是传值）：
数据源给的 ``%evt.rawres`` 是**内核原始返回值**，不同调用族语义完全不同——

  openat  成功 -> 文件描述符（进程内局部编号，跨事件无意义）
  mmap    成功 -> 虚拟地址
  write   成功 -> 写入字节数
  connect 失败 -> 负错误码

如果原样落到 ``result``，「字节数 / 负错误码 / 零字节」这条单轨语义就会被
fd 号和内存地址污染（查询里 ``r.result > 0`` 会把地址算成外泄字节）。
所以所有边一律经过本函数，由调用族决定是否保留。

范围声明：同一条 ``result`` 装三种单位（数据类=字节数、失败=负错误码、零=实测零）。
这是设计上承认的单字段多语义，不允许当成“统一是字节数”来读。

本模块是纯函数，不 import 任何其它模块。
"""

from __future__ import annotations

# 成功时返回地址的调用：按 §3.2 例外，成功不写、失败写负错误码。
_ADDRESS_RETURNS = frozenset({"mmap", "mmap2", "shmat"})

# 成功时返回 fd 号（或新套接字）的调用：成功值不是结果，必须挡掉。
_FD_RETURNS = frozenset(
    {
        "open", "openat", "openat2", "open64", "openat64", "creat",
        "accept", "accept4", "memfd_create",
    }
)

# 单向事件：数据源本来就不给返回值，写进去只会是占位。
_NO_RESULT_ACTIONS = frozenset({"exit"})


def norm_result(action: str, call_name: str, result: int | None) -> int | None:
    """边上的 ``result`` 唯一出口。

    - ``None``  -> ``None``（未观测，写库时属性不出现）
    - 成功且返回 fd/地址 -> ``None``（不能当结果）
    - 其余原样（字节数 / 0 / 负错误码）
    """
    if result is None:
        return None
    if action in _NO_RESULT_ACTIONS:
        return None
    # clone 成功返回子 pid，子进程身份在 dst 节点上，不是结果。
    if action == "clone":
        return None if result >= 0 else result
    if result >= 0 and call_name in _ADDRESS_RETURNS:
        return None
    if result >= 0 and call_name in _FD_RETURNS:
        return None
    return result


# ------------------------------------------------------------------ 报告口径
# 只用于报告里声明"这个 action 的 result 是什么语义"，不影响图。

_SIZE_ACTIONS = frozenset({"read", "write", "send", "recv"})
_ERRNO_ONLY_ACTIONS = frozenset({"mmap_read", "mmap_write", "mmap_exec"})
_ERRNO_ACTIONS = frozenset(
    {
        "unlink", "truncate", "chmod", "mount", "umount", "chroot", "setns", "ioctl",
        "stat", "connect", "signal", "wait", "ptrace", "mem_read",
        "mem_write", "pidfd_getfd",
    }
)
_SUCCESS_ACTIONS = frozenset(
    {"link", "rename", "bind", "listen", "exec"}
)

#: 报告用词表：action -> result 语义
RES_SEMANTICS: dict[str, str] = {name: "size" for name in _SIZE_ACTIONS}
RES_SEMANTICS.update({name: "errno_only" for name in _ERRNO_ONLY_ACTIONS})
RES_SEMANTICS.update({name: "errno_or_zero" for name in _ERRNO_ACTIONS})
RES_SEMANTICS.update({name: "zero_on_success" for name in _SUCCESS_ACTIONS})
RES_SEMANTICS.update({
    "create": "zero_or_none_on_success",
    "accept": "none",
    "clone": "none",
    "exit": "none",
})


def result_semantic(action: str) -> str:
    """报告里与每个 action 并列输出的 result 语义标签。"""
    return RES_SEMANTICS.get(action, "unknown")
