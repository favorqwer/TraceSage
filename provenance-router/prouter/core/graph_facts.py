# 边的五种关系名及其固定方向与标签
REL_DIRS = {
    "p2p": ("Process", "Process"),
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
}

CANONICAL_SYSCALL_MAP = {
    "readv": "read", "pread": "read", "preadv": "read", "preadv2": "read",
    "writev": "write", "pwrite": "write", "pwritev": "write", "pwritev2": "write",
    "send": "sendto", "sendmsg": "sendto", "sendmmsg": "sendto",
    "recv": "recvfrom", "recvmsg": "recvfrom", "recvmmsg": "recvfrom",
    "renameat": "rename", "renameat2": "rename",
    "unlinkat": "unlink", "mkdirat": "mkdir", "symlinkat": "symlink",
    "fchmod": "chmod", "fchmodat": "chmod", "fchmodat2": "chmod",
    "fork": "clone", "vfork": "clone",
    "openat": "open", "openat2": "open", "creat": "open",
    "sendfile64": "sendfile",
}

def canonical_syscall(name: str) -> str:
    return CANONICAL_SYSCALL_MAP.get(name, name)
