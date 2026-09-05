"""System call name lists for each direction type."""


class MetaConfig:
    ptof_system_calls = ("write", "writev", "rename")
    ftop_system_calls = ("read", "readv", "rename")
    pton_system_calls = ("sendto", "sendmsg", "write", "writev")
    ntop_system_calls = ("read", "recvmsg", "readv", "recvfrom")
