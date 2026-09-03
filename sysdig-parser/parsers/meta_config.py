class MetaConfig:
    """System call name lists for each direction type."""

    ptof_system_call = ["write", "writev", "rename"]
    ftop_system_call = ["read", "readv", "rename"]
    pton_system_call = ["sendto", "sendmsg", "write", "writev"]
    ntop_system_call = ["read", "recvmsg", "readv", "recvfrom"]
