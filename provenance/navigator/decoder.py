"""
tmp/ 隔离测试模块：规则解码器与带规则上下文的判定驱动
"""
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "provenance"))

import settings as cfg
from domain.edge import edge_key

# ----------------- 1. 角色与基模解码器 -----------------

DIRECTION_MAP = {
    "both": "具备双向网络通信能力（既有入站连接又有外部出联）",
    "in": "曾接收外部网络入站连接（如服务端口监听）",
    "out": "曾发起外部网络主动出联",
    "none": "无网络通信的本地程序",
}

SPAWN_MAP = {
    "multi": "既克隆自身又派生执行新镜像（活跃派生型）",
    "exec": "派生执行新二进制程序镜像",
    "clone": "克隆自身子进程",
    "leaf": "未派生任何子进程的叶子进程",
}

INST_MAP = {
    "single": "系统内全局单实例",
    "few": "系统内中低频少量实例",
    "many": "系统内高频爆发多实例",
}

def decode_proc_role(role: str) -> str:
    parts = role.split(".")
    if len(parts) < 5 or parts[0] != "P":
        return role
    _, direct, spawn, inst, priv = parts[:5]
    desc = [
        DIRECTION_MAP.get(direct, direct),
        SPAWN_MAP.get(spawn, spawn),
        INST_MAP.get(inst, inst),
    ]
    if priv == "chg":
        desc.append("曾执行权限修改系统调用")
    return "、".join(desc) + "的进程"

def decode_file_role(role: str) -> str:
    parts = role.split(".")
    if len(parts) < 5 or parts[0] != "F":
        return role
    _, bits, writers, sens, place = parts[:5]
    desc = []
    if place == "usr":
        desc.append("用户空间目录（如 /tmp, /home）")
    elif place == "sys":
        desc.append("系统关键目录（如 /usr, /lib, /bin）")
    
    if sens == "auth":
        desc.append("认证凭证文件（如 shadow 或 authorized_keys）")
    elif sens == "cfg":
        desc.append("系统配置文件（/etc）")
    
    perm_desc = []
    if "w" in bits: perm_desc.append("写")
    if "r" in bits: perm_desc.append("读")
    if "x" in bits: perm_desc.append("执行")
    if "d" in bits: perm_desc.append("删除")
    if perm_desc:
        desc.append(f"具有[{''.join(perm_desc)}]行为")
    
    if writers == "multi":
        desc.append("被多个进程写入")
    elif writers == "single":
        desc.append("单一写入源")
    return "、".join(desc) + "的文件"

def decode_net_role(role: str) -> str:
    parts = role.split(".")
    if len(parts) < 3 or parts[0] != "N":
        return role
    _, direct, peers = parts[:3]
    d_text = "本地监听服务端口" if direct == "listen" else "外部主动回连端点" if direct == "dial" else "双向网络端点"
    p_text = "多外部对端" if peers == "multi" else "单一外部对端"
    return f"{d_text}（{p_text}）"

def decode_role(role_str: str) -> str:
    if role_str.startswith("P."):
        return decode_proc_role(role_str)
    if role_str.startswith("F."):
        return decode_file_role(role_str)
    if role_str.startswith("N."):
        return decode_net_role(role_str)
    return role_str

def decode_motif(m: Dict[str, Any], *, real_2hop: bool = True) -> str:
    """把 1 跳/多跳基模解码成模型可读的因果链文字。

    多跳基模的角色写在 chain 里（src_role/syscall/dst_role 逐跳），
    不在顶层的 src_role/dst_role；只读顶层会得到空角色。

    `real_2hop=False` 复现历史 B0 的旧解码：2 跳也只读顶层角色，得到空角色标签。
    """
    hops = int(m.get("hops", 1) or 1)
    support = len(m.get("support_scenarios_list") or [])
    chain = m.get("chain") or []

    if real_2hop and len(chain) >= 2:
        parts = [f"由 [{decode_role(chain[0].get('src_role', ''))}]"]
        for hop in chain:
            sc = hop.get("syscall", "")
            dst_r = decode_role(hop.get("dst_role", ""))
            parts.append(f"通过系统调用 [{sc}] 到 [{dst_r}]")
        behavior = "，".join(parts) + f"（{len(chain)}跳因果链）"
    else:
        src_r = decode_role(m.get("src_role", ""))
        dst_r = decode_role(m.get("dst_role", ""))
        scs = "+".join(m.get("syscalls") or [])
        behavior = f"由 [{src_r}] 通过系统调用 [{scs}] 作用于 [{dst_r}]（{hops}跳骨架）"

    return (
        f"【拓扑行为】{behavior}；\n"
        f"    【历史先验】在留一交叉的 {support} 个历史训练场景中属于标准答案攻击路径。"
    )
