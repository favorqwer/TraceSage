"""报告中的派生块：盲区、无边形、result 分类、边界清单。"""

from __future__ import annotations

from pathlib import Path

from ...core.results import result_semantic

# 客体来自上下文或返回值、不靠参数的调用：不参与「登记但不产边」披露
CONTEXT_OBJ = frozenset({"exit", "exit_group", "procexit"})

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[3] / "data"


def collector_blind(data_dir: str) -> dict:
    """读 data/collector_blind.txt：采集端不认识的系统调用清单。"""
    path = (Path(data_dir) if data_dir else _DEFAULT_DATA_DIR) / "collector_blind.txt"
    if not path.exists():
        return {"available": False, "note": "未找到 data/collector_blind.txt"}
    meta: dict[str, str] = {}
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if ":" in line:
                key, value = line[1:].split(":", 1)
                meta[key.strip()] = value.strip()
            continue
        names.append(line)
    counts = {
        key: int(meta[key])
        for key in ("defined_events", "observed_event_types", "all_syscalls",
                    "registered_syscalls", "unregistered_syscalls", "count")
        if meta.get(key, "").isdigit()
    }
    return {
        "available": True,
        "generated": meta.get("generated", ""),
        "counts": counts,
        "critical": [x for x in meta.get("critical", "").split(",") if x],
        "sample": names[:20],
        "note": "这些系统调用若发生，采集端只报 <unknown>（参数全空），"
                "无法归属调用名；反取证动作在本采集端完全不可见。",
    }


def no_edge_block(stats) -> list[dict]:
    """「登记但不产边」：动词表声明建边，本批却一条边也没产出的调用。"""
    out = []
    for name, calls in stats.emit_calls.items():
        if name in CONTEXT_OBJ:
            continue
        if stats.emit_calls_with_edge.get(name, 0) == 0:
            out.append({
                "call": name,
                "calls": calls,
                "reason": stats.emit_no_edge_reason.get(name, "unknown"),
            })
    return sorted(out, key=lambda x: -x["calls"])


def result_block(stats) -> dict:
    """每个 action 的 result 语义与四分类（null/negative/zero/positive）。"""
    bins: dict[str, dict[str, object]] = {}
    for action, b in sorted(stats.edge_result.items(), key=lambda kv: -sum(kv[1])):
        bins[action] = {
            "semantic": result_semantic(action),
            "null": b[0],
            "negative": b[1],
            "zero": b[2],
            "positive": b[3],
        }
    return {
        "bins": bins,
        "with_result": sum(b[1] + b[2] + b[3] for b in stats.edge_result.values()),
        "without_result": sum(b[0] for b in stats.edge_result.values()),
    }


def boundaries(node_registry_max: int) -> list[str]:
    items = [
        "主趟使用格式串最前面的 `*`：条件字段缺失输出 `<NA>` 占位，不会整行消失；"
        "缺号是文件内确实不存在的事件号，字段缺失统计见 placeholder_by_field。",
        "`%proc.duration` 只在 execve 行可打印；本版未启用第三趟，born_src=duration 不产出。",
        "fd 名字/类型/返回值从 evt.args 解，不使用 %fd.name / %fd.type / %evt.rawres；"
        "当前模板保持窄列，避免增加每行体积。",
        "edge.payload_b64 是 %evt.buffer -b 的前 payload_max_bytes 字节再 base64 编码，不是可打印文本；"
        "完整载荷需回原始 .scap。",
        "边的 result 只表达结果：数据类=字节数、失败=负错误码、零=实测零；未观测时不写属性"
        "（Neo4j 里属性不存在，edges.csv 里为空串）。",
        "open 家族与 accept 成功时返回的是文件描述符、mmap 成功时返回的是内存地址，"
        "这两类成功值不进 res（fd 号与地址不是结果，仅在失败时写负错误码）。",
        "结果缺失（退出行无 %evt.rawres 且参数里无 res=）不伪造 0：落“其他”桶的"
        " result_unobserved:<动词>，不进 attempts.csv。",
        "「登记但不产边」= 动词表声明建边、本批零客体零边的调用（见 registered_without_edge）；"
        "保留登记是为了换采集端后重测，但报告中不得把它当成已覆盖。",
        "「能力缺口」= 设计等级 L1/L2、却因数据源不给客体而归入记账/丢弃的调用"
        "（见 capability_gaps）；它们是换采集端后必须重测的清单。",
        "「采集端盲区」= 采集端不产出事件名、只报 <unknown>（参数全空）的调用"
        "（见 collector_blind）；反取证动作（reboot / 时间篡改 / 落盘同步）属于这一层，"
        "在图与 ops 中均无法体现。",
        "「未归类」桶为空只代表「采集端报了名字但账本表没登记」这件事没发生，"
        "不代表覆盖完整。",
        "param_availability 是调用级口径，edges.result 是边级口径：两者不能互推"
        "（一个调用可能不建边或建多条边），报告中不得用其互校。",
        "result_from_rawres 是 %evt.rawres 直接提供的条数；result_from_args_fallback 只在"
        " %evt.rawres 缺失时兜底，两者之和 = result_observed。",
        "File.file_type 只取 file / directory / pipe / unix / memfd / unknown；"
        "匿名 IPC（event/timerfd/signalfd/inotify/eventpoll/netlink/bpf）"
        "没有可区分名字，按 R3 不建节点，因此不设枚举值。",
        "memfd 用合成身份 memfd:<名字>（名字来自 memfd_create 调用者），"
        "不是文件系统路径，不得拿去拼 cwd 或当成真实文件。",
        "Network.proto 只在 fd token 带 t/u 时有值（accept 侧通常有，connect 进入行通常没有）。",
        "未连接 UDP 的 sendto 目的地不在参数里（tuple=NULL），该 fd 无客体 -> 未知句柄。",
        "PID 命名空间未做翻译：syscall 的 pid 参数是调用者命名空间内的号，命中不到时计"
        " target_unresolved；若该 pid 在别的容器存在，另计 target_pid_other_ns。",
        "rename 出两条边（源路径 -> 进程、进程 -> 新路径），但旧路径的历史边不迁移到新路径；"
        "link/symlink 的 to_path 只是属性，不建边；同路径删除后重建视为同一节点。",
        "同路径删除后重建视为同一节点（数据源无 inode/版本号进键）。",
        "节点登记表上限 %d；超过即阻断（内存纪律）。" % node_registry_max,
        "edges.csv 按事件顺序写出（确定性），未做全局排序。",
        "本版不做采集端独立审计：报告只保证内部账本自洽，不证明没有漏行；"
        "字段缺失统计见 placeholder_by_field。",
    ]
    return items
