#!/usr/bin/env python3
"""采集端盲区自检：算出「sysdig 不认识、解析器无法归属」的系统调用。

为什么需要这个工具：sysdig 只对**有专门解码器**的系统调用产出事件名；
其余一律渲染成 ``<unknown>`` 且 ``evt.args`` 全空。这类调用既进不了图，
也进不了 ops（没有调用名），连「它出现过」都无法计数。它是与「账本表
没登记」完全不同的一类盲区，必须单独披露。

判据：
  采集端认识 = ``sysdig -L`` 的事件定义 ∪ 某份捕获里实际出现过的事件类型

用法：
  # 只按 sysdig 定义算（最保守，不需要捕获）
  python tools/collector_awareness.py

  # 带上实际出现过的事件类型（更准，推荐）
  sysdig -r capture.scap -p "%evt.type" | sort | uniq -c > /tmp/types.txt
  python tools/collector_awareness.py --types /tmp/types.txt

输出：provenance-parser/data/collector_blind.txt
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "provenance-parser" / "data"

# 反取证 / 逃逸 / 句柄批量关闭：一旦不可见，直接削弱溯源结论
CRITICAL = frozenset(
    {
        "reboot", "sync", "syncfs", "sync_file_range", "sync_file_range2",
        "settimeofday", "clock_settime", "adjtimex", "clock_adjtime",
        "swapon", "swapoff", "vhangup", "setdomainname", "close_range",
        "kexec_file_load", "mount_setattr", "open_tree", "move_mount",
        "memfd_secret",
    }
)


def _run_sysdig(args: list[str]) -> str:
    """在 Windows 上自动走 WSL；其它平台直接调 sysdig。"""
    candidates: list[list[str]] = []
    if shutil.which("sysdig"):
        candidates.append(["sysdig", *args])
    if shutil.which("wsl"):
        candidates.append(["wsl", "sysdig", *args])
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
        except Exception:
            continue
        if result.returncode == 0:
            return result.stdout.decode("utf-8", "replace")
    raise RuntimeError("找不到可用的 sysdig（本地与 WSL 都失败）")


def collector_events() -> set[str]:
    """sysdig -L 里定义的事件名。"""
    text = _run_sysdig(["-L"])
    names = set()
    for line in text.splitlines():
        if line.startswith("> "):
            body = line[2:]
            names.add(body.split("(", 1)[0].strip())
    return names


def observed_types(path: Path | None) -> set[str]:
    """可选：某份捕获的 evt.type 直方图（``count<TAB>name`` 或纯名单）。"""
    if path is None:
        return set()
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        names.add(parts[-1])
    return names


def registered_calls() -> set[str]:
    verbs = tomllib.loads((DATA / "verbs.toml").read_text(encoding="utf-8"))["verb"]
    groups = tomllib.loads((DATA / "calls.toml").read_text(encoding="utf-8"))["group"]
    out: set[str] = set()
    for item in verbs:
        out |= set(item.get("calls", []))
    for item in groups:
        out |= set(item.get("calls", []))
    out |= {"open", "openat", "openat2", "open64", "openat64", "creat"}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="采集端盲区自检")
    ap.add_argument("--types", default="", help="evt.type 直方图文件（可选）")
    ap.add_argument("--out", default=str(DATA / "collector_blind.txt"))
    args = ap.parse_args(argv)

    all_syscalls = {
        line.strip()
        for line in (DATA / "syscalls_all.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    defined = collector_events()
    seen = observed_types(Path(args.types) if args.types else None)
    registered = registered_calls()

    known = defined | seen
    unknown = all_syscalls - registered          # 未登记的系统调用
    blind = sorted(unknown - known)              # 其中采集端也不认识的
    critical = sorted(CRITICAL & set(blind))

    header = [
        "# 采集端盲区：sysdig 不认识、解析器无法归属的系统调用",
        "# 这些调用若发生，采集端只报 <unknown>（evt.args 全空），连调用名都没有。",
        "# 生成方式：python tools/collector_awareness.py [--types <直方图>]",
        f"# generated: {date.today().isoformat()}",
        f"# defined_events: {len(defined)}",
        f"# observed_event_types: {len(seen)}",
        f"# all_syscalls: {len(all_syscalls)}",
        f"# registered_syscalls: {len(all_syscalls & registered)}",
        f"# unregistered_syscalls: {len(unknown)}",
        f"# count: {len(blind)}",
        f"# critical: {','.join(critical)}",
    ]
    Path(args.out).write_text("\n".join(header + blind) + "\n", encoding="utf-8")

    print(f"sysdig 定义事件 {len(defined)} 个；实际出现 {len(seen)} 个")
    print(f"系统调用全集 {len(all_syscalls)}；已登记 {len(all_syscalls & registered)}")
    print(f"未登记 {len(unknown)}；其中采集端盲区 {len(blind)}")
    print(f"关键盲区 {len(critical)}: {', '.join(critical)}")
    print(f"写出 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
