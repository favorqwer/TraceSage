"""因果闭包与拓扑底座：拓扑事实索引器（TopologyFacts）

职责：
记录图拓扑上的客观因果交付事实（入度写入/修改、出度外发/交付、因果污染传播等）。
纯图结构计算，绝不依赖特定场景的路径名称或特定进程名。
"""
from typing import Any, Dict, List, Set


class TopologyFacts:
    """
    记录图拓扑上的客观因果交付事实。
    纯图结构，绝不依赖特定场景的路径名称或特定进程名。
    """
    def __init__(self, edges: List[Dict[str, Any]]):
        self.written_objects: Set[str] = set()
        self.net_dropped_objects: Set[str] = set()
        self.process_written_targets: Dict[str, Set[str]] = {}
        self.process_has_outbound_delivery: Set[str] = set()
        self.inbound_net_endpoints: Set[str] = set()
        self.inbound_processes: Set[str] = set()
        self.process_modifies_batch: Dict[str, int] = {}
        self.tainted_processes: Set[str] = set()

        # 1. 基础事实抽取
        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))
            dst = str(e.get("dst", ""))
            pid = str(e.get("process_id", ""))

            # 入度事实：被写入、创建、修改过的客体
            if sc in ["write", "create", "mkdir", "rename", "chmod", "unlink", "symlink"]:
                if not dst.startswith("/proc/") and not dst.startswith("/sys/") and not dst.startswith("pipe:"):
                    self.written_objects.add(dst)
                if sc in ["rename", "symlink"]:
                    if not src.startswith("/proc/") and not src.startswith("/sys/") and not src.startswith("pipe:"):
                        self.written_objects.add(src)
                if pid:
                    if pid not in self.process_written_targets:
                        self.process_written_targets[pid] = set()
                    self.process_written_targets[pid].add(dst)
                    if sc in ["rename", "unlink"]:
                        self.process_modifies_batch[pid] = self.process_modifies_batch.get(pid, 0) + 1

            # 外部网络会话接收
            if sc in ["accept", "recvfrom"] and "->" in src:
                self.inbound_net_endpoints.add(src)
                if dst:
                    self.inbound_processes.add(dst)
                if pid:
                    self.inbound_processes.add(pid)

            # 出度事实：外部网络连接、管道写出
            if sc in ["write", "sendto", "connect"] and ("->" in dst or "pipe:" in dst):
                if pid:
                    self.process_has_outbound_delivery.add(pid)

            # 进程派生与执行
            if sc in ["clone", "fork", "execve"]:
                if pid:
                    self.process_has_outbound_delivery.add(pid)

        # 2. 拓扑因果污染传播（固定点迭代收敛）
        for _ in range(5):
            changed = False
            for e in edges:
                sc = e.get("syscall", "")
                src = str(e.get("src", ""))
                dst = str(e.get("dst", ""))
                pid = str(e.get("process_id", ""))

                # 被污染进程写入客体（客体落地）
                if (pid in self.tainted_processes or src in self.tainted_processes):
                    if sc in ["write", "create", "rename", "symlink"]:
                        if dst not in self.net_dropped_objects and not dst.startswith("/proc/") and not dst.startswith("/dev/"):
                            self.net_dropped_objects.add(dst)
                            changed = True

                # 进程派生执行
                if sc == "execve":
                    # 执行了写入/落地的客体 -> 被派生进程受污染
                    if src in self.written_objects or src in self.net_dropped_objects:
                        if pid and pid not in self.tainted_processes:
                            self.tainted_processes.add(pid)
                            changed = True
                        if dst and dst not in self.tainted_processes:
                            self.tainted_processes.add(dst)
                            changed = True

                    # 入站外部会话派生了交互式命令或工具 -> 被派生进程受污染
                    if (src in self.inbound_processes or pid in self.inbound_processes):
                        name = dst.split("/")[-1]
                        if name in ["sh", "bash", "dash", "zsh", "python", "python3", "perl", "php", "tar", "curl", "wget", "socat"]:
                            if pid and pid not in self.tainted_processes:
                                self.tainted_processes.add(pid)
                                changed = True
                            if dst and dst not in self.tainted_processes:
                                self.tainted_processes.add(dst)
                                changed = True

                    # 被污染父进程派生子进程 -> 子进程继承污染状态
                    if (src in self.tainted_processes or pid in self.tainted_processes):
                        if dst and dst not in self.tainted_processes:
                            self.tainted_processes.add(dst)
                            changed = True
            if not changed:
                break

    def is_tainted(self, target_path: str) -> bool:
        return target_path in self.written_objects or target_path in self.net_dropped_objects

    def has_delivery(self, pid: str) -> bool:
        return pid in self.process_has_outbound_delivery

    def is_tainted_proc(self, pid: str) -> bool:
        return pid in self.tainted_processes or pid in self.inbound_processes
