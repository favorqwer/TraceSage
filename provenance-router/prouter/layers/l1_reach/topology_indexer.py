class TopologyFacts:
    """
    记录图拓扑上的客观因果交付事实。
    纯图结构，绝不依赖特定场景的路径名称或特定进程名。
    """
    def __init__(self, edges):
        self.written_objects = set()
        self.net_dropped_objects = set()
        self.process_written_targets = {}
        self.process_has_outbound_delivery = set()
        self.inbound_net_endpoints = set()
        self.inbound_processes = set()
        self.process_spawned = set()
        self.process_modifies_batch = {}
        self.tainted_processes = set()

        interpreters = {
            "sh", "bash", "dash", "zsh", "python", "python3", "perl", "php", "base64",
            "chmod", "curl", "wget", "tar", "gzip", "mkdir", "systemctl", "cron", "crontab"
        }

        # 1. 基础事实抽取
        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))
            dst = str(e.get("dst", ""))
            pid = str(e.get("process_id", ""))

            # 入度事实：被写入、创建、修改过的客体
            if sc in ["write", "create", "mkdir", "rename", "chmod", "unlink", "symlink"]:
                self.written_objects.add(dst)
                if sc in ["rename", "symlink"]:
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
                    self.tainted_processes.add(pid)

            # 出度事实：外部网络连接、管道写出
            if sc in ["write", "sendto", "connect"] and ("->" in dst or "pipe:" in dst):
                if pid:
                    self.process_has_outbound_delivery.add(pid)

            # 进程派生与执行
            if sc in ["clone", "fork", "execve"]:
                if pid:
                    self.process_has_outbound_delivery.add(pid)

            if sc == "execve":
                prog = dst.split("/")[-1]
                if prog in interpreters:
                    self.process_spawned.add(pid)

        # 2. 拓扑因果污染传播（固定点迭代收敛）
        for _ in range(5):
            changed = False
            for e in edges:
                sc = e.get("syscall", "")
                src = str(e.get("src", ""))
                dst = str(e.get("dst", ""))
                pid = str(e.get("process_id", ""))

                if pid and pid in self.tainted_processes:
                    if sc in ["write", "create", "rename", "symlink"]:
                        if dst not in self.net_dropped_objects:
                            self.net_dropped_objects.add(dst)
                            changed = True

                if sc == "execve":
                    if src in self.written_objects or src in self.net_dropped_objects:
                        if pid and pid not in self.tainted_processes:
                            self.tainted_processes.add(pid)
                            changed = True
                    if pid and pid in self.tainted_processes:
                        if dst not in self.net_dropped_objects and "/" in dst:
                            self.net_dropped_objects.add(dst)
                            changed = True
            if not changed:
                break

    def is_tainted(self, target_path: str) -> bool:
        return target_path in self.written_objects or target_path in self.net_dropped_objects

    def has_delivery(self, pid: str) -> bool:
        return pid in self.process_has_outbound_delivery

    def is_tainted_proc(self, pid: str) -> bool:
        return pid in self.tainted_processes or pid in self.inbound_processes
