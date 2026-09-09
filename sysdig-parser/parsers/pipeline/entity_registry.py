"""Entity registry: deduplicates vertices and extracts them from records.

Owns the three vertex dictionaries, their pending-for-write counterparts
(refilled on attribute backfill so updates reach the next flush), and the
audit counters for degenerate objects (pipes, socket fragments without a
full 4-tuple, conflicting protocols).
"""

from typing import Dict, List, Optional

from ..jsonl.fields import extract_process_file
from ..jsonl.record import record_file_socket
from ..model.entities import Entity, FileEntity, NetworkEntity, Process
from .fd_table import FdTable

# fd.l4proto 中“非真实协议”的取值：视为解析不出来，不写入 Network.protocol。
_L4PROTO_NOT_APPLICABLE = frozenset({"", "<NA>"})


def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    return normalized if normalized else None


class EntityRegistry:
    """Deduplicating factory for Process / File / Network vertices."""

    def __init__(self) -> None:
        self._files: Dict[str, FileEntity] = {}
        self._processes: Dict[str, Process] = {}
        self._networks: Dict[str, NetworkEntity] = {}
        self._pending_files: Dict[str, FileEntity] = {}
        self._pending_processes: Dict[str, Process] = {}
        self._pending_networks: Dict[str, NetworkEntity] = {}

        self._incomplete_network_count = 0
        self._no_object_count = 0
        # 同一四元组出现不同协议的冲突次数（保留首个，仅计数上报）
        self._network_protocol_conflicts = 0

        # fd 生命周期表：把裸 fd=N(<p>) 管道解析为真实身份 pipe:[<ino>]。
        # 跨 flush 持久（进程级状态，与写入缓冲无关），由主循环在配对两侧
        # 分别喂记录（见 parser.parse_entry / _process_event）。
        self._fdtable = FdTable()

    # ==================================================================
    # Record -> entities
    # ==================================================================
    def extract_entities(
        self, record: Dict[str, str]
    ) -> List[Optional[Entity]]:
        entities: List[Optional[Entity]] = [None, None]
        pid = record.get("pid", "")
        process_name = record.get("process", "")
        process_key = pid + process_name
        exe_path = record.get("exepath", "")
        proc_args = record.get("proc_args", "")
        cwd = record.get("cwd", "")
        entities[0] = self.get_or_create_process(
            process_key, pid, process_name, exe_path,
            args=proc_args, cwd=cwd,
        )

        args = record.get("args", "")
        file_socket = record_file_socket(record)
        process_file = extract_process_file(args)

        if "path" in file_socket:
            path = file_socket["path"]
            entities[1] = self.get_or_create_file(path, path)
        elif process_file is not None:
            entities[1] = self.get_or_create_file(process_file, process_file)
        elif "pipe" in file_socket:
            # 管道建模为合成路径 File 顶点。sysdig 两种形态：
            #   fd=N(<p>pipe:[inode]) -> pipe:[inode]（sysdig 已给出 inode，
            #     直接用作顶点键，可区分具体管道）
            #   fd=N(<p>)             -> 裸匿名管道，inode 未解析。优先查 fd
            #     生命周期表还原真实身份（pipe() 退出记录登记的 ino，经
            #     fork 继承 / dup 复制传播到使用侧），解析为 pipe:[<ino>]；
            #     失败（pipe() 早于采集起点、事件丢失）回落按事件秒分桶的
            #     哨兵 pipe:[anonymous@<sec>]。哨兵桶是有意的过近似/欠近似
            #     权衡：跨秒慢管道会断链，同秒不同管道会合流。
            # 写家族 -> p2f（进程->管道），读家族 -> f2p（管道->进程），
            # 指纹 (write/read, FileEntity, None) 自动命中现有通用方向
            # handler，引擎无感。
            name = file_socket["pipe"]
            if name:
                entities[1] = self.get_or_create_file(name, name)
            else:
                ino = self._fdtable.resolve(
                    record.get("pid", ""), file_socket.get("fd_num", "")
                )
                if ino is not None:
                    resolved = f"pipe:[{ino}]"
                    entities[1] = self.get_or_create_file(resolved, resolved)
                else:
                    sec = record.get("_ns", 0) // 1_000_000_000
                    anon = f"pipe:[anonymous@{sec}]"
                    entities[1] = self.get_or_create_file(anon, anon)
        elif (
            "sip" in file_socket
            and "sport" in file_socket
            and "dip" in file_socket
            and "dport" in file_socket
        ):
            entities[1] = self.get_or_create_network(
                file_socket["sip"], file_socket["sport"],
                file_socket["dip"], file_socket["dport"],
                protocol=record.get("l4proto", ""),
            )
        elif "socket" in file_socket:
            # socket 但无完整四元组（如 unix socket `ffff->ffff`、内核 fd 地址）
            self._incomplete_network_count += 1
            entities[1] = None
        elif "fd_num" in file_socket:
            # 有 fd 编号但无可建模实体：eventfd(<e>)、anon_inode、目录(<d>)、
            # 未识别类型。管道改建模后这才是 no_object 的真实口径
            self._no_object_count += 1
            entities[1] = None
        else:
            entities[1] = None

        return entities

    # ==================================================================
    # fd 生命周期表（裸管道身份解析），由主循环喂记录
    # ==================================================================
    def observe_fd_start(self, record: Dict[str, str]) -> None:
        """进入 (>) 记录钩子：close 失效、dup/fcntl 暂存 oldfd。"""
        self._fdtable.observe_start(record)

    def observe_fd_end(self, record: Dict[str, str]) -> None:
        """退出 (<) 记录钩子：pipe 登记、clone 继承、dup/fcntl 完成复制。"""
        self._fdtable.observe_end(record)

    def fd_table_stats(self) -> Dict[str, int]:
        return self._fdtable.stats()

    # ==================================================================
    # Factories
    # ==================================================================
    def get_or_create_process(
        self,
        process_key: str,
        pid: str,
        process_name: str,
        exe_path: str,
        args: str = "",
        cwd: str = "",
    ) -> Process:
        normalized_exe = _normalize_optional_text(exe_path)
        normalized_args = _normalize_optional_text(args)
        normalized_cwd = _normalize_optional_text(cwd)
        proc = self._processes.get(process_key)
        if proc is not None:
            # 首个非空 wins：已设置的属性不被后续记录覆盖（与 exepath 同规则）
            updated = False
            if proc.exe_path is None and normalized_exe is not None:
                proc.exe_path = normalized_exe
                updated = True
            if proc.args is None and normalized_args is not None:
                proc.args = normalized_args
                updated = True
            if proc.cwd is None and normalized_cwd is not None:
                proc.cwd = normalized_cwd
                updated = True
            if updated:
                # 回填后重新标脏，随下一轮 flush 写库
                self._pending_processes[process_key] = proc
            return proc

        created = Process(pid, process_name, normalized_exe,
                          normalized_args, normalized_cwd)
        self._processes[process_key] = created
        self._pending_processes[process_key] = created
        return created

    def get_or_create_file(self, file_key: str, path: str) -> FileEntity:
        f = self._files.get(file_key)
        if f is not None:
            return f
        created = FileEntity(path)
        self._files[file_key] = created
        self._pending_files[file_key] = created
        return created

    def get_or_create_network(
        self,
        src_ip: str,
        src_port: str,
        dst_ip: str,
        dst_port: str,
        protocol: str = "",
    ) -> NetworkEntity:
        # fd.l4proto 为 null/<NA>/空 时视为解析不出来，不写入 protocol
        normalized_protocol = _normalize_optional_text(protocol)
        if normalized_protocol is not None and normalized_protocol in _L4PROTO_NOT_APPLICABLE:
            normalized_protocol = None
        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        n = self._networks.get(key)
        if n is not None:
            if n.protocol is None and normalized_protocol is not None:
                n.protocol = normalized_protocol
                self._pending_networks[key] = n
            elif (
                n.protocol is not None
                and normalized_protocol is not None
                and n.protocol != normalized_protocol
            ):
                # 同一四元组出现不同协议：保留首个，计数上报
                self._network_protocol_conflicts += 1
            return n
        created = NetworkEntity(src_ip, dst_ip, src_port, dst_port, normalized_protocol)
        self._networks[key] = created
        self._pending_networks[key] = created
        return created

    # ==================================================================
    # Audit counters (also fed by syscall actions via the parser)
    # ==================================================================
    def note_incomplete_network(self) -> None:
        self._incomplete_network_count += 1

    @property
    def incomplete_network_count(self) -> int:
        return self._incomplete_network_count

    @property
    def no_object_count(self) -> int:
        return self._no_object_count

    @property
    def network_protocol_conflicts(self) -> int:
        return self._network_protocol_conflicts

    @property
    def process_count(self) -> int:
        return len(self._processes)

    @property
    def file_count(self) -> int:
        return len(self._files)

    @property
    def network_count(self) -> int:
        return len(self._networks)

    # ==================================================================
    # Pending-for-write access (consumed by flush)
    # ==================================================================
    def has_pending(self) -> bool:
        return (
            bool(self._pending_files)
            or bool(self._pending_processes)
            or bool(self._pending_networks)
        )

    @property
    def pending_processes(self) -> Dict[str, Process]:
        return self._pending_processes

    @property
    def pending_files(self) -> Dict[str, FileEntity]:
        return self._pending_files

    @property
    def pending_networks(self) -> Dict[str, NetworkEntity]:
        return self._pending_networks

    def clear_pending(self) -> None:
        self._pending_files.clear()
        self._pending_processes.clear()
        self._pending_networks.clear()

    def mark_file_referenced(self, f: FileEntity) -> None:
        """建边端点标脏：重新放回待写清单。

        不变式：凡参与过边的顶点，写边时必然已在库中。上清单的常规时机
        只有"第一次创建"，而待写清单每轮 flush 清空——若顶点创建后隔了
        flush 边界才首次参与建边，它将永远不再入清单，写边时 MATCH 不到
        端点而静默丢边。queue_edge 对每个端点调用本方法封死该路径。
        dict 赋值幂等；已入库顶点随下轮 flush 重写一次属可接受的冗余
        MERGE（热顶点每轮一次，量级远小于边写入）。
        """
        self._pending_files[f.path] = f

    def mark_process_referenced(self, p: Process) -> None:
        """建边端点标脏，见 mark_file_referenced。"""
        self._pending_processes[p.pid_and_name] = p

    def mark_network_referenced(self, n: NetworkEntity) -> None:
        """建边端点标脏，见 mark_file_referenced。"""
        self._pending_networks[n.src_and_dst_ip] = n
