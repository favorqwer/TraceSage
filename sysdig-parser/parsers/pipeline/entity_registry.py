"""Entity registry: deduplicates vertices and extracts them from records.

Owns the three vertex dictionaries, their pending-for-write counterparts
(refilled on attribute backfill so updates reach the next flush), and the
audit counters for degenerate objects (pipes, socket fragments without a
full 4-tuple, conflicting protocols).
"""

from typing import Dict, List, Optional

from ..jsonl.fields import extract_process_file, normalize_file_path
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
        self._connect_in_progress_count = 0
        self._no_object_count = 0
        # unix socket 文件系统路径（G1 类①）的细分审计
        self._unix_path_count = 0          # 注记里直接带路径
        self._unix_resolved_count = 0      # 裸/地址对注记经 fd 表回填出路径
        self._unix_unresolved_count = 0    # 回填失败（无名字）
        self._unix_abstract_count = 0      # 抽象命名空间（@name），当前不建模
        self._netlink_skipped_count = 0    # <n> netlink，当前不建模
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

        if "path" not in file_socket and process_file is not None:
            # execve 的 filename= 通道（与 fd 注记互斥：有 fd 注记时以注记为准）
            entities[1] = self.get_or_create_file(process_file, process_file)
        else:
            entities[1] = self.entity_from_descriptor(record, file_socket)

        return entities

    def entity_from_descriptor(
        self, record: Dict[str, str], file_socket: Dict[str, str]
    ) -> Optional[Entity]:
        """fd 描述符 dict -> 顶点实体（File / Network / None），含未建模计数。

        这是"描述符 -> 实体"的唯一映射点：extract_entities 走它；sendfile
        这类双 fd 系统调用（handlers 里按 in_fd=/out_fd= 分别抽取）也走它。
        集中的理由是历史教训：映射逻辑分散会出现"某条通道忘了归一/忘了
        审计"（G3 的 filename= 通道、chmod 家族注册表各丢过一类边）。
        """
        pid = record.get("pid", "")
        fd_num = file_socket.get("fd_num", "")

        if "path" in file_socket:
            path = file_socket["path"]
            return self.get_or_create_file(path, path)

        if "pipe" in file_socket:
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
                return self.get_or_create_file(name, name)
            ino = self._fdtable.resolve(pid, fd_num)
            if ino is not None:
                resolved = f"pipe:[{ino}]"
                return self.get_or_create_file(resolved, resolved)
            sec = record.get("_ns", 0) // 1_000_000_000
            anon = f"pipe:[anonymous@{sec}]"
            return self.get_or_create_file(anon, anon)

        if "unix_path" in file_socket:
            # unix socket 类①（文件系统路径）：合成 File 顶点 `unix:[<path>]`，
            # 与管道同构——沿用 File 标签、不新增标签、不塞 Network 四元组
            # （get_or_create_network 的键是 ip:port->ip:port，塞入会污染
            # Network 顶点集）。前缀命名与 pipe:[...] 同族，且
            # normalize_file_path 已把 unix:[ 列为合成顶点前缀、不会被改写。
            unix = f"unix:[{file_socket['unix_path']}]"
            self._unix_path_count += 1
            return self.get_or_create_file(unix, unix)

        if (
            "sip" in file_socket
            and "sport" in file_socket
            and "dip" in file_socket
            and "dport" in file_socket
        ):
            return self.get_or_create_network(
                file_socket["sip"], file_socket["sport"],
                file_socket["dip"], file_socket["dport"],
                protocol=record.get("l4proto", ""),
            )

        if "socket" in file_socket:
            # socket 但无完整四元组：unix（`<u>` 注记）/ 内核 fd 地址 / 半绑定 IP。
            # unix 先试 fd 表回填（同一 (pid,fd) 在 connect/bind/sendmsg/recvmsg
            # 等记录上学到的路径）——这是把裸 `<u>`（实测占 <u> 的 68%）接上
            # 具名顶点的唯一途径。回填不到就不建顶点（绝不归到全局单点，否则
            # 所有无关 unix socket 会合流成一个 hub）。
            if file_socket.get("fd_type", "").startswith("u"):
                resolved_path = self._fdtable.resolve_unix_path(pid, fd_num)
                if resolved_path is not None:
                    self._unix_resolved_count += 1
                    unix = f"unix:[{resolved_path}]"
                    return self.get_or_create_file(unix, unix)
                if file_socket.get("unix_abstract"):
                    self._unix_abstract_count += 1
                else:
                    self._unix_unresolved_count += 1
            self._incomplete_network_count += 1
            return None

        if "fd_num" in file_socket:
            # 有 fd 编号但无可建模实体：eventfd(<e>)、anon_inode、目录(<d>)、
            # netlink(<n>)、未识别类型。管道改建模后这才是 no_object 的真实口径。
            if file_socket.get("fd_type_raw") == "n":
                self._netlink_skipped_count += 1
            self._no_object_count += 1
            return None

        return None

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
        # File 顶点身份归一的唯一 chokepoint（G3 剥括号注记 + G4 词法归一）。
        # File 的 MERGE 键就是 FileEntity.path（见 storage/neo4j_writer），
        # 因此键与实体属性必须一起归一，否则图里仍会留下未归一的顶点。
        # 调用方均传 (path, path)；传不同值时各自归一，不交叉。
        normalized_key = normalize_file_path(file_key)
        normalized_path = (
            normalized_key if path == file_key else normalize_file_path(path)
        )
        f = self._files.get(normalized_key)
        if f is not None:
            return f
        created = FileEntity(normalized_path)
        self._files[normalized_key] = created
        self._pending_files[normalized_key] = created
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

    def note_connect_in_progress(self) -> None:
        """connect 以 EINPROGRESS(-115) 收尾、按“已发起”建边的次数。"""
        self._connect_in_progress_count += 1

    @property
    def connect_in_progress_count(self) -> int:
        return self._connect_in_progress_count

    @property
    def no_object_count(self) -> int:
        return self._no_object_count

    @property
    def unix_audit(self) -> Dict[str, int]:
        return {
            "unix_path": self._unix_path_count,
            "unix_resolved_via_fdtable": self._unix_resolved_count,
            "unix_unresolved": self._unix_unresolved_count,
            "unix_abstract_skipped": self._unix_abstract_count,
            "netlink_skipped": self._netlink_skipped_count,
        }

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
