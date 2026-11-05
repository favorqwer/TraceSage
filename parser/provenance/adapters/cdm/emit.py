"""一条 CDM Event -> Node / Edge / Outcome。

这一层是语义的唯一落点：客体类别怎么变顶点、方向怎么定、返回值怎么落，
全在这里；``runtime/cdm_runner.py`` 只负责读、计数、结算与写库。

方向规则（与项目既有口径一致，见 parser/README.md）：

    ProcessToFile / ProcessToNetwork / ProcessToProcess : 进程 -> 客体
    FileToProcess / NetworkToProcess                    : 客体 -> 进程

``result`` 一律经过 ``core/results.norm_result`` 过滤：成功返回 fd 号或内存地址
的调用不能把编号当成字节数写进图。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...core import paths as P
from ...core.graph import Edge, Node, Outcome
from ...core.kinds import Bucket, EdgeClass, FileKey, FileKind, NetKey, NodeKey, ProcKey
from ...core.options import EmitOptions
from ...core.results import norm_result
from . import decode as D
from .mapping import SKIP_BUCKETS, Branch, EventRule
from .objects import FILE_TYPE_MAP, FileRec, NetRec, ObjectIndex, SubjectRec, file_path_of

#: 未规整的文件路径计数（与 sysdig 侧 PATH_AUDIT 同口径，但本模块不能依赖
#: provenance.graph，因此本地维护一份）。
PATH_AUDIT: dict[str, Any] = {"dirty": 0, "samples": []}

_SYNTHETIC_PREFIXES = ("pipe:[", "socket:[", "netlink:[", "unix:[", "memfd:")

#: 容器维度在 CDM 里不存在（两套数据都是单机裸系统）。
CONTAINER_ID = ""


@dataclass(slots=True)
class EventContext:
    """一条 Event 在派发前已经解好的全部输入。"""

    event_id: int
    ts_ns: int
    etype: str
    body: dict
    props: dict[str, str]
    subject: SubjectRec | None
    obj_kind: str = ""          # "subject" | "file" | "net" | ""
    obj: Any = None             # SubjectRec / FileRec / NetRec
    obj2_kind: str = ""
    obj2: Any = None
    result_raw: int | None = None
    # 客体类别标签：subject / file / net / unresolved（uuid 有值但索引里没有）/ none
    obj_label: str = "none"


def audit_path(path: str, strict: bool) -> None:
    if path.startswith(_SYNTHETIC_PREFIXES) or path.startswith("?"):
        return
    dirty = not path.startswith("/") or ".(" in path or "(/" in path
    if not dirty:
        return
    PATH_AUDIT["dirty"] += 1
    if len(PATH_AUDIT["samples"]) < 20:
        PATH_AUDIT["samples"].append(path)
    if strict:
        raise ValueError(f"未规整的文件路径进入图：{path!r}")


def _endpoints(cls: EdgeClass, proc: NodeKey, obj: NodeKey) -> tuple[NodeKey, NodeKey]:
    if cls in (EdgeClass.F2P, EdgeClass.N2P):
        return obj, proc
    return proc, obj


class CdmEmitter:
    def __init__(self, host_id: str, index: ObjectIndex, options: EmitOptions) -> None:
        self.host = host_id
        self.index = index
        self.options = options
        self.counts: dict[str, int] = {
            "self_loop": 0,
            "path_missing": 0,
            "endpoints_missing": 0,
            "process_unseen": 0,
            "object_unseen": 0,
            "parent_by_ppid": 0,
            "parent_unresolved": 0,
            "exec_file_unresolved": 0,
            "start_ns_zero": 0,
            "host_mismatch": 0,
            "object_unnamed_file": 0,
            "object_unnamed_net": 0,
            "result_absent_edges": 0,
        }

    # -- 顶点 ----------------------------------------------------------
    def process_node(self, subject: SubjectRec) -> tuple[ProcKey, Node] | None:
        if subject is None or not subject.uuid or subject.pid <= 0:
            self.counts["process_unseen"] += 1
            return None
        if not subject.start_ns:
            self.counts["start_ns_zero"] += 1
        uid, euid = self.index.principal_of(subject)
        props: dict[str, Any] = {
            "exe_path": subject.path or None,
            "cmdline": subject.cmdline or None,
            "ppid": subject.ppid,
            "uid": uid or None,
            "euid": int(euid) if euid.isdigit() else None,
        }
        key = ProcKey(self.host, CONTAINER_ID, subject.pid, subject.start_ns)
        return key, Node(key, props)

    def file_node(self, rec: FileRec | None, *, path: str = "", ftype: str = "") -> tuple[FileKey, Node] | None:
        raw = path or (file_path_of(rec) if rec is not None else "")
        if rec is not None and rec.host_id and self._source_host and rec.host_id != self._source_host:
            self.counts["host_mismatch"] += 1
        if not raw:
            self.counts["path_missing"] += 1
            return None
        cwd = ""
        normalized = P.normalize(raw, cwd)
        if not normalized or P.is_unresolved(normalized):
            self.counts["path_missing"] += 1
            return None
        audit_path(normalized, self.options.strict_paths)
        kind = FILE_TYPE_MAP.get(ftype or (rec.ftype if rec is not None else ""), FileKind.UNKNOWN)
        key = FileKey(self.host, CONTAINER_ID, normalized)
        return key, Node(key, {"file_type": kind.value})

    def network_node(self, rec: NetRec | None) -> tuple[NetKey, Node] | None:
        if rec is None or not rec.endpoints:
            self.counts["endpoints_missing"] += 1
            return None
        key = NetKey(self.host, rec.endpoints)
        return key, Node(key, {"proto": rec.proto or None})

    # 由 runner 在拿到 Host 记录后注入，用于跨主机记录的计数
    _source_host: str = ""

    def set_source_host(self, host_id: str) -> None:
        self._source_host = host_id

    # -- 边 ------------------------------------------------------------
    def edge(
        self,
        cls: EdgeClass,
        action: str,
        syscall: str,
        src: NodeKey,
        dst: NodeKey,
        ev: EventContext,
        *,
        result: int | None = None,
        to_path: str = "",
        mode: str = "",
    ) -> Edge | None:
        if src == dst:
            self.counts["self_loop"] += 1
            return None
        # mmap 成功返回的是内存地址，不是字节数：地址绝不能落 result。
        # （sysdig 侧由 core/results.norm_result 的 _ADDRESS_RETURNS 挡住，
        #  那里认的是调用名 mmap，这里的动作名是 mmap_read/mmap_write/mmap_exec，
        #  不吃那条规则，因此在本层再挡一次。）
        normalized = norm_result(action, action, result)
        if action.startswith("mmap_") and normalized is not None and normalized >= 0:
            normalized = None
        return Edge(
            cls=cls,
            action=action,
            src=src,
            dst=dst,
            event_id=ev.event_id,
            start_ns=ev.ts_ns,
            # CDM 一条记录只有一个时刻，没有 sysdig 的 %evt.latency；
            # end_ns 与 start_ns 相同，不代表耗时。
            end_ns=ev.ts_ns,
            syscall=syscall or action,
            result=normalized,
            # CDM 不带载荷内容，payload_b64 恒为 None（无法从该数据源恢复外泄内容）。
            payload_b64=None,
            to_path=to_path or None,
            mode=mode or None,
        )

    # -- 结果 ----------------------------------------------------------
    @staticmethod
    def result_of(rule: EventRule, ev: EventContext) -> int | None:
        rc = ev.result_raw
        if rule.result == "none":
            return None
        if rule.result == "data":
            if rc is not None:
                return rc
            size = D.number(ev.body.get("size"))
            return size
        return rc  # errno

    # -- 派发 ----------------------------------------------------------
    def apply(self, rule: EventRule, ev: EventContext) -> tuple[Outcome, Bucket, str]:
        out = Outcome()
        if rule.special:
            return self._special(rule.special, rule, ev, out)
        branch = rule.branches.get(ev.obj_kind)
        if branch is None:
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        if branch.skip:
            return out, SKIP_BUCKETS[branch.skip], f"skip:{branch.skip}"
        return self._emit_branch(branch, rule, ev, out)

    def _emit_branch(
        self, branch: Branch, rule: EventRule, ev: EventContext, out: Outcome
    ) -> tuple[Outcome, Bucket, str]:
        proc = self.process_node(ev.subject) if ev.subject is not None else None
        if proc is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        proc_key, proc_node = proc

        obj = self._object_node(ev)
        if obj is None:
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        obj_key, obj_node = obj

        result = self.result_of(rule, ev)
        if rule.gate == "success":
            if result is not None and result < 0:
                return out, Bucket.ATTEMPT, f"result_{result}"
            if result is None:
                # 数据源没给返回值：不声称成功，但也不抹掉事件本身。
                # 边照建、result 留空，计数进 gaps.result_absent_edges。
                self.counts["result_absent_edges"] += 1

        edge = self._build(branch, proc_key, obj_key, ev, result)
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.extend([proc_node, obj_node])
        out.edges.append(edge)
        return out, Bucket.COVERED, ""

    def _build(
        self,
        branch: Branch,
        proc_key: NodeKey,
        obj_key: NodeKey,
        ev: EventContext,
        result: int | None,
        *,
        to_path: str = "",
        mode: str = "",
    ) -> Edge | None:
        src, dst = _endpoints(branch.edge, proc_key, obj_key)
        return self.edge(
            branch.edge, branch.action, branch.syscall, src, dst, ev,
            result=result, to_path=to_path, mode=mode,
        )

    def _object_node(self, ev: EventContext) -> tuple[NodeKey, Node] | None:
        if ev.obj_kind == "file":
            return self.file_node(ev.obj)
        if ev.obj_kind == "net":
            return self.network_node(ev.obj)
        if ev.obj_kind == "subject":
            return self.process_node(ev.obj)
        return None

    # -- 具名处理 ------------------------------------------------------
    def _special(self, name: str, rule: EventRule, ev: EventContext, out: Outcome):
        handler = getattr(self, f"_on_{name}", None)
        if handler is None:  # 理论上 mapping 加载时已经挡住
            return out, Bucket.UNMAPPED, f"special_not_implemented:{name}"
        return handler(rule, ev, out)

    def _on_handle(self, rule: EventRule, ev: EventContext, out: Outcome):
        return out, Bucket.HANDLE, "no_fd_table"

    def _on_drop_kernel(self, rule: EventRule, ev: EventContext, out: Outcome):
        return out, Bucket.DROP, "kernel_object"

    def _on_unmapped(self, rule: EventRule, ev: EventContext, out: Outcome):
        return out, Bucket.UNMAPPED, ev.etype

    def _on_blind(self, rule: EventRule, ev: EventContext, out: Outcome):
        return out, Bucket.COLLECTOR_BLIND, "event_blind"

    def _on_no_owner(self, rule: EventRule, ev: EventContext, out: Outcome):
        return out, Bucket.NO_OWNER, ev.etype

    def _on_attr(self, rule: EventRule, ev: EventContext, out: Outcome):
        if ev.etype == "EVENT_CHANGE_PRINCIPAL" and ev.subject is not None:
            proc = self.process_node(ev.subject)
            if proc is not None:
                out.nodes.append(proc[1])
            return out, Bucket.ATTR, "principal_update"
        return out, Bucket.ATTR, "object_attribute"

    def _on_open_attr(self, rule: EventRule, ev: EventContext, out: Outcome):
        if ev.obj_kind != "file":
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        node = self.file_node(ev.obj)
        if node is None:
            return out, Bucket.NO_OBJECT, "file_path_missing"
        out.nodes.append(node[1])
        return out, Bucket.ATTR, "file_type"

    def _on_chmod(self, rule: EventRule, ev: EventContext, out: Outcome):
        branch = rule.branches.get("file") or Branch(
            edge=EdgeClass.P2F, action="chmod", syscall="chmod"
        )
        if ev.obj_kind != "file":
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        proc = self.process_node(ev.subject) if ev.subject is not None else None
        if proc is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        obj = self.file_node(ev.obj)
        if obj is None:
            return out, Bucket.NO_OBJECT, "file_path_missing"
        edge = self._build(
            branch, proc[0], obj[0], ev, self.result_of(rule, ev),
            mode=ev.props.get("mode", ""),
        )
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.extend([proc[1], obj[1]])
        out.edges.append(edge)
        return out, Bucket.COVERED, ""

    def _on_mmap(self, rule: EventRule, ev: EventContext, out: Outcome):
        if ev.obj_kind != "file":
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        proc = self.process_node(ev.subject) if ev.subject is not None else None
        if proc is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        obj = self.file_node(ev.obj)
        if obj is None:
            return out, Bucket.NO_OBJECT, "file_path_missing"
        prot = (ev.props.get("protection") or ev.props.get("prot") or "").upper()
        flags = (ev.props.get("flags") or ev.props.get("opm") or "").upper()
        if "PROT_EXEC" in prot:
            action = "mmap_exec"
        elif "PROT_WRITE" in prot and "MAP_SHARED" in flags:
            action = "mmap_write"
        else:
            action = "mmap_read"
        branch = Branch(edge=EdgeClass.F2P, action=action, syscall="mmap")
        edge = self._build(branch, proc[0], obj[0], ev, self.result_of(rule, ev))
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.extend([proc[1], obj[1]])
        out.edges.append(edge)
        return out, Bucket.COVERED, "mmap_file"

    def _on_exec(self, rule: EventRule, ev: EventContext, out: Outcome):
        result = self.result_of(rule, ev)
        if ev.obj_kind == "file":
            # THEIA：predicateObject 就是被执行的可执行文件。
            proc = self.process_node(ev.subject) if ev.subject is not None else None
            if proc is None:
                return out, Bucket.NO_OWNER, "subject_unseen"
            obj = self.file_node(ev.obj)
            if obj is None:
                return out, Bucket.NO_OBJECT, "file_path_missing"
            branch = Branch(edge=EdgeClass.F2P, action="exec", syscall="exec")
            edge = self._build(branch, proc[0], obj[0], ev, result)
            if edge is None:
                return out, Bucket.OTHER, "self_loop"
            out.nodes.extend([proc[1], obj[1]])
            out.edges.append(edge)
            return out, Bucket.COVERED, "exec_file"

        if ev.obj_kind == "subject":
            # TRACE：predicateObject 是 exec 之后的新 Subject。
            old = self.process_node(ev.subject) if ev.subject is not None else None
            new = self.process_node(ev.obj)
            if old is None:
                return out, Bucket.NO_OWNER, "subject_unseen"
            if new is None:
                return out, Bucket.NO_OWNER, "exec_target_unseen"
            branch = Branch(edge=EdgeClass.P2P, action="exec", syscall="exec")
            edge = self._build(branch, old[0], new[0], ev, result)
            if edge is not None:
                out.nodes.extend([old[1], new[1]])
                out.edges.append(edge)
            # 可执行文件：新身份自身的 path（TRACE 的 Subject 只有 name，没有路径）
            path = ev.obj.path
            if path:
                node = self.file_node(None, path=path)
                if node is not None:
                    file_edge = self.edge(
                        EdgeClass.F2P, "exec", "exec", node[0], new[0], ev, result=result
                    )
                    if file_edge is not None:
                        out.nodes.append(node[1])
                        out.edges.append(file_edge)
            else:
                self.counts["exec_file_unresolved"] += 1
            if out.edges:
                return out, Bucket.COVERED, "exec_subject"
            return out, Bucket.ATTEMPT, "exec_self_loop"

        return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"

    def _on_exit(self, rule: EventRule, ev: EventContext, out: Outcome):
        child = self.process_node(ev.subject) if ev.subject is not None else None
        if child is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        parent_key: NodeKey | None = None
        parent_node: Node | None = None
        parent_uuid = ev.subject.parent
        found = self.index.get(parent_uuid) if parent_uuid else None
        if found is not None and found[0] == "subject":
            parent = self.process_node(found[1])
            if parent is not None:
                parent_key, parent_node = parent
        if parent_key is None and ev.subject.ppid > 0:
            # 出生时刻未知时用 start_ns=0（模型定义：0 = 未知），不是伪造。
            parent_key = ProcKey(self.host, CONTAINER_ID, ev.subject.ppid, 0)
            # 端点必须在节点表里，否则写库时 MATCH 不到、整条边被静默跳过
            # （dry-run 不暴露：CSV 是直写的）。属性留空，不拿子进程的信息冒充父进程。
            parent_node = Node(parent_key, {})
            self.counts["parent_by_ppid"] += 1
        if parent_key is None:
            self.counts["parent_unresolved"] += 1
            return out, Bucket.ATTEMPT, "exit_parent_unresolved"
        edge = self.edge(EdgeClass.P2P, "exit", "exit", parent_key, child[0], ev)
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.append(child[1])
        if parent_node is not None:
            out.nodes.append(parent_node)
        out.edges.append(edge)
        return out, Bucket.COVERED, ""

    def _on_signal(self, rule: EventRule, ev: EventContext, out: Outcome):
        return self._process_to_process("signal", "signal", rule, ev, out, forward=True)

    def _on_wait(self, rule: EventRule, ev: EventContext, out: Outcome):
        return self._process_to_process("wait", "wait", rule, ev, out, forward=False)

    def _process_to_process(self, action: str, syscall: str, rule: EventRule,
                            ev: EventContext, out: Outcome, *, forward: bool) -> tuple[Outcome, Bucket, str]:
        proc = self.process_node(ev.subject) if ev.subject is not None else None
        target = self._object_node(ev)
        if proc is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        if target is None:
            return out, Bucket.NO_OBJECT, f"unnamed_object:{ev.obj_label}"
        src, dst = (proc[0], target[0]) if forward else (target[0], proc[0])
        result = self.result_of(rule, ev)
        edge = self.edge(EdgeClass.P2P, action, syscall, src, dst, ev, result=result)
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.extend([proc[1], target[1]])
        out.edges.append(edge)
        return out, Bucket.COVERED, ""

    def _on_rename(self, rule: EventRule, ev: EventContext, out: Outcome):
        return self._move_file("rename", rule, ev, out)

    def _on_link(self, rule: EventRule, ev: EventContext, out: Outcome):
        return self._move_file("link", rule, ev, out)

    def _move_file(self, action: str, rule: EventRule, ev: EventContext, out: Outcome):
        """rename / link：destination = predicateObject，source = predicateObject2。

        CDM 里 predicateObject 是先被引用的那个（源），predicateObject2 是目标；
        与 sysdig 侧「客体=新路径、to_path=源路径」的约定保持一致：
        ProcessToFile 的终点是新路径，另出一条 FileToProcess（源路径 -> 进程）。
        """
        proc = self.process_node(ev.subject) if ev.subject is not None else None
        if proc is None:
            return out, Bucket.NO_OWNER, "subject_unseen"
        result = self.result_of(rule, ev)
        if rule.gate == "success":
            if result is None:
                return out, Bucket.ATTEMPT, "result_absent"
            if result < 0:
                return out, Bucket.ATTEMPT, f"result_{result}"
        source_path = ""
        if ev.obj_kind == "file":
            source_path = file_path_of(ev.obj)
        target_rec = ev.obj2 if ev.obj2_kind == "file" else None
        target_path = file_path_of(target_rec) if target_rec is not None else ""
        if not target_path:
            # 没有目标路径时不能声称"重命名到某处"，只登记源端读取。
            node = self.file_node(None, path=source_path) if source_path else None
            if node is None:
                return out, Bucket.NO_OBJECT, "path_missing"
            edge = self.edge(EdgeClass.F2P, action, action, node[0], proc[0], ev, result=result)
            if edge is None:
                return out, Bucket.OTHER, "self_loop"
            out.nodes.extend([proc[1], node[1]])
            out.edges.append(edge)
            return out, Bucket.COVERED, f"{action}_target_missing"

        target = self.file_node(target_rec)
        if target is None:
            return out, Bucket.NO_OBJECT, "file_path_missing"
        edge = self._build(
            Branch(edge=EdgeClass.P2F, action=action, syscall=action),
            proc[0], target[0], ev, result, to_path=source_path,
        )
        if edge is None:
            return out, Bucket.OTHER, "self_loop"
        out.nodes.extend([proc[1], target[1]])
        out.edges.append(edge)
        if source_path:
            source = self.file_node(None, path=source_path)
            if source is not None:
                back = self.edge(
                    EdgeClass.F2P, action, action, source[0], proc[0], ev, result=result
                )
                if back is not None:
                    out.nodes.append(source[1])
                    out.edges.append(back)
        return out, Bucket.COVERED, ""
