"""TraceSage Graph (.tsg v2) 单文件分区段二进制格式读写器（纯标准库，mmap 零拷贝）。

v2 核心优化：
  1. 独立 vkeys 字节区：按 (kind_code, key) 排序，find_vertex_id 直接用 memoryview 字节切片二分，零 json.loads；
  2. 按顶点类别分块：Process 合并为单个按 (start_ns, event_id) 升序块（单次 C 层 iter_unpack，零双指针归并），
     File / Network 保持 in(写/发) 与 out(读/收) 双块（零无效扫描）；
  3. 40 字节紧凑主边记录（原 56 字节）：只存对端 peer_vid + 4 字节 event_id + 4 字节 dur_ns（超 4.29 秒自动无损落附加区）；
  4. 紧凑二进制稀疏附加区：去掉 JSON 包装并将 payload_b64 解码为原始二进制字节存储，读取时无损还原；
  5. 12 字节 event_id 倒排表 (event_id, block_vid, adj_index)（原 16 字节）。
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import mmap
import os
from pathlib import Path
import struct
import tempfile
import time
from typing import Any, Iterator, Optional

MAGIC = b"TSG2"
TSG_VERSION = 2

# Header: magic(4s), version(I), flags(I), pad(I),
#         vertex_count(Q), edge_count(Q), incidence_count(Q), max_event_id(Q),
#         8 sections * (off Q, len Q) = 16 Q, + 16 bytes reserved = 192 bytes
HEADER_STRUCT = struct.Struct("<4sIIIQQQQQQQQQQQQQQQQQQQQ16x")
assert HEADER_STRUCT.size == 192

# 顶点目录：key_off(Q), key_len(I), prop_off(Q), prop_len(I), kind_code(B), ft_code(B), host_code(H), pid(i), ppid(i) = 36 bytes
VDIR_RECORD = struct.Struct("<QIQIBBHii")
assert VDIR_RECORD.size == 36

# 邻接偏移：in_start(Q), in_count(I), out_start(Q), out_count(I) = 24 bytes
# Process(kind=0): 单块存放在 (in_start, in_count)，out_count=0
# File/Network(kind=1,2): in=写入/发送侧(p2f/p2n), out=读取/接收侧(f2p/n2p)
ADJ_OFF_RECORD = struct.Struct("<QIQI")
assert ADJ_OFF_RECORD.size == 24

# 主边记录（40 字节，8 字节对齐）：
# peer_vid(I), event_id(I), start_ns(q), result(q), dur_ns(I), extra_off(I),
# syscall_id(H), action_id(H), rel_code(B), flags(B), pad(2x)
EDGE_RECORD = struct.Struct("<IIqqIIHHBB2x")
assert EDGE_RECORD.size == 40
_START_NS_OFFSET = 8

# 外部排序分桶记录：block_vid(I), block_slot(B: Process恒0; 对象 in=0/out=1), + EDGE_RECORD (40 bytes) = 45 bytes
BUCKET_RECORD = struct.Struct("<IBIIqqIIHHBB2x")
assert BUCKET_RECORD.size == 45

# event_id 倒排索引：event_id(I), block_vid(I), adj_index(I) = 12 bytes
EID_RECORD = struct.Struct("<III")
assert EID_RECORD.size == 12

_I64_STRUCT = struct.Struct("<q")
_U16_STRUCT = struct.Struct("<H")
_U32_STRUCT = struct.Struct("<I")

# 顶点类别码
KIND_CODES: dict[str, int] = {"Process": 0, "File": 1, "Network": 2}
KIND_BY_CODE: tuple[str, ...] = ("Process", "File", "Network")

# 5 类关系码（顺序与 attack_graph/domain/edge.py 一致）
REL_CODES: dict[str, int] = {
    "p2f": 0, "ProcessToFile": 0,
    "f2p": 1, "FileToProcess": 1,
    "p2n": 2, "ProcessToNetwork": 2,
    "n2p": 3, "NetworkToProcess": 3,
    "p2p": 4, "ProcessToProcess": 4,
}
REL_BY_CODE: tuple[str, ...] = ("p2f", "f2p", "p2n", "n2p", "p2p")
REL_FULL_BY_CODE: tuple[str, ...] = (
    "ProcessToFile",
    "FileToProcess",
    "ProcessToNetwork",
    "NetworkToProcess",
    "ProcessToProcess",
)
PRODUCER_REL_CODES = frozenset((0, 2))   # p2f, p2n
CONSUMER_REL_CODES = frozenset((1, 3))   # f2p, n2p

# flags 位掩码
FLAG_HAS_START = 1 << 0
FLAG_HAS_END = 1 << 1
FLAG_HAS_RESULT = 1 << 2
FLAG_EFFECT_SHIFT = 3
FLAG_EFFECT_MASK = 0b11 << FLAG_EFFECT_SHIFT
FLAG_LEGACY_BYTES = 1 << 5
FLAG_IS_OUT = 1 << 6         # 1 表示 block_vid == src_vid，0 表示 block_vid == dst_vid
FLAG_END_OVERFLOW = 1 << 7   # 1 表示 end_ns 无法用 uint32 dur_ns 表示，精确值存在 edge_extras

# edge_extras 二进制掩码
EXTRA_PAYLOAD_RAW = 1 << 0     # payload_b64 解码后的原始字节流
EXTRA_PAYLOAD_TEXT = 1 << 1    # 非标准 base64 回退原文本存储
EXTRA_TO_PATH = 1 << 2
EXTRA_MODE = 1 << 3
EXTRA_END_NS = 1 << 4

EFFECT_NAMES: tuple[str, ...] = ("", "success", "failure")
BUCKET_COUNT = 64
_MAX_U32 = 0xFFFFFFFF

# 写阶段原始边暂存格式：src_vid(I), dst_vid(I), event_id(I), start_ns(q), result(q), dur_ns(I), extra_off(I),
# syscall_id(H), action_id(H), rel_code(B), flags(B) = 42 bytes
_RAW_EDGE_STAGING = struct.Struct("<IIIqqIIHHBB")


def effect_code_from_result(result: Optional[int]) -> int:
    if result is None:
        return 0
    return 1 if int(result) >= 0 else 2


def pack_flags(
    *,
    has_start: bool,
    has_end: bool,
    has_result: bool,
    effect_code: int,
    legacy_bytes: bool = False,
    is_out: bool = False,
    end_overflow: bool = False,
) -> int:
    f = 0
    if has_start:
        f |= FLAG_HAS_START
    if has_end:
        f |= FLAG_HAS_END
    if has_result:
        f |= FLAG_HAS_RESULT
    f |= (int(effect_code) & 0b11) << FLAG_EFFECT_SHIFT
    if legacy_bytes:
        f |= FLAG_LEGACY_BYTES
    if is_out:
        f |= FLAG_IS_OUT
    if end_overflow:
        f |= FLAG_END_OVERFLOW
    return f


def unpack_effect(flags: int) -> str:
    code = (flags & FLAG_EFFECT_MASK) >> FLAG_EFFECT_SHIFT
    return EFFECT_NAMES[code] if 0 <= code < len(EFFECT_NAMES) else ""


def _parse_process_key(key: str) -> Optional[tuple[str, str, int, int]]:
    parts = key.split("|")
    if len(parts) < 4:
        return None
    try:
        return parts[0], (parts[1] or "host"), int(parts[2]), int(parts[3])
    except ValueError:
        return None


def _encode_extras(
    payload_b64: Optional[str],
    to_path: Optional[str],
    mode: Optional[str],
    overflow_end_ns: Optional[int],
) -> bytes:
    mask = 0
    parts: list[bytes] = []
    if payload_b64 is not None:
        try:
            raw = base64.b64decode(payload_b64.encode("ascii"), validate=True)
            if base64.b64encode(raw).decode("ascii") == payload_b64 and len(raw) <= 65535:
                mask |= EXTRA_PAYLOAD_RAW
                parts.append(_U16_STRUCT.pack(len(raw)) + raw)
            else:
                raw_txt = payload_b64.encode("utf-8")
                mask |= EXTRA_PAYLOAD_TEXT
                parts.append(_U16_STRUCT.pack(len(raw_txt)) + raw_txt)
        except Exception:
            raw_txt = payload_b64.encode("utf-8")
            mask |= EXTRA_PAYLOAD_TEXT
            parts.append(_U16_STRUCT.pack(len(raw_txt)) + raw_txt)
    if to_path is not None:
        b = to_path.encode("utf-8")
        mask |= EXTRA_TO_PATH
        parts.append(_U16_STRUCT.pack(len(b)) + b)
    if mode is not None:
        b = str(mode).encode("utf-8")
        mask |= EXTRA_MODE
        parts.append(_U16_STRUCT.pack(len(b)) + b)
    if overflow_end_ns is not None:
        mask |= EXTRA_END_NS
        parts.append(_I64_STRUCT.pack(int(overflow_end_ns)))
    return bytes([mask]) + b"".join(parts)


@dataclass(slots=True)
class TSGEdge:
    """从 .tsg 读取的单条完整边（可选惰性读取稀疏附加属性）。"""

    event_id: int
    rel: str
    rel_full: str
    syscall: str
    action: str
    start_ns: Optional[int]
    end_ns: Optional[int]
    result: Optional[int]
    bytes: int
    effect: str
    src_vid: int
    dst_vid: int
    src_kind: str
    src_key: str
    dst_kind: str
    dst_key: str
    src_host: str
    dst_host: str
    src_file_type: Optional[str]
    dst_file_type: Optional[str]
    extra_off: int = 0
    payload_b64: Optional[str] = None
    to_path: Optional[str] = None
    mode: Optional[str] = None


class TSGWriter:
    """流式外部排序构建器：接收顶点与边，原子写出单文件 .tsg v2 索引。"""

    def __init__(
        self,
        out_path: str | Path,
        *,
        scenario: str = "",
        database: str = "",
        source_scap: str = "",
        source_scap_size: int = 0,
        source_scap_mtime: int = 0,
        log: Any = None,
    ) -> None:
        self.out_path = Path(out_path)
        self.scenario = scenario
        self.database = database
        self.source_scap = source_scap
        self.source_scap_size = int(source_scap_size or 0)
        self.source_scap_mtime = int(source_scap_mtime or 0)
        self._log = log or (lambda _msg: None)
        self._t0 = time.time()

        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmpdir = Path(tempfile.mkdtemp(prefix=".tsg_build_", dir=str(self.out_path.parent)))
        self._raw_edges_path = self._tmpdir / "raw_edges.bin"
        self._extras_path = self._tmpdir / "extras.bin"
        self._raw_edges_fh = self._raw_edges_path.open("wb")
        self._extras_fh = self._extras_path.open("wb")
        self._extras_size = 0

        self._vmap: dict[tuple[int, str], int] = {}
        self._vprops: list[dict[str, Any]] = []
        self._syscall_ids: dict[str, int] = {}
        self._action_ids: dict[str, int] = {}
        self._edge_count = 0
        self._max_event_id = 0
        self._closed = False

    def add_vertex(self, kind: str, key: str, props: Optional[dict[str, Any]] = None) -> int:
        kcode = KIND_CODES[kind]
        vpair = (kcode, str(key))
        vid = self._vmap.get(vpair)
        if vid is None:
            vid = len(self._vprops)
            self._vmap[vpair] = vid
            rec: dict[str, Any] = {"kind": kind, "key": str(key)}
            if props:
                for k, v in props.items():
                    if v is not None:
                        rec[k] = v
            if "content" not in rec or not rec["content"]:
                rec["content"] = str(key)
            self._vprops.append(rec)
        elif props:
            rec = self._vprops[vid]
            for k, v in props.items():
                if v is not None and (v != "" or k not in rec):
                    rec[k] = v
        return vid

    def add_edge(
        self,
        *,
        rel: str,
        src_kind: str,
        src_key: str,
        dst_kind: str,
        dst_key: str,
        event_id: int,
        start_ns: Optional[int],
        end_ns: Optional[int],
        syscall: str = "",
        action: str = "",
        result: Optional[int] = None,
        bytes_val: Optional[int] = None,
        payload_b64: Optional[str] = None,
        to_path: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> None:
        eid = int(event_id)
        if eid < 0 or eid > _MAX_U32:
            raise OverflowError(f"TSG v2 event_id 超出 uint32 上限：{eid}")
        src_vid = self.add_vertex(src_kind, src_key)
        dst_vid = self.add_vertex(dst_kind, dst_key)
        rel_code = REL_CODES[rel]

        sc = str(syscall or action or "")
        sid = self._syscall_ids.get(sc)
        if sid is None:
            sid = self._syscall_ids[sc] = len(self._syscall_ids)
        act = str(action or "")
        aid = self._action_ids.get(act)
        if aid is None:
            aid = self._action_ids[act] = len(self._action_ids)

        has_start = start_ns is not None
        has_end = end_ns is not None
        has_result = result is not None
        st = int(start_ns) if has_start else 0
        en = int(end_ns) if has_end else st

        end_overflow = False
        overflow_end_ns: Optional[int] = None
        if has_end:
            delta = en - st
            if 0 <= delta <= _MAX_U32:
                dur_ns = delta
            else:
                dur_ns = 0
                end_overflow = True
                overflow_end_ns = en
        else:
            dur_ns = 0

        legacy_bytes = False
        if has_result:
            res_val = int(result)
            eff_code = effect_code_from_result(res_val)
        elif bytes_val is not None and int(bytes_val) > 0:
            res_val = int(bytes_val)
            eff_code = 0
            legacy_bytes = True
        else:
            res_val = 0
            eff_code = 0

        flags = pack_flags(
            has_start=has_start,
            has_end=has_end,
            has_result=has_result,
            effect_code=eff_code,
            legacy_bytes=legacy_bytes,
            is_out=False,
            end_overflow=end_overflow,
        )

        extra_off = 0
        if payload_b64 is not None or to_path is not None or mode is not None or overflow_end_ns is not None:
            blob = _encode_extras(payload_b64, to_path, mode, overflow_end_ns)
            if self._extras_size + 1 > _MAX_U32:
                raise OverflowError("TSG v2 edge_extras 区超出 4GB 上限")
            extra_off = self._extras_size + 1  # 1-based offset
            self._extras_fh.write(blob)
            self._extras_size += len(blob)

        if eid > self._max_event_id:
            self._max_event_id = eid
        self._raw_edges_fh.write(
            _RAW_EDGE_STAGING.pack(src_vid, dst_vid, eid, st, res_val, dur_ns, extra_off, sid, aid, rel_code, flags)
        )
        self._edge_count += 1

    def finish(self) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("TSGWriter 已关闭")
        self._closed = True
        tmp_tsg = self.out_path.with_name(self.out_path.name + ".tmp")
        try:
            self._raw_edges_fh.close()
            self._extras_fh.close()

            # 1) 按 (kind_code, key_utf8) 严格升序排列顶点（确保 UTF-8 字节序与二分查找一致）
            vcount = len(self._vprops)
            order = sorted(
                range(vcount),
                key=lambda i: (KIND_CODES[self._vprops[i]["kind"]], self._vprops[i]["key"].encode("utf-8")),
            )
            old_to_new = [0] * vcount
            new_kind_of = bytearray(vcount)
            sorted_vprops: list[dict[str, Any]] = []
            for new_vid, old_vid in enumerate(order):
                old_to_new[old_vid] = new_vid
                vp = self._vprops[old_vid]
                new_kind_of[new_vid] = KIND_CODES[vp["kind"]]
                sorted_vprops.append(vp)
            self._vprops.clear()
            self._vmap.clear()

            host_ids: dict[str, int] = {"": 0}
            ft_ids: dict[str, int] = {"": 0}
            for vp in sorted_vprops:
                h = str(vp.get("host_id") or "")
                if h not in host_ids:
                    host_ids[h] = len(host_ids)
                ft = str(vp.get("file_type") or "")
                if ft not in ft_ids:
                    ft_ids[ft] = len(ft_ids)

            hosts = [""] * len(host_ids)
            for k, i in host_ids.items():
                hosts[i] = k
            file_types = [""] * len(ft_ids)
            for k, i in ft_ids.items():
                file_types[i] = k
            syscalls = [""] * len(self._syscall_ids)
            for k, i in self._syscall_ids.items():
                syscalls[i] = k
            actions = [""] * len(self._action_ids)
            for k, i in self._action_ids.items():
                actions[i] = k

            # 2) 构建 Section 2 (vdir)、Section 3 (vkeys) 与 Section 4 (vprop)
            vdir_path = self._tmpdir / "vdir.bin"
            vkeys_path = self._tmpdir / "vkeys.bin"
            vprop_path = self._tmpdir / "vprop.bin"
            vkey_off = 0
            vprop_off = 0
            with vdir_path.open("wb") as f_dir, vkeys_path.open("wb") as f_key, vprop_path.open("wb") as f_prop:
                for vp in sorted_vprops:
                    kcode = KIND_CODES[vp["kind"]]
                    hcode = host_ids[str(vp.get("host_id") or "")]
                    ftcode = ft_ids[str(vp.get("file_type") or "")]
                    pid_raw = vp.get("pid")
                    ppid_raw = vp.get("ppid")
                    try:
                        pid_i = int(pid_raw) if pid_raw is not None and str(pid_raw) != "" else -1
                    except (TypeError, ValueError):
                        pid_i = -1
                    try:
                        ppid_i = int(ppid_raw) if ppid_raw is not None and str(ppid_raw) != "" else -1
                    except (TypeError, ValueError):
                        ppid_i = -1
                    kbytes = vp["key"].encode("utf-8")
                    pbytes = json.dumps(vp, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    f_dir.write(
                        VDIR_RECORD.pack(vkey_off, len(kbytes), vprop_off, len(pbytes), kcode, ftcode, hcode, pid_i, ppid_i)
                    )
                    f_key.write(kbytes)
                    f_prop.write(pbytes)
                    vkey_off += len(kbytes)
                    vprop_off += len(pbytes)
            sorted_vprops.clear()

            # 3) 分桶写入入射记录：
            #    Process(kind=0) -> block_slot 恒为 0（合并为单块按时间排序，用 FLAG_IS_OUT 区分方向）
            #    File/Network(kind=1,2) -> dst 侧 slot=0 (in/写发), src 侧 slot=1 (out/读收)
            bucket_paths = [self._tmpdir / f"bucket-{i:02d}.bin" for i in range(BUCKET_COUNT)]
            bucket_fhs = [p.open("wb") for p in bucket_paths]
            incidences = 0
            try:
                chunk_bytes = _RAW_EDGE_STAGING.size * 8192
                with self._raw_edges_path.open("rb") as rf:
                    while True:
                        raw = rf.read(chunk_bytes)
                        if not raw:
                            break
                        for rec in _RAW_EDGE_STAGING.iter_unpack(raw):
                            old_src, old_dst, eid, st, res_val, dur_ns, extra_off, sid, aid, rel_code, base_flags = rec
                            src_vid = old_to_new[old_src]
                            dst_vid = old_to_new[old_dst]
                            # dst 侧入射记录（peer = src_vid, FLAG_IS_OUT = 0）
                            dst_slot = 0
                            bucket_fhs[dst_vid % BUCKET_COUNT].write(
                                BUCKET_RECORD.pack(
                                    dst_vid, dst_slot, src_vid, eid, st, res_val, dur_ns, extra_off,
                                    sid, aid, rel_code, base_flags,
                                )
                            )
                            # src 侧入射记录（peer = dst_vid, FLAG_IS_OUT = 1）
                            src_slot = 0 if new_kind_of[src_vid] == 0 else 1
                            bucket_fhs[src_vid % BUCKET_COUNT].write(
                                BUCKET_RECORD.pack(
                                    src_vid, src_slot, dst_vid, eid, st, res_val, dur_ns, extra_off,
                                    sid, aid, rel_code, base_flags | FLAG_IS_OUT,
                                )
                            )
                            incidences += 2
            finally:
                for fh in bucket_fhs:
                    fh.close()
            self._raw_edges_path.unlink(missing_ok=True)
            del old_to_new

            if incidences > _MAX_U32:
                raise OverflowError(f"TSG v2 总入射边数超出 uint32 上限：{incidences}")

            # 4) 逐桶外部排序，写出 Section 6 (adj_edges)、Section 5 (adj_off) 和 Section 8 (eid_index)
            adj_path = self._tmpdir / "adj.bin"
            in_starts = [0] * vcount
            in_counts = [0] * vcount
            out_starts = [0] * vcount
            out_counts = [0] * vcount
            eid_entries: list[tuple[int, int, int]] = []
            rec_idx = 0
            with adj_path.open("wb") as f_adj:
                for bpath in bucket_paths:
                    raw = bpath.read_bytes()
                    if not raw:
                        bpath.unlink(missing_ok=True)
                        continue
                    recs = list(BUCKET_RECORD.iter_unpack(raw))
                    # 排序键：(block_vid, block_slot, start_ns, event_id, rel_code, action_id)
                    recs.sort(key=lambda r: (r[0], r[1], r[4], r[3], r[10], r[9]))
                    for r in recs:
                        bvid, slot, peer_vid, eid, st, res_val, dur_ns, extra_off, sid, aid, rel_code, flags = r
                        if slot == 0:
                            if in_counts[bvid] == 0:
                                in_starts[bvid] = rec_idx
                            in_counts[bvid] += 1
                        else:
                            if out_counts[bvid] == 0:
                                out_starts[bvid] = rec_idx
                            out_counts[bvid] += 1
                        # 每条唯一边恰好有一条 FLAG_IS_OUT=1 的入射记录 -> 记入 eid_index
                        if flags & FLAG_IS_OUT:
                            eid_entries.append((eid, bvid, rec_idx))
                        f_adj.write(
                            EDGE_RECORD.pack(peer_vid, eid, st, res_val, dur_ns, extra_off, sid, aid, rel_code, flags)
                        )
                        rec_idx += 1
                    bpath.unlink(missing_ok=True)

            adj_off_path = self._tmpdir / "adj_off.bin"
            with adj_off_path.open("wb") as f_off:
                for vid in range(vcount):
                    f_off.write(ADJ_OFF_RECORD.pack(in_starts[vid], in_counts[vid], out_starts[vid], out_counts[vid]))

            eid_entries.sort(key=lambda t: (t[0], t[2]))
            eid_path = self._tmpdir / "eid.bin"
            with eid_path.open("wb") as f_eid:
                for eid, bvid, idx in eid_entries:
                    f_eid.write(EID_RECORD.pack(eid, bvid, idx))
            del eid_entries

            # 5) 组装 Section 1 (meta) JSON
            meta = {
                "format": TSG_VERSION,
                "scenario": self.scenario,
                "database": self.database,
                "source_scap": self.source_scap,
                "source_scap_size": self.source_scap_size,
                "source_scap_mtime": self.source_scap_mtime,
                "vertices": vcount,
                "edges": self._edge_count,
                "incidences": incidences,
                "max_event_id": self._max_event_id,
                "syscalls": syscalls,
                "actions": actions,
                "hosts": hosts,
                "file_types": file_types,
                "built_at": int(time.time()),
                "build_seconds": round(time.time() - self._t0, 2),
            }
            meta_bytes = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

            # 6) 顺序拼接 8 个区段原子写出单文件
            section_paths = (vdir_path, vkeys_path, vprop_path, adj_off_path, adj_path, self._extras_path, eid_path)
            section_sizes = [len(meta_bytes)] + [p.stat().st_size for p in section_paths]
            offsets: list[tuple[int, int]] = []
            cursor = HEADER_STRUCT.size
            for sz in section_sizes:
                offsets.append((cursor, sz))
                cursor += sz

            header = HEADER_STRUCT.pack(
                MAGIC,
                TSG_VERSION,
                0,
                0,
                vcount,
                self._edge_count,
                incidences,
                self._max_event_id,
                offsets[0][0], offsets[0][1],
                offsets[1][0], offsets[1][1],
                offsets[2][0], offsets[2][1],
                offsets[3][0], offsets[3][1],
                offsets[4][0], offsets[4][1],
                offsets[5][0], offsets[5][1],
                offsets[6][0], offsets[6][1],
                offsets[7][0], offsets[7][1],
            )

            with tmp_tsg.open("wb") as out:
                out.write(header)
                out.write(meta_bytes)
                for spath in section_paths:
                    with spath.open("rb") as sf:
                        while True:
                            buf = sf.read(1024 * 1024)
                            if not buf:
                                break
                            out.write(buf)
            os.replace(tmp_tsg, self.out_path)
            size_mb = self.out_path.stat().st_size / 1048576
            self._log(
                f"[tsg-v2] 写出完成：{self.out_path.name} | 顶点 {vcount:,} / 边 {self._edge_count:,} / "
                f"{size_mb:.2f} MB / {meta['build_seconds']}s"
            )
            return meta
        except BaseException:
            tmp_tsg.unlink(missing_ok=True)
            raise
        finally:
            self._cleanup_tmp()

    def abort(self) -> None:
        self._closed = True
        for fh in (self._raw_edges_fh, self._extras_fh):
            try:
                fh.close()
            except Exception:
                pass
        self._cleanup_tmp()

    def _cleanup_tmp(self) -> None:
        if not self._tmpdir.exists():
            return
        for p in self._tmpdir.glob("*"):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            self._tmpdir.rmdir()
        except Exception:
            pass


class TSGReader:
    """单文件 .tsg v2 索引 mmap 零拷贝只读器。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"TSG 索引文件不存在：{self.path}")
        self._fh = self.path.open("rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self._mv = memoryview(self._mm)
        try:
            if len(self._mm) < HEADER_STRUCT.size:
                raise ValueError(f"TSG 文件过短或已损坏：{self.path}")
            hdr = HEADER_STRUCT.unpack_from(self._mm, 0)
            magic, version, _flags, _pad = hdr[0], hdr[1], hdr[2], hdr[3]
            if magic != MAGIC:
                raise ValueError(f"非法 TSG 文件标识：{magic!r}（期望 {MAGIC!r}，文件：{self.path}）")
            if version != TSG_VERSION:
                raise ValueError(f"不支持的 TSG 格式版本：{version}（期望 {TSG_VERSION}）")
            self.vertex_count: int = hdr[4]
            self.edge_count: int = hdr[5]
            self.incidence_count: int = hdr[6]
            self.max_event_id: int = hdr[7]
            (
                self._meta_off, self._meta_len,
                self._vdir_off, self._vdir_len,
                self._vkeys_off, self._vkeys_len,
                self._vprop_off, self._vprop_len,
                self._adj_off_off, self._adj_off_len,
                self._adj_off, self._adj_len,
                self._extras_off, self._extras_len,
                self._eid_off, self._eid_len,
            ) = hdr[8:24]

            self.meta: dict[str, Any] = json.loads(
                self._mm[self._meta_off:self._meta_off + self._meta_len].decode("utf-8")
            )
            self._syscalls: tuple[str, ...] = tuple(self.meta.get("syscalls") or ())
            self._actions: tuple[str, ...] = tuple(self.meta.get("actions") or ())
            self._hosts: tuple[str, ...] = tuple(self.meta.get("hosts") or ("",))
            self._file_types: tuple[str, ...] = tuple(self.meta.get("file_types") or ("",))

            self._vcache: dict[int, dict[str, Any]] = {}
            self._vid_cache: dict[tuple[int, str], Optional[int]] = {}
            self._pid_index: Optional[dict[tuple[str, int], list[tuple[int, str]]]] = None
            self._ppid_of: dict[str, int] = {}
            self._net_protocols: Optional[dict[str, str]] = None
            self._kind_bounds: Optional[dict[int, tuple[int, int]]] = None
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        mv = getattr(self, "_mv", None)
        if mv is not None:
            mv.release()
            self._mv = None
        mm = getattr(self, "_mm", None)
        if mm is not None:
            mm.close()
            self._mm = None
        fh = getattr(self, "_fh", None)
        if fh is not None:
            fh.close()
            self._fh = None

    def __enter__(self) -> "TSGReader":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # ---- 顶点目录与零 JSON 二分定位 ----

    def _vdir_entry(self, vid: int) -> tuple[int, int, int, int, int, int, int, int, int]:
        return VDIR_RECORD.unpack_from(self._mm, self._vdir_off + vid * VDIR_RECORD.size)

    def vertex_props(self, vid: int) -> dict[str, Any]:
        cached = self._vcache.get(vid)
        if cached is not None:
            return cached
        _ko, _kl, prop_off, prop_len, _kc, _ft, _hc, _pid, _ppid = self._vdir_entry(vid)
        raw = self._mm[self._vprop_off + prop_off:self._vprop_off + prop_off + prop_len]
        obj = json.loads(raw.decode("utf-8"))
        self._vcache[vid] = obj
        return obj

    def _ensure_kind_bounds(self) -> dict[int, tuple[int, int]]:
        if self._kind_bounds is not None:
            return self._kind_bounds
        bounds: dict[int, tuple[int, int]] = {}
        n = self.vertex_count
        vdir_off = self._vdir_off
        vdir_sz = VDIR_RECORD.size
        mm = self._mm
        # kind_code 在 VDIR_RECORD 中的字节偏移：8+4+8+4 = 24
        for kcode in (0, 1, 2):
            lo, hi = 0, n
            while lo < hi:
                mid = (lo + hi) // 2
                if mm[vdir_off + mid * vdir_sz + 24] < kcode:
                    lo = mid + 1
                else:
                    hi = mid
            start = lo
            lo, hi = start, n
            while lo < hi:
                mid = (lo + hi) // 2
                if mm[vdir_off + mid * vdir_sz + 24] <= kcode:
                    lo = mid + 1
                else:
                    hi = mid
            bounds[kcode] = (start, lo)
        self._kind_bounds = bounds
        return bounds

    def find_vertex_id(self, kind: str, key: str) -> Optional[int]:
        """O(log V) 零 JSON 二分定位顶点编号（直接比较 vkeys UTF-8 字节切片）。"""
        kcode = KIND_CODES.get(kind)
        if kcode is None:
            return None
        cache_key = (kcode, key)
        if cache_key in self._vid_cache:
            return self._vid_cache[cache_key]
        lo, hi = self._ensure_kind_bounds()[kcode]
        target = key.encode("utf-8")
        mm = self._mm
        vdir_off = self._vdir_off
        vdir_sz = VDIR_RECORD.size
        vkeys_off = self._vkeys_off
        unpack_kl = struct.Struct("<QI").unpack_from
        found: Optional[int] = None
        while lo < hi:
            mid = (lo + hi) // 2
            ko, kl = unpack_kl(mm, vdir_off + mid * vdir_sz)
            mid_bytes = mm[vkeys_off + ko:vkeys_off + ko + kl]
            if mid_bytes == target:
                found = mid
                break
            if mid_bytes < target:
                lo = mid + 1
            else:
                hi = mid
        self._vid_cache[cache_key] = found
        return found

    def iter_vertices(self, kind: Optional[str] = None) -> Iterator[tuple[int, dict[str, Any]]]:
        if kind is None:
            lo, hi = 0, self.vertex_count
        else:
            kcode = KIND_CODES[kind]
            lo, hi = self._ensure_kind_bounds()[kcode]
        for vid in range(lo, hi):
            yield vid, self.vertex_props(vid)

    def _ensure_pid_index(self) -> None:
        if self._pid_index is not None:
            return
        by_pid: dict[tuple[str, int], list[tuple[int, str]]] = {}
        ppid_of: dict[str, int] = {}
        lo, hi = self._ensure_kind_bounds()[0]
        mm = self._mm
        vdir_off = self._vdir_off
        vdir_sz = VDIR_RECORD.size
        vkeys_off = self._vkeys_off
        unpack_vdir = VDIR_RECORD.unpack_from
        for vid in range(lo, hi):
            ko, kl, _po, _pl, _kc, _ft, _hc, _pid, ppid_i = unpack_vdir(mm, vdir_off + vid * vdir_sz)
            key = mm[vkeys_off + ko:vkeys_off + ko + kl].decode("utf-8")
            parsed = _parse_process_key(key)
            if not parsed:
                continue
            _host, container, pid, start = parsed
            by_pid.setdefault((container, pid), []).append((start, key))
            if ppid_i > 0:
                ppid_of[key] = ppid_i
        self._pid_index = by_pid
        self._ppid_of = ppid_of

    def parent_of_process(self, key: str) -> Optional[str]:
        self._ensure_pid_index()
        ppid = self._ppid_of.get(str(key))
        if not ppid:
            return None
        parsed = _parse_process_key(str(key))
        if not parsed:
            return None
        _host, container, _pid, start = parsed
        cands = [(st, pkey) for st, pkey in (self._pid_index or {}).get((container, ppid), ()) if st <= start]
        if not cands:
            return None
        parent = max(cands)[1]
        return parent if parent != key else None

    def network_protocols(self) -> dict[str, str]:
        if self._net_protocols is not None:
            return dict(self._net_protocols)
        out: dict[str, str] = {}
        for _vid, vp in self.iter_vertices("Network"):
            proto = str(vp.get("protocol") or vp.get("proto") or "").strip()
            if proto:
                out[str(vp["key"])] = proto
        self._net_protocols = out
        return dict(out)

    # ---- 邻接块零拷贝二分读取 ----

    def _adj_block(self, vid: int, *, outgoing: bool) -> tuple[int, int]:
        in_s, in_c, out_s, out_c = ADJ_OFF_RECORD.unpack_from(
            self._mm, self._adj_off_off + vid * ADJ_OFF_RECORD.size
        )
        return (out_s, out_c) if outgoing else (in_s, in_c)

    def _edge_tuple_at(self, adj_index: int) -> tuple:
        return EDGE_RECORD.unpack_from(self._mm, self._adj_off + adj_index * EDGE_RECORD.size)

    def iter_block_raw(
        self, vid: int, lo: int, hi: int, *, outgoing: bool = False
    ) -> Iterator[tuple]:
        """在指定顶点的目标块内做零拷贝二分并用 C 层 iter_unpack 产出 (lo, hi] 的 40 字节原始边元组。

        注意：Process 顶点为单块存储（outgoing 恒传 False 即可一次遍历全部入边与出边）；
        File / Network 顶点为读写双块（outgoing=False 为写/发侧，outgoing=True 为读/收侧）。
        """
        start_idx, count = self._adj_block(vid, outgoing=outgoing)
        if count <= 0:
            return
        left, right = 0, count
        rec_size = EDGE_RECORD.size
        base_off = self._adj_off + start_idx * rec_size
        mm = self._mm
        unpack_i64 = _I64_STRUCT.unpack_from
        while left < right:
            mid = (left + right) // 2
            if unpack_i64(mm, base_off + mid * rec_size + _START_NS_OFFSET)[0] <= lo:
                left = mid + 1
            else:
                right = mid
        if left >= count:
            return
        lo_u, hi_u = left, count
        while lo_u < hi_u:
            mid = (lo_u + hi_u) // 2
            if unpack_i64(mm, base_off + mid * rec_size + _START_NS_OFFSET)[0] <= hi:
                lo_u = mid + 1
            else:
                hi_u = mid
        if lo_u <= left:
            return
        slice_start = base_off + left * rec_size
        slice_end = base_off + lo_u * rec_size
        yield from EDGE_RECORD.iter_unpack(self._mv[slice_start:slice_end])

    def read_edge_extras(self, extra_off: int) -> dict[str, Any]:
        """按 1-based 偏移解码紧凑二进制边附加属性。"""
        if extra_off <= 0:
            return {}
        mm = self._mm
        pos = self._extras_off + (extra_off - 1)
        mask = mm[pos]
        pos += 1
        out: dict[str, Any] = {}
        if mask & EXTRA_PAYLOAD_RAW:
            ln = _U16_STRUCT.unpack_from(mm, pos)[0]
            pos += 2
            out["payload_b64"] = base64.b64encode(mm[pos:pos + ln]).decode("ascii")
            pos += ln
        elif mask & EXTRA_PAYLOAD_TEXT:
            ln = _U16_STRUCT.unpack_from(mm, pos)[0]
            pos += 2
            out["payload_b64"] = mm[pos:pos + ln].decode("utf-8")
            pos += ln
        if mask & EXTRA_TO_PATH:
            ln = _U16_STRUCT.unpack_from(mm, pos)[0]
            pos += 2
            out["to_path"] = mm[pos:pos + ln].decode("utf-8")
            pos += ln
        if mask & EXTRA_MODE:
            ln = _U16_STRUCT.unpack_from(mm, pos)[0]
            pos += 2
            out["mode"] = mm[pos:pos + ln].decode("utf-8")
            pos += ln
        if mask & EXTRA_END_NS:
            out["end_ns"] = _I64_STRUCT.unpack_from(mm, pos)[0]
        return out

    def decode_edge(self, block_vid: int, rec: tuple, *, with_extras: bool = False) -> TSGEdge:
        peer_vid, event_id, start_ns, res_val, dur_ns, extra_off, sid, aid, rel_code, flags = rec
        if flags & FLAG_IS_OUT:
            src_vid, dst_vid = block_vid, peer_vid
        else:
            src_vid, dst_vid = peer_vid, block_vid

        src_vp = self.vertex_props(src_vid)
        dst_vp = self.vertex_props(dst_vid)
        _, _, _, _, src_kc, src_ftc, src_hc, _, _ = self._vdir_entry(src_vid)
        _, _, _, _, dst_kc, dst_ftc, dst_hc, _, _ = self._vdir_entry(dst_vid)

        has_start = bool(flags & FLAG_HAS_START)
        has_end = bool(flags & FLAG_HAS_END)
        has_result = bool(flags & FLAG_HAS_RESULT)
        legacy_bytes = bool(flags & FLAG_LEGACY_BYTES)
        end_overflow = bool(flags & FLAG_END_OVERFLOW)

        extras = self.read_edge_extras(extra_off) if ((with_extras or end_overflow) and extra_off > 0) else {}
        if has_end:
            end_ns: Optional[int] = extras["end_ns"] if end_overflow else (start_ns + dur_ns)
        else:
            end_ns = None

        result = res_val if has_result else None
        if has_result:
            nbytes = res_val if res_val > 0 else 0
        elif legacy_bytes:
            nbytes = res_val
        else:
            nbytes = 0

        return TSGEdge(
            event_id=event_id,
            rel=REL_BY_CODE[rel_code],
            rel_full=REL_FULL_BY_CODE[rel_code],
            syscall=self._syscalls[sid] if sid < len(self._syscalls) else "",
            action=self._actions[aid] if aid < len(self._actions) else "",
            start_ns=start_ns if has_start else None,
            end_ns=end_ns,
            result=result,
            bytes=nbytes,
            effect=unpack_effect(flags),
            src_vid=src_vid,
            dst_vid=dst_vid,
            src_kind=KIND_BY_CODE[src_kc],
            src_key=str(src_vp["key"]),
            dst_kind=KIND_BY_CODE[dst_kc],
            dst_key=str(dst_vp["key"]),
            src_host=self._hosts[src_hc] if src_hc < len(self._hosts) else "",
            dst_host=self._hosts[dst_hc] if dst_hc < len(self._hosts) else "",
            src_file_type=(self._file_types[src_ftc] or None) if src_ftc < len(self._file_types) else None,
            dst_file_type=(self._file_types[dst_ftc] or None) if dst_ftc < len(self._file_types) else None,
            extra_off=extra_off,
            payload_b64=extras.get("payload_b64") if with_extras else None,
            to_path=extras.get("to_path") if with_extras else None,
            mode=extras.get("mode") if with_extras else None,
        )

    def find_edges_by_event_id(self, event_id: int, *, with_extras: bool = True) -> list[TSGEdge]:
        count = self._eid_len // EID_RECORD.size
        if count <= 0:
            return []
        lo, hi = 0, count
        base = self._eid_off
        rsize = EID_RECORD.size
        mm = self._mm
        unpack_u32 = _U32_STRUCT.unpack_from
        target = int(event_id)
        while lo < hi:
            mid = (lo + hi) // 2
            if unpack_u32(mm, base + mid * rsize)[0] < target:
                lo = mid + 1
            else:
                hi = mid
        out: list[TSGEdge] = []
        idx = lo
        while idx < count:
            eid, bvid, adj_idx = EID_RECORD.unpack_from(mm, base + idx * rsize)
            if eid != target:
                break
            out.append(self.decode_edge(bvid, self._edge_tuple_at(adj_idx), with_extras=with_extras))
            idx += 1
        return out

    def find_poi(self, *, kind: str, rel: str, syscall: str, key: str) -> list[dict[str, Any]]:
        kind_label = {"file": "File", "network": "Network"}.get(kind.lower(), kind)
        rel_code = REL_CODES[rel]
        vids: list[int] = []
        direct = self.find_vertex_id(kind_label, key)
        if direct is not None:
            vids.append(direct)
        elif kind_label == "File":
            suffix = "|" + key
            for vid, vp in self.iter_vertices("File"):
                if vp.get("content") == key or str(vp.get("key") or "").endswith(suffix):
                    vids.append(vid)

        rows: list[dict[str, Any]] = []
        for vid in vids:
            o_vp = self.vertex_props(vid)
            for rec in self.iter_block_raw(vid, -1, (1 << 63) - 1, outgoing=False):
                if rec[8] != rel_code:
                    continue
                sc = self._syscalls[rec[6]] if rec[6] < len(self._syscalls) else ""
                act = self._actions[rec[7]] if rec[7] < len(self._actions) else ""
                if sc != syscall and act != syscall:
                    continue
                ev = self.decode_edge(vid, rec, with_extras=False)
                p_vp = self.vertex_props(ev.src_vid)
                rows.append({
                    "event_id": ev.event_id,
                    "rel": ev.rel,
                    "starttime": ev.start_ns,
                    "endtime": ev.end_ns,
                    "syscall": ev.syscall,
                    "action": ev.action,
                    "res": ev.result,
                    "bytes": ev.bytes,
                    "relationship_id": f"{ev.rel_full}:{ev.event_id}:{ev.action}",
                    "process_id": ev.src_key,
                    "process_content": str(p_vp.get("content") or ev.src_key),
                    "src_host": ev.src_host,
                    "dst_host": ev.dst_host,
                    "dst_kind": ev.dst_file_type,
                    "other_key": ev.dst_key,
                    "other": str(o_vp.get("content") or ev.dst_key),
                    "other_label": ev.dst_kind,
                    "other_protocol": str(o_vp.get("protocol") or o_vp.get("proto") or ""),
                })
        rows.sort(key=lambda r: (r["starttime"] if r["starttime"] is not None else -1, r["event_id"]))
        return rows
