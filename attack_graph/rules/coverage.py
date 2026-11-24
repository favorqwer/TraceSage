"""覆盖表：场景 × 拓扑形态 → 边键位图，并保留边键内容以支持历史重放。

设计要点（见 docs 与方案说明）：
  1. 存边键内容（端点、系统调用、顶点类型、进程标识），不是只存位图。
     这样任何新出现的拓扑形态都能在历史场景上重放匹配，不需要重新查图。
  2. 追加式增量维护：新场景只追加自己的分片，集合并集满足交换律，
     最终内容与接入顺序无关。
  3. 端点字符串做场景内字典编码，避免 JSON 体积膨胀。

本模块不连数据库、不读标准答案，只做数据结构与位图运算。
"""
from __future__ import annotations

import base64
import json
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

Bitmask = int


# ---------- 位图工具 ----------

def bits_set(buf: bytearray, i: int) -> None:
    buf[i >> 3] |= 1 << (i & 7)


def bits_to_int(buf: bytearray) -> Bitmask:
    return int.from_bytes(bytes(buf), "little")


def int_to_b64(value: Bitmask, n_bits: int) -> str:
    nbytes = (n_bits + 7) // 8
    return base64.b64encode(value.to_bytes(nbytes, "little")).decode("ascii")


def b64_to_int(text: str) -> Bitmask:
    return int.from_bytes(base64.b64decode(text.encode("ascii")), "little")


def ints_to_b64(sorted_ints: Iterable[int], n_bits: int) -> str:
    """紧凑位图：只把稀疏的整数集合写成位图再 base64。"""
    buf = bytearray((n_bits + 7) // 8)
    for i in sorted_ints:
        bits_set(buf, i)
    return base64.b64encode(bytes(buf)).decode("ascii")


# ---------- 覆盖表 ----------

class ScenarioShard:
    """一个场景的分片：边键内容、标签位图、各形态的场景内位图。"""

    __slots__ = ("name", "endpoints", "keys", "idents", "pos", "ignore", "neg", "hits")

    def __init__(self, name: str) -> None:
        self.name = name
        self.endpoints: List[str] = []
        self.keys: List[Tuple[int, str, int, str, str]] = []
        self.idents: List[Tuple[List[str], List[str], str]] = []
        self.pos: List[int] = []
        self.ignore: List[int] = []
        self.neg: List[int] = []
        self.hits: Dict[str, List[int]] = {}

    @property
    def n_keys(self) -> int:
        return len(self.keys)

    # --- 写入 ---

    def load(self, edges: Sequence[Dict[str, Any]], labels: Dict[Tuple[str, str, str], str],
             hits: Dict[str, Iterable[int]]) -> None:
        """从一个场景的候选边池装载分片。

        edges 与 hits 的下标必须一致（都由同一份 clean 候选边顺序决定）。
        """
        ep_index: Dict[str, int] = {}
        for e in edges:
            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            for s in (src, dst):
                if s not in ep_index:
                    ep_index[s] = len(self.endpoints)
                    self.endpoints.append(s)
        self.keys = []
        self.idents = []
        self.pos = []
        self.ignore = []
        self.neg = []
        for idx, e in enumerate(edges):
            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            sc = str(e.get("syscall") or "")
            self.keys.append((ep_index[src], sc, ep_index[dst],
                              str(e.get("src_label") or ""), str(e.get("dst_label") or "")))
            src_ids = [str(v) for _, v in (e.get("src_identities") or [])]
            dst_ids = [str(v) for _, v in (e.get("dst_identities") or [])]
            self.idents.append((src_ids, dst_ids, str(e.get("process_id") or "")))
            key = (src, sc, dst)
            lab = labels.get(key, "neg")
            (self.pos if lab == "pos" else self.ignore if lab == "ignore" else self.neg).append(idx)

        self.hits = {mid: sorted(set(v)) for mid, v in hits.items()}

    # --- 读取 ---

    def edge_dicts(self) -> List[Dict[str, Any]]:
        """把分片重建成与闭包输出同形状的边字典，供 MatchIndex / TopologyFacts 使用。"""
        out: List[Dict[str, Any]] = []
        eps = self.endpoints
        for idx, (si, sc, di, sl, dl) in enumerate(self.keys):
            src_ids, dst_ids, pid = self.idents[idx]
            out.append({
                "src": eps[si], "syscall": sc, "dst": eps[di],
                "src_label": sl, "dst_label": dl,
                "process_id": pid,
                "src_identities": [["Process", v] for v in src_ids],
                "dst_identities": [["Process", v] for v in dst_ids],
            })
        return out

    # --- 序列化 ---

    def to_payload(self) -> Dict[str, Any]:
        n = self.n_keys
        return {
            "name": self.name,
            "endpoints": self.endpoints,
            "keys": [list(k) for k in self.keys],
            "idents": [[a, b, c] for a, b, c in self.idents],
            "pos": ints_to_b64(self.pos, n),
            "ignore": ints_to_b64(self.ignore, n),
            "neg": ints_to_b64(self.neg, n),
            "hits": {mid: ints_to_b64(v, n) for mid, v in self.hits.items()},
        }

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "ScenarioShard":
        sh = cls(str(payload["name"]))
        sh.endpoints = list(payload.get("endpoints") or [])
        sh.keys = [(int(a), str(b), int(c), str(d), str(e))
                   for a, b, c, d, e in (payload.get("keys") or [])]
        sh.idents = [([str(x) for x in a], [str(x) for x in b], str(c))
                     for a, b, c in (payload.get("idents") or [])]

        def unpack(text: str) -> List[int]:
            value = b64_to_int(text)
            out: List[int] = []
            i = 0
            while value:
                if value & 1:
                    out.append(i)
                value >>= 1
                i += 1
            return out

        sh.pos = unpack(payload.get("pos") or "")
        sh.ignore = unpack(payload.get("ignore") or "")
        sh.neg = unpack(payload.get("neg") or "")
        sh.hits = {mid: unpack(v) for mid, v in (payload.get("hits") or {}).items()}
        return sh


class CoverageStore:
    """全部场景的覆盖表。分片按接入顺序保存，全局位置由偏移量拼接。"""

    FORMAT = 1

    def __init__(self) -> None:
        self.shards: Dict[str, ScenarioShard] = {}
        self.order: List[str] = []
        # 预置位图（从 bitmaps.bin 读入时填充；命中则跳过 keys/idents 计算）
        self._preset_total: int = 0
        self._preset_pos: Optional[int] = None
        self._preset_ignore: Optional[int] = None
        self._preset_rules: Dict[str, int] = {}

    def attach_bitmaps(self, total: int, pos: int, ignore: int,
                       rule_bitmaps: Dict[str, int]) -> None:
        """挂上预先算好的位图，使 label_bitmap / rule_bitmap 免于重算。"""
        self._preset_total = int(total)
        self._preset_pos = int(pos)
        self._preset_ignore = int(ignore)
        self._preset_rules = {str(k): int(v) for k, v in rule_bitmaps.items()}

    # --- 基本属性 ---

    def __len__(self) -> int:
        return len(self.order)

    def names(self) -> List[str]:
        return list(self.order)

    def total_keys(self) -> int:
        if self._preset_pos is not None:
            return self._preset_total
        return sum(self.shards[n].n_keys for n in self.order)

    def offsets(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        off = 0
        for n in self.order:
            out[n] = off
            off += self.shards[n].n_keys
        return out

    # --- 追加 ---

    def add(self, shard: ScenarioShard) -> None:
        if shard.name in self.shards:
            raise ValueError(f"场景已在覆盖表中，禁止重复追加：{shard.name}")
        self.shards[shard.name] = shard
        self.order.append(shard.name)

    def has(self, name: str) -> bool:
        return name in self.shards

    # --- 全局位图 ---

    def label_bitmap(self, label: str) -> Bitmask:
        if label == "pos" and self._preset_pos is not None:
            return self._preset_pos
        if label == "ignore" and self._preset_ignore is not None:
            return self._preset_ignore
        total = self.total_keys()
        buf = bytearray((total + 7) // 8)
        off = 0
        for n in self.order:
            sh = self.shards[n]
            idxs = sh.pos if label == "pos" else sh.ignore if label == "ignore" else sh.neg
            for i in idxs:
                bits_set(buf, off + i)
            off += sh.n_keys
        return bits_to_int(buf)

    def rule_bitmap(self, motif_id: str) -> Bitmask:
        if motif_id in self._preset_rules:
            return self._preset_rules[motif_id]
        total = self.total_keys()
        buf = bytearray((total + 7) // 8)
        off = 0
        for n in self.order:
            sh = self.shards[n]
            for i in sh.hits.get(motif_id, ()):
                bits_set(buf, off + i)
            off += sh.n_keys
        return bits_to_int(buf)

    def all_rule_ids(self) -> List[str]:
        seen: Dict[str, None] = {}
        for n in self.order:
            for mid in self.shards[n].hits:
                seen.setdefault(mid, None)
        return list(seen.keys())

    # --- 序列化 ---

    def to_payload(self) -> Dict[str, Any]:
        return {
            "format": self.FORMAT,
            "order": list(self.order),
            "scenarios": [self.shards[n].to_payload() for n in self.order],
        }

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "CoverageStore":
        if int(payload.get("format", 0)) != cls.FORMAT:
            raise RuntimeError(f"覆盖表格式不匹配：{payload.get('format')!r}，本版要求 {cls.FORMAT}")
        store = cls()
        for item in payload.get("scenarios") or []:
            store.add(ScenarioShard.from_payload(item))
        return store

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "CoverageStore":
        return cls.from_payload(json.loads(text))


# ---------- 位图二进制旁挂（贪心专用，跳过 keys/idents 解析） ----------

_BITMAP_MAGIC = b"RBM1"
_BITMAP_HEAD = struct.Struct("<4sIII")


def save_bitmaps(path, store: "CoverageStore", rule_ids: Sequence[str]) -> int:
    """把贪心需要的最小数据写成二进制：pos/ignore 位图 + 每条形态位图。

    不写 keys/idents（那是重放匹配才要的）。返回文件字节数。
    """
    total = store.total_keys()
    nbytes = (total + 7) // 8
    pos = store.label_bitmap("pos")
    ignore = store.label_bitmap("ignore")
    blob = bytearray()
    blob += _BITMAP_HEAD.pack(_BITMAP_MAGIC, total, len(rule_ids), nbytes)
    blob += pos.to_bytes(nbytes, "little")
    blob += ignore.to_bytes(nbytes, "little")
    for rid in rule_ids:
        blob += store.rule_bitmap(rid).to_bytes(nbytes, "little")
    tmp = Path(str(path) + ".tmp")
    tmp.write_bytes(bytes(blob))
    tmp.replace(path)
    return len(blob)


def load_bitmaps(path) -> Dict[str, Any]:
    """读回位图旁挂文件。返回 {total, pos, ignore, rule_bitmaps}。"""
    raw = Path(path).read_bytes()
    magic, total, n_motifs, nbytes = _BITMAP_HEAD.unpack_from(raw, 0)
    if magic != _BITMAP_MAGIC:
        raise RuntimeError(f"位图文件魔数不符：{magic!r}（期望 {_BITMAP_MAGIC!r}）")
    off = _BITMAP_HEAD.size
    pos = int.from_bytes(raw[off:off + nbytes], "little"); off += nbytes
    ignore = int.from_bytes(raw[off:off + nbytes], "little"); off += nbytes
    names = json.loads(Path(str(path).replace(".bitmaps.bin", ".bitmaps.idx.json")).read_text(encoding="utf-8"))
    if len(names) != n_motifs:
        raise RuntimeError(f"位图文件形态数 {n_motifs} 与索引 {len(names)} 不符")
    maps: Dict[str, int] = {}
    for name in names:
        maps[str(name)] = int.from_bytes(raw[off:off + nbytes], "little")
        off += nbytes
    return {"total": total, "pos": pos, "ignore": ignore, "rule_bitmaps": maps}
