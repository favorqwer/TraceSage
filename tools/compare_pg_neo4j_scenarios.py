#!/usr/bin/env python3
"""单个攻击场景：PostgreSQL 基准库 vs Neo4j 新导入库 的详细对比（一份一次）。

两侧都归一化到同一"实体键-边键"空间：
    Process (pid:int, 可执行路径)   PG process.exename / Neo4j n.exepath
    File    路径字符串              PG file.name        / Neo4j n.file_id
    Network (lip,lport,rip,rport)   PG network.srcip/../dstip/../（去 /32）
                                    Neo4j network_id "lip:lport->rip:rport"
    边方向由端点类型决定：PG 的 process/file/network 三张表共用一个 id 序列
    （实测六库跨表 id 交集为 0），端点类型可由 id 唯一查得；不能按 optype 猜方向
    ——旧 sysdig-parser/compare_pg_neo4j.py 按 `optype=='write'` 判方向，把 PG
    rename 的 Process->File 半边（场景 1 有 152 条）错标成了 File->Process。

边比较粒度（带 x 的级别把进程端点的 pid 去掉，只按可执行路径对齐）：
    L1  (src, dst, syscall)                             结构：因果边在不在
    L1x 同上但进程忽略 pid                              结构的身份口径修正
    S1  = L1 的去重取值集合                            判断一侧是否合并过重复边
    L2  (src, dst, syscall, starttime)                  事件实例
    L2x 同上但进程忽略 pid                              “PG 是不是 Neo4j 子集”的关键判据
    L3  (..., endtime, bytes)                           严格等价（旧工具判据）
    L3x 同上但进程忽略 pid
另：PG 的 optype 先过一遍解析器自己的 CANONICAL_SYSCALL_MAP（旧导入器存原始
系统调用名，新解析器把同族变体归一到家族基本名，不归一会让 recvmsg/sendmsg/writev
看起来像“PG 独有的边”）；--pg-raw-names 可关掉该项。

内存：每场景每级只存 8 字节打包整数（高 56 位哈希 | 低 8 位分组号），
用 array('Q')，百万级边约 8MB/级，逐场景释放。

用法：
    python tools/compare_pg_neo4j_scenarios.py --scenario 1 --out-dir output/cmp
    python tools/compare_pg_neo4j_scenarios.py --scenario all --out-dir output/cmp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from array import array
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "sysdig-parser"))

import psycopg2  # noqa: E402
import xxhash  # noqa: E402
from neo4j import GraphDatabase  # noqa: E402

from parsers.config import load_dotenv  # noqa: E402
from parsers.dispatch.meta_config import canonical_syscall  # noqa: E402

load_dotenv()

DB_PREFIX = "tracesage-"
LEVELS = ("L1", "L1x", "L2", "L2x", "L3", "L3x")
REL_ENDPOINTS = {
    "p2p": ("Process", "Process"), "p2f": ("Process", "File"), "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"), "n2p": ("Network", "Process"),
}
SHAPE_TO_REL = {("P", "P"): "p2p", ("P", "F"): "p2f", ("F", "P"): "f2p",
                ("P", "N"): "p2n", ("N", "P"): "n2p"}
SEP, SEP2 = "\x1f", "\x1e"
GID_MASK = 0xFF
MAX_SAMPLES = 200_000   # 人类可读样本上限（条）
SAMPLES_PER_GROUP = 4   # 每组展示几条差异样本
CHUNK = 100_000
NL = chr(10)   # Markdown 行分隔（避免源码里出现转义字面量）
SEPSTR = "; "  # 样本列表分隔


# ---------------------------------------------------------------- 归一化
def norm_ip(v) -> str:
    s = (v or "").strip()
    return s[:-3] if s.endswith("/32") else (s[:-4] if s.endswith("/128") else s)


def norm_int(v) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def norm_pid(v) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return -1


def proc_key(pid, exe) -> str:
    return f"P{SEP}{norm_pid(pid)}{SEP}{(exe or '').strip()}"


def file_key(p) -> str:
    return f"F{SEP}{p or ''}"


def net_key(lip, lport, rip, rport) -> str:
    return f"N{SEP}{norm_ip(lip)}{SEP}{norm_int(lport)}{SEP}{norm_ip(rip)}{SEP}{norm_int(rport)}"


def loosen(key: str) -> str:
    """Process 端点去掉 pid（只留可执行路径），其他类型原样。"""
    if key.startswith("P"):
        p = key.split(SEP)
        return f"P{SEP}{SEP}{p[2] if len(p) > 2 else ''}"
    return key


def h64(s: str) -> int:
    return xxhash.xxh64(s.encode("utf-8", "surrogatepass")).intdigest()


def pack(digest: int, gid: int) -> int:
    return (digest & ~GID_MASK) | gid


def readable(k: str) -> str:
    p = k.split(SEP)
    if p[0] == "P":
        return f"proc[{p[1]}:{p[2] or '∅'}]"
    if p[0] == "F":
        return f"file[{p[1] or '∅'}]"
    if p[0] == "N":
        return f"net[{p[1]}:{p[2]}->{p[3]}:{p[4]}]"
    return k


class Side:
    """一侧（PG 或 Neo4j）的归一化结果。"""

    def __init__(self) -> None:
        self.vertices: Dict[str, set] = {"P": set(), "F": set(), "N": set()}
        self.level: Dict[str, array] = {lv: array("Q") for lv in LEVELS}
        self.samples: Dict[int, Tuple[str, str, str]] = {}     # L1 打包值 -> (src,dst,syscall)
        self.samples_x: Dict[int, Tuple[str, str, str]] = {}   # L1x 打包值 -> (src,dst,syscall)
        self.by_group: Counter = Counter()
        self.ref_vertices: Dict[str, set] = {"P": set(), "F": set(), "N": set()}
        self.t_min: Optional[int] = None
        self.t_max: Optional[int] = None
        self.n_edges = 0
        self.notes: Counter = Counter()
        self.extra: Dict[str, object] = {}

    def add_edge(self, gid: int, s: str, d: str, syscall: str, st: int, et: int, amt: int) -> None:
        l1 = h64(f"{s}{SEP2}{d}{SEP2}{syscall}")
        # 带 x 的级别把进程端点的 pid 去掉（只按可执行路径对齐），用于归因
        # “旧导入器按线程记录进程、新解析器按 pid 建顶点”造成的键空间错位。
        ls, ld = loosen(s), loosen(d)
        l1x = h64(f"{ls}{SEP2}{ld}{SEP2}{syscall}")
        l2 = h64(f"{l1}{SEP2}{st}")
        l2x = h64(f"{l1x}{SEP2}{st}")
        l3 = h64(f"{l2}{SEP2}{et}{SEP2}{amt}")
        l3x = h64(f"{l2x}{SEP2}{et}{SEP2}{amt}")
        for lv, digest in (("L1", l1), ("L1x", l1x), ("L2", l2),
                           ("L2x", l2x), ("L3", l3), ("L3x", l3x)):
            self.level[lv].append(pack(digest, gid))
        self.n_edges += 1
        self.by_group[gid] += 1
        self.ref_vertices[s[0]].add(s)
        self.ref_vertices[d[0]].add(d)
        if self.t_min is None or st < self.t_min:
            self.t_min = st
        if self.t_max is None or st > self.t_max:
            self.t_max = st
        # 样本按层级分开存：L1 的差集里混着“pid 口径”造成的假缺口，
        # 只有 L1x 的差集才是真实语义缺口，两层不能共用一份样本。
        if len(self.samples) < MAX_SAMPLES:
            self.samples.setdefault(pack(l1, gid), (s, d, syscall))
        if len(self.samples_x) < MAX_SAMPLES:
            self.samples_x.setdefault(pack(l1x, gid), (s, d, syscall))

    def sample_text(self, level: str, val: int) -> str:
        """把某层的差异样本值渲染成可读串（L1 用 samples，其余用 samples_x）。"""
        store = self.samples if level == "L1" else self.samples_x
        hit = store.get(val)
        if not hit:
            return f"<哈希 {val & ~GID_MASK:#018x}，超出样本上限>"
        s, d, sc = hit
        return f"{readable(s)} -[{sc}]-> {readable(d)}"


# ---------------------------------------------------------------- PG 侧
def pg_conn(db: str):
    if not os.environ.get("PG_PASSWORD"):
        raise SystemExit("缺少 PG_PASSWORD（写在 .env 或环境变量里，不要硬编码）")
    return psycopg2.connect(
        host=os.environ.get("PG_HOST", "localhost"), port=os.environ.get("PG_PORT", "5432"),
        user=os.environ.get("PG_USER", "postgres"), password=os.environ["PG_PASSWORD"], dbname=db,
    )


def load_pg(db: str, gid_of, side: Side, keep_synthetic: bool, pg_raw_names: bool) -> None:
    conn = pg_conn(db)
    # 只读事务：既保证服务端游标可用（named cursor 要求在事务内），
    # 又让整场景扫描看到同一个一致性快照。
    conn.set_session(readonly=True)
    ent: Dict[int, str] = {}
    with conn.cursor() as cur:
        cur.execute("SELECT id, pid, exename FROM process")
        for rid, pid, exe in cur:
            ent[rid] = proc_key(pid, exe)
        cur.execute("SELECT id, name FROM file")
        for rid, name in cur:
            ent[rid] = file_key(name)
        cur.execute("SELECT id, srcip, srcport, dstip, dstport FROM network")
        for rid, a, b, c, d in cur:
            ent[rid] = net_key(a, b, c, d)
        side.vertices["P"] = {k for k in ent.values() if k[0] == "P"}
        side.vertices["F"] = {k for k in ent.values() if k[0] == "F"}
        side.vertices["N"] = {k for k in ent.values() if k[0] == "N"}
        # 同一个 pid 在 PG 里对应多个 exename：旧导入器按线程记录进程的证据
        bypid: Dict[int, set] = {}
        for k in side.vertices["P"]:
            p = k.split(SEP)
            bypid.setdefault(int(p[1]), set()).add(p[2])
        side.extra["pg_pid_with_multiple_exename"] = sum(1 for v in bypid.values() if len(v) > 1)
        cur.execute("SELECT count(*) FROM processevent WHERE coalesce(is_synthetic_reverse,false)")
        side.notes["pg_processevent_合成反向边"] = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM networkevent WHERE coalesce(is_synthetic_reverse,false)")
        side.notes["pg_networkevent_合成反向边"] = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM file WHERE coalesce(name,'')=''")
        side.notes["pg_空路径File"] = int(cur.fetchone()[0])
    for table in ("fileevent", "networkevent", "processevent"):
        where = "" if keep_synthetic or table == "fileevent" else \
            " WHERE coalesce(is_synthetic_reverse, false) IS DISTINCT FROM true"
        # processevent 没有 amount 列（进程事件不携带字节数）
        amt_col = "0" if table == "processevent" else "coalesce(amount,0)"
        with conn.cursor(name=f"c_{table}") as cur:
            cur.itersize = CHUNK
            cur.execute(f"SELECT srcid, dstid, optype, starttime, endtime, {amt_col} "
                        f"FROM {table}{where}")
            while True:
                rows = cur.fetchmany(CHUNK)
                if not rows:
                    break
                for srcid, dstid, optype, st, et, amt in rows:
                    s, d = ent.get(srcid), ent.get(dstid)
                    if s is None or d is None:
                        side.notes["悬空端点"] += 1
                        continue
                    rel = SHAPE_TO_REL.get((s[0], d[0]))
                    if rel is None:
                        side.notes[f"非五类方向{s[0]}{d[0]}"] += 1
                        continue
                    raw = optype or ""
                    # 旧导入器存原始系统调用名，新解析器存家族基本名；
                    # 不归一会把 recvmsg/sendmsg/writev 当成 "PG 独有的边"。
                    name = raw if pg_raw_names else canonical_syscall(raw)
                    if name != raw:
                        side.notes["pg_名称归一行数"] += 1
                    side.add_edge(gid_of(rel, name), s, d, name,
                                  norm_int(st), norm_int(et), norm_int(amt))
    conn.commit()
    conn.close()


# ------------------------------------------------------------- Neo4j 侧
def _endpoint(m: dict, p: str) -> Optional[str]:
    if m.get(f"{p}_path") is not None:
        return file_key(m[f"{p}_path"])
    if m.get(f"{p}_net"):
        try:
            left, right = m[f"{p}_net"].split("->", 1)
            sip, sp = left.rsplit(":", 1)
            dip, dp = right.rsplit(":", 1)
            return net_key(sip, sp, dip, dp)
        except ValueError:
            return net_key("", 0, "", 0)
    if m.get(f"{p}_pid") is not None or m.get(f"{p}_exe") is not None:
        return proc_key(m.get(f"{p}_pid"), m.get(f"{p}_exe"))
    return None


_SELECT = {"Process": lambda a: f"{a}.pid AS {a}_pid, {a}.exepath AS {a}_exe",
           "File": lambda a: f"{a}.file_id AS {a}_path",
           "Network": lambda a: f"{a}.network_id AS {a}_net"}


def load_neo(uri_args, db: str, gid_of, side: Side) -> None:
    uri, auth = uri_args
    drv = GraphDatabase.driver(uri, auth=auth)
    with drv.session(database=db) as sess:
        for rec in sess.run("MATCH (n:Process) RETURN n.pid AS pid, n.name AS name, n.exepath AS exe"):
            side.vertices["P"].add(proc_key(rec["pid"], rec["exe"]))
        for rec in sess.run("MATCH (n:File) RETURN n.file_id AS p"):
            side.vertices["F"].add(file_key(rec["p"]))
        for rec in sess.run("MATCH (n:Network) RETURN n.lip AS a, n.lport AS b, "
                            "n.rip AS c, n.rport AS d"):
            side.vertices["N"].add(net_key(rec["a"], rec["b"], rec["c"], rec["d"]))
        names = sess.run("MATCH (n:Process) RETURN n.pid AS pid, collect(DISTINCT n.name) AS names")
        multi = sum(1 for r in names if len(r["names"]) > 1)
        side.extra["neo_pid_with_multiple_threadname_vertices"] = multi
        for rel, (sl, dl) in REL_ENDPOINTS.items():
            query = (f"MATCH (a:{sl})-[r:{rel}]->(b:{dl}) RETURN "
                     f"{_SELECT[sl]('a')}, {_SELECT[dl]('b')}, "
                     "r.syscall AS sc, r.starttime AS st, r.endtime AS et, r.bytes AS by")
            res = sess.run(query)
            # 同步 Result 是流式游标，逐条消费即不会在客户端堆积整批结果
            for r in res:
                m = dict(r)
                s, d = _endpoint(m, "a"), _endpoint(m, "b")
                if s is None or d is None:
                    side.notes["悬空端点"] += 1
                    continue
                sc = m["sc"] or ""
                side.add_edge(gid_of(rel, sc), s, d, sc,
                              norm_int(m["st"]), norm_int(m["et"]), norm_int(m["by"]))
    drv.close()


# ---------------------------------------------------------------- 差异
def diff_level(pa: array, na: array, samples_pg: Dict[int, str],
               samples_neo: Dict[int, str]) -> Dict[int, dict]:
    """按分组号做多重集差异，并记录"每个结构键重复多少次"的分布。

    重复次数分布用来区分两种完全不同的差异来源：
      A. 一侧把同一对实体的多次访问全量记录，另一侧只留了少量（copies 差很多）；
      B. 结构键本身不同（keys 差很多）。
    只有 A 会让"边数"看起来差几倍而结构几乎一致。
    """
    a, b = sorted(pa), sorted(na)
    out: Dict[int, dict] = {}
    la, lb = len(a), len(b)

    def slot(gid: int) -> dict:
        return out.setdefault(gid, {
            "common": 0, "only_pg": 0, "only_neo": 0, "s_pg": [], "s_neo": [],
            "keys_pg": 0, "keys_neo": 0, "max_pg": 0, "max_neo": 0,
            "multi_keys_pg": 0, "multi_keys_neo": 0})

    def take_sample(st: dict, bucket: str, val: int, samples: dict) -> None:
        """只给“有样本表”的层级（L1 / L1x）收集，且只存原始打包值；
        可读文本由上层按层级用各自的样本表渲染，避免两层样本互串。"""
        if not samples or len(st[bucket]) >= SAMPLES_PER_GROUP:
            return
        st[bucket].append(val)

    i = j = 0
    while i < la and j < lb:
        if a[i] == b[j]:
            v, k, m = a[i], i, j
            while k < la and a[k] == v:
                k += 1
            while m < lb and b[m] == v:
                m += 1
            ca, cb = k - i, m - j
            st = slot(v & GID_MASK)
            st["common"] += min(ca, cb)
            st["only_pg"] += max(0, ca - cb)
            st["only_neo"] += max(0, cb - ca)
            st["keys_pg"] += 1
            st["keys_neo"] += 1
            st["max_pg"] = max(st["max_pg"], ca)
            st["max_neo"] = max(st["max_neo"], cb)
            st["multi_keys_pg"] += ca > 1
            st["multi_keys_neo"] += cb > 1
            if ca > cb:
                take_sample(st, "s_pg", v, samples_pg)
            elif cb > ca:
                take_sample(st, "s_neo", v, samples_neo)
            i, j = k, m
        elif a[i] < b[j]:
            v, k = a[i], i
            while k < la and a[k] == v:
                k += 1
            st = slot(v & GID_MASK)
            st["only_pg"] += k - i
            st["keys_pg"] += 1
            st["max_pg"] = max(st["max_pg"], k - i)
            st["multi_keys_pg"] += (k - i) > 1
            take_sample(st, "s_pg", v, samples_pg)
            i = k
        else:
            v, m = b[j], j
            while m < lb and b[m] == v:
                m += 1
            st = slot(v & GID_MASK)
            st["only_neo"] += m - j
            st["keys_neo"] += 1
            st["max_neo"] = max(st["max_neo"], m - j)
            st["multi_keys_neo"] += (m - j) > 1
            take_sample(st, "s_neo", v, samples_neo)
            j = m
    while i < la:
        v, k = a[i], i
        while k < la and a[k] == v:
            k += 1
        st = slot(v & GID_MASK)
        st["only_pg"] += k - i
        st["keys_pg"] += 1
        st["max_pg"] = max(st["max_pg"], k - i)
        st["multi_keys_pg"] += (k - i) > 1
        take_sample(st, "s_pg", v, samples_pg)
        i = k
    while j < lb:
        v, m = b[j], j
        while m < lb and b[m] == v:
            m += 1
        st = slot(v & GID_MASK)
        st["only_neo"] += m - j
        st["keys_neo"] += 1
        st["max_neo"] = max(st["max_neo"], m - j)
        st["multi_keys_neo"] += (m - j) > 1
        take_sample(st, "s_neo", v, samples_neo)
        j = m
    return out


def set_overlap(pa: array, na: array) -> Dict[int, dict]:
    """S1：L1 去重取值集合（打包值本身就是 (哈希,组) 的唯一键）。"""
    sa, sb = set(pa), set(na)
    out: Dict[int, dict] = {}

    def slot(gid: int) -> dict:
        return out.setdefault(gid, {"both": 0, "only_pg": 0, "only_neo": 0})

    for x in sa:
        st = slot(x & GID_MASK)
        st["both" if x in sb else "only_pg"] += 1
    for x in sb - sa:
        slot(x & GID_MASK)["only_neo"] += 1
    return out


def is_degenerate_net(key: str) -> bool:
    """退化四元组：任一端地址为空或端口为 0（新解析器不为其建边）。"""
    if not key.startswith("N"):
        return False
    p = key.split(SEP)
    try:
        return (not p[1]) or (not p[3]) or int(p[2]) == 0 or int(p[4]) == 0
    except (IndexError, ValueError):
        return True


def describe_residual(side: "Side", other: "Side", vals: List[int], nmax: int = 3) -> List[dict]:
    """把 L1x 层“仅本侧”的样本按端点归属拆开：到底是哪个端点不在对方图里。"""
    out: List[dict] = []
    for v in vals[:nmax]:
        hit = side.samples_x.get(v)
        if not hit:
            out.append({"text": f"<哈希 {v & ~GID_MASK:#018x}，超出样本上限>",
                        "src_in_other": None, "dst_in_other": None, "degenerate": None,
                        "edge_missing": None})
            continue
        s, d, sc = hit
        src_in = s in other.vertices[s[0]]
        dst_in = d in other.vertices[d[0]]
        out.append({
            "text": f"{readable(s)} -[{sc}]-> {readable(d)}",
            "src_kind": {"P": "Process", "F": "File", "N": "Network"}[s[0]],
            "dst_kind": {"P": "Process", "F": "File", "N": "Network"}[d[0]],
            "src_in_other": src_in, "dst_in_other": dst_in,
            "degenerate": is_degenerate_net(s) or is_degenerate_net(d),
            # 两端顶点都在、边却不存在：才是真正需要解释的“丢边”
            "edge_missing": bool(src_in and dst_in),
        })
    return out


def compare(pg_db: str, neo_db: str, uri_args, keep_synthetic: bool, pg_raw_names: bool) -> Dict:
    gids: Dict[Tuple[str, str], int] = {}
    gid_name: List[Tuple[str, str]] = []

    def gid_of(rel: str, syscall: str) -> int:
        key = (rel, syscall)
        g = gids.get(key)
        if g is None:
            g = len(gid_name)
            gids[key] = g
            gid_name.append(key)
        return g

    t0 = time.monotonic()
    pg, neo = Side(), Side()
    load_pg(pg_db, gid_of, pg, keep_synthetic, pg_raw_names)
    load_neo(uri_args, neo_db, gid_of, neo)

    vres = {}
    for k, label in (("P", "Process"), ("F", "File"), ("N", "Network")):
        a, b = pg.vertices[k], neo.vertices[k]
        ra = pg.ref_vertices[k]
        only_pg = a - b
        unreferenced = a - ra        # PG 登记但从未被任何事件引用（新图不写入无边顶点）
        vres[label] = {
            "pg_all": len(a), "neo_all": len(b), "both_all": len(a & b),
            "only_pg": len(only_pg), "only_neo": len(b - a),
            "pg_referenced": len(ra), "referenced_in_neo": len(ra & b),
            # “仅 PG”里有多少其实是 PG 自己登记但无事件的顶点（必然不出现），
            # 剩下的是真被 PG 事件用过、却没在新图里出现的实体。
            "only_pg_unreferenced": len(only_pg & unreferenced),
            "only_pg_but_referenced": len(only_pg - unreferenced),
            "sample_only_pg": [readable(x) for x in sorted(only_pg)[:SAMPLES_PER_GROUP]],
            "sample_only_neo": [readable(x) for x in sorted(b - a)[:SAMPLES_PER_GROUP]],
        }
    pgp = {int(x.split(SEP)[1]) for x in pg.vertices["P"]}
    nep = {int(x.split(SEP)[1]) for x in neo.vertices["P"]}
    vres["Process_pid_only"] = {"pg": len(pgp), "neo": len(nep), "both": len(pgp & nep),
                                "only_pg": len(pgp - nep), "only_neo": len(nep - pgp)}

    per_level = {}
    for lv in LEVELS:
        gate_pg = pg.samples if lv == "L1" else (pg.samples_x if lv == "L1x" else {})
        gate_neo = neo.samples if lv == "L1" else (neo.samples_x if lv == "L1x" else {})
        per_level[lv] = diff_level(pg.level[lv], neo.level[lv], gate_pg, gate_neo)
    s1 = set_overlap(pg.level["L1"], neo.level["L1"])

    groups = []
    # 注意：gid 按首次出现顺序分配，enumerate 必须按 gid_name 原序走（不能先排序，
    # 否则组号与统计结果错位），展示顺序最后再排。
    for g, (rel, syscall) in enumerate(gid_name):
        empty = {"common": 0, "only_pg": 0, "only_neo": 0, "s_pg": [], "s_neo": [],
                 "keys_pg": 0, "keys_neo": 0, "max_pg": 0, "max_neo": 0,
                 "multi_keys_pg": 0, "multi_keys_neo": 0}
        rows = {lv: per_level[lv].get(g, dict(empty)) for lv in LEVELS}
        rows["S1"] = s1.get(g, {"both": 0, "only_pg": 0, "only_neo": 0})
        # 差异样本按层级各自渲染（L1 用 samples，L1x 用 samples_x）
        rows["L1"]["s_pg"] = [pg.sample_text("L1", v) for v in rows["L1"]["s_pg"]]
        rows["L1"]["s_neo"] = [neo.sample_text("L1", v) for v in rows["L1"]["s_neo"]]
        resid = describe_residual(pg, neo, rows["L1x"]["s_pg"]) if rows["L1x"]["only_pg"] else []
        rows["L1x"]["s_pg"] = [x["text"] for x in resid]
        rows["L1x"]["s_neo"] = [neo.sample_text("L1x", v) for v in rows["L1x"]["s_neo"]]
        groups.append({"rel": rel, "syscall": syscall,
                       "pg_n": pg.by_group.get(g, 0), "neo_n": neo.by_group.get(g, 0),
                       "residual_x": resid,
                       **rows})
    groups.sort(key=lambda x: (x["rel"], -max(x["pg_n"], x["neo_n"])))
    totals = {lv: {k: sum(r[lv][k] for r in groups) for k in ("common", "only_pg", "only_neo")}
              for lv in LEVELS}
    by_rel = {rel: {"pg": 0, "neo": 0} for rel in REL_ENDPOINTS}
    for g, (rel, _syscall) in enumerate(gid_name):
        if rel in by_rel:
            by_rel[rel]["pg"] += pg.by_group.get(g, 0)
            by_rel[rel]["neo"] += neo.by_group.get(g, 0)
    return {
        "pg_db": pg_db, "neo_db": neo_db,
        "edges": {"pg": pg.n_edges, "neo": neo.n_edges},
        "time_span": {"pg": [pg.t_min, pg.t_max], "neo": [neo.t_min, neo.t_max]},
        "vertices": vres, "groups": groups, "totals": totals,
        "notes": {"pg": dict(pg.notes), "neo": dict(neo.notes)},
        "extra": {**pg.extra, **neo.extra},
        "by_rel": by_rel,
        "elapsed_s": round(time.monotonic() - t0, 1),
    }


# ---------------------------------------------------------------- 输出
def fmt(v) -> str:
    return "∅" if v is None else f"{v:,}"


def render(name: str, r: Dict) -> str:
    """把一个场景的对比结果渲染成 Markdown 小节（无转义字面量，行分隔用 NL）。"""
    L = [f"## 场景 {name}", ""]
    L.append(f"- PG `{r['pg_db']}` vs Neo4j `{r['neo_db']}`，用时 {r['elapsed_s']}s")
    L.append(f"- 边总数 PG {fmt(r['edges']['pg'])} vs Neo4j {fmt(r['edges']['neo'])}")
    ts = r["time_span"]
    L.append(f"- 事件时间跨度(ns) PG [{fmt(ts['pg'][0])}, {fmt(ts['pg'][1])}] "
               f"vs Neo4j [{fmt(ts['neo'][0])}, {fmt(ts['neo'][1])}]")
    L.append(f"- 数据质量注记 PG `{r['notes']['pg']}` / Neo4j `{r['notes']['neo']}`")
    L.append(f"- 其他 `{r['extra']}`")
    L += ["", "### 全场景边差异合计", "", "| 粒度 | 一致(common) | 仅 PG | 仅 Neo4j |", "|---|---|---|---|"]
    for lv, desc in (("L1", "L1 结构 (src,dst,syscall)"),
                     ("L1x", "L1x 结构，进程端点忽略 pid（只按可执行路径对齐）"),
                     ("L2", "L2 结构 + starttime"),
                     ("L2x", "L2x 结构 + starttime，进程端点忽略 pid"),
                     ("L3", "L3 结构 + starttime + endtime + bytes"),
                     ("L3x", "L3x 同 L3，进程端点忽略 pid")):
        t = r["totals"][lv]
        L.append(f"| {desc} | {fmt(t['common'])} | {fmt(t['only_pg'])} | {fmt(t['only_neo'])} |")
    L += ["", "### 顶点", "",
          "| 类型 | PG全部 | Neo4j | 交集 | 仅PG | 其中PG未引用 | 仅PG且被引用(真缺) | 仅Neo4j | PG被事件引用数 | 其中在Neo4j存在 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for label in ("Process", "File", "Network"):
        v = r["vertices"][label]
        L.append(f"| {label} | {v['pg_all']} | {v['neo_all']} | {v['both_all']} | {v['only_pg']} "
                 f"| {v['only_pg_unreferenced']} | {v['only_pg_but_referenced']} | {v['only_neo']} "
                 f"| {v['pg_referenced']} | {v['referenced_in_neo']} |")
    po = r["vertices"]["Process_pid_only"]
    L.append(f"| Process(只比 pid) | {po['pg']} | {po['neo']} | {po['both']} | {po['only_pg']} "
             f"| | | {po['only_neo']} | | |")
    for label in ("Process", "File", "Network"):
        v = r["vertices"][label]
        if v["sample_only_pg"]:
            L.append(f"- 仅 PG 的 {label} 例：`" + SEPSTR.join(v["sample_only_pg"]) + "`")
        if v["sample_only_neo"]:
            L.append(f"- 仅 Neo4j 的 {label} 例：`" + SEPSTR.join(v["sample_only_neo"]) + "`")
    L += ["", "### 表 A：结构层（边的存在性）", "",
          "| 方向 | syscall | PG边 | Neo边 | PG结构键 | Neo结构键 | L1仅PG | L1仅Neo | L1x仅PG | L1x仅Neo |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for g in r["groups"]:
        L.append(f"| {g['rel']} | {g['syscall']} | {fmt(g['pg_n'])} | {fmt(g['neo_n'])} "
                 f"| {fmt(g['L1']['keys_pg'])} | {fmt(g['L1']['keys_neo'])} "
                 f"| {fmt(g['L1']['only_pg'])} | {fmt(g['L1']['only_neo'])} "
                 f"| {fmt(g['L1x']['only_pg'])} | {fmt(g['L1x']['only_neo'])} |")
    L += ["", "### 表 B：粒度层（重复次数与时间/字节口径）", "",
          "| 方向 | syscall | S1去重仅PG | S1去重仅Neo | L2仅PG | L2仅Neo | L2x仅PG | L2x仅Neo "
          "| L3仅PG | L3仅Neo | L3x仅PG | L3x仅Neo |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for g in r["groups"]:
        L.append(f"| {g['rel']} | {g['syscall']} | {fmt(g['S1']['only_pg'])} | {fmt(g['S1']['only_neo'])} "
                 f"| {fmt(g['L2']['only_pg'])} | {fmt(g['L2']['only_neo'])} "
                 f"| {fmt(g['L2x']['only_pg'])} | {fmt(g['L2x']['only_neo'])} "
                 f"| {fmt(g['L3']['only_pg'])} | {fmt(g['L3']['only_neo'])} "
                 f"| {fmt(g['L3x']['only_pg'])} | {fmt(g['L3x']['only_neo'])} |")
    L += ["", "### 表 C：同一结构键上的重复次数分布（是谁在聚合、谁在全量记录）", "",
          "| 方向 | syscall | PG边 | Neo边 | PG结构键 | Neo结构键 | PG同键最大重复 | Neo同键最大重复 "
          "| PG重复键数 | Neo重复键数 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for g in r["groups"]:
        L.append(f"| {g['rel']} | {g['syscall']} | {fmt(g['pg_n'])} | {fmt(g['neo_n'])} "
                 f"| {fmt(g['L1']['keys_pg'])} | {fmt(g['L1']['keys_neo'])} "
                 f"| {fmt(g['L1']['max_pg'])} | {fmt(g['L1']['max_neo'])} "
                 f"| {fmt(g['L1']['multi_keys_pg'])} | {fmt(g['L1']['multi_keys_neo'])} |")
    resid = [g for g in r["groups"] if g["L1x"]["only_pg"]]
    if resid:
        L += ["", "### 真实缺口（L1x 仅PG）样本与端点归属", ""]
        for g in resid:
            L.append(f"- `{g['rel']}/{g['syscall']}` {g['L1x']['only_pg']} 条：")
            for x in g.get("residual_x", []):
                tags = []
                if x.get("degenerate"):
                    tags.append("退化四元组")
                if x.get("src_in_other") is False:
                    tags.append(f"{x.get('src_kind')} 端点不在 Neo4j")
                if x.get("dst_in_other") is False:
                    tags.append(f"{x.get('dst_kind')} 端点不在 Neo4j")
                if x.get("edge_missing"):
                    tags.append("两端都在但边缺失")
                L.append(f" - `{x['text']}` （{'，'.join(tags) if tags else '端点均在'}）")
    diffs = [g for g in r["groups"] if g["L1"]["only_pg"] or g["L1"]["only_neo"]]
    if diffs:
        L += ["", "### 结构级(L1)差异样本（含进程 pid 口径造成的假缺口）", ""]
        for g in diffs:
            if g["L1"]["only_pg"]:
                L.append(f"- `{g['rel']}/{g['syscall']}` 仅 PG {fmt(g['L1']['only_pg'])} 条：")
                L += [f" - `{s}`" for s in g["L1"]["s_pg"]]
            if g["L1"]["only_neo"]:
                L.append(f"- `{g['rel']}/{g['syscall']}` 仅 Neo4j {fmt(g['L1']['only_neo'])} 条：")
                L += [f" - `{s}`" for s in g["L1"]["s_neo"]]
    return NL.join(L) + NL


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True, help="all 或场景序号（1-6）")
    ap.add_argument("--input-dir", default=str(REPO_ROOT / "input/sysdig"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--keep-synthetic", action="store_true",
                    help="PG 侧保留 is_synthetic_reverse 的合成反向边（默认剔除）")
    ap.add_argument("--pg-raw-names", action="store_true",
                    help="PG 侧不做系统调用家族名归一（默认按解析器的 CANONICAL_SYSCALL_MAP 归一）")
    args = ap.parse_args()

    files = sorted(Path(args.input_dir).glob("*.jsonl"), key=lambda p: p.name)
    todo = files if args.scenario == "all" else [
        f for f in files if f.stem.split("_")[0] == args.scenario]
    if not todo:
        print(f"找不到场景 {args.scenario}", file=sys.stderr)
        return 1
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    uri_args = (os.environ["NEO4J_URI"], (os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]))
    allres = []
    for f in todo:
        stem = f.stem
        neo_db = DB_PREFIX + stem.lower().replace("_", "-")
        print(f"=== {stem}: PG {stem} vs Neo4j {neo_db}", flush=True)
        r = compare(stem, neo_db, uri_args, args.keep_synthetic, args.pg_raw_names)
        r["scenario"] = stem
        allres.append(r)
        (out / f"{stem}.json").write_text(
            json.dumps(r, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
        (out / f"{stem}.md").write_text(render(stem, r), encoding="utf-8")
        t = r["totals"]
        print(f"  edges pg={r['edges']['pg']:,} neo={r['edges']['neo']:,} | "
              f"L1 仅PG={t['L1']['only_pg']:,} 仅Neo={t['L1']['only_neo']:,} | "
              f"L1x(忽略pid) 仅PG={t['L1x']['only_pg']:,} 仅Neo={t['L1x']['only_neo']:,} | "
              f"L2x 仅PG={t['L2x']['only_pg']:,} 仅Neo={t['L2x']['only_neo']:,} | "
              f"L3x 仅PG={t['L3x']['only_pg']:,} 仅Neo={t['L3x']['only_neo']:,} "
              f"| {r['elapsed_s']}s -> {out / (stem + '.md')}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
