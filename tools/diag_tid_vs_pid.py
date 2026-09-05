#!/usr/bin/env python3
"""诊断：验证 compare_pg_neo4j 差异是否全部来自 PG(tid) vs Neo4j(pid)。

方法：
1. 宽松对比：把边的 Process 端点匿名化为固定占位符，只保留
   (File/Network 键, syscall, starttime, endtime, amount) 参与多重集比较。
   若宽松后差异为 0，则原始差异只能由进程身份（tid vs pid）造成。
2. p2p 边验证：检查 Neo4j 的 46 条 p2p 是否都在 PG 中存在，
   且 PG 多出的 46 条是否恰好是它们的反向（src/dst 互换、其余字段相同）。

用法: python tools/diag_tid_vs_pid.py [--pg-db 1_Multi_Stage_Data_Exfiltration_new]
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sysdig-parser"))

import compare_pg_neo4j as cmp  # noqa: E402  (import 时会 load_dotenv)

_PROC_PLACEHOLDER = ("Proc", "<anon>")


def relax(edge):
    """把 Process 端点替换为占位符（tid/pid 不参与比较）。"""
    s, t, syscall, st, et, amount = edge
    if s[0] == "Proc":
        s = _PROC_PLACEHOLDER
    if t[0] == "Proc":
        t = _PROC_PLACEHOLDER
    return (s, t, syscall, st, et, amount)


def reverse(edge):
    s, t, syscall, st, et, amount = edge
    return (t, s, syscall, st, et, amount)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pg-db", default="1_Multi_Stage_Data_Exfiltration_new")
    args = ap.parse_args()

    pg = cmp.load_pg(args.pg_db)
    neo = cmp.load_neo4j()

    print(f"PG({args.pg_db}) vs Neo4j —— 宽松(进程匿名)对比")
    for name in ("file_edges", "net_edges", "proc_edges"):
        a = [relax(e) for e in pg[name]]
        b = [relax(e) for e in neo[name]]
        ca, cb = Counter(a), Counter(b)
        only_pg, only_neo = ca - cb, cb - ca
        print(
            f"{name}: PG={len(a)} NEO4J={len(b)} "
            f"onlyPG={sum(only_pg.values())} onlyNeo={sum(only_neo.values())}"
        )
        for label, side in (("onlyPG", only_pg), ("onlyNeo", only_neo)):
            if side:
                print(f"  {label} sample: {list(side.elements())[:3]}")

    # --- p2p：PG 多出的边是否恰为 Neo4j 边的反向 ---
    pg_p2p = Counter(pg["proc_edges"])
    neo_p2p = Counter(neo["proc_edges"])
    only_pg = pg_p2p - neo_p2p
    only_neo = neo_p2p - pg_p2p
    neo_rev = Counter(reverse(e) for e in neo["proc_edges"])
    covered = only_pg - neo_rev  # 反向后仍多出的（不应存在）
    print(
        f"\np2p: onlyPG={sum(only_pg.values())} onlyNeo={sum(only_neo.values())} "
        f"onlyPG-反向后仍多出={sum(covered.values())}"
    )
    print("=> PG 多出的 p2p 是否全部为合成反向边:",
          "是" if not covered and not only_neo else "否")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
