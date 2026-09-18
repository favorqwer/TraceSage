#!/usr/bin/env python3
"""日志侧 vs 图侧 覆盖度缺口报告。

回答的问题：**原始日志里有的信息，Neo4j 库里缺了哪些？**

三层对照：
    日志侧清单   tools/log_inventory.py 产出（raw JSONL 的结构化穷举）
    图侧清单     tools/db_inventory.py 产出（labels/rel/属性/syscall）
    契约         tools/coverage_spec.json（当前解析器声称消费什么）

事件类型的"是否已建模"不在契约里手写，而是运行时调
`handlers.build_handlers()` 反查注册表得到，避免清单与代码脱节。
唯一的例外是契约里的 `declared_no_edge_events`：这些事件解析器仍注册，但已决策
不建边（当前只有 `fcntl`，理由与证据写在契约字段里），因此既不算"已建模（建边）"、
也不进哨兵，而是归入"内部支撑（不建边）"并在报告 A1c 单列。

用法：
    python tools/coverage_gap.py \
        --log output/inventory/1_Multi_Stage_Data_Exfiltration.log-inventory.json \
        --database tracesage-1-multi-stage-data-exfiltration \
        --out-dir output/coverage
    # 也可复用已生成的图侧清单，避免重复查库
    python tools/coverage_gap.py --log <log.json> --db-inventory <db.json> --out-dir out/
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sysdig-parser"))
sys.path.insert(0, str(ROOT / "tools"))

from parsers.dispatch.handlers import _OPEN_NO_EDGE_EVENTS, build_handlers  # noqa: E402
from parsers.dispatch.meta_config import canonical_syscall  # noqa: E402

NL = chr(10)


# ---------------------------------------------------------------- 建模表反查
class _DummyCtx:
    """build_handlers 只在闭包内用 ctx，构建期不调用任何方法。"""

    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            return None
        return _noop


def modeled_events(log_event_types: List[str]) -> Dict[str, str]:
    """从注册表反查：日志里出现的 evt.type 中哪些已注册 handler。

    事件名直接读 `Fingerprint.event`（解析器构造时已知的原名），不再从
    fingerprint 字符串反推：指纹是「事件名 + 实体类名 + 实体类名」无分隔符
    拼接，用后缀正则反推会把 `send`/`recv` 这类已注册名的真前缀误判为
    已建模（`sendtoFileEntitynull` 的后缀 `toFileEntitynull` 也匹配宽松正则），
    把「未建模」错报成「可疑丢边」。
    """
    registered = {fp.event for fp in build_handlers(_DummyCtx())}
    return {
        et: canonical_syscall(et)
        for et in log_event_types
        if et in registered
    }


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def display_path(path: str) -> str:
    """产物里记录的路径：项目内文件统一写成相对路径（POSIX 风格）。

    否则跨机器重跑同一命令会因绝对路径前缀（如本机工作区根目录）不同而使产物
    无法逐字比对（内容其实相同）。项目外路径原样返回。
    """
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except (ValueError, OSError):
        return str(path)


def fmt(n) -> str:
    return "—" if n is None else f"{n:,}"


# ---------------------------------------------------------------- 报告渲染
def _suspected_payload_key(key: str) -> bool:
    """是否疑似来自多 token 取值内的伪字段（env/argv 里的 NAME=value）。

    sysdig 的字段名只用小写字母/数字/下划线；实测噪声键形如
    `LOG.WINDOWPATH`、`Reports.SNAP_EUID`、`PATH`、`z.`，均含大写、`.` 或 `:`。
    判据透明且不改写原始统计——可疑键单独列，不混入“未消费参数名”。
    """
    return ("." in key) or (":" in key) or any(c.isupper() for c in key)


def build_report(log: dict, db: dict, spec: dict, log_path: str, db_name: str) -> dict:
    events = log["events"]
    log_event_types = sorted(
        events, key=lambda k: -(events[k]["enter"] + events[k]["exit"]))
    modeled = modeled_events(log_event_types)
    no_edge = set(_OPEN_NO_EDGE_EVENTS)
    support = set(spec.get("support_events", []))
    declared_no_edge = spec.get("declared_no_edge_events", {})
    # 已决策不建边：注册表里仍有 handler，但不期望它产边，故从"已建模"里摘出
    for et in declared_no_edge:
        modeled.pop(et, None)

    # 图侧 syscall 计数（跨关系类型合计）
    graph_syscalls: Counter = Counter()
    for rel, info in db["relationships"].items():
        for sc, c in info["syscalls"].items():
            graph_syscalls[sc] += c
    graph_syscall_keys = set(graph_syscalls)

    event_rows = []
    for et in log_event_types:
        ev = events[et]
        exit_n = ev["exit"]
        if et in modeled:
            status = "已建模（不建边）" if et in no_edge else "已建模（建边）"
            canon = modeled[et]
        elif et in support or et in declared_no_edge:
            status = "内部支撑（不建边）"
            canon = ""
        else:
            status = "未建模"
            canon = ""
        gcount = graph_syscalls.get(canon, 0) if canon else None
        event_rows.append({
            "evt_type": et, "enter": ev["enter"], "exit": exit_n,
            "status": status, "canonical": canon,
            "graph_edges": gcount,
            "declared_no_edge": declared_no_edge.get(et),
        })

    # 哨兵：声明建模、日志有退出记录，但图里 0 条边。按下述原因分类：
    #   设计上不建边 / 端点种类未建模 / 端点注记不完整 / 可疑
    no_edge_rows = []
    fdtype_map = spec.get("fdtype_map", {})
    prec = spec.get("event_precondition", {})

    def _yields(ft: str, form: str, kind: str) -> bool:
        label = fdtype_map.get(ft)
        net = label == "Network" and form == "quad"
        fil = label == "File" and (form == "path" or ft == "p")
        if kind == "network":
            return net
        if kind == "file":
            return fil
        if kind == "any":
            return net or fil
        return False

    for r in event_rows:
        if r["graph_edges"] != 0:
            continue
        et, canon = r["evt_type"], r["canonical"]
        if et not in modeled:
            continue
        combos = []
        for c in events[et].get("fd_forms", {}):
            ft, _, form = c.partition("/")
            combos.append((ft, form))
        kind = prec.get(canon) or prec.get(et) or "any"
        if et in no_edge:
            reason = "设计上不建边"
        elif kind == "none":
            reason = "可疑：该事件应无需 fd 端点却 0 条边"
        elif any(_yields(ft, form, kind) for ft, form in combos):
            reason = "可疑：所需端点齐全却 0 条边"
        elif any(fdtype_map.get(ft) is not None for ft, _ in combos):
            reason = "端点注记不完整（无四元组/无路径）"
        elif combos:
            reason = "所需端点种类未建模"
        else:
            reason = "无 fd 端点（端点来自 args 路径字段）"
        r["zero_edge_reason"] = reason
        no_edge_rows.append(r)
    sentinel_missing = [r for r in no_edge_rows if r["zero_edge_reason"].startswith("可疑")]
    # 哨兵 2：图里的 syscall 值，日志里没有任何事件归一得到它
    log_canon = {canonical_syscall(et) for et in log_event_types}
    graph_orphan = sorted(graph_syscall_keys - log_canon)

    # 参数名
    arg_rows = []
    arg_map = spec.get("argkey_map", {})
    exec_meta = set(spec.get("exec_meta_args", []))
    # 反查：每个参数名出现在哪些事件类型里
    key_events: Dict[str, set] = defaultdict(set)
    for et, ev in log["events"].items():
        for k in ev.get("arg_keys", {}):
            key_events[k].add(et)

    def _suspect(key: str) -> bool:
        if _suspected_payload_key(key):
            return True
        # 只出现在 execve/clone 记录里、又不是 sysdig 进程元信息字段的，
        # 必然是 env=/argv 空格分隔区里的 NAME=value（实测：found/prefix/
        # rel/snap/ts/sep/indefault）
        evs = key_events.get(key, set())
        return bool(evs) and evs <= {"execve", "clone"} and key not in exec_meta

    for k, v in sorted(log["arg_keys"].items(),
                       key=lambda kv: -kv[1].get("freq", 0)):
        arg_rows.append({
            "arg_key": k, "freq": v.get("freq", 0),
            "enter": v.get("enter", 0), "exit": v.get("exit", 0),
            "forms": v.get("forms", {}), "annotations": v.get("annotations", {}),
            "mapped": arg_map.get(k),
            "suspected_payload_key": _suspect(k),
            "source_events": sorted(key_events.get(k, set())),
        })
    real_args = [a for a in arg_rows if not a["suspected_payload_key"]]
    unmapped_args = [a for a in real_args if not a["mapped"]]

    # fd 类型符
    fd_rows = []
    fd_labels = spec.get("fdtype_label", {})
    fd_partial = spec.get("fdtype_partial", {})
    fd_union = Counter()
    for key, st in log["fd_keys"].items():
        for t, c in st["types"].items():
            fd_union[t] += c
    for t, c in sorted(fd_union.items(), key=lambda kv: -kv[1]):
        fd_rows.append({"type": t, "count": c, "mapped": fdtype_map.get(t),
                        "partial": fd_partial.get(t),
                        "label": fd_labels.get(t, "")})

    # JSONL 键
    json_rows = []
    jmap = spec.get("jsonkey_map", {})
    for k, v in log["jsonl_keys"].items():
        json_rows.append({"key": k, "count": v["count"], "null": v["null"],
                          "empty": v["empty"], "distinct": v["distinct"],
                          "mapped": jmap.get(k)})

    graph_props = set(db["meta"]["property_keys"])
    return {
        "meta": {
            "log_inventory": display_path(log_path),
            "database": db_name,
            "log_valid_lines": log["completeness"]["valid"],
            "log_events": len(log_event_types),
            "log_arg_keys": len(real_args),
            "log_arg_keys_suspected_payload": len(arg_rows) - len(real_args),
            "log_fd_keys": len(log["fd_keys"]),
            "graph_vertices": {k: v["count"] for k, v in db["vertices"].items()},
            "graph_edges": {k: v["count"] for k, v in db["relationships"].items()},
            "graph_property_keys": sorted(graph_props),
        },
        "events": event_rows,
        "declared_no_edge_events": [
            {"evt_type": et, "reason": reason}
            for et, reason in sorted(declared_no_edge.items())
        ],
        "sentinel_modeled_but_zero_edges": sentinel_missing,
        "zero_edge_rows": no_edge_rows,
        "sentinel_graph_syscall_not_in_log": graph_orphan,
        "arg_keys": arg_rows,
        "fd_types": fd_rows,
        "jsonl_keys": json_rows,
        "graph_syscalls": dict(sorted(graph_syscalls.items())),
        "db_inventory": db,
        "log_inventory_ref": display_path(log_path),
    }


def render(r: dict) -> str:
    L: List[str] = []
    m = r["meta"]
    L.append(f"# 日志 vs 图 覆盖度缺口报告 — `{m['database']}`")
    L.append("")
    L.append(f"- 日志清单：`{m['log_inventory']}`（有效行 {fmt(m['log_valid_lines'])}）")
    L.append(f"- 图规模：顶点 `{m['graph_vertices']}`，边 `{m['graph_edges']}`")
    L.append(f"- 日志侧：事件类型 {m['log_events']} 个、参数名 {m['log_arg_keys']} 个、"
             f"fd 键 {m['log_fd_keys']} 个")
    L.append("")

    # A. 事件类型
    mod = [e for e in r["events"] if e["status"].startswith("已建模")]
    unm = [e for e in r["events"] if e["status"] == "未建模"]
    sup = [e for e in r["events"] if e["status"].startswith("内部支撑")]
    L += ["## A. 事件类型覆盖", "",
          f"- 已建模 {len(mod)} 个，未建模 {len(unm)} 个，内部支撑 {len(sup)} 个", "",
          "### A1. 哨兵：可疑丢边（声明已建模、应有端点、却 0 条边）", ""]
    if r["sentinel_modeled_but_zero_edges"]:
        L += ["| evt.type | 退出记录 | 归一 syscall | 图中边数 | 原因 |", "|---|---|---|---|---|"]
        for e in r["sentinel_modeled_but_zero_edges"]:
            L.append(f"| `{e['evt_type']}` | {fmt(e['exit'])} | `{e['canonical']}` | 0 "
                     f"| {e['zero_edge_reason']} |")
    else:
        L.append("（无）")
    L += ["", "### A1b. 已建模但 0 条边（附原因，供确认是否预期）", "",
          "| evt.type | 退出记录 | 归一 syscall | 原因 |", "|---|---|---|---|"]
    for e in r.get("zero_edge_rows", []):
        L.append(f"| `{e['evt_type']}` | {fmt(e['exit'])} | `{e['canonical']}` "
                 f"| {e['zero_edge_reason']} |")
    dec = r.get("declared_no_edge_events", [])
    if dec:
        L += ["", "### A1c. 已决策不建边（口径收口，不算缺口、不计入哨兵）", "",
              "| evt.type | 决定与依据 |", "|---|---|"]
        for d in dec:
            L.append(f"| `{d['evt_type']}` | {d['reason']} |")
    L += ["", "### A2. 图里的 syscall 在日志里找不到来源", ""]
    if r["sentinel_graph_syscall_not_in_log"]:
        for x in r["sentinel_graph_syscall_not_in_log"]:
            L.append(f"- `{x}`（图中 {fmt(r['graph_syscalls'].get(x))} 条）")
    else:
        L.append("（无）")
    L += ["", "### A3. 未建模事件类型（按记录数降序）", "",
          "| evt.type | 进入 | 退出 | 累计 |", "|---|---|---|---|"]
    for e in sorted(unm, key=lambda x: -(x["enter"] + x["exit"])):
        L.append(f"| `{e['evt_type']}` | {fmt(e['enter'])} | {fmt(e['exit'])} "
                 f"| {fmt(e['enter'] + e['exit'])} |")
    L += ["", "### A4. 已建模事件类型", "",
          "| evt.type | 进入 | 退出 | 归一 syscall | 图中该 syscall 边数 |", "|---|---|---|---|---|"]
    for e in mod:
        L.append(f"| `{e['evt_type']}` | {fmt(e['enter'])} | {fmt(e['exit'])} "
                 f"| `{e['canonical']}` | {fmt(e['graph_edges'])} |")

    # B. 参数名
    unmapped = [a for a in r["arg_keys"]
                if not a["mapped"] and not a["suspected_payload_key"]]
    suspected = [a for a in r["arg_keys"] if a["suspected_payload_key"]]
    real_n = len(r["arg_keys"]) - len(suspected)
    L += ["", "## B. evt.args 参数名覆盖", "",
          f"- 日志出现 {len(r['arg_keys'])} 个参数名（真实字段 {real_n} 个，"
          f"疑似多 token 取值噪声 {len(suspected)} 个），契约已消费 "
          f"{real_n - len(unmapped)} 个，未消费 {len(unmapped)} 个", "",
          "### B1. 未消费参数名（按出现次数降序）", "",
          "| 参数 | 出现次数 | 退出记录 | 主要形态 | 主要注解 |", "|---|---|---|---|---|"]
    for a in unmapped[:120]:
        forms = ", ".join(f"{k}:{v}" for k, v in list(a["forms"].items())[:3])
        anns = ", ".join(f"{k}:{v}" for k, v in list(a["annotations"].items())[:3])
        L.append(f"| `{a['arg_key']}` | {fmt(a['freq'])} | {fmt(a['exit'])} "
                 f"| {forms or '—'} | {anns or '—'} |")
    if suspected:
        L += ["", "### B1b. 疑似多 token 取值噪声（env/argv 里的 NAME=value，不计入未消费）", "",
              "| 参数 | 出现次数 |", "|---|---|"]
        for a in suspected:
            L.append(f"| `{a['arg_key']}` | {fmt(a['freq'])} |")
    L += ["", "### B2. 已消费参数名", "",
          "| 参数 | 出现次数 | 用途 |", "|---|---|---|"]
    for a in r["arg_keys"]:
        if a["mapped"]:
            L.append(f"| `{a['arg_key']}` | {fmt(a['freq'])} | {a['mapped']} |")

    # C. fd 类型
    L += ["", "## C. 边端点实体种类（fd 类型符）", "",
          "| 类型符 | 含义 | 出现次数 | 映射 | 状态 |", "|---|---|---|---|---|"]
    for f in r["fd_types"]:
        if f["mapped"]:
            st, mp = "已建模", f["mapped"]
        elif f.get("partial"):
            st, mp = "部分建模", f["partial"]
        else:
            st, mp = "未建模", "—"
        L.append(f"| `<{f['type']}>` | {f.get('label') or '—'} | {fmt(f['count'])} "
                 f"| {mp} | {st} |")

    # D. JSONL 键 -> 图属性
    L += ["", "## D. JSONL 顶层键覆盖", "",
          "| JSONL 键 | 出现 | null | 空串 | distinct | 映射 |", "|---|---|---|---|---|---|"]
    for j in r["jsonl_keys"]:
        L.append(f"| `{j['key']}` | {fmt(j['count'])} | {fmt(j['null'])} "
                 f"| {fmt(j['empty'])} | {fmt(j['distinct'])} | {j['mapped'] or '—'} |")

    # E. 图侧属性填充
    L += ["", "## E. 图侧属性填充（参考）", ""]
    for lab, info in sorted(r["db_inventory"]["vertices"].items()):
        L.append(f"- `{lab}` {fmt(info['count'])} 个顶点，属性填充："
                 + ", ".join(f"{k}={fmt(v)}" for k, v in info["properties"].items()))
    for rel, info in sorted(r["db_inventory"]["relationships"].items()):
        L.append(f"- `{rel}` {fmt(info['count'])} 条边，属性填充："
                 + ", ".join(f"{k}={fmt(v)}" for k, v in info["properties"].items()))

    # F. 完整性
    c = r["db_inventory"]["event_ids"]
    lc = r["meta"]
    L += ["", "## F. 完整性注记", "",
          f"- 图 `event_id`：min={fmt(c['min'])} max={fmt(c['max'])} count={fmt(c['count'])} "
          f"null={fmt(c['null'])} 重复={fmt(c['duplicates'])} 缺口段={fmt(c['gap_segments'])}",
          f"- 日志清单文件：`{lc['log_inventory']}`（evt.num 缺口、snaplen、proc 字段缺失"
          f"等完整性注记见该文件的 `evt_num` / `data_payload` / `completeness` 段）"]
    return NL.join(L) + NL


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True, help="log_inventory.py 产出的 JSON")
    ap.add_argument("--database", help="Neo4j 数据库名（与 --db-inventory 二选一）")
    ap.add_argument("--db-inventory", help="已生成的 db_inventory JSON")
    ap.add_argument("--spec", default=str(ROOT / "tools" / "coverage_spec.json"))
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    if not args.database and not args.db_inventory:
        ap.error("需要 --database 或 --db-inventory")

    log = load(args.log)
    spec = load(args.spec)
    if args.db_inventory:
        db = load(args.db_inventory)
        db_name = db["meta"]["database"]
    else:
        import db_inventory
        db = db_inventory.collect(args.database)
        db_name = args.database

    report = build_report(log, db, spec, args.log, db_name)
    stem = Path(args.log).name.replace(".log-inventory.json", "")
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stem}.coverage-gap.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1, sort_keys=True),
        encoding="utf-8")
    (out / f"{stem}.coverage-gap.md").write_text(render(report), encoding="utf-8")

    s1 = len(report["sentinel_modeled_but_zero_edges"])
    s2 = len(report["sentinel_graph_syscall_not_in_log"])
    unm = sum(1 for a in report["arg_keys"]
              if not a["mapped"] and not a.get("suspected_payload_key"))
    print(f"{db_name}: 事件 {report['meta']['log_events']} 个；"
          f"声明建模但0边={s1}；图有日志无的syscall={s2}；未消费参数名={unm} "
          f"-> {out / (stem + '.coverage-gap.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
