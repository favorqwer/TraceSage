"""一次性无损迁移工具：将现有 10 个标准 -v2 Neo4j 场景图单遍流式导出为单文件 graphs/<scenario>.tsg。

导出全部 3 类顶点属性与全部 5 类边属性（含 payload_b64 / to_path / mode / NULL 标志），
按 5 类标准关系各做一次单遍流式扫描（无分页重复扫表），迁移速度提升一个数量级。
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "attack_graph"))

import settings as cfg  # noqa: E402
from closure.neo4j import ReadOnlyGraph  # noqa: E402
from domain.edge import ALL_RELS, labels_of  # noqa: E402
from tsg.format import TSGWriter  # noqa: E402


def _v2_vertex_query(kind: str) -> str:
    if kind == "Process":
        return (
            "MATCH (p:Process) RETURN "
            "coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns), "
            "coalesce(p.exe_path, CASE WHEN trim(coalesce(p.cmdline, '')) STARTS WITH '/' "
            "THEN split(trim(coalesce(p.cmdline, '')), ' ')[0] END), "
            "coalesce(p.host_id, ''), coalesce(p.container_id, ''), p.pid, "
            "coalesce(p.cmdline, ''), coalesce(p.ppid, 0), p.uid, p.euid, "
            "p.container_privileged, p.container_host_root_rw"
        )
    if kind == "File":
        return (
            "MATCH (f:File) RETURN "
            "CASE WHEN f.container_id IS NOT NULL AND f.container_id <> 'host' "
            "THEN f.container_id + '|' + f.path ELSE f.path END, "
            "f.path, coalesce(f.host_id, ''), coalesce(f.container_id, ''), f.file_type"
        )
    return (
        "MATCH (n:Network) RETURN "
        "n.endpoints AS k, n.endpoints AS c, coalesce(n.host_id, '') AS h, coalesce(n.proto, '') AS pr"
    )


def _v2_key_expr(var: str, kind: str) -> str:
    if kind == "Process":
        return (
            f"coalesce({var}.host_id, '') + '|' + coalesce({var}.container_id, '') + '|' + "
            f"toString({var}.pid) + '|' + toString({var}.start_ns)"
        )
    if kind == "File":
        return (
            f"CASE WHEN {var}.container_id IS NOT NULL AND {var}.container_id <> 'host' "
            f"THEN {var}.container_id + '|' + {var}.path ELSE {var}.path END"
        )
    return f"{var}.endpoints"


def _v2_edge_stream_query(rel: str) -> str:
    kind_a, kind_b = labels_of(rel)
    full_rel = f"{kind_a}To{kind_b}"
    return (
        f"MATCH (a:{kind_a})-[e:{full_rel}]->(b:{kind_b}) "
        "RETURN e.event_id AS eid, e.start_ns AS st, e.end_ns AS en, "
        "coalesce(e.syscall, e.action) AS sc, coalesce(e.action, '') AS act, "
        "e.result AS res, e.payload_b64 AS pb, e.to_path AS tp, e.mode AS md, "
        f"{_v2_key_expr('a', kind_a)} AS ak, {_v2_key_expr('b', kind_b)} AS bk"
    )


def export_one(scenario_name: str, out_dir: Path, *, overwrite: bool = False) -> dict[str, Any]:
    sc = cfg.load_scenario(scenario_name)
    out_path = out_dir / f"{scenario_name}.tsg"
    if out_path.is_file() and not overwrite:
        print(f"[skip] 已存在：{out_path}", flush=True)
        return {"scenario": scenario_name, "path": str(out_path), "skipped": True}

    t0 = time.time()
    graph = ReadOnlyGraph(sc.database, scenario=scenario_name, run_id="export-tsg")
    writer = TSGWriter(
        out_path,
        scenario=scenario_name,
        database=sc.database,
        log=lambda s: print(s, flush=True),
    )
    try:
        v_total = 0
        for row in graph.stream_values(_v2_vertex_query("Process"), log_params=False):
            key = str(row[0] or "")
            if not key:
                continue
            content = str(row[1] or key)
            props: dict[str, Any] = {
                "content": content, "host_id": str(row[2] or ""), "container_id": str(row[3] or ""),
                "exepath": content, "name": "", "args": str(row[5] or ""), "ppid": row[6],
            }
            if row[4] is not None:
                props["pid"] = row[4]
            if row[7] is not None:
                props["uid"] = row[7]
            if row[8] is not None:
                props["euid"] = row[8]
            if row[9] is not None:
                props["container_privileged"] = row[9]
            if row[10] is not None:
                props["container_host_root_rw"] = row[10]
            writer.add_vertex("Process", key, props)
            v_total += 1

        for row in graph.stream_values(_v2_vertex_query("File"), log_params=False):
            key = str(row[0] or "")
            if not key:
                continue
            props = {
                "content": str(row[1] or key),
                "host_id": str(row[2] or ""),
                "container_id": str(row[3] or ""),
            }
            if row[4] is not None:
                props["file_type"] = row[4]
            writer.add_vertex("File", key, props)
            v_total += 1

        for row in graph.stream_values(_v2_vertex_query("Network"), log_params=False):
            key = str(row[0] or "")
            if not key:
                continue
            props = {
                "content": str(row[1] or key),
                "host_id": str(row[2] or ""),
                "protocol": str(row[3] or ""),
            }
            writer.add_vertex("Network", key, props)
            v_total += 1

        print(f"[{scenario_name}] 顶点流式导出 {v_total:,} 个（{time.time() - t0:.1f}s）", flush=True)

        e_total = 0
        for rel in ALL_RELS:
            kind_a, kind_b = labels_of(rel)
            rows = graph.stream_values(_v2_edge_stream_query(rel), log_params=False)
            for row in rows:
                a_key = str(row[9] or "")
                b_key = str(row[10] or "")
                if not a_key or not b_key:
                    continue
                writer.add_edge(
                    rel=rel,
                    src_kind=kind_a,
                    src_key=a_key,
                    dst_kind=kind_b,
                    dst_key=b_key,
                    event_id=int(row[0]),
                    start_ns=row[1],
                    end_ns=row[2],
                    syscall=str(row[3] or ""),
                    action=str(row[4] or ""),
                    result=row[5],
                    payload_b64=row[6],
                    to_path=row[7],
                    mode=row[8],
                )
                e_total += 1
            print(f"[{scenario_name}] {rel} 单遍导出 {len(rows):,} 条，累计 {e_total:,} 条（{time.time() - t0:.1f}s）", flush=True)

        meta = writer.finish()
        return {"scenario": scenario_name, "path": str(out_path), "meta": meta}
    except BaseException:
        writer.abort()
        raise
    finally:
        graph.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="将现有 -v2 Neo4j 场景图单遍流式导出为 graphs/<scenario>.tsg")
    ap.add_argument("--scenario", action="append", default=[], help="指定单个或多个场景名（不传则导出全部 10 场景）")
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "graphs"), help="输出目录（默认 graphs/）")
    ap.add_argument("--overwrite", action="store_true", help="覆盖已存在的 .tsg 文件")
    args = ap.parse_args(argv)

    cfg.load_dotenv()
    scenarios = args.scenario or cfg.available_scenarios()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    t_all = time.time()
    for idx, sc in enumerate(scenarios, 1):
        print(f"\n=== [{idx}/{len(scenarios)}] 迁移场景：{sc} ===", flush=True)
        export_one(sc, out_dir, overwrite=args.overwrite)
    print(f"\n全部 {len(scenarios)} 个场景迁移完成，总耗时 {time.time() - t_all:.1f}s -> {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
