"""CDM18 数据源的装配根（对应 sysdig 侧的 main.py）。

用法示例（dry-run，不写库）：

    python parser/cdm_main.py \
      --archive Transparent_Computing_Engagement_3_Dataset/data/theia/ta1-theia-e3-official-6r.json.tar.gz \
      --scenario TC_E3_THEIA_20180410 \
      --member-from 0 --member-to 1 \
      --time-from 2018-04-10T17:30:00Z --time-to 2018-04-10T19:30:00Z \
      --dry-run

落库时去掉 ``--dry-run`` 并给出 ``--neo4j-database``。

边界声明：
  * 本入口只解析 CDM 数据源，不改变 sysdig 主干的任何行为；
  * 生产出的图与 sysdig 库共享同一套 3 顶点 5 边 schema，但 Network 顶点的
    endpoints 是「本机端点->对端端点」，与 sysdig 的观测方向字符串不是同一口径，
    两边的 Network 顶点不可直接对拍。
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm import decode as D  # noqa: E402
from provenance.adapters.cdm.archive import list_members  # noqa: E402
from provenance.adapters.cdm.mapping import EventTable  # noqa: E402
from provenance.adapters.cdm.run import CdmRunOptions, run_cdm  # noqa: E402
from provenance.adapters.neo4j import Neo4jWriter  # noqa: E402
from provenance.core.options import (  # noqa: E402
    EmitOptions,
    GraphLimits,
    Neo4jOptions,
)
from provenance.graph.store import GraphStore  # noqa: E402
from provenance.settings import load_dotenv  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="CDM18（DARPA TC E3）JSONL -> Neo4j 溯源图",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--archive", required=False, help="tar.gz 归档路径")
    ap.add_argument("--scenario", required=False, help="场景名（决定输出目录与默认库名）")
    ap.add_argument("--host-id", default="", help="主机命名空间前缀（默认取场景名）")
    ap.add_argument("--member-from", type=int, default=0,
                    help="起始成员逻辑序号（x.json 记 0）")
    ap.add_argument("--member-to", type=int, default=None, help="结束成员逻辑序号（含）")
    ap.add_argument("--tar-order", action="store_true",
                    help="按 tar 物理顺序单趟读（快，但时间戳可能不单调；"
                         "仅在成员物理序与时间序一致的切片场景使用）")
    ap.add_argument("--time-from", default="", help="事件时间窗起点，ISO-8601（UTC）")
    ap.add_argument("--time-to", default="", help="事件时间窗终点，ISO-8601（UTC）")
    ap.add_argument("--max-events", type=int, default=0, help="只处理前 N 个事件（开发用）")
    ap.add_argument("--event-id-base", type=int, default=0,
                    help="事件号基址：同一 host_id 追加多个时间窗到同一个库时必须错开，"
                         "否则关系唯一约束 (event_id, action) 撞号")
    ap.add_argument("--data-dir", default=str(ROOT / "data"), help="映射表目录")
    ap.add_argument("--out-dir", default="", help="报告目录（默认 output/parser-v2/<场景>-cdm）")
    ap.add_argument("--dry-run", action="store_true", help="只解析，不写 Neo4j")
    ap.add_argument("--edge-batch", type=int, default=10_000)
    ap.add_argument("--vertex-batch", type=int, default=5_000)
    ap.add_argument("--node-registry-max", type=int, default=3_000_000)
    ap.add_argument("--progress-every-s", type=int, default=10)
    ap.add_argument("--no-csv", action="store_true",
                    help="不写 edges.csv / nodes.csv（只做规模普查时使用）")
    ap.add_argument("--event-log", action="store_true",
                    help="额外写 events.csv（event_id -> 成员/行号/uuid，供标准答案回查）")
    ap.add_argument("--list-members", action="store_true",
                    help="列出归档成员（序号/名字/解压字节数）后退出")
    ap.add_argument("--neo4j-uri", default="")
    ap.add_argument("--neo4j-user", default="")
    ap.add_argument("--neo4j-password", default="")
    ap.add_argument("--neo4j-database", default="")
    ap.add_argument("--no-reset", action="store_true", help="不清空该 host_id 的旧图")
    return ap



def _ensure_database(options: Neo4jOptions, database: str) -> None:
    """库不存在就创建（新场景库必须显式建，Neo4j 不会为写入自动建库）。"""
    import re
    import time

    from neo4j import GraphDatabase

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", database):
        raise ValueError(f"库名只允许小写字母、数字与连字符：{database!r}")
    driver = GraphDatabase.driver(options.uri, auth=(options.user, options.password))
    try:
        with driver.session(database="system") as session:
            session.run(f"CREATE DATABASE `{database}` IF NOT EXISTS").consume()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                record = session.run(
                    "SHOW DATABASES YIELD name, currentStatus "
                    "WHERE name = $name RETURN currentStatus AS status",
                    name=database,
                ).single()
                if record and record["status"] == "online":
                    return
                time.sleep(1)
        raise RuntimeError(f"数据库 {database} 60 秒内未就绪")
    finally:
        driver.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_dotenv()

    if args.list_members:
        if not args.archive:
            parser.error("--list-members 需要 --archive")
        for index, name, size in list_members(args.archive):
            print(f"{index:>3}  {name:<45} {size / 1e9:>7.2f} GB")
        return 0

    if not args.archive or not args.scenario:
        parser.error("--archive 与 --scenario 必填（--list-members 除外）")

    archive_path = Path(args.archive)
    if not archive_path.is_file():
        print(f"[BLOCKED] 归档不存在：{archive_path}", file=sys.stderr)
        return 2

    table_path = Path(args.data_dir) / "cdm_events.toml"
    if not table_path.is_file():
        print(f"[BLOCKED] 映射表不存在：{table_path}", file=sys.stderr)
        return 2
    try:
        table = EventTable.load(table_path)
    except ValueError as exc:
        print(f"[BLOCKED] 映射表非法：{exc}", file=sys.stderr)
        return 2

    time_from = D.ns_from_iso(args.time_from)
    time_to = D.ns_from_iso(args.time_to)
    if args.time_from and time_from is None:
        print(f"[BLOCKED] --time-from 无法解析：{args.time_from}", file=sys.stderr)
        return 2
    if args.time_to and time_to is None:
        print(f"[BLOCKED] --time-to 无法解析：{args.time_to}", file=sys.stderr)
        return 2
    if time_from is not None and time_to is not None and time_from >= time_to:
        print("[BLOCKED] --time-from 必须早于 --time-to", file=sys.stderr)
        return 2

    host_id = args.host_id or args.scenario
    limits = GraphLimits(
        node_registry_max=args.node_registry_max,
        vertex_batch=args.vertex_batch,
        edge_batch=args.edge_batch,
    )
    emit_options = EmitOptions(keep_payload=False)
    database = args.neo4j_database or f"attack-{args.scenario.lower().replace('_', '-')}"

    writer = None
    if not args.dry_run:
        options = Neo4jOptions(
            uri=args.neo4j_uri or os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687"),
            user=args.neo4j_user or os.environ.get("NEO4J_USER", "neo4j"),
            password=args.neo4j_password or os.environ.get("NEO4J_PASSWORD", ""),
            database=database,
            reset_db=not args.no_reset,
        )
        try:
            _ensure_database(options, database)
            writer = Neo4jWriter(options)
        except Exception as exc:  # 连不上库就必须停，不能退回 dry-run 交差
            print(f"[BLOCKED] Neo4j 不可用：{exc}", file=sys.stderr)
            return 2
        if options.reset_db:
            writer.reset(host_id)

    graph = GraphStore(writer, limits)
    run_options = replace(
        CdmRunOptions(
            scenario=args.scenario,
            host_id=host_id,
            archive=str(archive_path),
            database=database,
            dry_run=args.dry_run,
            member_from=args.member_from,
            member_to=args.member_to,
            sort_members=not args.tar_order,
            time_from_ns=time_from,
            time_to_ns=time_to,
            progress_every_s=args.progress_every_s,
            max_events=args.max_events,
            event_id_base=args.event_id_base,
            out_dir=args.out_dir,
            event_log=args.event_log,
            write_csv=not args.no_csv,
        )
    )

    print(f"[1/2] 解析 {archive_path.name}（成员 {run_options.member_from}"
          f"..{run_options.member_to if run_options.member_to is not None else 'end'}）", flush=True)
    try:
        payload = run_cdm(run_options, limits, emit_options, table, graph)
    except Exception as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2
    finally:
        graph.close()

    events = payload["events"]
    graph_info = payload["graph"]
    print("")
    print(f"记录：{payload['records_total']:,} 条；Event 接入 {events['ingested']:,}，"
          f"窗口外 {events['out_of_window']:,}")
    print(f"账本：接入 {events['ingested']:,} = 已结算 {events['settled']:,}"
          f"（平衡={events['balanced']}）")
    print(f"图：节点 {graph_info['nodes']:,}，边 {graph_info['edges']:,} {graph_info['by_class']}")
    print(f"事件号区间：[{payload['event_id_range'][0]:,} .. {payload['event_id_range'][1]:,}]"
          f"（基址 {payload['event_id_base']:,}；同一 host_id 追加时区间不得与已有窗口重叠）")
    print(f"CDM 缺口：{payload['gaps']}")
    print(f"耗时：{payload['elapsed_s']}s　报告：{payload['report_dir']}")
    if args.dry_run:
        print("dry-run：未写库")
    else:
        print(f"已写入数据库 {database}"
              f"（节点 {graph_info['written_nodes']:,}，边 {graph_info['written_edges']:,}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
