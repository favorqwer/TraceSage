#!/usr/bin/env python3
"""GT annotation helper for pi (read-only Neo4j).

Commands:
    schema   check current parser schema + orientation stats
    time     convert local clock time to ns
    edges    main edge query; --edge-key for one edge
    tree     clone/exec process lineage
    activity all edges of a process tree
    summary  grouped counts for bursts/possible sets
    path     shortest path between edges or vertex keys
    validate validate GT facts, connectivity, time, rules
    steps    attack steps state machine and checklist management
"""

from __future__ import annotations

import argparse

import path as path_tool
import query
import steps as steps_tool
import validate as validate_tool
from common import fail
from db import DB


def add_db(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", required=True, help="Neo4j 数据库名")


def add_time(p: argparse.ArgumentParser) -> None:
    p.add_argument("--from-ns", type=int, default=None)
    p.add_argument("--to-ns", type=int, default=None)
    p.add_argument("--from-clock", default=None, help="本地时间 HH:MM:SS[.mmm]")
    p.add_argument("--to-clock", default=None, help="本地时间 HH:MM:SS[.mmm]")
    p.add_argument("--clock-date", default=None, help="跨天时指定 YYYY-MM-DD")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="gt.py",
        description="GT 标注辅助工具：只读查图 + GT 校验。",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("schema", help="检查 schema + 节点/边/action/时间统计")
    add_db(p)
    p.set_defaults(func=query.cmd_schema)

    p = sub.add_parser("time", help="查看库时间范围 / 把本地时钟转成纳秒")
    add_db(p)
    p.add_argument("--clock", default=None, help="本地时间 HH:MM:SS[.mmm]")
    p.add_argument("--date", default=None, help="跨天时指定 YYYY-MM-DD")
    p.set_defaults(func=query.cmd_time)

    p = sub.add_parser("edges", help="查边；--edge-key 时返回单条边")
    add_db(p)
    add_time(p)
    p.add_argument("--edge-key", default=None, help="关系:event_id:action")
    p.add_argument("--rel", default="", help="逗号分隔的关系类型")
    p.add_argument("--action", default="", help="逗号分隔的 action")
    p.add_argument("--syscall", default="", help="逗号分隔的 syscall")
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--start-ns", type=int, default=None, help="进程实例 start_ns，需配合 --pid")
    p.add_argument("--exe", default=None, help="端点进程 exe_path 精确匹配")
    p.add_argument("--src-exe", default=None, help="源端进程 exe_path 精确匹配")
    p.add_argument("--dst-exe", default=None, help="目标端进程 exe_path 精确匹配")
    p.add_argument("--src-cmdline", default=None, help="源端进程 cmdline 精确匹配")
    p.add_argument("--dst-cmdline", default=None, help="目标端进程 cmdline 精确匹配")
    p.add_argument("--src-cmdline-contains", default=None, help="源端进程 cmdline 包含")
    p.add_argument("--dst-cmdline-contains", default=None, help="目标端进程 cmdline 包含")
    p.add_argument("--src-pid", type=int, default=None, help="源端进程 pid")
    p.add_argument("--dst-pid", type=int, default=None, help="目标端进程 pid")
    p.add_argument("--exe-null", action="store_true", help="端点进程 exe_path 为空（<NA>）")
    p.add_argument("--cmdline", default=None, help="端点进程 cmdline 精确匹配")
    p.add_argument("--cmdline-contains", default=None, help="端点进程 cmdline 包含")
    p.add_argument("--uid", default=None, help="端点进程 uid（日志观测值）")
    p.add_argument("--euid", default=None, help="端点进程 euid")
    p.add_argument("--ppid", type=int, default=None, help="端点进程 ppid")
    p.add_argument("--path", default=None, help="端点文件 path 精确匹配")
    p.add_argument("--path-prefix", default=None, help="端点文件 path 前缀")
    p.add_argument("--path-suffix", default=None, help="端点文件 path 后缀")
    p.add_argument("--path-contains", default=None, help="端点文件 path 包含")
    p.add_argument("--file-type", default=None, help="端点文件 file_type")
    p.add_argument("--endpoint", default=None, help="端点网络 endpoints 精确匹配")
    p.add_argument("--port", type=int, default=None, help="网络端点端口")
    p.add_argument("--to-path", default=None, help="边属性 to_path 精确匹配")
    p.add_argument("--to-path-prefix", default=None, help="边属性 to_path 前缀")
    p.add_argument("--host-id", default=None, help="任一端点 host_id")
    p.add_argument("--container-id", default=None, help="任一端点 container_id")
    p.add_argument("--result-sign", choices=["success", "failure"], default=None)
    p.add_argument("--order", choices=["time", "event", "none"], default="time")
    p.add_argument("--desc", action="store_true", help="按 order 降序")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--count", action="store_true", help="只返回总数")
    p.add_argument("--jsonl", action="store_true", help="一行一条 JSON")
    p.set_defaults(func=query.cmd_edges)

    p = sub.add_parser("tree", help="进程 clone/exec 父子链")
    add_db(p)
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--start-ns", type=int, required=True)
    p.add_argument("--host-id", default=None)
    p.add_argument("--container-id", default=None)
    p.add_argument("--direction", choices=["up", "down"], default="up")
    p.add_argument("--depth", type=int, default=5)
    p.set_defaults(func=query.cmd_tree)

    p = sub.add_parser("activity", help="进程树的全部活动边")
    add_db(p)
    add_time(p)
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--start-ns", type=int, required=True)
    p.add_argument("--host-id", default=None)
    p.add_argument("--container-id", default=None)
    p.add_argument("--direction", choices=["up", "down"], default="down")
    p.add_argument("--depth", type=int, default=5)
    p.add_argument("--limit", type=int, default=1000)
    p.set_defaults(func=query.cmd_activity)

    p = sub.add_parser("summary", help="按 action/端点分组计数")
    add_db(p)
    add_time(p)
    p.add_argument("--rel", default="")
    p.add_argument("--action", default="")
    p.add_argument("--syscall", default="")
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--start-ns", type=int, default=None)
    p.add_argument("--exe", default=None, help="端点进程 exe_path 精确匹配")
    p.add_argument("--exe-null", action="store_true", help="端点进程 exe_path 为空")
    p.add_argument("--src-exe", default=None, help="源端进程 exe_path")
    p.add_argument("--dst-exe", default=None, help="目标端进程 exe_path")
    p.add_argument("--path", default=None, help="端点文件 path 精确匹配")
    p.add_argument("--path-prefix", default=None, help="端点文件 path 前缀")
    p.add_argument("--endpoint", default=None, help="端点网络 endpoints 精确匹配")
    p.add_argument("--result-sign", choices=["success", "failure"], default=None)
    p.add_argument("--host-id", default=None)
    p.add_argument("--container-id", default=None)
    p.add_argument("--group-by",
                   choices=["action,dst", "action,src", "action", "dst", "src"],
                   default="action,dst")
    p.add_argument("--min-count", type=int, default=1)
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=query.cmd_summary)

    p = sub.add_parser("path", help="候选边/顶点键之间的样例路径")
    add_db(p)
    add_time(p)
    p.add_argument("--from-edge", default=None)
    p.add_argument("--to-edge", default=None)
    p.add_argument("--from-key", default=None)
    p.add_argument("--to-key", default=None)
    p.add_argument("--max-depth", type=int, default=10)
    p.add_argument("--causal", action="store_true", help="强制寻找时间单调递增的因果路径")
    p.set_defaults(func=path_tool.cmd_path)

    p = sub.add_parser("validate", help="校验 GT：事实、连通性、时间、规则")
    add_db(p)
    p.add_argument("--gt", required=True)
    p.add_argument("--no-check-time", dest="check_time", action="store_false",
                   help="允许 must 边晚于 POI（默认禁止）")
    p.add_argument("--time-tolerance-ns", type=int, default=0)
    p.add_argument("--strict-instances", action="store_true",
                   help="按 edge_key 的进程实例建连通图")
    p.add_argument("--rule-count-cap", type=int, default=2000)
    p.add_argument("--check-steps", action="store_true",
                   help="联动校验 tmp/<场景>/steps.json 步骤销账状态（不能有 absent 项）")
    p.set_defaults(func=validate_tool.cmd_validate)

    p = sub.add_parser("steps", help="攻击步骤状态机与自动销账管理")
    p.add_argument("steps_action", choices=["init", "add", "update", "status"], help="动作")
    p.add_argument("--scenario", required=True, help="场景名称")
    p.add_argument("--from-attack", default=None, help="从 attack/*.md 提取初始步骤清单")
    p.add_argument("--id", default=None, help="步骤 ID，如 S01")
    p.add_argument("--desc", default=None, help="步骤动作描述")
    p.add_argument("--phase", default=None, help="步骤所属阶段")
    p.add_argument("--status", choices=["found", "context", "absent"], default=None, help="状态")
    p.add_argument("--edge-key", default=None, help="关联 edge_key")
    p.add_argument("--why", default=None, help="判定理由或证据备注")
    p.set_defaults(func=steps_tool.cmd_steps)

    return ap


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    if getattr(args, "limit", 1) is not None:
        if args.command in ("edges", "summary", "activity"):
            if args.limit < 1:
                fail("--limit 必须 >= 1")
            if args.command == "edges" and args.limit > 1000:
                fail("--limit 最大 1000；需要更多请用 --count 或缩小过滤")
            if args.command == "activity" and args.limit > 5000:
                fail("--limit 最大 5000；请加时间窗或缩小进程树")
            if args.command == "summary" and args.limit > 2000:
                fail("--limit 最大 2000；请缩小过滤")
    if getattr(args, "offset", 0) is not None and getattr(args, "offset", 0) < 0:
        fail("--offset 必须 >= 0")
    if args.command == "edges":
        if args.start_ns is not None and args.pid is None:
            fail("--start-ns 必须配合 --pid")
        if args.exe is not None and args.exe_null:
            fail("--exe 与 --exe-null 不能同时用")
    if args.command == "validate":
        if getattr(args, "rule_count_cap", 1) < 1:
            fail("--rule-count-cap 必须 >= 1")
        if getattr(args, "time_tolerance_ns", 0) < 0:
            fail("--time-tolerance-ns 必须 >= 0")
    if args.command == "steps":
        args.func(args)
        return 0
    db = DB(args.db)
    try:
        args.func(db, args)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
