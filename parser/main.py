#!/usr/bin/env python3
"""parser 入口：CLI 解析 + 装配，流程本身在 runtime/runner。"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provenance.adapters.neo4j import Neo4jWriter  # noqa: E402
from provenance.adapters.report import ReportCollector, ReportWriter  # noqa: E402
from provenance.adapters.scap import ScapCapture  # noqa: E402
from provenance.adapters.scap.backends import detect_available_backends  # noqa: E402
from provenance.adapters.config import load_classifier  # noqa: E402
from provenance.graph.store import GraphStore  # noqa: E402
from provenance.runtime.runner import run as run_pipeline  # noqa: E402
from provenance.settings import Settings  # noqa: E402


def _build() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python parser/main.py",
        description="Sysdig .scap 流式解析 -> Neo4j 溯源图（V2 设计实现）",
    )
    ap.add_argument("--scap", default=None, help=".scap 捕获文件路径")
    ap.add_argument("--scenario", default=None, help="场景名，如 1_Web_Exploit_Ransomware")
    ap.add_argument("--host-id", default="", help="主机命名空间前缀（默认取场景名）")
    ap.add_argument("--backend", default="auto", choices=["auto", "local", "wsl", "ssh", "docker"])
    ap.add_argument("--ssh-host", default="")
    ap.add_argument("--ssh-user", default="")
    ap.add_argument("--ssh-port", type=int, default=None)
    ap.add_argument("--ssh-cache-dir", default="")
    ap.add_argument("--no-ssh-sync", action="store_true", help="禁止把本地 .scap 上传到远端缓存")
    ap.add_argument("--sysdig-bin", default="sysdig")
    ap.add_argument("--docker-image", default="")
    ap.add_argument("--wsl-distro", default="")
    ap.add_argument("--detect-backends", action="store_true", help="探测并打印后端可用性后退出")
    ap.add_argument("--max-events", type=int, default=0, help="只读前 N 个事件（开发用）")
    ap.add_argument("--no-payload", action="store_true", help="边属性不写 payload_b64 载荷")
    ap.add_argument("--dry-run", action="store_true", help="只解析，不写 Neo4j")
    ap.add_argument("--out-dir", default="", help="报告目录（默认 output/parser-v2/<scenario>）")
    ap.add_argument("--fd-cap", type=int, default=4096)
    ap.add_argument("--neo4j-uri", default="")
    ap.add_argument("--neo4j-user", default="")
    ap.add_argument("--neo4j-password", default="")
    ap.add_argument("--neo4j-database", default="")
    ap.add_argument("--no-reset", action="store_true", help="不清空该 host_id 的旧图")
    ap.add_argument("--strict-paths", action="store_true",
                    help="路径审计严格模式：未规整的文件路径直接抛错（重建验收用）")
    return ap


def _apply_args(settings: Settings, args: argparse.Namespace) -> Settings:
    scap = replace(
        settings.scap,
        backend=args.backend,
        sysdig_bin=args.sysdig_bin,
        max_events=args.max_events or None,
        ssh_host=args.ssh_host or settings.scap.ssh_host,
        ssh_user=args.ssh_user or settings.scap.ssh_user,
        ssh_port=args.ssh_port or settings.scap.ssh_port,
        ssh_cache_dir=args.ssh_cache_dir or settings.scap.ssh_cache_dir,
        ssh_auto_sync=False if args.no_ssh_sync else settings.scap.ssh_auto_sync,
        docker_image=args.docker_image or settings.scap.docker_image,
        wsl_distro=args.wsl_distro or settings.scap.wsl_distro,
    )
    run = replace(
        settings.run,
        host_id=args.host_id or settings.run.host_id,
        dry_run=args.dry_run,
    )
    graph = replace(settings.graph, fd_table_max=args.fd_cap)
    emit = replace(settings.emit, keep_payload=not args.no_payload,
                   strict_paths=bool(args.strict_paths))
    database = args.neo4j_database or settings.database
    neo4j = replace(
        settings.neo4j,
        uri=args.neo4j_uri or settings.neo4j.uri,
        user=args.neo4j_user or settings.neo4j.user,
        password=args.neo4j_password or settings.neo4j.password,
        database=database,
        reset_db=not args.no_reset,
    )
    report = replace(
        settings.report,
        host_id=run.host_id,
        database=database,
        dry_run=run.dry_run,
        out_dir=args.out_dir or settings.report.out_dir,
        node_registry_max=graph.node_registry_max,
        data_dir=str(settings.data_dir),
    )
    return replace(
        settings,
        scap=scap,
        run=run,
        graph=graph,
        emit=emit,
        neo4j=neo4j,
        report=report,
    )


def _print_summary(payload: dict) -> None:
    eq = payload["ledger"]["equation"]
    edges = payload["edges"]
    print("")
    print(f"账本：接入 {eq['ingested']:,} = 已结算 {eq['settled']:,} + 异常 {eq['abnormal']:,}"
          f"（平衡={eq['balanced']}）")
    print(f"图：节点 {payload['nodes']['total']:,}，边 {edges['total']:,} {edges['by_class']}")
    gaps = payload["gaps"]
    print(f"事件号：末号 {gaps['max_event_num']:,}，缺号 {gaps['missing_numbers']:,}")
    audit = payload.get("path_audit") or {}
    print(f"路径审计：未规整路径 {audit.get('dirty', 0)} 个"
          + (f"，示例 {audit.get('samples', [])[:3]}" if audit.get('dirty') else ""))
    print(f"耗时：{payload['elapsed_s']}s　报告：{payload['report_dir']}")


def main(argv: list[str] | None = None) -> int:
    parser = _build()
    args = parser.parse_args(argv)

    if args.detect_backends:
        settings = Settings.from_env(args.scenario or "", args.scap or "", args.host_id)
        readiness = detect_available_backends(
            ssh_host=args.ssh_host or settings.scap.ssh_host,
            ssh_user=args.ssh_user or settings.scap.ssh_user,
            ssh_port=args.ssh_port or settings.scap.ssh_port,
            sysdig_bin=args.sysdig_bin,
            wsl_distribution=args.wsl_distro or settings.scap.wsl_distro,
        )
        print("[SCAP Source] 后端可用性：")
        for name in ("local", "wsl", "ssh", "docker"):
            print(f"  {name:<7}: {'可用' if readiness[name] else '不可用'}")
        from provenance.adapters.scap.backends import choose_backend

        try:
            print(f"  auto   : {choose_backend(readiness)}")
        except Exception as exc:
            print(f"  auto   : 无（{exc}）")
        return 0

    if not args.scap or not args.scenario:
        parser.error("--scap 和 --scenario 必填（--detect-backends 除外）")

    settings = _apply_args(
        Settings.from_env(args.scenario, args.scap, args.host_id), args
    )
    try:
        settings.validate()
        classifier = load_classifier(settings.data_dir)
        capture = ScapCapture(settings.scap)
        writer = None
        if not settings.run.dry_run:
            writer = Neo4jWriter(settings.neo4j)
            if settings.neo4j.reset_db:
                writer.reset(settings.run.host_id)
        graph = GraphStore(writer, settings.graph)
        collector = ReportCollector(settings.report)
        snapshot = run_pipeline(
            settings.run,
            settings.graph,
            settings.emit,
            capture,
            graph,
            collector,
            classifier,
            scap=settings.scap.scap,
            database=settings.database,
        )
        print("[3/3] 收尾：节点快照与报告…", flush=True)
        payload = ReportWriter(settings.report).write(snapshot)
        payload["report_dir"] = str(settings.report_dir)
        from provenance.graph.emitter import PATH_AUDIT

        payload["path_audit"] = {"dirty": PATH_AUDIT["dirty"],
                                 "samples": PATH_AUDIT["samples"]}
        _print_summary(payload)
    except Exception as exc:
        print(f"\n[BLOCKED] {exc}", file=sys.stderr, flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
