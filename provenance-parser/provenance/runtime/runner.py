"""流程编排：读 -> 配对 -> 分类 -> 产出 -> 记账。"""

from __future__ import annotations

import time

from ..core.classify import Tables
from ..core.events import BadRow, Call
from ..core.kinds import Bucket
from ..core.options import EmitOptions, GraphLimits, RunOptions
from ..core.pair import PairingPool, should_pair
from ..core.ports import Capture, RunObserver
from ..core.snapshots import RunSnapshot
from ..graph.context import EmitContext
from ..graph.handlers import dispatch
from ..graph.state import State
from ..graph.store import GraphStore
from .ledger import Ledger


def _progress(start: float, ledger: Ledger, graph: GraphStore, pool: PairingPool) -> str:
    elapsed = max(0.001, time.monotonic() - start)
    rate = ledger.ingested / elapsed
    return (
        f"[progress] rows={ledger.ingested:,} rate={rate:,.0f}/s "
        f"nodes={len(graph.nodes):,} edges={graph.written_edges + len(graph.buf_edges):,} "
        f"pending={pool.size:,}"
    )


def run(
    run_options: RunOptions,
    graph_limits: GraphLimits,
    emit_options: EmitOptions,
    capture: Capture,
    graph: GraphStore,
    observer: RunObserver,
    tables: Tables,
    *,
    audit_enabled: bool,
    scap: str,
    database: str,
) -> RunSnapshot:
    t0 = time.time()
    t_mono = time.monotonic()
    state = State.build(run_options.host_id, graph_limits.fd_table_max)
    ctx = EmitContext(state, emit_options)

    print(f"[1/4] 容器元数据扫描（后端 {capture.backend}）…", flush=True)
    for meta in capture.containers():
        state.containers.observe(meta)
    infos = state.containers.listing()
    if infos:
        print(
            f"      容器 {len(infos)} 个；回填 {state.containers.counts['backfilled']} 次",
            flush=True,
        )
    else:
        print("      本场景无容器事件", flush=True)

    audit = None
    if audit_enabled:
        print("[2/4] 采集端审计（2 趟，用于对账与丢弃量化）…", flush=True)
        audit = capture.audit()
        print(
            f"      全部可打印 {audit.total_rows:,} 行；可归属进程 {audit.pid_rows:,} 行；"
            f"采集端丢弃 {audit.total_rows - audit.pid_rows:,} 行",
            flush=True,
        )
    else:
        print("[2/4] 跳过审计（--no-audit）", flush=True)

    print("[3/4] 主解析…", flush=True)
    ledger = Ledger()
    pool = PairingPool(run_options.pair_timeout_ns, run_options.pair_pool_max)
    last_report = time.monotonic()

    try:
        for item in capture.events():
            if isinstance(item, BadRow):
                ledger.ingest_bad(item.reason)
                observer.on_bad(item)
                continue

            ledger.ingest(item)
            observer.on_event(item)

            if item.is_enter and should_pair(item):
                for evicted in pool.push(item):
                    ledger.settle(evicted.num, Bucket.UNPAIRED, "evicted")
                continue

            if item.is_enter:
                enter, exit_row = item, None
                observer.on_single_line()
            else:
                enter, exit_row = pool.take(item), item
            call = Call.build(enter, exit_row)
            if call.pid <= 0:
                ledger.settle_call(call, Bucket.NO_OWNER)
                observer.on_no_owner(len(call.rows))
                continue

            state.proc.observe(call.head_row)
            decision = tables.decide(call)
            outcome = dispatch(call, decision, ctx)
            for num, bucket, reason in outcome.buckets:
                ledger.settle(num, bucket, reason)
            observer.on_call(call, decision, outcome)
            graph.add(outcome)

            if ledger.ingested % run_options.checkpoint_every == 0:
                ledger.check(pool.size)
            now = time.monotonic()
            if now - last_report >= run_options.progress_every_s:
                last_report = now
                print(_progress(t_mono, ledger, graph, pool), flush=True)

        for row in pool.drain():
            ledger.settle(row.num, Bucket.UNPAIRED, "stream_end")
        ledger.final()
        graph.flush()
        elapsed = time.time() - t0
        return RunSnapshot(
            scenario=run_options.scenario,
            host_id=run_options.host_id,
            scap=scap,
            backend=capture.backend,
            dry_run=run_options.dry_run,
            database=database,
            elapsed_s=elapsed,
            coverage=tables.coverage(),
            ledger=ledger.snapshot(),
            stats=observer.snapshot(),
            graph=graph.snapshot(),
            state=state.snapshot(),
            audit=audit,
            node_registry_max=graph_limits.node_registry_max,
        )
    finally:
        observer.close()
        graph.close()

