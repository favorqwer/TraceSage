"""TraceSage-Studio 调查引擎适配层 (AsyncPipelineExecutor)。

将 provenance-navigator 的同步调查计算解耦为非阻塞协程，并驱动图事件分发与人在回路 (HITL) 决策挂起。
"""

from __future__ import annotations

import asyncio
import functools
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from server.bus import EventStreamBus
from server.config import settings
from server.schemas import InvestigationParameters, InvestigationStage
from server.state_machine import InvestigationStateMachine

# 确保 provenance-navigator 路径在 sys.path 中
nav_path = str(settings.NAVIGATOR_PATH)
if nav_path not in sys.path:
    sys.path.insert(0, nav_path)

from closure import extract_raw_closure, list_scenarios  # noqa: E402
from common.graph import labels_of, normalize_rel  # noqa: E402
from llm.judge import LlmChannel  # noqa: E402
from pipeline import load_patterns  # noqa: E402
from routing.report import build_report_from_outcome, save_report  # noqa: E402
from routing.route import route  # noqa: E402


class AsyncPipelineExecutor:
    def __init__(
        self,
        task_id: str,
        scenario_name: str,
        mode: str,
        rules_from: str,
        sm: InvestigationStateMachine,
        bus: EventStreamBus,
        params: Optional[InvestigationParameters] = None,
    ):
        self.task_id = task_id
        self.scenario_name = scenario_name
        self.mode = mode
        self.rules_from = rules_from
        self.sm = sm
        self.bus = bus
        self.params = params or InvestigationParameters()
        self.output_report = str(settings.OUTPUT_RUNS_DIR / f"{scenario_name}.json")

    def _extract_pid(self, edge: Dict[str, Any], endpoint_val: str, is_src: bool) -> Optional[int]:
        """从边属性或复合进程主键中可靠解析真实 OS PID。"""
        direct_pid = edge.get("pid") if is_src else edge.get("dst_pid")
        if direct_pid is not None:
            try:
                return int(direct_pid)
            except (ValueError, TypeError):
                pass
        proc_id = str(edge.get("process_id") or "")
        if "|" in proc_id:
            parts = proc_id.split("|")
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
        if "|" in endpoint_val:
            parts = endpoint_val.split("|")
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
        return None

    def _extract_nodes_from_edges(self, edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """从边集合中提取规范化的 Process / File / Network 顶点列表，确保与边的 source/target 100% 对齐。"""
        nodes_dict: Dict[str, Dict[str, Any]] = {}

        for edge in edges:
            src = str(edge.get("src") or "")
            dst = str(edge.get("dst") or "")
            if not src or not dst:
                continue

            rels = edge.get("rels") or []
            rel = normalize_rel(str(rels[0] if rels else (edge.get("rel") or edge.get("type") or "p2f")))
            src_label = str(edge.get("src_label") or "")
            dst_label = str(edge.get("dst_label") or "")
            if not src_label or not dst_label:
                def_src, def_dst = labels_of(rel)
                src_label = src_label or def_src
                dst_label = dst_label or def_dst

            # 规范化源端点
            if src not in nodes_dict:
                src_pid = self._extract_pid(edge, src, is_src=True)
                exe = str(edge.get("process_content") or edge.get("exe_path") or "")
                if "/" in src:
                    name = src.split("/")[-1]
                    exe_path = src
                elif exe and "/" in exe:
                    name = exe.split("/")[-1]
                    exe_path = exe
                elif src_pid:
                    name = f"进程 (PID {src_pid})"
                    exe_path = None
                else:
                    name = src
                    exe_path = None

                nodes_dict[src] = {
                    "id": src,
                    "label": src_label,
                    "host_id": str(edge.get("host_id") or "host"),
                    "properties": {
                        "name": name,
                        "full_identifier": src,
                        "pid": src_pid,
                        "exe_path": exe_path,
                        "path": src if src_label == "File" else None,
                        "process_id": edge.get("process_id"),
                        "file_type": "file" if src_label == "File" else None,
                        "endpoints": src if src_label == "Network" else None,
                        "container_privileged": edge.get("container_privileged", False),
                    },
                }

            # 规范化目标端点
            if dst not in nodes_dict:
                dst_pid = self._extract_pid(edge, dst, is_src=False)
                if "/" in dst:
                    name = dst.split("/")[-1]
                    exe_path = dst if dst_label == "Process" else None
                elif dst_pid and dst_label == "Process":
                    name = f"进程 (PID {dst_pid})"
                    exe_path = None
                else:
                    name = dst
                    exe_path = None

                nodes_dict[dst] = {
                    "id": dst,
                    "label": dst_label,
                    "host_id": str(edge.get("host_id") or "host"),
                    "properties": {
                        "name": name,
                        "full_identifier": dst,
                        "pid": dst_pid,
                        "exe_path": exe_path,
                        "path": dst if dst_label == "File" else None,
                        "file_type": "file" if dst_label == "File" else None,
                        "endpoints": dst if dst_label == "Network" else None,
                        "container_privileged": edge.get("container_privileged", False),
                    },
                }

        return list(nodes_dict.values())

    def _normalize_edge(self, edge: Dict[str, Any], status: str = "confirmed", confirmed_by: str = "") -> Dict[str, Any]:
        """将底层边格式统一转为前端渲染契约，保证 edge_id 全局唯一稳定。"""
        src = str(edge.get("src") or "")
        dst = str(edge.get("dst") or "")
        syscall = str(edge.get("syscall") or edge.get("action") or "unknown")
        action = str(edge.get("action") or syscall)
        t0 = int(edge.get("t0") or edge.get("start_ns") or 0)
        t1 = int(edge.get("t1") or edge.get("end_ns") or t0)
        event_ids = edge.get("event_ids") or []
        ev_id = str(event_ids[0]) if event_ids else str(edge.get("event_id") or f"{t0}")
        rels = edge.get("rels") or []
        rel = normalize_rel(str(rels[0] if rels else (edge.get("rel") or edge.get("type") or "p2f")))

        # 唯一边主键，杜绝 ID 碰撞
        edge_id = f"e_{src}_{syscall}_{dst}_{ev_id}"
        return {
            "id": edge_id,
            "source": src,
            "target": dst,
            "type": rel,
            "action": action,
            "syscall": syscall,
            "start_ns": t0,
            "end_ns": t1,
            "result": edge.get("result") or edge.get("bytes") or 0,
            "status": status,
            "confirmed_by": confirmed_by,
            "properties": edge,
        }

    def _project_canvas_edges(self, edges: List[Dict[str, Any]], max_bulk_samples: int = 3) -> List[Dict[str, Any]]:
        """对高频大批量同构数据操作（如勒索加密/粉碎数千个业务文件）进行骨干投影，保留关键攻击步骤与代表性样例。"""
        # 1. 过滤完全匿名的管道描述符（如 pipe:[12345]），避免其破坏拓扑全局布局
        filtered_edges = [
            e for e in edges
            if not str(e.get("src") or "").startswith("pipe:[") and not str(e.get("dst") or "").startswith("pipe:[")
        ]

        if len(filtered_edges) <= 180:
            return filtered_edges

        # 2. 统计高频重复路径前缀（如 /srv/data/）
        bulk_counts: Dict[str, int] = {}
        for e in filtered_edges:
            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            for p in ("/srv/data/", "/var/log/"):
                if (p in src or p in dst) and "README_RESTORE" not in src and "README_RESTORE" not in dst:
                    bulk_counts[p] = bulk_counts.get(p, 0) + 1

        seen_bulk: Dict[str, int] = {}
        summary_created: set[str] = set()
        projected: List[Dict[str, Any]] = []

        for e in filtered_edges:
            src = str(e.get("src") or "")
            dst = str(e.get("dst") or "")
            is_bulk = False
            matched_prefix = None
            for p in ("/srv/data/", "/var/log/"):
                if (p in src or p in dst) and "README_RESTORE" not in src and "README_RESTORE" not in dst:
                    is_bulk = True
                    matched_prefix = p
                    break

            if is_bulk and matched_prefix:
                seen_bulk[matched_prefix] = seen_bulk.get(matched_prefix, 0) + 1
                if seen_bulk[matched_prefix] <= max_bulk_samples:
                    projected.append(e)
                elif matched_prefix not in summary_created:
                    summary_created.add(matched_prefix)
                    total_cnt = bulk_counts.get(matched_prefix, 0)
                    synth_node_id = f"{matched_prefix}* (共 {total_cnt} 个文件受影响)"
                    synth_e = dict(e)
                    if matched_prefix in dst:
                        synth_e["dst"] = synth_node_id
                        synth_e["dst_label"] = "File"
                    else:
                        synth_e["src"] = synth_node_id
                        synth_e["src_label"] = "File"
                    synth_e["syscall"] = "batch_impact"
                    synth_e["action"] = "batch_encrypt/shred"
                    synth_e["motif_name"] = "批量加密与粉碎"
                    projected.append(synth_e)
            else:
                projected.append(e)

        return projected

    async def execute(self) -> None:
        start_time = time.time()
        loop = asyncio.get_running_loop()

        try:
            # 1. 闭包提取阶段
            await self.sm.transition_to(InvestigationStage.EXTRACTING_CLOSURE)
            await self.bus.emit_log(f"开始启动场景 [{self.scenario_name}] 因果图谱调查...")
            await self.bus.emit_progress("EXTRACTING_CLOSURE", 5.0, "正在连接 Neo4j 数据库并检索 POI 告警锚点...")

            need_deps = self.mode in ("hybrid", "llm-only")

            # 注入实时进度回调，捕获展开轮次日志
            def progress_callback(msg: str):
                try:
                    asyncio.run_coroutine_threadsafe(self.bus.emit_log(msg), loop)
                    if "[closure]" in msg and "第" in msg and "轮" in msg:
                        m = re.search(r"第\s*(\d+)\s*轮", msg)
                        r = int(m.group(1)) if m else 1
                        pct = min(10.0 + r * 6.0, 85.0)
                        asyncio.run_coroutine_threadsafe(
                            self.bus.emit_progress(
                                stage="EXTRACTING_CLOSURE",
                                percent=pct,
                                description=msg.strip(),
                                current_round=r,
                            ),
                            loop,
                        )
                    elif "[intake]" in msg:
                        asyncio.run_coroutine_threadsafe(
                            self.bus.emit_progress(
                                stage="EXTRACTING_CLOSURE",
                                percent=10.0,
                                description=msg.strip(),
                            ),
                            loop,
                        )
                    elif "[expand]" in msg:
                        asyncio.run_coroutine_threadsafe(
                            self.bus.emit_progress(
                                stage="EXTRACTING_CLOSURE",
                                percent=88.0,
                                description=msg.strip(),
                            ),
                            loop,
                        )
                except Exception:
                    pass

            # 异步执行 Neo4j 拓扑闭包展开
            if need_deps:
                raw_edges, closure_stats, deps = await loop.run_in_executor(
                    None,
                    functools.partial(extract_raw_closure, self.scenario_name, True, False, progress_callback),
                )
            else:
                raw_edges, closure_stats = await loop.run_in_executor(
                    None,
                    functools.partial(extract_raw_closure, self.scenario_name, False, False, progress_callback),
                )
                deps = None

            anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]

            await self.bus.emit_log(
                f"拓扑闭包计算完成：展开 {closure_stats.get('closure_rounds', 0)} 轮，收集 {len(raw_edges)} 条候选边，耗时 {closure_stats.get('closure_time_seconds', 0):.2f}s"
            )

            # 2. 符号规则匹配阶段与闭包指标同步
            await self.sm.transition_to(
                InvestigationStage.MATCHING_RULES,
                {
                    "raw_candidate_edges": len(raw_edges),
                    "closure_time_seconds": float(closure_stats.get("closure_time_seconds") or 0.0),
                    "anchor_count": len(anchor_triples),
                },
            )
            await self.bus.emit_progress("MATCHING_RULES", 90.0, "加载准入规则库，执行 Fisher-FDR 显著性因果基模匹配...")
            patterns, library_audit = load_patterns(self.mode, self.rules_from)
            await self.bus.emit_log(f"已装载因果拓扑基模规则库，规则数: {len(patterns)} 条")

            # 3. 路由推理与仲裁
            t_route_0 = time.time()
            llm_channel = LlmChannel(deps=deps) if (need_deps and deps is not None) else None

            # 执行主干路由决策
            await self.bus.emit_log(
                f"正在执行因果拓扑双向路由编排 (模式: {self.mode}, LOR>={self.params.matcher_min_lor}, Prec>={int(self.params.matcher_min_conf*100)}%)..."
            )
            outcome = await loop.run_in_executor(
                None,
                functools.partial(
                    route,
                    [],
                    raw_edges,
                    anchor_triples,
                    patterns=patterns,
                    llm_channel=llm_channel,
                    mode=self.mode,
                    min_conf=self.params.matcher_min_conf,
                    min_lor=self.params.matcher_min_lor,
                ),
            )
            route_time = time.time() - t_route_0

            confirmed_raw_edges = list(outcome.confirmed.values())
            await self.bus.emit_log(
                f"因果拓扑路由收敛：确认攻击边 {len(outcome.confirmed)} 条，未排除候选边 {len(outcome.unexcluded)} 条，排除噪声边 {len(outcome.excluded)} 条"
            )

            # 4. 前端画布投影与图拓扑推流
            # 为确保 Web 渲染帧率与图可读性，对大规模重复文件执行骨干投影
            canvas_raw_edges = self._project_canvas_edges(confirmed_raw_edges)
            confirmed_nodes = self._extract_nodes_from_edges(canvas_raw_edges)
            confirmed_items = [
                self._normalize_edge(
                    edge,
                    status="confirmed",
                    confirmed_by=str(edge.get("motif_name") or edge.get("motif") or "anchor"),
                )
                for edge in canvas_raw_edges
            ]

            # 提取代表性高危基模事件推流（最多 40 条，避免事件拥塞）
            unique_motifs: set[str] = set()
            for edge in confirmed_raw_edges:
                motif_id = str(edge.get("motif") or "")
                if motif_id and motif_id not in unique_motifs:
                    unique_motifs.add(motif_id)
                    motif_name = str(edge.get("motif_name") or motif_id)
                    await self.bus.emit("rule_matched", {
                        "edge_id": f"e_{edge.get('src')}_{edge.get('syscall')}_{edge.get('dst')}",
                        "motif_id": motif_id,
                        "motif_name": motif_name,
                        "confidence": float(edge.get("precision") or 1.0),
                    })
                    if len(unique_motifs) >= 40:
                        break

            # 图拓扑元素写入状态机并推流
            await self.sm.record_graph_elements(nodes=confirmed_nodes, edges=confirmed_items)
            await self.bus.flush()

            # 生成报告落盘（保存全量无损的全部确诊边）
            elapsed = time.time() - start_time
            llm_calls = deps.budget.calls if (deps and deps.budget) else 0
            report = build_report_from_outcome(
                outcome,
                self.scenario_name,
                elapsed_seconds=elapsed,
                llm_calls=llm_calls,
                llm_enabled=need_deps,
            )
            Path(self.output_report).parent.mkdir(parents=True, exist_ok=True)
            save_report(report, self.output_report)
            await self.bus.emit_log(f"取证报告已生成并持久化落盘: {self.output_report}")

            # 5. 转移至完成态
            await self.bus.emit_progress("COMPLETED", 100.0, "全流程因果调查收敛完成")
            await self.sm.transition_to(
                InvestigationStage.COMPLETED,
                {
                    "confirmed_count": len(outcome.confirmed),
                    "unexcluded_count": len(outcome.unexcluded),
                    "excluded_count": len(outcome.excluded),
                    "canvas_nodes_count": len(confirmed_nodes),
                    "canvas_edges_count": len(confirmed_items),
                    "elapsed_seconds": elapsed,
                    "route_seconds": route_time,
                    "llm_calls": llm_calls,
                },
            )

        except Exception as exc:
            self.sm.fail(str(exc))
            await self.bus.emit_log(f"调查任务异常中断: {exc}", level="error")
            await self.sm.transition_to(InvestigationStage.FAILED, {"error": str(exc)})
            raise exc
