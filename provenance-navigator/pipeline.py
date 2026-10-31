"""单次调查装配：闭包 → 规则库 → 路由 → 三段报告。

`main.py` 与 `run_loo_folds.py` 只负责 CLI 与折循环，不再各自复制装配逻辑。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from closure import extract_raw_closure, list_scenarios
from common import config as cfg
from llm.judge import LlmChannel
from routing.report import build_report_from_outcome, save_report
from routing.route import route
from rules import offline as frozen
from rules.offline import OfflineDistiller


def load_rule_matcher() -> Any:
    """加载评测口径的规则匹配器；只在 fresh 蒸馏时使用。"""
    tools = cfg.REPO_ROOT / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import rules_match
    return rules_match


FOLD_LIB_DIR = cfg.REPO_ROOT / "output" / "navigator-baseline" / "distill" / "fold-libraries"


def fold_library_path(scenario: str) -> Optional[Path]:
    """留一折库：测场景 k 时只由其余场景蒸馏出的那份库。没有就返回 None。"""
    p = FOLD_LIB_DIR / f"{scenario}.json"
    return p if p.is_file() else None


def load_library_file(path: Any) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """读一份规则库文件（留一折库或全量库都行），返回（准入形态清单, 审计信息）。"""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"未找到规则库文件: {p}")
    lib = json.loads(p.read_text(encoding="utf-8"))
    if not lib.get("motifs") or lib.get("selected") is None:
        raise RuntimeError(f"规则库文件缺 motifs/selected 字段: {p}")
    picked = set(str(x) for x in lib["selected"])
    patterns = [m for m in lib["motifs"] if str(m.get("id")) in picked]
    fp = lib.get("fingerprint")
    audit = {
        "path": str(p),
        "train_scenarios": list(lib.get("train_scenarios") or []),
        "generated_at": lib.get("generated_at"),
        "fingerprint": fp.get("digest") if isinstance(fp, dict) else fp,
        "role_cuts": lib.get("role_cuts"),
        "motifs": lib["motifs"],
        "selected": list(lib["selected"]),
        "greedy_trace": lib.get("greedy_trace") or [],
        "stats": lib.get("stats") or {},
        "fold_library": bool(lib.get("test_scenario")),
        "test_scenario": lib.get("test_scenario"),
    }
    return patterns, audit


def make_pool_provider() -> Callable[[str], List[Dict[str, Any]]]:
    """训练候选池提供器：同一运行期内每个场景只现算一次轻量闭包。"""
    cache: Dict[str, List[Dict[str, Any]]] = {}

    def provider(scenario: str) -> List[Dict[str, Any]]:
        if scenario not in cache:
            edges, _stats = extract_raw_closure(scenario, light=True)
            cache[scenario] = edges
        return cache[scenario]

    return provider


def load_patterns(mode: str, rules_from: str, *,
                  scenarios: Optional[List[str]] = None,
                  pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                  rule_matcher: Any = None,
                  library: Optional[tuple] = None,
                  scenario: Optional[str] = None,
                  library_path: Optional[str] = None) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """按模式与来源取规则清单；llm-only 不读规则库。

    frozen 的取库顺序：显式 library → 显式 library_path → 该场景自己的留一折库 →
    全量库。留一折库存在时绝不退回全量库（那会把测试场景自己的答案带进来）。
    """
    if mode == "llm-only":
        return [], {}
    if library is not None:
        patterns, audit = library
        return list(patterns), dict(audit)
    if library_path:
        patterns, audit = load_library_file(library_path)
        print(f"  规则库：{Path(library_path).name}（显式指定，训练场景 "
              f"{len(audit['train_scenarios'])} 个）")
        return patterns, audit
    if rules_from == "frozen":
        fp = fold_library_path(scenario) if scenario else None
        if fp is not None:
            patterns, audit = load_library_file(fp)
            if audit["test_scenario"] != scenario:
                raise RuntimeError(f"折库 {fp} 标注的测试场景是 {audit['test_scenario']}，"
                                   f"与本次调查的 {scenario} 不符")
            if scenario in audit["train_scenarios"]:
                raise RuntimeError(f"折库 {fp} 的训练场景里出现了被测试场景 {scenario}")
            print(f"  规则库：{fp.name}（留一折库，训练场景 {len(audit['train_scenarios'])} 个，"
                  f"不含 {scenario}，候选形态 {len(audit['motifs'])} 条 → 准入 {len(audit['selected'])} 条）")
            return patterns, audit
        patterns, audit = frozen.load_library()
        print(f"  规则库：{audit['path']}（全量库：本场景没有留一折库，视为未参与训练的新场景；"
              f"训练场景 {len(audit['train_scenarios'])} 个，"
              f"候选形态 {len(audit.get('motifs') or [])} 条",
              f"→ 准入 {len(audit.get('selected') or [])} 条）")
        return patterns, audit

    train_scenarios = list(scenarios or list_scenarios())
    provider = pool_provider or make_pool_provider()
    distiller = OfflineDistiller(rule_matcher=rule_matcher or load_rule_matcher())
    patterns = distiller.distill(train_scenarios, pool_provider=provider)
    print(f"  现蒸馏规则库：训练集 = {len(train_scenarios)} 个场景 → 入选 {len(patterns)} 条")
    return patterns, dict(distiller.last_report)


def _role_cuts(audit: Any) -> Any:
    """从规则库审计信息还原角色档位分界（离线在线共用同一组）。"""
    try:
        from common.roles import RoleCuts
        return RoleCuts.from_dict((audit or {}).get("role_cuts"))
    except Exception:  # noqa: BLE001 - 缺字段退回默认档位
        return None


def investigate(scenario_name: str, *,
                mode: str = "rules",
                rules_from: str = "frozen",
                input_report: Optional[str] = None,
                output_report: Optional[str] = None,
                pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                rule_matcher: Any = None,
                train_scenarios: Optional[List[str]] = None,
                library: Optional[tuple] = None,
                library_path: Optional[str] = None,
                return_audit: bool = False) -> Any:
    """跑一次完整调查，返回报告字典（同时落盘到 output_report）。"""
    start_time = time.time()
    closure_stats: Dict[str, Any] = {}
    if not output_report:
        output_report = f"output/navigator-runs/{scenario_name}.json"

    all_scenarios = list_scenarios()
    if scenario_name not in all_scenarios:
        raise KeyError(f"未知场景 {scenario_name}；可选场景: {all_scenarios}")

    need_deps = mode in ("hybrid", "llm-only")
    deps = None
    anchor_triples: List[tuple] = []

    if input_report:
        if not Path(input_report).exists():
            raise FileNotFoundError(f"未找到输入候选文件: {input_report}")
        with open(input_report, "r", encoding="utf-8") as f:
            data = json.load(f)
        confirmed_edges = data.get("edges", [])
        unexcluded_edges = data.get("unexcluded", [])
        excluded_edges = data.get("excluded", [])
        print(f"[{scenario_name}] 从已有报告加载: {input_report} "
              f"(确认边={len(confirmed_edges)}, 未排除={len(unexcluded_edges)})")
    else:
        print(f"[{scenario_name}] 正在直连 Neo4j 图数据库，从 POI 终点事件自主展开反向因果闭包...")
        if need_deps:
            raw_edges, closure_stats, deps = extract_raw_closure(
                scenario_name, return_deps=True
            )
        else:
            raw_edges, closure_stats = extract_raw_closure(scenario_name, return_deps=False)
        anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]
        confirmed_edges = []
        unexcluded_edges = raw_edges
        excluded_edges = []
        print(f"[{scenario_name}] 因果闭包完成: 原始候选边={len(raw_edges)} 条 "
              f"(闭包耗时: {closure_stats['closure_time_seconds']:.2f}s, "
              f"POI 锚点 {len(anchor_triples)} 条)")

    patterns, library_audit = load_patterns(
        mode, rules_from, scenarios=train_scenarios, pool_provider=pool_provider,
        rule_matcher=rule_matcher, library=library, scenario=scenario_name,
        library_path=library_path,
    )

    t_route_0 = time.time()
    llm_channel = LlmChannel(deps=deps) if (need_deps and deps is not None) else None
    outcome = route(
        confirmed_edges,
        unexcluded_edges,
        anchor_triples=anchor_triples,
        patterns=patterns,
        llm_channel=llm_channel,
        mode=mode,
        admitted=library_audit.get("selected"),
        role_cuts=_role_cuts(library_audit),
    )
    route_time = time.time() - t_route_0

    elapsed = time.time() - start_time
    llm_calls = deps.budget.calls if (deps and deps.budget) else 0
    report = build_report_from_outcome(
        outcome, scenario_name,
        elapsed_seconds=elapsed,
        llm_calls=llm_calls,
        llm_enabled=need_deps,
        library={
            "path": library_audit.get("path"),
            "generated_at": library_audit.get("generated_at"),
            "digest": library_audit.get("fingerprint"),
            "n_selected": len(library_audit.get("selected") or []),
            "n_candidates": len(library_audit.get("motifs") or []),
            "mode": mode,
            "fold_library": bool(library_audit.get("fold_library")),
            "test_scenario": library_audit.get("test_scenario"),
            "train_scenarios": list(library_audit.get("train_scenarios") or []),
        },
    )
    Path(output_report).parent.mkdir(parents=True, exist_ok=True)
    save_report(report, output_report)

    audit = dict(outcome.audit)
    audit.update({
        "raw_closure_edges": len(raw_edges),
        "closure_seconds": float(closure_stats.get("closure_time_seconds") or 0.0),
        "anchor_count": len(anchor_triples),
        "route_seconds": route_time,
        "elapsed_seconds": elapsed,
        "library_audit": library_audit,
    })
    print(f"[{scenario_name}] 调查完成（模式: {mode}）:")
    print(f"  已确认边数: {len(report['edges'])} 条 "
          f"(锚点强制确认 {audit['anchor_confirmed_count']} 条)")
    print(f"  因果初筛剥离背景: {audit['pruned_count']} 条")
    print(f"  抽象基模与桥接确认: {audit['promoted_count']} 条 "
          f"({', '.join(f'{k}×{v}' for k, v in audit['promoted_by_motif'].items()) or '无'})")
    print(f"  大模型仲裁确认: {audit['llm_confirmed_count']} 条 (模型调用: {llm_calls} 次)")
    print(f"  未排除保留候选边: {len(report['unexcluded'])} 条")
    print(f"  总耗时: {elapsed:.2f} 秒 (图闭包: {elapsed - route_time:.2f}s, "
          f"符号路由: {route_time:.3f}s)")
    print(f"  输出报告: {output_report}")
    return (report, audit) if return_audit else report
