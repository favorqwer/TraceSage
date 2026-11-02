"""规则库装载：折库、全量库、现蒸馏与角色档位还原。"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import settings as cfg
from rules import offline as frozen
from rules.offline import OfflineDistiller

def load_rule_matcher() -> Any:
    """加载评测口径的规则匹配器；只在 fresh 蒸馏时使用。"""
    tools = cfg.REPO_ROOT / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import rules_match
    return rules_match


FOLD_LIB_DIR = cfg.fold_library_dir()


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
    from closure import extract_raw_closure
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

    from closure import list_scenarios
    train_scenarios = list(scenarios or list_scenarios())
    provider = pool_provider or make_pool_provider()
    distiller = OfflineDistiller(rule_matcher=rule_matcher or load_rule_matcher())
    patterns = distiller.distill(train_scenarios, pool_provider=provider)
    print(f"  现蒸馏规则库：训练集 = {len(train_scenarios)} 个场景 → 入选 {len(patterns)} 条")
    return patterns, dict(distiller.last_report)


def _role_cuts(audit: Any) -> Any:
    """从规则库审计信息还原角色档位分界（离线在线共用同一组）。"""
    try:
        from rules.roles import RoleCuts
        return RoleCuts.from_dict((audit or {}).get("role_cuts"))
    except Exception:  # noqa: BLE001 - 缺字段退回默认档位
        return None
