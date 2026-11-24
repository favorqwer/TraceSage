"""逐规则先验：从冻结覆盖表 + 折掩码计算攻击/背景/忽略命中与查准率。

关键口径：
- 测场景 k 的整块位必须从掩码中剔除；分母只算掩码内位数。
- `GapStore.total_keys()` 是全局位数，不能直接当分母。
- 查准率分母 = attack_hits + background_hits；ignore 边不计入分母。
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

_NAV = Path(__file__).resolve().parents[1]
if str(_NAV) not in sys.path:
    sys.path.insert(0, str(_NAV))


@dataclass(frozen=True)
class RuleStats:
    motif_id: str
    hits_total: int
    attack_hits: int
    background_hits: int
    ignore_hits: int
    precision: Optional[float]
    train_keys: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def fold_mask(total_bits: int, offset: int, size: int) -> int:
    """全部位中剔除 [offset, offset+size) 这一块，得到训练折掩码。"""
    if total_bits <= 0:
        return 0
    full = (1 << total_bits) - 1
    block = ((1 << size) - 1) << offset if size > 0 else 0
    return full & ~block


def compute_rule_stats(rule_bitmaps: Dict[str, int], pos_bitmap: int, ignore_bitmap: int,
                       mask: int, motif_ids: Iterable[str]) -> Dict[str, RuleStats]:
    """对给定规则集合，逐条计算掩码内的攻击/背景/忽略命中与查准率。"""
    pos = int(pos_bitmap) & mask
    ignore = int(ignore_bitmap) & mask
    background = mask & ~pos & ~ignore
    train_keys = mask.bit_count()
    out: Dict[str, RuleStats] = {}
    for mid in motif_ids:
        rb = int(rule_bitmaps.get(str(mid), 0)) & mask
        attack = (rb & pos).bit_count()
        bg = (rb & background).bit_count()
        ign = (rb & ignore).bit_count()
        denom = attack + bg
        out[str(mid)] = RuleStats(
            motif_id=str(mid),
            hits_total=rb.bit_count(),
            attack_hits=attack,
            background_hits=bg,
            ignore_hits=ign,
            precision=(attack / denom if denom else None),
            train_keys=train_keys,
        )
    return out


_FROZEN_CACHE: Optional[tuple] = None


def _load_frozen_cached() -> tuple:
    """进程内缓存冻结库/覆盖表，避免 10 折重复加载同一个大 JSON。"""
    global _FROZEN_CACHE
    if _FROZEN_CACHE is None:
        from run_loo_folds import load_frozen
        _FROZEN_CACHE = load_frozen()
    return _FROZEN_CACHE


def clear_frozen_cache() -> None:
    global _FROZEN_CACHE
    _FROZEN_CACHE = None


def load_fold_rule_stats(scenario: str, fold_library_path: str | Path,
                         motif_ids: Optional[Iterable[str]] = None) -> Dict[str, RuleStats]:
    """加载冻结覆盖表，按测场景去掉整块位，计算指定规则（默认 selected）的统计。"""
    from run_loo_folds import offsets_of

    _name, _lib_path, payload, bm, _store = _load_frozen_cached()
    order, offsets = offsets_of(payload, bm)
    if scenario not in offsets:
        raise KeyError(f"场景不在冻结覆盖表中：{scenario}")
    size = int(payload["pool_sizes"][scenario])
    mask = fold_mask(int(bm["total"]), int(offsets[scenario]), size)

    fold = json.loads(Path(fold_library_path).read_text(encoding="utf-8"))
    if motif_ids is None:
        motif_ids = [str(x) for x in (fold.get("selected") or [])]
    return compute_rule_stats(
        bm["rule_bitmaps"], int(bm["pos"]), int(bm["ignore"]), mask, motif_ids)


def stats_to_dict(stats: Dict[str, RuleStats]) -> Dict[str, Dict[str, Any]]:
    return {mid: rec.to_dict() for mid, rec in stats.items()}
