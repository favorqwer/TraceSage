"""留一交叉（规则模式）：每个场景只用「其余 9 个场景」蒸馏出的规则库测一次。

阶段一（离线，不查图）
  1. 读冻结规则库的覆盖表，得到 10 个场景各自的候选边池、三值标签、端点表；
  2. 每个场景建一次角色上下文（RoleContext），10 折共用；
  3. 每折用其余 9 个场景的合并上下文算档位分界，只在这些场景的攻击边上枚举形态；
  4. 命中位图：档位与冻结库相同时直接用覆盖表里已存的下标（等价于冻结位图），
     不同时按该档位重算一遍（同一档位的折共用一个位图集）；
  5. 每折只在自己的 9 个场景上跑贪心选名单，落一份折库。

位图一律由 rules.coverage.CoverageStore / ScenarioShard 自己的打包代码生成，
本文件不手写任何位运算拼接。

阶段二（在线，只抽 10 个场景的闭包各一次）
  6. 场景 k 用「不含 k」的那份折库路由，评分；
  7. 汇总：逐场景 + 合并平均（微平均）+ 最小值/中位数/最大值 + 分母占比。

自检：
  python provenance-navigator/run_loo_folds.py --selftest
      只走冻结档位那一组（直接读覆盖表里已存的命中），断言重建位图与冻结库逐位相同。
      断言不过立即中止，不进入任何重算与评测。

正式跑：
  python provenance-navigator/run_loo_folds.py --out output/navigator-runs/loo
  单折试跑：--only 6_Web_SQLi_Data_Exfiltration
"""

from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import json
import pickle
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPO = BASE_DIR.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(REPO))

from pipeline import investigate, load_rule_matcher  # noqa: E402
from rules.roles import build_context, merge_contexts  # noqa: E402
from rules.admission import assign_ids, compute_hits, greedy_select, motif_sort_key  # noqa: E402
from rules.coverage import CoverageStore, load_bitmaps  # noqa: E402
from rules.offline import FrequentSubgraphMiner  # noqa: E402

LIBDIR = BASE_DIR / "config" / "rules-library"
CACHE_DIR = REPO / "tmp" / "loo_run" / "bitmap_cache"


def log(msg):
    print(msg, flush=True)


def die(msg):
    raise SystemExit(f"[阻断] {msg}")


# ---------- 冻结产物 ----------

def load_frozen():
    name = (LIBDIR / "latest.txt").read_text(encoding="utf-8").strip()
    lib_path = LIBDIR / name
    payload = json.loads(lib_path.read_text(encoding="utf-8"))
    bm = load_bitmaps(lib_path.with_suffix(".bitmaps.bin"))
    cov_path = LIBDIR / payload["coverage_table_ref"]
    store = CoverageStore.from_payload(
        json.loads(gzip.decompress(cov_path.read_bytes()).decode("utf-8")))
    if sum(payload["pool_sizes"][s] for s in payload["train_scenarios"]) != bm["total"]:
        die("覆盖表位数与各场景池子之和不符")
    return name, lib_path, payload, bm, store


def offsets_of(payload, bm):
    order = list(payload["train_scenarios"])
    off, o = {}, 0
    for s in order:
        off[s] = o
        o += payload["pool_sizes"][s]
    if o != bm["total"]:
        die("场景偏移量之和与位图位数不符")
    return order, off


# ---------- 位图：只用库自带代码 ----------

class LightShard:
    """只保留 CoverageStore 生成位图所需的字段（不复制 keys/idents，省内存）。"""

    __slots__ = ("name", "n_keys", "pos", "ignore", "neg", "hits")

    def __init__(self, name, n_keys, pos, ignore, neg, hits):
        self.name = name
        self.n_keys = n_keys
        self.pos = pos
        self.ignore = ignore
        self.neg = neg
        self.hits = hits


def build_group_bits(order, store, cuts, motifs, rm, use_stored_hits):
    """生成一组档位下的命中位图。

    use_stored_hits=True：命中直接取覆盖表已存的（即冻结档位），不重算。
    """
    gs = CoverageStore()
    t0 = time.time()
    for name in order:
        sh = store.shards[name]
        if use_stored_hits:
            hits = sh.hits
        else:
            edges = sh.edge_dicts()
            hits = compute_hits(edges, motifs, rm, role_cuts=cuts)
            del edges
            gc.collect()
        gs.add(LightShard(name, sh.n_keys, sh.pos, sh.ignore, sh.neg, hits))
    bits = {m["id"]: gs.rule_bitmap(m["id"]) for m in motifs}
    log(f"  位图生成完成（CoverageStore.rule_bitmap）：用时 {time.time() - t0:.1f}s")
    return {"total": gs.total_keys(), "pos": gs.label_bitmap("pos"),
            "ignore": gs.label_bitmap("ignore"), "rules": bits}


def cache_file(cuts_key, ids, lib_name):
    h = hashlib.sha1(json.dumps([lib_name, cuts_key, sorted(ids)]).encode("utf-8")).hexdigest()[:16]
    return CACHE_DIR / f"{h}.pkl"


def cache_load(cuts_key, ids, lib_name):
    f = cache_file(cuts_key, ids, lib_name)
    if not f.is_file():
        return None
    try:
        with open(f, "rb") as fh:
            return pickle.load(fh)
    except Exception:  # noqa: BLE001 - 缓存坏了当没有
        return None


def cache_save(cuts_key, ids, lib_name, payload):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(cache_file(cuts_key, ids, lib_name), "wb") as fh:
        pickle.dump(payload, fh, protocol=4)


# ---------- 阶段一 ----------

def build_fold_libraries(order, store, payload, bm, lib_name, wanted=None):
    total = bm["total"]
    sizes = [payload["pool_sizes"][s] for s in order]
    frozen_cuts = json.dumps(payload.get("role_cuts"), sort_keys=True)
    frozen_rules = bm["rule_bitmaps"]

    log("建角色上下文（每场景一次，10 折共用）…")
    t0 = time.time()
    ctxs, pos_edges = {}, {}
    for name in order:
        sh = store.shards[name]
        edges = sh.edge_dicts()
        ctxs[name] = build_context(edges)
        keep = set(sh.pos)
        pos_edges[name] = [{"src": e["src"], "syscall": e["syscall"], "dst": e["dst"]}
                           for i, e in enumerate(edges) if i in keep]
        del edges
        gc.collect()
    log(f"  上下文完成，用时 {time.time() - t0:.1f}s")

    miner = FrequentSubgraphMiner(min_support=1)
    rm = load_rule_matcher()
    folds = {}
    for k in order:
        if wanted and k not in wanted:
            continue
        nine = [s for s in order if s != k]
        cuts = merge_contexts(ctxs[n] for n in nine).to_cuts()
        folds[k] = {
            "train": nine,
            "cuts": cuts,
            "cuts_key": json.dumps(cuts.to_dict(), sort_keys=True),
            "motifs": assign_ids(miner.mine({n: pos_edges[n] for n in nine},
                                            {n: ctxs[n] for n in nine}, cuts)),
        }
    log("形态枚举完成：" + ", ".join(f"{k.split('_')[0]}={len(v['motifs'])}"
                                for k, v in folds.items()))

    groups = {}
    for k, f in folds.items():
        groups.setdefault(f["cuts_key"], []).append(k)

    group_maps = {}
    for gi, (cuts_key, members) in enumerate(groups.items(), 1):
        cuts = folds[members[0]]["cuts"]
        use_stored = (cuts_key == frozen_cuts)
        by_id = {}
        for k in members:
            for m in folds[k]["motifs"]:
                by_id[m["id"]] = m
        ids = sorted(by_id)
        uni = [by_id[i] for i in ids]
        log(f"[档位 {gi}/{len(groups)}] {cuts_key}｜折 {len(members)} 个｜形态 {len(uni)} 条｜"
            + ("读覆盖表已存命中（冻结档位，不重算）" if use_stored else "重算命中"))

        got = None if use_stored else cache_load(cuts_key, ids, lib_name)
        if got is None:
            got = build_group_bits(order, store, cuts, uni, rm, use_stored)
            if not use_stored:
                cache_save(cuts_key, ids, lib_name, got)
        else:
            log("  位图取自已缓存的重算结果")

        if got["total"] != total:
            die(f"位图总位数 {got['total']} 与冻结库 {total} 不符")
        if got["pos"] != bm["pos"] or got["ignore"] != bm["ignore"]:
            die("重建的 pos/ignore 标签位图与冻结库不一致")
        if use_stored:
            bad = [m for m in ids if got["rules"].get(m, 0) != frozen_rules.get(m, 0)]
            if bad:
                die(f"冻结档位下 {len(bad)} 条形态位图与冻结库不一致，例：{bad[:3]}")
            log(f"  断言·冻结档位逐位相同：通过（{len(ids)} 条形态）")
        else:
            common = [m for m in ids if m in frozen_rules]
            a = sum(got["rules"].get(m, 0).bit_count() for m in common)
            b = sum(frozen_rules[m].bit_count() for m in common)
            ratio = a / b if b else 0.0
            if not (0.5 <= ratio <= 2.0):
                die(f"重算位图总位数是冻结值的 {ratio:.3f} 倍，超出 0.5~2.0，判定计算有误")
            log(f"  断言·量级一致：通过（{a} / 冻结 {b} = {ratio:.3f}）")
        group_maps[cuts_key] = got

    full_mask = (1 << total) - 1
    off, o = {}, 0
    for s, n in zip(order, sizes):
        off[s] = o
        o += n
    out = {}
    for k, f in folds.items():
        lo, n = off[k], sizes[order.index(k)]
        mask = full_mask & ~(((1 << n) - 1) << lo)
        got = group_maps[f["cuts_key"]]
        ids = [m["id"] for m in f["motifs"]]
        keys = {m["id"]: motif_sort_key(m) for m in f["motifs"]}
        st = GapStore(total, got["pos"], got["ignore"], got["rules"], mask)
        res = greedy_select(st, ids, keys)
        if not res["selected"]:
            die(f"折 {k} 没有选出任何形态")
        if res["stats"]["coverage_rate"] < 0.95:
            die(f"折 {k} 训练集攻击边覆盖率仅 {res['stats']['coverage_rate']:.3f}，低于 0.95")
        empty = [m for m in res["selected"] if not got["rules"].get(m, 0)]
        if empty:
            die(f"折 {k} 有 {len(empty)} 条入选形态位图为空")

        by_id = {m["id"]: m for m in f["motifs"]}
        selected_motifs = []
        for step in res["trace"]:
            rec = dict(by_id[step["rule"]])
            rec.update(greedy_step=step["step"], greedy_gain=step["gain"],
                       greedy_cost=step["cost"], greedy_efficiency=step["efficiency"])
            selected_motifs.append(rec)

        pos_k = (got["pos"] >> lo) & ((1 << n) - 1)
        cov = 0
        for mid in res["selected"]:
            cov |= (got["rules"].get(mid, 0) >> lo) & pos_k
        out[k] = {
            "test_scenario": k,
            "train_scenarios": f["train"],
            "role_cuts": f["cuts"].to_dict(),
            "motifs": f["motifs"],
            "selected": res["selected"],
            "selected_motifs": selected_motifs,
            "greedy_trace": res["trace"],
            "stats": res["stats"],
            "pool_sizes": {s: payload["pool_sizes"][s] for s in f["train"]},
            "gt_edge_coverage": {"covered": cov.bit_count(), "total": pos_k.bit_count()},
        }
        log(f"  折 {k.split('_')[0]}：入选 {len(res['selected'])} 条｜训练集攻击边覆盖 "
            f"{res['stats']['coverage_rate'] * 100:.1f}%｜测试场景池内攻击边覆盖 "
            f"{cov.bit_count()}/{pos_k.bit_count()}")
    return out


class GapStore:
    """只暴露 greedy_select 需要的三个方法；位位置与冻结库一致，按掩码剔除某些场景的块。"""

    def __init__(self, total, pos, ignore, rules, mask):
        self._total = total
        self._pos = pos & mask
        self._ignore = ignore & mask
        self._rules = {k: v & mask for k, v in rules.items()}

    def total_keys(self):
        return self._total

    def label_bitmap(self, label):
        return self._pos if label == "pos" else self._ignore

    def rule_bitmap(self, mid):
        return self._rules.get(mid, 0)


# ---------- 阶段二 ----------

def evaluate(fold_libs, out_dir, mode="rules", keep_dir=None):
    tmp = REPO / "tmp" / "loo_run" / "reports"
    tmp.mkdir(parents=True, exist_ok=True)
    if keep_dir:
        keep_dir = REPO / keep_dir
        keep_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for i, (k, lib) in enumerate(fold_libs.items(), 1):
        t0 = time.time()
        sel = set(lib["selected"])
        patterns = [m for m in lib["motifs"] if m["id"] in sel]
        audit = {
            "path": str(out_dir / "library" / f"{k}.json"),
            "train_scenarios": lib["train_scenarios"],
            "generated_at": lib.get("generated_at"),
            "fingerprint": lib.get("fingerprint"),
            "role_cuts": lib["role_cuts"],
            "motifs": lib["motifs"],
            "selected": lib["selected"],
            "greedy_trace": lib["greedy_trace"],
            "stats": lib["stats"],
            "fold_library": True,
            "test_scenario": k,
        }
        log(f"[{i}/{len(fold_libs)}] 测试场景 {k}（库来自其余 {len(lib['train_scenarios'])} 个场景，"
            f"入选 {len(patterns)} 条形态）…")
        rep_path = tmp / f"{k}.json"
        report, aud = investigate(k, mode=mode, library=(patterns, audit),
                                  output_report=str(rep_path), return_audit=True)
        ev_path = tmp / f"eval_{k}.json"
        subprocess.run([sys.executable, "tools/score_report_product.py",
                        "--report", str(rep_path),
                        "--gt", f"groundtruth/{k}.groundtruth.json",
                        "--json-out", str(ev_path)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ev = json.loads(ev_path.read_text(encoding="utf-8"))["scenarios"][0]
        if keep_dir:
            name = f"rules_{k}.json" if mode == "rules" else f"{k}.json"
            shutil.copyfile(rep_path, keep_dir / name)
        rep_path.unlink(missing_ok=True)
        ev_path.unlink(missing_ok=True)
        row = {
            "scenario": k,
            "train_scenarios": lib["train_scenarios"],
            "role_cuts": lib["role_cuts"],
            "n_motifs": len(lib["motifs"]),
            "n_selected": len(lib["selected"]),
            "gt_edge_coverage": lib["gt_edge_coverage"],
            "raw_closure_edges": aud.get("raw_closure_edges", 0),
            "anchor_confirmed": aud.get("anchor_confirmed_count", 0),
            "promoted": aud.get("promoted_count", 0),
            "promoted_by_motif": aud.get("promoted_by_motif") or {},
            "llm_calls": (report.get("stats") or {}).get("llm_calls", 0),
            "confirmed_edges": len(report.get("edges") or []),
            "unexcluded_edges": len(report.get("unexcluded") or []),
            "hit": ev["steps_hit"],
            "total": ev["steps_total"],
            "recall": ev["recall"],
            "correct": ev["correct_edges"],
            "reported": ev["reported_triples"],
            "precision": ev["precision"],
            "extra": ev["extra_triples"],
            "elapsed": time.time() - t0,
        }
        results.append(row)
        log(f"      召回 {row['hit']}/{row['total']} ({row['recall'] * 100:.1f}%)｜"
            f"查准 {row['correct']}/{row['reported']} ({row['precision'] * 100:.1f}%)｜"
            f"确认边 {row['confirmed_edges']}｜用时 {row['elapsed']:.1f}s")
    return results


def summarize(results, lib_name, folds_total, elapsed):
    hit = sum(r["hit"] for r in results)
    total = sum(r["total"] for r in results)
    correct = sum(r["correct"] for r in results)
    reported = sum(r["reported"] for r in results)
    rec = sorted(r["recall"] for r in results)
    pre = sorted(r["precision"] for r in results)
    return {
        "protocol": "留一交叉：测试场景的标准答案与其候选池不参与蒸馏，"
                    "每折规则库只由其余 9 个场景生成（含档位分界与形态枚举）",
        "mode": "rules（0 次大模型调用）",
        "source_library": lib_name,
        "folds": folds_total,
        "results": results,
        "micro": {
            "hit": hit, "total": total, "recall": hit / total if total else 0.0,
            "correct": correct, "reported": reported,
            "precision": correct / reported if reported else 0.0,
            "calls": sum(r["llm_calls"] for r in results),
            "elapsed": elapsed,
        },
        "distribution": {
            "recall_min": rec[0], "recall_median": rec[len(rec) // 2], "recall_max": rec[-1],
            "precision_min": pre[0], "precision_median": pre[len(pre) // 2],
            "precision_max": pre[-1],
        },
        "denominators": [{"scenario": r["scenario"], "steps": r["total"],
                          "reported": r["reported"],
                          "step_share": r["total"] / total if total else 0.0,
                          "report_share": r["reported"] / reported if reported else 0.0}
                         for r in results],
    }


# ---------- 入口 ----------

def main():
    ap = argparse.ArgumentParser(description="留一交叉：每个场景用其余 9 个场景蒸馏的规则库测试")
    ap.add_argument("--out", default="output/navigator-runs/loo")
    ap.add_argument("--mode", default="rules", choices=["rules", "hybrid"])
    ap.add_argument("--keep-reports", default="", help="把每折报告另存到这个目录")
    ap.add_argument("--only", default="", help="只跑一个场景")
    ap.add_argument("--selftest", action="store_true",
                    help="只做冻结档位的位图重建与逐位断言，不重算、不评测")
    args = ap.parse_args()

    t_all = time.time()
    lib_name, lib_path, payload, bm, store = load_frozen()
    order, _ = offsets_of(payload, bm)
    log(f"冻结库：{lib_name}（形态 {len(payload['motifs'])} / 入选 {len(payload['selected'])} / "
        f"池子 {bm['total']} 条）")

    if args.selftest:
        frozen_key = json.dumps(payload.get("role_cuts"), sort_keys=True)
        wanted = set(order)
        t0 = time.time()
        # 只跑冻结档位那一组：先用全部形态模拟，断言与冻结位图逐位相同
        miner = FrequentSubgraphMiner(min_support=1)
        rm = load_rule_matcher()
        ctxs = {n: build_context(store.shards[n].edge_dicts()) for n in order}
        eight_nine = {k: [s for s in order if s != k] for k in order}
        target = [k for k in order
                  if json.dumps(merge_contexts(ctxs[n] for n in eight_nine[k]).to_cuts().to_dict(),
                                sort_keys=True) == frozen_key]
        log(f"冻结档位的折：{[k.split('_')[0] for k in target]}（自检只验证其中一折）")
        k = target[0]
        nine = eight_nine[k]
        pos_edges = {n: [{"src": e["src"], "syscall": e["syscall"], "dst": e["dst"]}
                         for i, e in enumerate(store.shards[n].edge_dicts())
                         if i in set(store.shards[n].pos)] for n in nine}
        motifs = assign_ids(miner.mine(pos_edges, {n: ctxs[n] for n in nine},
                                       merge_contexts(ctxs[n] for n in nine).to_cuts()))
        got = build_group_bits(order, store, None, motifs, rm, use_stored_hits=True)
        bad = [m["id"] for m in motifs if got["rules"].get(m["id"], 0) != bm["rule_bitmaps"].get(m["id"], 0)]
        ok_pos = (got["pos"] == bm["pos"] and got["ignore"] == bm["ignore"])
        log(f"自检：形态 {len(motifs)} 条，位图不一致 {len(bad)} 条，"
            f"标签位图一致={ok_pos}，用时 {time.time() - t0:.1f}s")
        if bad or not ok_pos:
            die(f"自检失败，例：{bad[:3]}")
        log("自检通过：库自带位图代码重建结果与冻结库逐位相同")
        return

    out_dir = REPO / args.out
    (out_dir / "library").mkdir(parents=True, exist_ok=True)

    wanted = {args.only} if args.only else set(order)
    if args.only and args.only not in order:
        die(f"未知场景 {args.only}")

    t0 = time.time()
    fold_libs = build_fold_libraries(order, store, payload, bm, lib_name, wanted=wanted)
    log(f"阶段一完成，用时 {time.time() - t0:.1f}s")
    del store
    gc.collect()

    for k, lib in fold_libs.items():
        lib["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        lib["source_library"] = lib_name
        (out_dir / "library" / f"{k}.json").write_text(
            json.dumps(lib, ensure_ascii=False), encoding="utf-8")

    results = evaluate(fold_libs, out_dir, mode=args.mode, keep_dir=args.keep_reports or None)
    summary = summarize(results, lib_name, len(fold_libs), time.time() - t_all)
    summary["mode"] = ("rules（0 次大模型调用）" if args.mode == "rules"
                       else "hybrid（规则 + 大模型仲裁）")
    name = f"summary_{args.mode}.json" if not args.only else f"summary_{args.mode}_{args.only.split('_')[0]}.json"
    out_file = out_dir / name
    out_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    m = summary["micro"]
    log(f"\n合计（微平均）：召回 {m['hit']}/{m['total']} = {m['recall'] * 100:.1f}%｜"
        f"查准 {m['correct']}/{m['reported']} = {m['precision'] * 100:.1f}%｜"
        f"大模型调用 {m['calls']} 次")
    log(f"结果已写入 {out_file}")


if __name__ == "__main__":
    main()
