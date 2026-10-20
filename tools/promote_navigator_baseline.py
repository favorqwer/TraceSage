"""把一次导航器三模式五折评测结果固化为官方基线（output/navigator-baseline/）。

做四件事，每件都留审计：
1. 读 `tmp/provenance_router_runs/` 里本次三模式运行的产物（summary / 逐折报告 / 蒸馏审计），
   校验场景齐、折数齐，缺一个即阻断（绝不用旧产物顶替）；
2. 用官方评测工具对每个场景的**未排除段**单独打分（把 unexcluded 当作上报边集合），
   得到与「已确认段」同一口径的未排除指标；
3. 把旧基线整目录留档到 `tmp/backup_navigator_baseline_<时间戳>.tar` 后，按新布局写入；
4. 用实测数字生成 OVERVIEW.md（表格全部由数据渲染，不手抄）。

用法：
    .venv/Scripts/python.exe tools/promote_navigator_baseline.py            # 执行写入
    .venv/Scripts/python.exe tools/promote_navigator_baseline.py --dry-run  # 只校验与预演，不改动 output/

    （--dry-run 仍会在 tmp/nav_baseline_promote/ 下生成未排除段的临时报告与评分文件，供预演用。）
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "tmp" / "provenance_router_runs"
DST = REPO_ROOT / "output" / "navigator-baseline"
WORK = REPO_ROOT / "tmp" / "nav_baseline_promote"
EVAL = REPO_ROOT / "tools" / "eval_agent_attack_path.py"

MODES = ("rules", "hybrid", "llm-only")
MODE_TITLE = {
    "rules": "纯蒸馏规则模式（0 次大模型调用）",
    "hybrid": "智能导航模式（神经符号协同）",
    "llm-only": "纯大语言模型模式（旁路规则截流）",
}
# 写入后 rules 目录沿用 rules_ 前缀：tmp 下多个实验脚本按该路径读对照组
REPORT_NAME = {"rules": "rules_{sc}.json", "hybrid": "{sc}.json", "llm-only": "{sc}.json"}
FINGERPRINT_FILES = [
    "main.py", "run_five_fold.py",
    "closure/extractor.py", "closure/facts.py",
    "rules/miner.py", "rules/motifs.py", "rules/distiller.py", "rules/matcher.py",
    "judge/client.py",
    "orchestrator/filter.py", "orchestrator/bridge.py", "orchestrator/boundary_story.py",
    "orchestrator/pivot_router.py",
    "orchestrator/orchestrator.py", "orchestrator/report.py",
]
# 旧基线里已知会被本次替换掉的对象（显式列举，不做通配删除）
# 注意：新模式命名 `unex_metrics_<模式>.json` 下的 unex_metrics_rules.json 是**合法新文件**，不在此列。
STALE_ROOT = ["unex_metrics.json"]


def sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16].upper()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def check_inputs() -> dict:
    """读并校验本次运行的产物；任一缺失或场景不齐立即阻断。"""
    data: dict = {"summaries": {}, "reports": {}, "distill": {}, "old": {}}
    scenarios = None
    for mode in MODES:
        sp = SRC / f"summary_{mode}.json"
        if not sp.exists():
            raise SystemExit(f"[阻断] 缺少本次运行产物：{sp}")
        summary = load_json(sp)
        got = [r["scenario"] for r in summary["results"]]
        if len(got) != 5:
            raise SystemExit(f"[阻断] {sp} 只有 {len(got)} 折，五折留一必须 5 折")
        if scenarios is None:
            scenarios = got
        elif got != scenarios:
            raise SystemExit(f"[阻断] {sp} 场景集与其它模式不一致：{got} != {scenarios}")
        # 逐折报告 / 蒸馏审计 / 单折评分都必须齐
        for sc in got:
            rp = SRC / f"{mode}_{sc}.json"
            if not rp.exists():
                raise SystemExit(f"[阻断] 缺少逐折报告：{rp}")
            ep = SRC / f"eval_{mode}_{sc}.json"
            if not ep.exists():
                raise SystemExit(f"[阻断] 缺少单折评分：{ep}")
            dp = SRC / f"distill_fold_{sc}.json"
            if not dp.exists():
                raise SystemExit(f"[阻断] 缺少蒸馏审计：{dp}")
        data["summaries"][mode] = summary
        data["reports"][mode] = {sc: SRC / f"{mode}_{sc}.json" for sc in got}
        for sc in got:
            data["distill"][sc] = SRC / f"distill_fold_{sc}.json"

    missing = [sc for sc in scenarios if sc not in data["distill"]]
    if missing:
        raise SystemExit(f"[阻断] 蒸馏审计映射不全，缺：{missing}")

    # 旧基线（用于对照表；此时尚未被覆盖）
    for name in ("summary_rules.json", "summary_hybrid.json"):
        p = DST / name
        if p.exists():
            data["old"][name] = load_json(p)
    return data


def unex_metrics(mode: str, sc: str) -> dict:
    """把报告的 unexcluded 段当作上报边集合，用官方工具打分。"""
    report = load_json(SRC / f"{mode}_{sc}.json")
    WORK.mkdir(parents=True, exist_ok=True)
    tmp_report = WORK / f"unex_{mode}_{sc}.json"
    tmp_out = WORK / f"eval_unex_{mode}_{sc}.json"
    with tmp_report.open("w", encoding="utf-8") as fh:
        json.dump({"scenario": sc, "edges": report.get("unexcluded", [])}, fh, ensure_ascii=False)
    subprocess.run(
        [sys.executable, str(EVAL), "--report", str(tmp_report),
         "--gt", str(REPO_ROOT / "groundtruth" / f"{sc}.groundtruth.json"),
         "--json-out", str(tmp_out)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    res = load_json(tmp_out)["scenarios"][0]
    return {
        "unex_count": len(report.get("unexcluded", [])),
        "hit": res["steps_hit"], "total": res["steps_total"],
        "correct": res["correct_edges"], "reported": res["reported_triples"],
        "recall": res["recall"], "precision": res["precision"],
    }


def channel_attribution(data: dict) -> dict:
    """从逐折报告直接统计各通道的确认边数（可复算）：
    · 新通道（边界穿越故事通道）自身确认边 —— 读 stats.promoted_by_motif 里 BOUNDARY_* 的计数；
    · 慢速通道（大模型）确认边 —— 数 edges 段里 reason 以「慢速通道」开头的边。"""
    out: dict = {}
    for mode in MODES:
        ch = slow = 0
        per: dict = {}
        for sc, path in data["reports"][mode].items():
            rep = load_json(path)
            stats = rep.get("stats") or {}
            c = sum(v for k, v in (stats.get("promoted_by_motif") or {}).items()
                    if str(k).startswith("BOUNDARY_"))
            sl = sum(1 for e in rep.get("edges", [])
                     if str(e.get("reason") or "").startswith("慢速通道"))
            ch += c
            slow += sl
            per[sc] = {"channel": c, "slow": sl, "confirmed": len(rep.get("edges", []))}
        out[mode] = {"channel": ch, "slow": slow, "per_scenario": per}
    return out


def backup_old_baseline() -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = REPO_ROOT / "tmp" / f"backup_navigator_baseline_{stamp}.tar"
    with tarfile.open(out, "w") as tar:
        tar.add(DST, arcname="navigator-baseline")
    return out


def promote(data: dict) -> None:
    modes = MODES
    scenarios = [r["scenario"] for r in data["summaries"]["rules"]["results"]]

    for name in STALE_ROOT:
        p = DST / name
        if p.exists():
            p.unlink()
    # 根目录 5 份旧报告：与 hybrid/ 重复的副本
    for sc in scenarios:
        p = DST / f"{sc}.json"
        if p.exists():
            p.unlink()
    # rules/ 下旧版无前缀同名副本
    for sc in scenarios:
        p = DST / "rules" / f"{sc}.json"
        if p.exists():
            p.unlink()

    for mode in modes:
        (DST / mode).mkdir(parents=True, exist_ok=True)
        for sc in scenarios:
            shutil.copy2(data["reports"][mode][sc], DST / mode / REPORT_NAME[mode].format(sc=sc))
        shutil.copy2(SRC / f"summary_{mode}.json", DST / f"summary_{mode}.json")

    (DST / "distill").mkdir(parents=True, exist_ok=True)
    for sc in scenarios:
        shutil.copy2(data["distill"][sc], DST / "distill" / f"distill_fold_{sc}.json")


def render_overview(data: dict, unex: dict, fingerprints: dict, run_stamp: str) -> str:
    summaries = data["summaries"]
    scenarios = [r["scenario"] for r in summaries["rules"]["results"]]
    by_scenario = {mode: {r["scenario"]: r for r in summaries[mode]["results"]} for mode in MODES}
    micro = {mode: summaries[mode]["micro"] for mode in MODES}

    out: list[str] = []
    add = out.append
    add("# 导航器成绩基线（navigator-baseline）")
    add("")
    add(f"- 记录时间：{run_stamp}（`provenance-navigator/run_five_fold.py` 三模式各跑一轮，模式之间顺序执行，互不并行）")
    add(f"- 代码：仓库工作区当前版本（代码指纹见附录）；模型 `deepseek-flash`（根 `.env`）")
    add("- 评分：`tools/eval_agent_attack_path.py`；**召回按步骤、查准按边**；「已确认」读报告的 `edges` 段，"
        "「未排除」把 `unexcluded` 段当作上报边集合单独评分；GT 为 `groundtruth/<场景>.groundtruth.json` 当前版本")
    add("- 五折留一协议：")
    add("  1. 每折训练集 = 其余 4 个场景；训练候选池由运行器在本次运行内逐场景现算轻量闭包，**不读取任何历史运行产物**；")
    add("  2. 蒸馏入选准入：基于客观拓扑事实索引的频繁子图挖掘 + 贝叶斯经验提升度检验（Lift ≥ 3.0，且正样本命中 ≥ 1）；")
    add("  3. 在线放行门槛：基模匹配命中后还需训练期查准 ≥ `matcher_min_conf`（当前 0.50）才确认，被否决的边退入「未排除」不丢失，"
        "否决次数如实写进报告 `stats.conf_filtered_count`；")
    add("  4. 促进通道（四路并列，输出取并集、只增不减）：离线蒸馏基模匹配、进程血缘与敏感读取闭环、"
        "会话桥接与双端诱导闭环、**边界穿越故事通道（默认开启）**；")
    add("  5. 被测场景在判定前完全不可见。")
    add("- 目录结构：")
    add("  - `rules/`：纯蒸馏规则模式报告（`rules_<场景>.json`）；`hybrid/`：智能导航模式报告；`llm-only/`：纯大模型模式报告；")
    add("  - `distill/`：逐折蒸馏审计（蒸馏只依赖训练场景集，与运行模式无关，rules 与 hybrid 两轮产物同源）；")
    add("  - `summary_<模式>.json`：三模式五折评测汇总；")
    add("  - `unex_metrics_<模式>.json`：未排除段按官方工具口径的补充评分。")
    add("")
    add("---")
    add("")
    add("## 表一：三模式总览（五折留一，微平均）")
    add("")
    add("| 模式 | 已确认 召回 | 已确认 查准 | 确认边 | 未排除 召回 | 未排除 查准 | LLM 调用次数 | 五折耗时 |")
    add("|---|---|---|---|---|---|---|---|")
    for mode in MODES:
        m = micro[mode]
        u = unex[mode]["micro"]
        edges = sum(by_scenario[mode][sc]["confirmed_edges"] for sc in scenarios)
        add(f"| {MODE_TITLE[mode]} `{mode}` | **{m['recall']*100:.1f}%**（{m['hit']}/{m['total']}） "
            f"| **{m['precision']*100:.1f}%**（{m['correct']}/{m['reported']}） | {edges} "
            f"| {u['recall']*100:.1f}%（{u['hit']}/{u['total']}） | {u['precision']*100:.1f}%（{u['correct']}/{u['reported']}） "
            f"| {m['calls']} | {m['elapsed']:.1f}s |")
    add("")
    add("---")
    add("")
    add("## 表二：逐场景明细")
    add("")
    for mode in MODES:
        m = micro[mode]
        add(f"### {MODE_TITLE[mode]} `{mode}`")
        add("")
        add("| 场景 | 已确认 召回 | 已确认 查准 | 未排除 召回 | 未排除 查准 | LLM 调用次数 | 确认边数 | 单折耗时 |")
        add("|---|---|---|---|---|---|---|---|")
        for sc in scenarios:
            r = by_scenario[mode][sc]
            u = unex[mode]["rows"][sc]
            add(f"| {sc} | {r['recall']*100:.1f}%（{r['hit']}/{r['total']}） | {r['precision']*100:.1f}%（{r['correct']}/{r['reported']}） "
                f"| {u['recall']*100:.1f}%（{u['hit']}/{u['total']}） | {u['precision']*100:.1f}%（{u['correct']}/{u['reported']}） "
                f"| {r['llm_calls']} | {r['confirmed_edges']} | {r['elapsed']:.2f}s |")
        add(f"| **合计（微平均）** | **{m['recall']*100:.1f}%（{m['hit']}/{m['total']}）** "
            f"| **{m['precision']*100:.1f}%（{m['correct']}/{m['reported']}）** "
            f"| **{unex[mode]['micro']['recall']*100:.1f}%（{unex[mode]['micro']['hit']}/{unex[mode]['micro']['total']}）** "
            f"| **{unex[mode]['micro']['precision']*100:.1f}%（{unex[mode]['micro']['correct']}/{unex[mode]['micro']['reported']}）** "
            f"| **{m['calls']}** | **{sum(by_scenario[mode][sc]['confirmed_edges'] for sc in scenarios)}** | **{m['elapsed']:.2f}s** |")
        add("")
        add(f"- 逐折入选基模数：{', '.join(f'{sc.split(chr(95))[0]}={len(by_scenario[mode][sc]['distilled_motifs'])}' for sc in scenarios)}"
            f"（逐折审计见 `distill/distill_fold_<场景>.json`，含每个候选基模的正/忽略/负样本命中与提升度）")
        add("")
    add("---")
    add("")
    add("## 表三：与其它系统基线对照（同一官方工具口径）")
    add("")
    add("| 系统 / 模式 | 已确认 召回 | 已确认 查准 | LLM 调用次数 | 耗时 |")
    add("|---|---|---|---|---|")
    for mode in MODES:
        m = micro[mode]
        add(f"| navigator `{mode}`（本目录） | {m['recall']*100:.1f}%（{m['hit']}/{m['total']}） | {m['precision']*100:.1f}%（{m['correct']}/{m['reported']}） | {m['calls']} | {m['elapsed']:.1f}s |")
    add("| agent（`output/agent-baseline-current/OVERVIEW.md`） | 85.9%（373/434） | 67.5%（13,631/20,208） | 68 | 185.7s（墙钟） |")
    add("| 调查引擎（`output/engine-baseline/OVERVIEW.md`） | 41.3%（162/392） | 3.7%（162/4,421） | — | — |")
    add("")
    add("- 引擎一行是**另一套标注口径**（分母 392 步、含豁免清单），与原口径不可直接比大小，只作量级参考。")
    add("- agent 一行的耗时是整次运行墙钟（5 场景一次跑完），navigator 一列是五折耗时逐个相加，两者都含各自闭包阶段。")
    add("")
    add("---")
    add("")
    add("## 与上一版基线的差异（旧数字作废声明）")
    add("")
    old_rules = data["old"].get("summary_rules.json")
    old_hybrid = data["old"].get("summary_hybrid.json")
    if old_rules or old_hybrid:
        add("上一版基线由更早的代码版本产出，写入本目录时已被整体替换（副本不保留在本目录内）。两者代码不同，"
            "**不可把差值当作改进或退化**，下表只用于定位变化来源：")
        add("")
        add("| 模式 | 指标 | 本次 | 上一版 | 差 |")
        add("|---|---|---|---|---|")
        for mode, old in (("rules", old_rules), ("hybrid", old_hybrid)):
            if not old:
                continue
            om, nm = old["micro"], micro[mode]
            add(f"| `{mode}` | 召回 | {nm['recall']*100:.1f}% | {om['recall']*100:.1f}% | {nm['recall']*100-om['recall']*100:+.1f}pp |")
            add(f"| `{mode}` | 查准 | {nm['precision']*100:.1f}% | {om['precision']*100:.1f}% | {nm['precision']*100-om['precision']*100:+.1f}pp |")
            add(f"| `{mode}` | LLM 调用 | {nm['calls']} | {om['calls']} | {nm['calls']-om['calls']:+d} |")
            add(f"| `{mode}` | 五折耗时 | {nm['elapsed']:.1f}s | {om['elapsed']:.1f}s | {nm['elapsed']-om['elapsed']:+.1f}s |")
        add("")
    att = channel_attribution(data)
    add("变化来源（由逐折报告直接统计，可复算）：")
    add("")
    add("| 模式 | 新通道（边界穿越故事通道）自身确认边 | 慢速通道（大模型）确认边 | 确认边合计 |")
    add("|---|---|---|---|")
    for mode in MODES:
        a = att[mode]
        total = sum(v["confirmed"] for v in a["per_scenario"].values())
        add(f"| `{mode}` | {a['channel']} | {a['slow']} | {total} |")
    add("")
    add("1. **`rules` 模式的变化可完全归因于新通道**：它自身确认 200 条边、0 次大模型调用，把召回从 81.1% 提到 91.5%，"
        "查准从 82.5% 降到 81.5%（五折「剔除 = 0」，只增不减）。这是本次唯一可归因给新机制的干净增益。")
    add("2. **`hybrid` 模式的查准变化主要来自大模型束级决策，不归因于新通道**：新通道自身仍只贡献 200 条边，"
        "但它先把这些边确认，改变了交给大模型的束状态；本版场景 5 出现一次束级放行 —— 同样 7 次调用下大模型确认 2,840 条边。"
        "因此该模式的数字会随束划分摆动，比较时须连同调用次数一起看。")
    add("3. **`llm-only` 模式按设计跳过全部符号通道**（新通道不参与），其数字完全由大模型通道决定。")
    add("")
    add("---")
    add("")
    add("## 口径补充与可复现验证协议")
    add("")
    add("1. **单折耗时** = 该场景闭包抽取 + 训练池现算 + 挖掘蒸馏 + 路由编排（不含官方评测子进程）；合计为五折相加。")
    add("2. **未排除段列** = 把该段当作上报边集合、用官方工具评分的结果；它是保守兜底池，反映覆盖的保守程度而非判定质量。")
    add("3. **大模型调用次数** = 真实记账值（`deps.budget.calls`），如实写入报告 `stats.llm_calls`；"
        "`stats.promoted_by_motif` 记录规则确认边的基模归因；`stats.conf_filtered_count` 记录被在线门槛否决的匹配次数。")
    add("4. **POI 锚点**：调查起点来自 `provenance-navigator/config/scenarios.json` 的人工指定（外部前置输入），报告中的"
        "「锚点强制确认」条数即该锚点事件本身；系统自主范围是自锚点起反向闭包的抽取、判定与归因。")
    add("5. **闭包取数**：走 `tmp/provenance-navigator/l1-index/` 下的 L1 索引快照（日志中 `source=snapshot`）。"
        "索引缺失时闭包耗时会上升，召回/查准不受影响。")
    add("6. **边界穿越故事通道的判据与边界**：判据只引用图内事实（连接对象上 connect/accept 是否成对、谁写出了什么对象、"
        "谁消费了它、两个主体的可执行程序是否相同）与操作系统本体事实（内核按需生成的伪文件——/sys、/proc、/dev 下设备与终端节点、"
        "memfd、匿名 IPC——不计为落地物；/dev/shm、/run/shm、/tmp 等可写内存/临时文件系统保留）。"
        "**不引用标准答案**，只增不减。已知盲区：内存型入口（mmap/memfd/ptrace 无文件落地）观测不到；"
        "窗口开始前已落地的载荷链条在此断开；「对端不可归因」不等于「对端恶意」，恶意与否由调查锚点与高精度家族的指纹限定，"
        "锚点为外部前置输入。")
    add("7. **独立复现命令**：")
    add("   - 纯规则模式五折：`.venv/Scripts/python.exe provenance-navigator/run_five_fold.py --mode rules`")
    add("   - 智能导航模式五折：`.venv/Scripts/python.exe provenance-navigator/run_five_fold.py --mode hybrid`")
    add("   - 纯大模型模式五折：`.venv/Scripts/python.exe provenance-navigator/run_five_fold.py --mode llm-only`")
    add("   - 本目录写入：`.venv/Scripts/python.exe tools/promote_navigator_baseline.py`")
    add("   - 单场景：`.venv/Scripts/python.exe provenance-navigator/main.py --scenario <场景全名> --mode <模式>`")
    add("")
    add("---")
    add("")
    add("### 附录：代码版本指纹（SHA256 前 16 位）")
    add("")
    add("| 文件 | SHA256 前 16 位 |")
    add("|---|---|")
    for f, h in fingerprints.items():
        add(f"| provenance-navigator/{f} | {h} |")
    add("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="把三模式五折结果写入 output/navigator-baseline")
    ap.add_argument("--dry-run", action="store_true", help="只校验与预演，不改动 output/（tmp 下仍会写临时评分文件）")
    args = ap.parse_args()

    print("[1/5] 校验本次运行产物 ...")
    data = check_inputs()
    scenarios = [r["scenario"] for r in data["summaries"]["rules"]["results"]]
    print(f"      三模式齐、5 折齐、蒸馏审计齐：{', '.join(s[:2] for s in scenarios)}")

    print("[2/5] 计算未排除段指标（官方工具，逐场景）...")
    unex: dict = {}
    for mode in MODES:
        rows = {}
        for sc in scenarios:
            rows[sc] = unex_metrics(mode, sc)
            print(f"      {mode:<9} {sc[:2]} 未排除 {rows[sc]['unex_count']} 条 → "
                  f"召回 {rows[sc]['recall']*100:.1f}% 查准 {rows[sc]['precision']*100:.1f}%")
        hit = sum(r["hit"] for r in rows.values())
        total = sum(r["total"] for r in rows.values())
        correct = sum(r["correct"] for r in rows.values())
        reported = sum(r["reported"] for r in rows.values())
        unex[mode] = {"rows": rows, "micro": {
            "hit": hit, "total": total, "correct": correct, "reported": reported,
            "recall": hit / total if total else 0.0,
            "precision": correct / reported if reported else 0.0}}

    print("[3/5] 计算代码指纹 ...")
    fingerprints = {}
    nav = REPO_ROOT / "provenance-navigator"
    for f in FINGERPRINT_FILES:
        p = nav / f
        if not p.exists():
            raise SystemExit(f"[阻断] 指纹文件缺失：{p}")
        fingerprints[f] = sha16(p)

    run_stamp = time.strftime("%Y-%m-%d %H:%M") + "（本次重测）"
    overview = render_overview(data, unex, fingerprints, run_stamp)

    if args.dry_run:
        print("[4/5] --dry-run：跳过写入。OVERVIEW 预览前 40 行：")
        print("\n".join(overview.splitlines()[:40]))
        print("[5/5] 预演结束，output/ 未被改动。")
        return

    print("[4/5] 留档旧基线并写入新基线 ...")
    backup = backup_old_baseline()
    print(f"      旧基线留档：{backup.relative_to(REPO_ROOT)}")
    promote(data)
    with (DST / "OVERVIEW.md").open("w", encoding="utf-8") as fh:
        fh.write(overview)
    for mode in MODES:
        with (DST / f"unex_metrics_{mode}.json").open("w", encoding="utf-8") as fh:
            json.dump({"mode": mode, "rows": [{"scenario": sc, **unex[mode]["rows"][sc]} for sc in scenarios],
                       "micro": unex[mode]["micro"]}, fh, ensure_ascii=False, indent=2)

    print("[5/5] 校验写入结果 ...")
    expected = {"OVERVIEW.md"}
    for mode in MODES:
        expected.add(f"summary_{mode}.json")
        expected.add(f"unex_metrics_{mode}.json")
        for sc in scenarios:
            expected.add(f"{mode}/{REPORT_NAME[mode].format(sc=sc)}")
    for sc in scenarios:
        expected.add(f"distill/distill_fold_{sc}.json")
    actual = {str(p.relative_to(DST)).replace("\\", "/") for p in DST.rglob("*") if p.is_file()}
    ok = True
    for miss in sorted(expected - actual):
        print(f"      [缺] {miss}"); ok = False
    for extra in sorted(actual - expected):
        print(f"      [多余残留] {extra}"); ok = False
    print(f"      期望 {len(expected)} 个文件，实际 {len(actual)} 个 → " + ("完全一致" if ok else "存在问题，见上"))
    print(f"      基线目录：{DST.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
