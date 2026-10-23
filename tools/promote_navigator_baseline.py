"""把一次导航器评测结果固化为官方基线（output/navigator-baseline/）。

做四件事，每件都留审计：
1. 读 `tmp/provenance_router_runs/` 里本次三模式运行的产物（summary / 逐折报告 / 蒸馏审计），
   校验场景齐、折数齐，缺一个即阻断（绝不用旧产物顶替）；
2. 用官方评测工具对每个场景的**未排除段**单独打分（把 unexcluded 当作上报边集合），
   得到与「已确认段」同一口径的未排除指标；
3. 直接清空 `output/navigator-baseline/` 后按新布局写入（不保留旧基线）；
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
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "tmp" / "provenance_router_runs"
DST = REPO_ROOT / "output" / "navigator-baseline"
WORK = REPO_ROOT / "tmp" / "nav_baseline_promote"
EVAL = REPO_ROOT / "tools" / "score_report_product.py"
FROZEN_DISTILL = REPO_ROOT / "provenance-navigator" / "config"
ENGINE_OVERVIEW = REPO_ROOT / "output" / "engine-baseline" / "OVERVIEW.md"

MODES = ("rules", "hybrid", "llm-only")
MODE_TITLE = {
    "rules": "纯蒸馏规则模式（0 次大模型调用）",
    "hybrid": "智能导航模式（神经符号协同）",
    "llm-only": "纯大语言模型模式（旁路规则截流）",
}
# 写入后 rules 目录沿用 rules_ 前缀：tmp 下多个实验脚本按该路径读对照组
REPORT_NAME = {"rules": "rules_{sc}.json", "hybrid": "{sc}.json", "llm-only": "{sc}.json"}
FINGERPRINT_FILES = [
    "main.py", "pipeline.py", "run_leave_one_out.py",
    "closure/walk.py", "closure/fold.py", "closure/extractor.py",
    "rules/offline.py", "rules/online.py",
    "common/config.py", "common/graph.py", "common/facts.py", "common/model.py",
    "routing/route.py", "routing/filters.py", "routing/report.py",
    "llm/judge.py",
    "config/closure_rules.json", "config/navigator.toml", "config/scenarios.json",
]# 旧基线里已知会被本次替换掉的对象（显式列举，不做通配删除）
# 注意：新模式命名 `unex_metrics_<模式>.json` 下的 unex_metrics_rules.json 是**合法新文件**，不在此列。
STALE_ROOT = ["unex_metrics.json"]


def sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16].upper()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_library() -> Path:
    """规则库：全部场景蒸馏成的一份，所有场景共用（config/rules-library.json）。"""
    path = FROZEN_DISTILL / "rules-library.json"
    if not path.is_file():
        raise SystemExit(
            f"[阻断] 缺少规则库：{path}；先生成：python provenance-navigator/run_leave_one_out.py "
            f"--mode rules --rules-from fresh --freeze --freeze-only"
        )
    return path


def check_inputs() -> dict:
    """读并校验本次运行的产物；任一缺失或场景不齐立即阻断。"""
    data: dict = {"summaries": {}, "reports": {}, "distill": {}, "old": {}}
    expected_scenarios = sorted(load_json(REPO_ROOT / "provenance-navigator" / "config" / "scenarios.json")["scenarios"])
    scenarios = None
    for mode in MODES:
        sp = SRC / f"summary_{mode}.json"
        if not sp.exists():
            raise SystemExit(f"[阻断] 缺少本次运行产物：{sp}")
        summary = load_json(sp)
        got = [r["scenario"] for r in summary["results"]]
        if sorted(got) != expected_scenarios:
            raise SystemExit(
                f"[阻断] {sp} 的场景集与场景清单不一致：{sorted(got)} != {expected_scenarios}"
                "（留一交叉必须覆盖 config/scenarios.json 的全部场景）"
            )
        if scenarios is None:
            scenarios = got
        elif got != scenarios:
            raise SystemExit(f"[阻断] {sp} 场景集与其它模式不一致：{got} != {scenarios}")
        # 逐折报告 / 单折评分都必须齐（蒸馏产物统一在下面按 distill_source 解析）
        for sc in got:
            rp = SRC / f"{mode}_{sc}.json"
            if not rp.exists():
                raise SystemExit(f"[阻断] 缺少逐折报告：{rp}")
            ep = SRC / f"eval_{mode}_{sc}.json"
            if not ep.exists():
                raise SystemExit(f"[阻断] 缺少单折评分：{ep}")
        data["summaries"][mode] = summary
        data["reports"][mode] = {sc: SRC / f"{mode}_{sc}.json" for sc in got}

    # 规则库：一份给所有场景用
    data["library"] = _resolve_library()

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


def promote(data: dict) -> None:
    modes = MODES
    scenarios = [r["scenario"] for r in data["summaries"]["rules"]["results"]]

    # 基线只保留当前这一版：先清空目录，避免上一版模式目录/汇总残留
    for path in sorted(DST.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()

    for mode in modes:
        (DST / mode).mkdir(parents=True, exist_ok=True)
        for sc in scenarios:
            shutil.copy2(data["reports"][mode][sc], DST / mode / REPORT_NAME[mode].format(sc=sc))
        shutil.copy2(SRC / f"summary_{mode}.json", DST / f"summary_{mode}.json")

    (DST / "distill").mkdir(parents=True, exist_ok=True)
    shutil.copy2(data["library"], DST / "distill" / "rules-library.json")


def _mode_label() -> str:
    return "三模式" if len(MODES) == 3 else "+".join(MODES) + " 模式"


def engine_reference() -> dict | None:
    """读引擎基线 OVERVIEW 的自述数字，供表三对照行使用（不手抄、不推算）。

    引擎基线目录不存在时返回 None（表三不列该行）；存在但解析不出数字即阻断，
    绝不退回任何手写数字。
    """
    if not ENGINE_OVERVIEW.is_file():
        return None
    text = ENGINE_OVERVIEW.read_text(encoding="utf-8")
    recall = re.search(r"召回 \*\*([\d.]+)%\*\*（([\d,]+)/([\d,]+) 步）", text)
    precision = re.search(r"查准 \*\*([\d.]+)%\*\*（([\d,]+)/([\d,]+) 四元组）", text)
    stamp = re.search(r"记录时间：([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:~]+)", text)
    elapsed = re.search(r"引擎总墙钟 \*\*([\d.]+) s\*\*", text)
    calls = re.search(r"模型调用：\*\*(\d+) 次\*\*", text)
    if not (recall and precision and stamp and elapsed):
        raise SystemExit(
            f"[阻断] 无法从 {ENGINE_OVERVIEW.relative_to(REPO_ROOT)} 解析引擎基线数字"
            "（汇总行格式变动或被手工改写）；请先核对引擎基线，再跑本脚本"
        )
    return {
        "rel": ENGINE_OVERVIEW.relative_to(REPO_ROOT).as_posix(),
        "stamp": stamp.group(1),
        "recall": recall.group(1), "hit": recall.group(2), "total": recall.group(3),
        "total_n": int(recall.group(3).replace(",", "")),
        "precision": precision.group(1), "correct": precision.group(2), "reported": precision.group(3),
        "elapsed": elapsed.group(1),
        "calls": calls.group(1) if calls else "—",
    }


def engine_table_rows(eng: dict | None, nav_totals: list[int]) -> list[str]:
    """渲染表三的引擎对照行与下方口径说明（数字全部来自引擎基线自述）。"""
    if eng is None:
        return [f"- 对照对象当前不存在（`{ENGINE_OVERVIEW.relative_to(REPO_ROOT).as_posix()}` 缺失），"
                "故表三只列 navigator 自身；需要对照时先重跑该系统的基线。"]
    rows = [
        f"| 调查引擎（`{eng['rel']}`，记录于 {eng['stamp']}） | {eng['recall']}%（{eng['hit']}/{eng['total']}） "
        f"| {eng['precision']}%（{eng['correct']}/{eng['reported']}） | {eng['calls']} "
        f"| {eng['elapsed']}s（引擎进程墙钟） |"
    ]
    if nav_totals == [eng["total_n"]]:
        caliber = f"召回分母同为 {eng['total_n']} 步，与上表可直接比大小"
    else:
        caliber = (f"召回分母为 {eng['total']} 步，与上表 {'/'.join(str(t) for t in nav_totals)} 步不同，"
                   "属另一套标注口径，不可直接比大小，只作量级参考")
    rows.append("")
    rows.append(f"- 引擎一行由本脚本从该文件汇总行实时读取（不手抄）；记录时间 {eng['stamp']}，"
                f"读数时需连同代码版本一起看。{caliber}。")
    rows.append("- 判等口径已统一：两侧产物都带成败（图上 `result` 换算：<0 → failure、≥0 → success、无 → 空），"
                "命中须四元组成败一致；任一侧无成败证据时按三元命中并披露条数。"
                "耗时口径不同：引擎是 Java 引擎进程单次运行墙钟、不含评分，navigator 是各折耗时逐个相加（含闭包阶段）。")
    rows.append("- 两侧数字各自只在自身记录时间与代码版本下成立：任一系统重跑后须重新生成本表，旧数字作废。")
    return rows


def render_overview(data: dict, unex: dict, fingerprints: dict, run_stamp: str) -> str:
    summaries = data["summaries"]
    scenarios = [r["scenario"] for r in summaries["rules"]["results"]]
    by_scenario = {mode: {r["scenario"]: r for r in summaries[mode]["results"]} for mode in MODES}
    micro = {mode: summaries[mode]["micro"] for mode in MODES}

    out: list[str] = []
    add = out.append
    add("# 导航器成绩基线（navigator-baseline）")
    add("")
    add(f"- 记录时间：{run_stamp}（`provenance-navigator/run_leave_one_out.py` {_mode_label()}各跑一轮，模式之间顺序执行，互不并行）")
    add(f"- 代码：仓库工作区当前版本（代码指纹见附录）；模型 `deepseek-flash`（根 `.env`）")
    add("- 评分：`tools/score_report_product.py`；**召回按步骤、查准按边**；「已确认」读报告的 `edges` 段，"
        "「未排除」把 `unexcluded` 段当作上报边集合单独评分；GT 为 `groundtruth/<场景>.groundtruth.json` 当前版本")
    add("- 规则库：全部场景的标准答案与候选池蒸馏一次，生成一份规则库，所有场景共用；运行时直接读取、不重复蒸馏；"
        "指纹（标准答案、场景清单、蒸馏相关源码）校验失败即阻断。")
    add("  闭包回溯口径：同进程 / 同顶点交付 / 派生边 / 记录到的父子关系（ppid，同容器内解析）。")
    add("  1. 蒸馏入选准入：基于客观拓扑事实索引的频繁子图挖掘 + 贝叶斯经验提升度检验（Lift ≥ 3.0，且正样本命中 ≥ 1）；")
    add("  2. 在线放行门槛：基模匹配命中后还需训练期查准 ≥ `matcher_min_conf`（当前 0.50）才确认，被否决的边退入「未排除」不丢失，"
        "否决次数如实写进报告 `stats.conf_filtered_count`；")
    add("  3. 促进通道（四路并列，输出取并集、只增不减）：离线蒸馏基模匹配、进程血缘与敏感读取闭环、"
        "会话桥接与双端诱导闭环、**边界穿越故事通道（默认开启）**。")
    add("- 目录结构：")
    add("  - `rules/`：纯蒸馏规则模式报告（`rules_<场景>.json`）；")
    add("  - `distill/`：本轮使用的规则库（`rules-library.json`，含每个候选基模的正/忽略/负样本命中与提升度）；")
    add("  - `summary_<模式>.json`：本轮各模式评测汇总；")
    add("  - `unex_metrics_<模式>.json`：未排除段按官方工具口径的补充评分。")
    add("")
    add("---")
    add("")
    add(f"## 表一：{_mode_label()}总览（全场景，微平均）")
    add("")
    add("| 模式 | 已确认 召回 | 已确认 查准 | 确认边 | 未排除 召回 | 未排除 查准 | LLM 调用次数 | 全折耗时 |")
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
            f"（规则库见 `distill/rules-library.json`，含每个候选基模的正/忽略/负样本命中与提升度）")
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
    nav_totals = sorted({micro[mode]["total"] for mode in MODES})
    for line in engine_table_rows(engine_reference(), nav_totals):
        add(line)
    add("")
    add("---")
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
    for mode in MODES:
        a = att[mode]
        total = sum(v["confirmed"] for v in a["per_scenario"].values())
        share = f"{a['channel'] / total * 100:.1f}%" if total else "—"
        add(f"- `{mode}`：新通道自身确认 {a['channel']} 条（占该模式确认集 {share}）；"
            f"慢速通道（大模型）确认 {a['slow']} 条；该模式确认边合计 {total} 条、大模型调用 {micro[mode]['calls']} 次。")
    add("")
    add("以上归因数字全部由本轮逐折报告直接统计（`stats.promoted_by_motif` 的 `BOUNDARY_*` 计数、"
        "`edges[].reason` 以「慢速通道」开头的边数），不含手写数字。`hybrid` 的确认集还会随束划分摆动，"
        "跨运行或跨版本比较必须连同大模型调用次数一起看，不能当成改进或退化的证据。")
    add("")
    add("---")
    add("")
    add("## 口径补充与可复现验证协议")
    add("")
    add("1. **单折耗时** = 该场景闭包抽取 + 基模来源（读冻结产物或现蒸馏）+ 路由编排（不含官方评测子进程）；合计为各折相加。")
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
    add("   - 纯规则模式：`.venv/Scripts/python.exe provenance-navigator/run_leave_one_out.py --mode rules --rules-from frozen`")
    add("   - 智能导航模式：`.venv/Scripts/python.exe provenance-navigator/run_leave_one_out.py --mode hybrid --rules-from frozen`")
    add("   - 纯大模型模式：`.venv/Scripts/python.exe provenance-navigator/run_leave_one_out.py --mode llm-only`")
    add("   - 重新冻结蒸馏产物：`.venv/Scripts/python.exe provenance-navigator/run_leave_one_out.py --mode rules --rules-from fresh --freeze`")
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
    global MODES
    ap = argparse.ArgumentParser(description="把留一交叉结果写入 output/navigator-baseline")
    ap.add_argument("--modes", default=",".join(MODES),
                    help="本次要写入的模式（逗号分隔，默认三模式全写）")
    ap.add_argument("--dry-run", action="store_true", help="只校验与预演，不改动 output/（tmp 下仍会写临时评分文件）")
    args = ap.parse_args()

    chosen = tuple(m.strip() for m in args.modes.split(",") if m.strip())
    unknown = [m for m in chosen if m not in ("rules", "hybrid", "llm-only")]
    if unknown or not chosen:
        raise SystemExit(f"[阻断] --modes 取值非法：{args.modes!r}")
    MODES = chosen

    print("[1/5] 校验本次运行产物 ...")
    data = check_inputs()
    scenarios = [r["scenario"] for r in data["summaries"]["rules"]["results"]]
    print(f"      {_mode_label()}、{len(scenarios)} 折齐、规则库齐：{', '.join(s[:2] for s in scenarios)}")

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

    print("[4/5] 写入新基线（覆盖旧基线，不留档）...")
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
    expected.add("distill/rules-library.json")
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
