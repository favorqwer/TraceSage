"""干跑：假判定模型驱动整条流水线（**不调真实 LLM**），把不变式逼出来。

用法：
    python provenance-agent/tests/dry_run.py [场景名]
    DRY_JUDGE_DROP_ID=always python provenance-agent/tests/dry_run.py   # 测"两轮都漏 id → 未判定"

单元检查（切批 / 粗筛 / 拆批重试）在 `tests/unit/`：
    python -m unittest discover -s provenance-agent/tests/unit -t provenance-agent
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from pagent import app
from pagent.core import scenarios, settings
from pagent.layers import l2_prepare as l2

FAILURES: list[str] = []


def check(cond: bool, label: str) -> None:
    print(("  OK   " if cond else "  FAIL ") + label)
    if not cond:
        FAILURES.append(label)


def _triple(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (edge.get("src", ""), edge.get("syscall", ""), edge.get("dst", ""))


# --------------------------------------------------------------------------- #
# 假判定模型
# --------------------------------------------------------------------------- #

class ScriptedJudgeModel(BaseChatModel):
    """从 user 里解析 `E001.` 形式的 id，按 id 生成确定性判定。

    - `drop_mode=pass1`：第一轮漏掉 `E003`（二次复核应该救回）；
    - `drop_mode=always`：两轮都漏（必须进 unjudged，且不得进 excluded / 报告）；
    - `E004` 第一轮给 0.45（贴阈值）→ 第二轮翻转成相关 0.6 → 争议边必须保留。
    """

    drop_mode: str = "pass1"
    calls: int = 0
    roles: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "scripted-judge"

    def _generate(self, messages: list[Any], stop: Optional[list[str]] = None,
                  run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs: Any) -> ChatResult:
        self.calls += 1
        system = messages[0].content if messages else ""
        user = messages[-1].content if messages else ""
        refute = "复核员" in system
        self.roles.append("refute" if refute else "judge")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self._reply(user, refute)))])

    def _reply(self, user: str, refute: bool) -> str:
        verdicts = []
        for vid in re.findall(r"^(E\d+)\.", user, re.M):
            n = int(vid[1:])
            if n == 3 and (self.drop_mode == "always" or not refute):
                continue                                    # E003：制造"漏 id"
            if n == 4:
                rel, conf = (True, 0.6) if refute else (False, 0.45)   # 边界边 → 争议
            elif n == 2:
                rel, conf = False, 0.2
            else:
                rel, conf = (n % 3 != 0), (0.9 if n % 3 != 0 else 0.2)
            verdicts.append({"id": vid, "is_relevant": rel, "confidence": conf,
                             "reason": f"scripted-{vid}"})
        return json.dumps({"verdicts": verdicts})


# --------------------------------------------------------------------------- #
# 端到端干跑（需要数据库）
# --------------------------------------------------------------------------- #

def run_scenario(name: str, drop_mode: str) -> None:
    scenario = scenarios.load_scenario(name)
    run_id = f"dry-{int(time.time())}"
    settings.ensure_work_dirs()
    judge_model = ScriptedJudgeModel(drop_mode=drop_mode)
    deps = app.build_deps(scenario, run_id, model=judge_model, log=lambda *_: None)
    print(f"\n=== 端到端干跑：{scenario.name}（run_id={run_id}，drop_mode={drop_mode}）===")
    try:
        t0 = time.time()
        result = app.run_once(deps, dry_run=False)
    finally:
        deps.graph.close()
    record = deps.record
    budget = deps.budget
    report = result["report"]
    judge_stats = result["judge"]
    expand = result["expand"]
    elapsed = time.time() - t0
    print(f"  展开 {expand['rounds']} 轮 / {len(record.steps)} 步 / {len(record.edges)} 条边；"
          f"判定 {judge_stats['batches']} 批 / {judge_model.calls} 次模型调用；{elapsed:.1f}s")
    print(f"  报告 {len(report['edges'])} 条边；相位 {report['tactics']}；停止原因 {report['stop_reason']}")

    print("\n=== 不变式检查 ===")
    check(set(judge_model.roles) <= {"judge", "refute"}, "只有判定在用模型（没有取证员/主管/记忆）")
    check(budget.calls == judge_model.calls, f"模型调用次数与假模型一致（{budget.calls}）")
    check(report["generated_by"] == "deterministic_reporter", "报告由代码生成")
    check(judge_stats["batches"] >= 2, f"判定多批并行（{judge_stats['batches']} 批）")
    check(all("mitre_technique" not in e for e in report["edges"]), "报告里没有 mitre_technique 字段")
    check(all(e.get("event_id") for e in report["edges"]), "报告每条边都有 event_id")
    judged = [e for e in record.confirmed.values() if e.get("judged") and e.get("event_ids")]
    check(len(report["edges"]) == len(judged), "报告默认全选已确认边（不丢边）")
    check(all(t not in record.excluded for t in record.unjudged), "未判定的边不得进 excluded")
    check(all(t not in {_triple(e) for e in report["edges"]} for t in record.unjudged),
          "未判定的边不得进报告")
    if drop_mode == "always":
        check(len(record.unjudged) >= 1, f"两轮都漏 id 的边进未判定（{len(record.unjudged)} 条）")
    else:
        check(len(record.unjudged) == 0, "第一轮漏 id 的边被二次复核救回（未判定=0）")
        check(any(e.get("contested") for e in record.confirmed.values())
              or any(e.get("contested") for e in record.excluded.values()),
              "边界边二次复核产生争议记录（取低值而非静默丢弃）")
    # 粗筛边不得出现在判定日志里（日志 = 真正送进模型的边）
    verdict_path = settings.LOG_DIR / f"verdicts-{run_id}.jsonl"
    judged_triples: set[tuple[str, str, str]] = set()
    if verdict_path.is_file():
        for line in verdict_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                judged_triples.add(tuple(json.loads(line)["triple"]))
    prefiltered = {t for t, e in record.edges.items() if l2.prefilter_reason(e)}
    check(not (prefiltered & judged_triples),
          f"粗筛边不进 LLM 判定（候选里残留 {len(prefiltered)} 条，泄漏 {len(prefiltered & judged_triples)} 条）")
    check(all(str(e.get("reason", "")).startswith("确定性粗筛")
              for e in record.excluded.values() if e.get("prefiltered")), "粗筛边带可审计理由")
    # 第 1 层在**遍历期**就把这三类边挡在闭包之外：候选集里本不该有，闭包统计里必须记着
    if True:
        dropped = (expand.get("closure") or {}).get("dropped") or {}
        check(prefiltered == set(), "第 1 层已把系统例行文件挡在闭包之外（候选里 0 条）")
        check({"r1", "r2"} <= set(dropped) or not dropped,
              f"第 1 层规则剔除有逐类计数（{dropped}）")
        check(all(str(e.get("step_key") or "") in record.steps for e in record.edges.values()),
              "每条候选边都归属到一个已登记的步骤（渲染上下文不缺）")
        steps_ok = all((m.get("summary") or {}).get("t0", 0) <= (m.get("summary") or {}).get("t1", 0)
                       for m in record.steps.values())
        check(steps_ok, "步骤摘要的时间区间合法（起始不晚于结束）")
    check(report["stop_reason"] not in (None, ""), "有 stop_reason")
    check(record.stats()["unclosed_hypotheses"] == 0, "假设全部收尾（无 tracing）")
    check(record.stats()["edges"] > 0 and any(r == "supports" for _, r, _, _ in record.links),
          "记录表有 supports 边（证据 → POI）")
    check(len(report["edges"]) > 0, "报告非空")

    # 闭包统计（确定性层）：来源、轮数、逐类剔除都要可审计
    closure = expand.get("closure") or {}
    check(int(closure.get("rounds") or 0) >= 1 and int(closure.get("events_included") or 0) > 0,
          f"闭包统计可审计（{closure.get('rounds')} 轮 / {closure.get('events_included')} 条事件）")
    source = (closure.get("source") or {})
    check(source.get("source") in ("db", "snapshot"), f"取边来源已记录（{source.get('source')}）")
    check(int(closure.get("events_included") or 0) >= len(record.edges),
          "闭包收进的事件数不少于折叠后的候选边数")
    expands = int(closure.get("process_expands") or 0) + int(closure.get("object_expands") or 0)
    reexpands = int(closure.get("reexpands") or 0)
    check(0 <= reexpands <= expands,
          f"补取次数已记录且不超过展开总数（补取 {reexpands} 次 / 展开 {expands} 次）")

    # 审计日志可解析
    log_path = settings.LOG_DIR / f"queries-{run_id}.jsonl"
    bad = 0
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    json.loads(line)
                except Exception:
                    bad += 1
    check(bad == 0, f"查询审计日志全部可解析（坏行 {bad}）")


def main() -> int:
    settings.load_dotenv()
    os.environ.setdefault("PAGENT_JUDGE_BATCH", "20")     # 干跑用小批，保证多批并行
    name = sys.argv[1] if len(sys.argv) > 1 else "1_Multi_Stage_Data_Exfiltration"
    run_scenario(name, os.environ.get("DRY_JUDGE_DROP_ID", "pass1"))
    print(f"\n=== 结论：{'全部通过' if not FAILURES else str(len(FAILURES)) + ' 项失败'} ===")
    for item in FAILURES:
        print("  -", item)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
