# 评分与汇总口径

**适用范围**：要出召回率、查准率、确认边数等数字，写评测报告，或固化、对比基线时读本文件。执行命令见 `docs/agents/test-runbook.md`。

## 基线产物落盘位置

- 调查引擎（provenance-engine）的基线一律写 `output/engine-baseline/<场景名>/`：`baseline.json` 是引擎交付的最终图，`groundtruth-eval.txt` 是 `tools/score_graph_product.py` 对同一份产物的完整评分输出；汇总与口径写在 `output/engine-baseline/OVERVIEW.md`。
- 导航器（provenance-navigator）的基线一律写 `output/navigator-baseline/`（留一口径：rules/hybrid 逐场景结果、10 份折库与 `OVERVIEW.md`），由 `tools/promote_loo_baseline.py` 校验后落盘。
- 当次用的运行产物写 `output/engine-runs/`、`output/navigator-runs/`；这两处不得当作基线，也不得被引用为成绩来源。
- `tools/run_all_engine_v2.py` 与 `provenance-engine/baseline/run-baseline.sh` 不带输出目录参数时都会写 `output/engine-baseline/`：前者用于批量重跑基线，后者只用于基线复跑；当次测试必须显式传 `output/engine-runs/<场景名>`，否则会覆盖正式基线。

## 多场景汇总口径（合并平均）

- 跨场景汇总一律用合并平均（又称加权平均、微平均）：先把所有场景的命中数相加、所有场景的判定对象数相加，再相除；禁止先算每个场景的比率再取算术平均（每个场景一票）当总成绩。
  - 召回 = Σ命中步骤 / Σ标注步骤；每个必须条目算 1 步，每条可能集合规则算 1 步。
  - 查准 = Σ命中边数 / Σ报告去重四元组数；四元组 = `(源, 系统调用, 目标, 成败)`，同一条边发生多次只计 1 个四元组。
  - 成败判等：两侧都有值时必须相等（图上 `result<0` 为 failure、`result≥0` 为 success）；任一侧无成败证据时按三元命中，并在输出里披露出「成败未核」的条数。
- 合并值必须与逐场景表同时给出，并披露三项分布：最小值、中位数、最大值；以及合并分母中各场景的占比（避免合并值被单一大输出场景主导而不被发现）。
- 禁止用调和平均当总成绩（它只反映最差场景的严重度，不是任何量的估计）；需要表达严重度时直接报最差场景。
- 召回与查准的分母不同，禁止合成单一的 F1 或「综合分」。
- 两套系统对比时，两侧必须使用同一汇总口径与同一分母，并额外给出逐场景配对差值（新方法减基线），不得只比合并值。
