# 评分与汇总口径

**适用范围**：要出召回率、查准率、确认边数等数字，写评测报告，或固化、对比基线时读本文件。执行命令见 `docs/agents/test-runbook.md`。

## 基线产物落盘位置

- 当前主线 `attack_graph/` 的唯一正式基线存放目录为 `output/attack-graph-baseline/`：基于零 Neo4j 环境（`graphs/*.tsg` 单文件 `tsg-v2` 索引 + `output/rule-kg/v1` 本地规则快照），固化 10 场景聚合报告（`reports_v2/*.json.gz`）、伴生单事件明细与去重实体属性表（`events_v2/*.events.json.gz`，供研究点二 `attack_path/loader.py` 零查库直读）、逐批判定重放轨迹（`traces/*.trace.jsonl`，供 `--replay-trace` 免模型调用复现）、`summary_v2.json`、输入与代码指纹（`input-fingerprints.json`、`code-fingerprints.json`）以及 `OVERVIEW.md`；在未经过全 10 场景完整实测并显式晋升前，不得将中间实验写入该目录。
- 既有 `provenance/` 模块的冻结基线/备份留在 `output/provenance-baseline/`：包含 10 份压缩报告、`summary_v2.json`、代码指纹与 `OVERVIEW.md`（由 `tools/promote_v2_baseline.py` 生成），作为历史对照组参照，严禁擅自覆盖。
- 调查引擎（DEPIMPACT，位于 `experiments/DEPIMPACT`）的基线一律写 `output/engine-baseline/<场景名>/`：`baseline.json` 是引擎交付的最终图，`groundtruth-eval.txt` 是 `tools/score_graph_product.py` 对同一份产物的完整评分输出；汇总与口径写在 `output/engine-baseline/OVERVIEW.md`。
- 当次用的运行时测试与消融产物分别写 `output/attack-graph-runs/`、`output/provenance-runs/`、`output/engine-runs/`、`output/plain-llm-runs/`；这些目录不得当作正式基线。
- 引擎批跑必须向 `tools/run_all_engine_v2.py` 显式传入 `--output-root`；当次评测使用独立目录。

## 多场景汇总口径（合并平均）

- 跨场景汇总一律用合并平均（又称加权平均、微平均）：先把所有场景的命中数相加、所有场景的判定对象数相加，再相除；禁止先算每个场景的比率再取算术平均（每个场景一票）当总成绩。
  - 召回 = Σ命中步骤 / Σ标注步骤；每个必须条目算 1 步，每条可能集合规则算 1 步。
  - 查准 = Σ命中三元组数 / Σ报告去重三元组数。三元组为 `(源, 系统调用, 目标)`。同一关系的多次发生及不同成败合并计数，命中必标条目或任一评测规则可计一次。
  - 成败用于单事件事实核验。评分忽略必标条目和评测规则的成败条件。数值条件在同一条单事件记录上核对。缺失所需属性的记录不能确认命中，并在评分中披露。
  - 机器可读结果以 `scoring_protocol: triplet-v1` 标记。
- 合并值必须与逐场景表同时给出，并披露三项分布：最小值、中位数、最大值；以及合并分母中各场景的占比（避免合并值被单一大输出场景主导而不被发现）。
- 禁止用调和平均当总成绩（它只反映最差场景的严重度，不是任何量的估计）；需要表达严重度时直接报最差场景。
- 召回与查准的分母不同，禁止合成单一的 F1 或「综合分」。
- 两套系统对比时，两侧必须使用同一汇总口径与同一分母，并额外给出逐场景配对差值（新方法减基线），不得只比合并值。
