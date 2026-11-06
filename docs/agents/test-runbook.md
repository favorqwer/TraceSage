# 场景测试执行手册

**适用范围**：要实际跑图数据导入、导航器评测、引擎测试或评分时读本文件。数据库命名与基线归属见根 `AGENTS.md` 第五部分；评分与汇总口径见 `docs/agents/evaluation-protocol.md`。

## 常用核心工具

| 脚本 | 用途 |
|---|---|
| `tools/score_graph_product.py` | 引擎产出 vs 标准答案评分（召回按步骤、查准按四元组，同一条边多次发生只计一次）；产物未内藏 syscall 时按 `-v2` 库反查补全，反查不到即阻断 |
| `tools/score_report_product.py` | 智能体 / 导航器报告 vs 标准答案评分（与上一条同一口径：召回按步骤、查准按四元组） |
| `tools/rules_match.py` | 评分公共模块：可能集合规则与端点条件判定，动作名 ↔ syscall 词表 |
| `tools/run_all_engine_v2.py` | 批量在 `-v2` 库上跑调查引擎并自动评分 |
| `tools/promote_v2_baseline.py` | 导航器 RAG v2 的 10 场景结果校验后写成正式基线（压缩报告、summary、代码指纹） |
| `tools/l1_index.py` | 手动建 / 重建导航器第 1 层顶点-时间索引 |
| `tools/neo4j_desktop_start.*` / `neo4j_desktop_stop.*` | 本机 Neo4j 桌面版启停 |

## 场景测试标准流程

用户触发测试时，直接在项目虚拟环境下运行对应系统的入口脚本。场景名以 `groundtruth/<场景全名>.groundtruth.json` 的文件名为准（大小写敏感）；`attack/data/<序号>/` 下的 `.jsonl` 文件名只作历史备份，不得作为 `--scenario` 的取值依据。

**图数据流式导入：**
```bash
python parser/main.py \
  --scap attack/data/<序号>/capture.scap \
  --scenario <场景全名> \
  --neo4j-database attack-<场景名小写连字符>-v2
```

**导航器评测（RAG v2 单一模式）**：规则证据（Motif/Hop）与技术证据（BehaviorObservable/Technique）分开检索、分开引用校验；默认取该场景的留一折库。
```bash
# 单场景正式运行
python provenance/main.py --scenario <场景全名> \
  --output output/provenance-runs/<场景全名>_rag.json

# 离线规则库维护（仅重建折库、核对覆盖表时使用，不参与日常评测）
python provenance/run_loo_folds.py --mode rules --out output/provenance-runs/loo --keep-reports tmp/loo_rules_reports
```
单场景报告默认写 `output/provenance-runs/<场景全名>_rag.json`。rules / hybrid / llm-only 运行模式已退出导航器入口。

**引擎测试（当次运行，不写基线）：**
```bash
NEO4J_DATABASE=attack-<场景名小写连字符>-v2 \
bash experiments/DEPIMPACT/baseline/run-baseline.sh \
  <场景全名> \
  output/engine-runs/<场景全名> \
  <POI 参数...>
```
POI 参数没有默认值，从 `provenance/config/scenarios.json` 的 `poi` 字段展开。场景 1 用 `--poi-file /srv/data/README_RESTORE.txt --poi-optype write`；场景 2 用 `--poi-endpoints 100.116.135.31:45794->100.86.108.4:22 --poi-optype write`。

**评测（按产物类型选脚本，两者口径相同但输入 schema 不同）：**

引擎 `baseline.json`：
```bash
python tools/score_graph_product.py output/engine-runs/<场景全名>/baseline.json \
  --gt groundtruth/<场景全名>.groundtruth.json \
  --database attack-<场景名小写连字符>-v2
```

导航器 / 智能体报告：
```bash
python tools/score_report_product.py --report output/provenance-runs/<场景全名>.json \
  --gt groundtruth/<场景全名>.groundtruth.json
```

- 第一段直接给出实测数据结果（召回率、查准率、确认边数、耗时与模型调用次数）。
- 若遇到关键前置依赖未就绪或测试环境异常，坚决执行「阻断诚实法则」，第一时间停止并汇报真实阻断原因，严禁使用非自主的下游数据伪造流程。
