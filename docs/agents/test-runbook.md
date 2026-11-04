# 场景测试执行手册

**适用范围**：要实际跑图数据导入、导航器评测、引擎测试或评分时读本文件。数据库命名与基线归属见根 `AGENTS.md` 第五部分；评分与汇总口径见 `docs/agents/evaluation-protocol.md`。

## 常用核心工具

| 脚本 | 用途 |
|---|---|
| `tools/score_graph_product.py` | 引擎产出 vs 标准答案评分（召回按步骤、查准按四元组，同一条边多次发生只计一次）；产物未内藏 syscall 时按 `-v2` 库反查补全，反查不到即阻断 |
| `tools/score_report_product.py` | 智能体 / 导航器报告 vs 标准答案评分（与上一条同一口径：召回按步骤、查准按四元组） |
| `tools/rules_match.py` | 评分公共模块：可能集合规则与端点条件判定，动作名 ↔ syscall 词表 |
| `tools/run_all_engine_v2.py` | 批量在 `-v2` 库上跑调查引擎并自动评分 |
| `tools/promote_loo_baseline.py` | 导航器留一交叉（10 场景逐折）结果校验后写成正式基线报告 |
| `tools/l1_index.py` | 手动建 / 重建导航器第 1 层顶点-时间索引 |
| `tools/neo4j_desktop_start.*` / `neo4j_desktop_stop.*` | 本机 Neo4j 桌面版启停 |

## 场景测试标准流程

用户触发测试时，直接在项目虚拟环境下运行对应系统的入口脚本。场景名以 `groundtruth/<场景全名>.groundtruth.json` 的文件名为准（大小写敏感）；`attack/data/<序号>/` 下的 `.jsonl` 文件名只作历史备份，不得作为 `--scenario` 的取值依据。

**图数据流式导入：**
```bash
python provenance-parser/main.py \
  --scap attack/data/<序号>/capture.scap \
  --scenario <场景全名> \
  --neo4j-database attack-<场景名小写连字符>-v2
```

**导航器评测（一律用留一交叉）**：测场景 k 时规则库只由其余 9 个场景生成，场景 k 的标准答案与候选边池不参与蒸馏。
```bash
# 全量留一（rules / hybrid 各一轮）
python provenance-navigator/run_loo_folds.py --mode rules  --out output/navigator-runs/loo        --keep-reports tmp/loo_rules_reports
python provenance-navigator/run_loo_folds.py --mode hybrid --out output/navigator-runs/loo-hybrid --keep-reports tmp/loo_hybrid_reports
# 单场景：自动取该场景的留一折库（没有折库的新场景才退回全量库）
python provenance-navigator/main.py --scenario <场景全名>
```
单场景报告默认写 `output/navigator-runs/<场景全名>.json`。

**引擎测试（当次运行，不写基线）：**
```bash
NEO4J_DATABASE=attack-<场景名小写连字符>-v2 \
bash provenance-engine/baseline/run-baseline.sh \
  <场景全名> \
  output/engine-runs/<场景全名> \
  <POI 参数...>
```
POI 参数没有默认值，从 `provenance-navigator/config/scenarios.json` 的 `poi` 字段展开。场景 1 用 `--poi-file /srv/data/README_RESTORE.txt --poi-optype write`；场景 2 用 `--poi-endpoints 100.116.135.31:45794->100.86.108.4:22 --poi-optype write`。

**评测（按产物类型选脚本，两者口径相同但输入 schema 不同）：**

引擎 `baseline.json`：
```bash
python tools/score_graph_product.py output/engine-runs/<场景全名>/baseline.json \
  --gt groundtruth/<场景全名>.groundtruth.json \
  --database attack-<场景名小写连字符>-v2
```

导航器 / 智能体报告：
```bash
python tools/score_report_product.py --report output/navigator-runs/<场景全名>.json \
  --gt groundtruth/<场景全名>.groundtruth.json
```

- 第一段直接给出实测数据结果（召回率、查准率、确认边数、耗时与模型调用次数）。
- 若遇到关键前置依赖未就绪或测试环境异常，坚决执行「阻断诚实法则」，第一时间停止并汇报真实阻断原因，严禁使用非自主的下游数据伪造流程。
