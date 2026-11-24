# 场景测试执行手册

**适用范围**：要实际跑 `.tsg` 图数据构建、`attack_graph` 主线开发评测、历史 `provenance` 基线复现、引擎测试或评分时读本文件。图存储与基线归属见根 `AGENTS.md` 第五部分；评分与汇总口径见 `docs/agents/evaluation-protocol.md`。

## 常用核心工具

| 脚本 | 用途 |
|---|---|
| `tools/score_report_product.py` | `attack_graph` / `provenance` / 智能体报告 vs 标准答案评分（召回按步骤、查准按四元组，同一条边多次发生只计一次）；优先从 `graphs/<场景名>.tsg` 读取顶点标签（零 Neo4j） |
| `tools/score_graph_product.py` | 引擎 `baseline.json` vs 标准答案评分（与上一条同一口径）；产物未内藏 syscall 时仍按 `-v2` Neo4j 库反查补全，反查不到即阻断 |
| `tools/rules_match.py` | 评分公共模块：可能集合规则与端点条件判定，动作名 ↔ syscall 词表（优先读取 `.tsg`） |
| `python -m tsg.query` | 离线 `.tsg` 图查询与 SQLite 导出 CLI（`info`/`find-vertex`/`event`/`edges`/`neighbors`/`export-sqlite`） |
| `tools/export_neo4j_to_tsg.py` | 将标准 `-v2` Neo4j 场景图一次性流式导出或重打包为 `graphs/<场景名>.tsg`（`TSG2`） |
| `tools/run_all_engine_v2.py` | 批量在 `-v2` Neo4j 库上跑调查引擎并自动评分 |
| `tools/promote_v2_baseline.py` | 历史 `provenance` 10 场景结果校验后晋升至 `output/provenance-baseline/` |
| `tools/l1_index.py` | 历史 `provenance/` 模块专用的第 1 层本地索引构建脚本（主线 `attack_graph` 已改用 `.tsg`，不再使用） |
| `tools/neo4j_desktop_start.*` / `neo4j_desktop_stop.*` | 本机 Neo4j 桌面版启停（仅 `DEPIMPACT` 引擎、`gt-annotator`、`plain_llm` 与历史 `provenance/` 需要） |

## 场景测试标准流程

用户触发测试时，直接在项目虚拟环境下运行对应系统的入口脚本。场景名以 `groundtruth/<场景全名>.groundtruth.json` 的文件名为准（大小写敏感）；`attack/data/<序号>/` 下的 `.jsonl` 文件名只作历史备份，不得作为 `--scenario` 的取值依据。

**图数据流式构建（默认直出 `.tsg` 单文件索引）：**
```bash
# 默认 --sink tsg，直接生成 graphs/<场景全名>.tsg（零 Neo4j）
python parser/main.py \
  --scap attack/data/<序号>/capture.scap \
  --scenario <场景全名>

# 可选：兼容导入历史 -v2 Neo4j 库
python parser/main.py \
  --scap attack/data/<序号>/capture.scap \
  --scenario <场景全名> \
  --sink neo4j \
  --neo4j-database attack-<场景名小写连字符>-v2
```

**`attack_graph` 主线评测（当前主要开发入口，零 Neo4j 运行）**：默认直接读取 `graphs/<场景全名>.tsg` 与 `output/rule-kg/v1/folds/<场景全名>.json`；运行时判定参数由 `attack_graph/config/navigator.toml` 控制（默认 `cap_calls = 0` 无上限自收敛）。支持通过 `--replay-trace` 复用已有的 `.trace.jsonl` 批次判定记录对后置剪枝与报告生成阶段做零 LLM 调用回归验证，并在写报告时同目录同步生成 `<输出文件去后缀>.events.json.gz`：
```bash
# 单场景实时运行（调用大模型，零 Neo4j）
python attack_graph/main.py --scenario <场景全名> \
  --output output/attack-graph-runs/<运行编号>/<场景全名>.json

# 单场景免调用重放（用于 Stage 5-7 消融验证与伴生事件导出）
python attack_graph/main.py --scenario <场景全名> \
  --replay-trace output/provenance-runs/attack-graph-20261124/reports/<场景全名>.trace.jsonl \
  --output output/attack-graph-runs/<运行编号>/<场景全名>.json

# 单元测试（修改 tsg / attack_graph / attack_path 后必跑）
python -m unittest discover -s tsg/tests -p "test_*.py"
python -m unittest discover -s attack_graph/tests/foundation -p "test_*.py"
python -m unittest discover -s attack_path/tests -p "test_*.py"
```

**历史 `provenance` 冻结基线复现 / 备份对照入口**（对应 `output/provenance-baseline/`）：
```bash
# 单场景历史基线代码运行
python provenance/main.py --scenario <场景全名> \
  --output output/provenance-runs/<场景全名>_rag.json

# 离线规则库维护（仅重建折库、核对覆盖表时使用，不参与日常评测）
python provenance/run_loo_folds.py --mode rules --out output/provenance-runs/loo --keep-reports tmp/loo_rules_reports
```
日常开发与测试单场景报告默认写 `output/attack-graph-runs/`（原 `provenance` 写 `output/provenance-runs/`），严禁直接写入 `output/attack-graph-baseline/` 或 `output/provenance-baseline/`。

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

`attack_graph` / `provenance` / 智能体报告（优先使用 `graphs/<场景全名>.tsg` 判定端点类别，零 Neo4j）：
```bash
python tools/score_report_product.py --report output/attack-graph-runs/<运行编号>/<场景全名>.json \
  --gt groundtruth/<场景全名>.groundtruth.json
```

- 第一段直接给出实测数据结果（召回率、查准率、确认边数、耗时与模型调用次数）。
- 若遇到关键前置依赖未就绪或测试环境异常，坚决执行「阻断诚实法则」，第一时间停止并汇报真实阻断原因，严禁使用非自主的下游数据伪造流程。
