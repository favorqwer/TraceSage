# Attack Graph：当前开发主线溯源图调查系统

> **目录定位**：`attack_graph/` 是 TraceSage 当前主要开发与优化的溯源系统主线目录；原 `provenance/` 目录现保留作为历史冻结基线与备份（对应 `output/provenance-baseline/`）。

## 1. 运行流程

系统从外部提供的目标事件开始调查，直接从单文件全属性溯源图索引 `graphs/<场景名>.tsg`（`TSGSource`）定位 POI 并抽取候选边，运行时从本地隔离折快照 `output/rule-kg/v1/folds/<场景名>.json` 查询训练折规则，生成规则证据卡并交给大模型判定（全程零 Neo4j 运行）。

```text
场景图与目标事件
  → 反向候选抽取 → 静态初筛 → 五级束划分
  → 训练折规则检索 → 大模型四值判定 → 规则引用校验
  → 因果公理补全与纯化 → 后置剪枝 → 报告与官方评分
```

一个束是同一程序、关系、系统调用及对象类别上的候选边组。判定为 all、none、mixed 或 unknown；后两种继续细分或保守保留。

## 2. 规则证据

- 来源：排除测试场景后，由其余训练场景蒸馏得到的规则。规则为 Motif，规则中的单步为 Hop。
- 第一路：按成员边的系统调用、源角色和目标角色查询。精确匹配要求三项一致；部分匹配要求系统调用和至少一端完整角色一致。
- 第一路排序：对齐等级、命中成员数、训练折加权似然比、训练折查准率、攻击命中数、规则编号。
- 第二路：按束内实际共用端点检查规则步骤能否连续走通，按走通程度、链长、训练折查准率和编号排序。
- 名额：`PROV_RULE_MIX` 控制两路规则数量，默认 `3+0`；例如 `2+1` 表示第一路两条、第二路一条。参数来自 `settings.rule_mix()`。
- 规则卡包含本束 R 编号、规则编号、对齐成员数、训练折统计及跳链。没有候选时显示“本束没有规则证据”，不生成编号。
- 两路均检索相同的训练折规则，使用同一套 R 编号和引用校验。

训练统计不保证当前场景正确；规则未命中不代表没有攻击。程序、对象、命令行和图上的实际行为仍是判定依据。

## 3. 引用校验

仅检查 all 结论。有规则证据时，模型必须引用有效 `rule_id` 与整数 `hop`。跳号必须存在，系统调用必须与束一致；精确匹配要求同一成员边的两端角色一致，部分匹配要求至少一端一致。结构检索按其顶点类型匹配契约校验。

无证据且无引用时按事实判断；无证据却编造规则引用，或有证据但引用缺失、无效时，降级为 mixed。引用从独立字段和理由文本中的 R 编号提取。校验计数写入 `RAG_GUARD` 日志。

## 4. 在线运行、免调用重放与评分

重放按轨迹恢复首层分组和组内成员的原始顺序，随后校验场景、模型和完整请求指纹。图、规则、提示词或判定配置发生影响请求的变化时，重放会报错。重放只读取已记录的判定。

```powershell
# 实时运行单场景（调用大模型判定）
& ./.venv/Scripts/python.exe attack_graph/main.py --scenario 8_FTP_WeakCreds_WebShell_Exfiltration --output output/attack-graph-runs/check/report.json

# 基于已有 .trace.jsonl 免 API 重放判定（用于判定后剪枝阶段回归与消融，0 LLM 调用）
& ./.venv/Scripts/python.exe attack_graph/main.py --scenario 8_FTP_WeakCreds_WebShell_Exfiltration --replay-trace output/attack-graph-baseline/traces/8_FTP_WeakCreds_WebShell_Exfiltration.trace.jsonl --output output/attack-graph-runs/check/report.json

# 官方口径评分
& ./.venv/Scripts/python.exe tools/score_report_product.py --report output/attack-graph-runs/check/report.json --gt groundtruth/8_FTP_WeakCreds_WebShell_Exfiltration.groundtruth.json

# 运行 foundation 基础单元测试与 tsg 引擎测试
& ./.venv/Scripts/python.exe -m unittest discover -s attack_graph/tests/foundation -p "test_*.py"
& ./.venv/Scripts/python.exe -m unittest discover -s tsg/tests -p "test_*.py"
```

默认结果目录为 `output/attack-graph-runs/<运行编号>/`；`attack_graph/` 的唯一正式基线归档至 `output/attack-graph-baseline/`。整体流程全程零 Neo4j：阶段 1（`intake.py` / `fold.py`）通过 `TSGSource` 从 `graphs/<场景名>.tsg` 离线定位 POI 并在内存保留原始单事件列表（`closure_events`）与当前 `tsg_path`；阶段 6 之后执行 `temporal_pruning.run_bidirectional` 直接复用阶段 1 内存单事件与 `TSGSource`（不再查询 Neo4j，也不再维护 `temporal_events.pkl`），阻断 `/dev/null`·广播总线·`systemd-*`·后台包更新守护进程与未确认包管理文件桥接，联合执行双向因果连通分量剪枝与时间窗进程保护；阶段 7（`s7_reporting.py` / `reporting.py`）在写聚合报告的同时，同目录同步导出伴生单事件明细 `<输出文件去后缀>.events.json.gz`（按 `(event_id, rel, identities)` 精确回配 `report_status`/`verdict`/`class`/`origin`/`reason`/`bundle_triple` 与去重 `entities` 表）。报告的 `edges` 是交给下游并用于评分的基础图，`unexcluded` 列出待复核保留边，`process_guard_evidence` 记录保护依据，`excluded` 记录被删边的事件编号与理由，`stats.temporal_pruning` 记录保护和剪枝数量。召回按标注步骤，查准按源、系统调用、目标三元组。

在线导航与碎片剪枝参数由 `attack_graph/config/navigator.toml` 统一配置（当前默认并发 `concurrency = 12`、单次请求超时 `timeout_seconds = 60`；发生限流或传输超时重试时 `llm/client.py` 输出 `[LLM_RETRY]` 日志；另含批大小、结构闸门、`[prune]` 包管理器词表与 FHS 静态资源子目录以及判定调用上限 `cap_calls`；`cap_calls = 0` 为默认的无上限模式，流程由 5 级拓扑划分与空拆/扇出闸门自收敛终止）。

## 5. 离线规则知识构建

```powershell
& ./.venv/Scripts/python.exe tools/build_rule_kg.py --fold-dir output/rule-kg/v1/fold-libraries --out output/rule-kg/v1
```

该命令生成本地隔离折规则知识快照 `output/rule-kg/v1/folds/<场景名>.json` 与 `manifest.json`，线上 `rag/graph_retrieve.py` 与 `rag/motif_likelihood.py` 直接读取该目录（零 Neo4j 连接）。规则节点只包含 Motif、Hop、Case，关系为 HAS_HOP、NEXT_HOP、DERIVED_FROM；全部按 fold 隔离。Case 是训练场景，保留其原有攻击阶段描述。在线规则检索不读取测试场景答案。（历史工具 `tools/build_rule_kg_neo4j.py` 仅保留作外部导入兼容，不再参与 `attack_graph/` 运行。）

知识快照包含规则、规则步骤、训练场景、角色分界和规则统计。现有训练折的来源、规则准入和蒸馏过程不因检索代码变动而重新计算。

## 6. 代码与工具

- `main.py`：单场景入口（支持 `--replay-trace`）；`core/runner.py`：七阶段装配；`settings.py`：`GRAPH_STORE_DIR`（默认 `graphs/`）与 `RULE_KG_DIR`（默认 `output/rule-kg/v1`）路径解析。
- `core/render.py`：规则检索结果和上下文渲染；`llm/guard.py`：规则引用校验；`llm/replay.py`：`.trace.jsonl` 免调用重放加载器。
- `core/axioms.py`、`core/stages/s5_causal_heal.py`：因果公理补全、图内写入路径记录（`collect_written_paths`）与 `.so`/`.pyc`/启动配置运行时加载纯化。
- `core/filters.py`、`core/stages/s6_pruning.py`：包管理碎片/基础设施辅助守护进程过滤与不复活已排除边规则。
- `core/stages/temporal_pruning.py`、`core/stages/process_protection.py`、`closure/snapshot.py`（`TSGSource`）：阶段 1 内存单事件复用、双向因果连通分量剪枝与进程保护（零 Neo4j）。
- `core/reporting.py`、`core/stages/s7_reporting.py`：聚合报告构建与伴生 `*.events.json.gz` 单事件明细导出。
- `rag/graph_retrieve.py`、`structure.py`、`motif_likelihood.py`：基于 `output/rule-kg/v1/folds/<fold>.json` 的本地规则检索、结构匹配与训练折排序。
- `rag/build_kg.py`、`schema.py`、`stats.py`：本地规则快照构建、结构定义与统计。
- `tools/eval_graph_retrieval.py`：对照符号规则匹配结果检查检索覆盖，不计算攻击正确率。
- `tools/audit_rag_entries.py`：规则入口和实际规则卡审计。
- `tools/sample_evidence_audit.py`：抽样检查规则步骤与成员边的结构对齐。

## 7. 边界与测量

1. 规则证据是束级证据，不代表束内每条边都已独立验证。
2. 规则库受训练场景限制；规则正确性没有独立完整的标准答案，不以规则候选覆盖代替攻击召回。
3. 没有跨主机对端流量自动对齐模块；目标事件和跨主机关联属于外部输入边界。
4. 模型单次运行存在波动。原 `provenance` 冻结基线成绩以 `output/provenance-baseline/OVERVIEW.md` 为准；`attack_graph/` 唯一正式基线固化在 `output/attack-graph-baseline/`（含 `reports_v2/`、`events_v2/` 与可离线重放的 `traces/`），日常测试与消融运行写 `output/attack-graph-runs/`。
5. 场景测试、评分和汇总遵循 `docs/agents/test-runbook.md` 与 `docs/agents/evaluation-protocol.md`。

## 8. 近期工程优化与重构说明

相比原冻结基线分支，当前 `attack_graph/` 目录已完成以下 4 项核心工程改造与泛化优化：

1. **彻底去 Neo4j 与单文件 `TSG2` 全属性图索引重构**（`tsg/`、`closure/snapshot.py`、`closure/intake.py`、`closure/fold.py`、`core/stages/temporal_pruning.py`、`rag/graph_retrieve.py`）：
   - 废除运行期 Neo4j 场景库查询、`trace-rules-kg-v1` 规则库连接以及 `tmp/provenance/l1-index/` / `temporal_events.pkl` 二级缓存，全面切换为 `graphs/<场景名>.tsg`（`TSGReader`/`TSGSource` `mmap` 零拷贝读取）与本地规则快照 `output/rule-kg/v1/folds/<fold>.json`。
   - 闭包遍历与时序剪枝统一采用 `(event_id, rel, syscall)` 三键去重匹配，避免同 `event_id` 的 `clone` 与 `execve` 等多系统调用边互相覆盖。
   - 阶段 1 保留原始单事件列表（`closure_events`）与 `tsg_path` 于内存；阶段 6.5 直接复用内存事件执行双向时序剪枝（零数据库查询）；阶段 7 同步导出伴生事件级明细 `*.events.json.gz`（当前 10 场景正式基线合计 **1,664,502** 条保留单事件，完整携带 `decision_source`、`llm_bundle_id`、`llm_bundle_level`、`llm_bundle_size`、`llm_verdict`、`rag_rules` 与排除集合的 `prune_stage`）。
2. **`.trace.jsonl` 逐批判定轨迹免调用重放**（`llm/replay.py`、`llm/judge.py`、`main.py --replay-trace`）：
   - 按 `(level, sorted(members))` 复用已记录的批次模型判定与规则引用校验后结论，支持在不修改阶段 1–4 逻辑与输入时以 **0 LLM API 调用**复现并迭代测试阶段 5–7 后置剪枝逻辑（详见 `tests/foundation/test_trace_replay.py`）；10 场景基线轨迹已随正式基线统一归档至 `output/attack-graph-baseline/traces/`。
3. **判定后纯化、不复活排除边与写入防投毒守卫**（`core/stages/s6_pruning.py`、`core/stages/s5_causal_heal.py`、`core/axioms.py`）：
   - 取消阶段 6 将 `excluded_edges`、`pruned_background`、`unpromoted_ambiguous`、`debris_pruned` 塞回 `final_unexcluded` 的做法；统一过滤未确认态 `verdict == "none"`、`ioctl`/元数据探测调用以及 `.so`/`.pyc`/启动初始化配置读取。
   - 新增 `collect_written_paths()` 检查：凡在图内曾被任何进程创建、写入或修改过的库文件与启动配置均受保护，防止借由伪装共享库或启动配置劫持的攻击被误剪。
4. **双向因果分量剪枝与通用运维噪音隔离**（`core/stages/temporal_pruning.py` `run_bidirectional`、`core/filters.py`、`config/navigator.toml`、`core/runner.py`）：
   - 反向可达遍历 `reachable()` 阻断 `/dev/null`·`/dev/zero`·`/dev/urandom` 等无状态设备、D-Bus/journal 广播套接字、`systemd-*` 基础设施守护进程、后台包更新守护进程及未确认包管理写桥接，防止无关进程借共读共享资源反向串联。
   - 以反向可达点、图内已写持久化单元/账号修改、非包管理外联伴随变更以及非包管理交互 Shell 派生作为初始种子，沿 `exec`/`clone`/`fork`、反向 `exit` 子进程关联及写后读数据流正向扩展，同时将 `[prune]` 收敛至标准 FHS 静态子目录（不整片屏蔽 `/usr/share/`）。
   - 验证结果（`attack_graph/tests/foundation` 128 项、`tsg/tests` 2 项、`tools/tests` 8 项、`attack_path/tests` 40 项全过；2026-11-27 替换场景 9 为 `9_Site_Defacement` 并基于更新后的 `output/rule-kg/v1` 完成全 10 场景正式重跑评测）：合并步骤召回率 **98.18%（810/825）**，合并查准率 **45.43%（18,248/40,170）**，导出保留单事件 **1,664,502** 条，实时大模型调用 `663` 次（`677` 次请求含重试）。
