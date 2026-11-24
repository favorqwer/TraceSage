# Attack Graph：当前开发主线溯源图调查系统

> **目录定位**：`attack_graph/` 是 TraceSage 当前主要开发与优化的溯源系统主线目录；原 `provenance/` 目录现保留作为历史冻结基线与备份（对应 `output/provenance-baseline/`）。

## 1. 运行流程

系统从外部提供的目标事件开始调查，在单个场景的标准 `-v2` 图数据库中抽取候选边。运行时通过 Neo4j 查询当前训练折的规则，生成规则证据卡并交给大模型判定。

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

```powershell
# 实时运行单场景（调用大模型判定）
& ./.venv/Scripts/python.exe attack_graph/main.py --scenario 8_FTP_WeakCreds_WebShell_Exfiltration --output output/attack-graph-runs/check/report.json

# 基于已有 .trace.jsonl 免 API 重放判定（用于判定后剪枝阶段回归与消融，0 LLM 调用）
& ./.venv/Scripts/python.exe attack_graph/main.py --scenario 8_FTP_WeakCreds_WebShell_Exfiltration --replay-trace output/provenance-runs/attack-graph-20261124/reports/8_FTP_WeakCreds_WebShell_Exfiltration.trace.jsonl --output output/attack-graph-runs/check/report.json

# 官方口径评分
& ./.venv/Scripts/python.exe tools/score_report_product.py --report output/attack-graph-runs/check/report.json --gt groundtruth/8_FTP_WeakCreds_WebShell_Exfiltration.groundtruth.json

# 运行 foundation 基础单元测试
& ./.venv/Scripts/python.exe -m unittest discover -s attack_graph/tests/foundation -p "test_*.py"
```

默认结果目录为 `output/attack-graph-runs/<运行编号>/`；`attack_graph/` 的正式冻结基线统一归档至 `output/attack-graph-baseline/`。正式入口默认在阶段 6 之后执行 `temporal_pruning.run_bidirectional`（先基于 `Neo4j` 单遍类型流式查询并在 `tmp/provenance/l1-index/<db>/temporal_events.pkl` 建立按库指纹校验的原子快照缓存，再阻断 `/dev/null`·广播总线·`systemd-*`·后台包更新守护进程与未确认包管理文件桥接，联合执行双向因果连通分量剪枝与时间窗进程保护）。报告的 `edges` 是交给下游并用于评分的基础图，`unexcluded` 列出待复核保留边，`process_guard_evidence` 记录保护依据，`excluded` 记录被删边的事件编号与理由，`stats.temporal_pruning` 记录保护和剪枝数量。召回按标注步骤，查准按源、系统调用、目标、成败四元组。

在线导航与碎片剪枝参数由 `attack_graph/config/navigator.toml` 统一配置（包括并发数、批大小、结构闸门、`[prune]` 包管理器词表与 FHS 静态资源子目录以及判定调用上限 `cap_calls`；`cap_calls = 0` 为默认的无上限模式，流程由 5 级拓扑划分与空拆/扇出闸门自收敛终止）。

## 5. 离线规则知识构建

```powershell
& ./.venv/Scripts/python.exe tools/build_rule_kg.py --fold-dir output/provenance-baseline/distill/fold-libraries --out output/rule-kg/v1
& ./.venv/Scripts/python.exe tools/build_rule_kg_neo4j.py --kg-dir output/rule-kg/v1
```

第二条命令写入独立规则库 `trace-rules-kg-v1`。节点只有 Motif、Hop、Case，关系为 HAS_HOP、NEXT_HOP、DERIVED_FROM；全部按 fold 隔离。Case 是训练场景，保留其原有攻击阶段描述。在线规则检索不读取测试场景答案。

知识快照包含规则、规则步骤、训练场景、角色分界和规则统计。现有训练折的来源、规则准入和蒸馏过程不因检索代码变动而重新计算。

## 6. 代码与工具

- `main.py`：单场景入口（支持 `--replay-trace`）；`core/runner.py`：七阶段装配。
- `core/render.py`：规则检索结果和上下文渲染；`llm/guard.py`：规则引用校验；`llm/replay.py`：`.trace.jsonl` 免调用重放加载器。
- `core/axioms.py`、`core/stages/s5_causal_heal.py`：因果公理补全、图内写入路径记录（`collect_written_paths`）与 `.so`/`.pyc`/启动配置运行时加载纯化。
- `core/filters.py`、`core/stages/s6_pruning.py`：包管理碎片/基础设施辅助守护进程过滤与不复活已排除边规则。
- `core/stages/temporal_pruning.py`、`core/stages/process_protection.py`、`closure/neo4j.py`：全库单遍流式缓存、双向因果连通分量剪枝与进程保护。
- `rag/graph_retrieve.py`、`structure.py`、`motif_likelihood.py`：规则查询、结构匹配和训练折排序。
- `rag/build_kg.py`、`neo4j_kg.py`、`schema.py`、`stats.py`：规则快照构建、数据库导入、结构定义与统计。
- `tools/eval_graph_retrieval.py`：对照符号规则匹配结果检查检索覆盖，不计算攻击正确率。
- `tools/audit_rag_entries.py`：规则入口和实际规则卡审计。
- `tools/sample_evidence_audit.py`：抽样检查规则步骤与成员边的结构对齐。

## 7. 边界与测量

1. 规则证据是束级证据，不代表束内每条边都已独立验证。
2. 规则库受训练场景限制；规则正确性没有独立完整的标准答案，不以规则候选覆盖代替攻击召回。
3. 没有跨主机对端流量自动对齐模块；目标事件和跨主机关联属于外部输入边界。
4. 模型单次运行存在波动。原 `provenance` 冻结基线成绩以 `output/provenance-baseline/OVERVIEW.md` 为准；`attack_graph/` 正式基线固化在 `output/attack-graph-baseline/`，日常测试与消融运行写 `output/attack-graph-runs/`（早期重放轨迹也见于 `output/provenance-runs/`）。
5. 场景测试、评分和汇总遵循 `docs/agents/test-runbook.md` 与 `docs/agents/evaluation-protocol.md`。

## 8. 近期工程优化与重构说明

相比原冻结基线分支，当前 `attack_graph/` 目录已完成以下 4 项核心工程改造与泛化优化：

1. **Neo4j 全库扫描性能优化与指纹缓存**（`closure/neo4j.py`、`core/stages/temporal_pruning.py`）：
   - 原实现通过无标签分页查询触发数百次 `DirectedAllRelationshipsScan`，在大规模图库（如场景 10）单次耗时超 15 分钟。
   - 改为 `ReadOnlyGraph.stream_values` 按 5 类标准边标签并发单遍流式拉取，并按数据库变更指纹原子持久化为 `tmp/provenance/l1-index/<db>/temporal_events.pkl`（冷加载大幅提速，热命中稳定在数秒内；详见 `tests/foundation/test_temporal_pruning_cache.py`）。
2. **`.trace.jsonl` 逐批判定轨迹免调用重放**（`llm/replay.py`、`llm/judge.py`、`main.py --replay-trace`）：
   - 按 `(level, sorted(members))` 复用已记录的批次模型判定与规则引用校验后结论，支持在不修改阶段 1–4 逻辑时以 **0 LLM API 调用**复现并迭代测试阶段 5–7 后置剪枝逻辑（详见 `tests/foundation/test_trace_replay.py`）。
3. **判定后纯化、不复活排除边与写入防投毒守卫**（`core/stages/s6_pruning.py`、`core/stages/s5_causal_heal.py`、`core/axioms.py`）：
   - 取消阶段 6 将 `excluded_edges`、`pruned_background`、`unpromoted_ambiguous`、`debris_pruned` 塞回 `final_unexcluded` 的做法；统一过滤未确认态 `verdict == "none"`、`ioctl`/元数据探测调用以及 `.so`/`.pyc`/启动初始化配置读取。
   - 新增 `collect_written_paths()` 检查：凡在图内曾被任何进程创建、写入或修改过的库文件与启动配置均受保护，防止借由伪装共享库或启动配置劫持的攻击被误剪。
4. **双向因果分量剪枝与通用运维噪音隔离**（`core/stages/temporal_pruning.py` `run_bidirectional`、`core/filters.py`、`config/navigator.toml`、`core/runner.py`）：
   - 反向可达遍历 `reachable()` 阻断 `/dev/null`·`/dev/zero`·`/dev/urandom` 等无状态设备、D-Bus/journal 广播套接字、`systemd-*` 基础设施守护进程、后台包更新守护进程及未确认包管理写桥接，防止无关进程借共读共享资源反向串联。
   - 以反向可达点、图内已写持久化单元/账号修改、非包管理外联伴随变更以及非包管理交互 Shell 派生作为初始种子，沿 `exec`/`clone`/`fork`、反向 `exit` 子进程关联及写后读数据流正向扩展，同时将 `[prune]` 收敛至标准 FHS 静态子目录（不整片屏蔽 `/usr/share/`）。
   - 验证结果（`tests/foundation` 全套 118 项单元测试通过；10 场景 `--replay-trace` 消融评测）：微观召回率由基线 **83.89%（760/906）** 保持至 **84.00%（761/906）**，微观查准率由 **10.66%（19,620/184,118）** 提升至 **53.43%（19,616/36,716）**。
