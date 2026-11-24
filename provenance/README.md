# Provenance：基于规则证据的溯源图调查（历史冻结基线与备份）

> **模块定位**：本目录当前作为 **历史冻结基线实现与备份** 保留（对应冻结成绩目录 `output/provenance-baseline/`），日常新功能开发与算法迭代已切换至 [attack_graph/](file:///E:/Work/TraceSage/attack_graph)（参见 [attack_graph/README.md](file:///E:/Work/TraceSage/attack_graph/README.md)）。

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

## 4. 在线运行与评分

```powershell
& ./.venv/Scripts/python.exe provenance/main.py --scenario 8_FTP_WeakCreds_WebShell_Exfiltration --output tmp/provenance-check/report.json
& ./.venv/Scripts/python.exe tools/score_report_product.py --report tmp/provenance-check/report.json --gt groundtruth/8_FTP_WeakCreds_WebShell_Exfiltration.groundtruth.json
```

默认结果目录为 `output/provenance-runs/`，不自动更新正式基线。评分按人工标准答案步骤计算召回，按源、系统调用、目标、成败四元组计算查准。未排除边不计入确认输出。

在线导航参数由 `provenance/config/navigator.toml` 统一配置（包括并发数、批大小、四道结构闸门以及判定调用上限 `cap_calls`；`cap_calls = 0` 为默认的无上限模式，流程由 5 级拓扑划分与空拆/扇出闸门自收敛终止，配置为正整数 N 时在达到 N 次调用后触发截断保护）。

## 5. 离线规则知识构建

```powershell
& ./.venv/Scripts/python.exe tools/build_rule_kg.py --fold-dir output/provenance-baseline/distill/fold-libraries --out output/rule-kg/v1
& ./.venv/Scripts/python.exe tools/build_rule_kg_neo4j.py --kg-dir output/rule-kg/v1
```

第二条命令写入独立规则库 `trace-rules-kg-v1`。节点只有 Motif、Hop、Case，关系为 HAS_HOP、NEXT_HOP、DERIVED_FROM；全部按 fold 隔离。Case 是训练场景，保留其原有攻击阶段描述。在线规则检索不读取测试场景答案。

知识快照包含规则、规则步骤、训练场景、角色分界和规则统计。现有训练折的来源、规则准入和蒸馏过程不因检索代码变动而重新计算。

## 6. 代码与工具

- `main.py`：单场景入口；`core/runner.py`：七阶段装配。
- `core/render.py`：规则检索结果和上下文渲染；`llm/guard.py`：规则引用校验。
- `rag/graph_retrieve.py`、`structure.py`、`motif_likelihood.py`：规则查询、结构匹配和训练折排序。
- `rag/build_kg.py`、`neo4j_kg.py`、`schema.py`、`stats.py`：规则快照构建、数据库导入、结构定义与统计。
- `tools/eval_graph_retrieval.py`：对照符号规则匹配结果检查检索覆盖，不计算攻击正确率。
- `tools/audit_rag_entries.py`：规则入口和实际规则卡审计。
- `tools/sample_evidence_audit.py`：抽样检查规则步骤与成员边的结构对齐。

## 7. 边界与测量

1. 规则证据是束级证据，不代表束内每条边都已独立验证。
2. 规则库受训练场景限制；规则正确性没有独立完整的标准答案，不以规则候选覆盖代替攻击召回。
3. 没有跨主机对端流量自动对齐模块；目标事件和跨主机关联属于外部输入边界。
4. 模型单次运行存在波动。现有冻结成绩及其代码版本以 `output/provenance-baseline/OVERVIEW.md` 为准，不作为当前修改版本的实测成绩。
5. 场景测试、评分和汇总遵循 `docs/agents/test-runbook.md` 与 `docs/agents/evaluation-protocol.md`。
