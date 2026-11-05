# Provenance-Navigator: 规则证据与技术证据的溯源图 RAG 导航

## 1. 当前正式方案

导航器运行时只有一个模式：**RAG v2**。

对每个候选束，系统同时检索两段独立证据：

1. **规则证据 R**：只查离线蒸馏得到的规则库（Motif/Hop）。
2. **技术证据 E**：只查 MITRE ATT&CK 行为观测（BehaviorObservable/Technique）。

两段证据分开检索、分开编号、分开排序、分开引用校验，不互相转化：

- 规则卡不含 ATT&CK 技术编号；
- 技术卡不含规则编号和跳号；
- 不允许用「技术反查规则」把技术标签包装成规则证据；
- 没有对应证据时，不允许编造 R/E 编号。

入口：

```bash
.venv/Scripts/python.exe provenance-navigator/main.py --scenario <场景全名>
```

默认输出 `output/navigator-runs/<场景全名>_rag.json`。

## 2. 两段证据

### 2.1 规则证据

| 维度 | 定义 |
|---|---|
| 来源 | 9 个训练场景蒸馏出的 Motif，按折隔离 |
| 匹配等级 | R2 精确：系统调用、源角色、目标角色三项全同；R1 部分：系统调用相同，且至少一个完整角色相同 |
| 排序 | R2 优先；再按训练折查准率、攻击命中、匹配成员数 |
| 上限 | 每束最多 3 条 |
| 卡片字段 | R 编号、Motif 编号、精确/部分对齐成员数、训练折查准率、攻击/背景/忽略命中、支持场景数、跳链 |
| 空结果 | 显示「本束没有规则证据」，不生成 R 编号 |

规则卡不显示 ATT&CK 技术。规则与技术的对应关系只保留在离线知识库中，用于评测，不进入检索和提示词。

### 2.2 技术证据

| 维度 | 定义 |
|---|---|
| 来源 | ATT&CK 技术库 + 45 条人工行为观测 |
| T-强 | 系统调用匹配，且观测的角色模式与成员边角色匹配；注入提示词 |
| T-弱 | 只有进程名或路径匹配，或观测本身只有系统调用条件；默认不注入，只写运行记录 |
| 排序 | 观测置信度、命中成员数、命中条件数 |
| 上限 | 每束最多 3 个 |
| 卡片字段 | E 编号、ATT&CK 编号、技术名称、战术、命中条件、观测置信度、是否人工核验 |
| 空结果 | 显示「本束没有技术证据」，不生成 E 编号 |

E 是束内证据编号，不是 ATT&CK 编号；ATT&CK 编号形如 T1071，只用于识别技术。

## 3. 引用约束

判 all 时：

- 引用规则：写 `rule_id`（R1）和 `hop`（规则里真实存在的跳号）；跳的系统调用必须与束一致；精确规则要求源/目标角色都与同一个成员边一致，部分规则要求至少一个角色一致。
- 引用技术：写 `tech_id`（E1）；不要求跳号。
- 有证据时至少引用一个有效编号；任何一个被引用的编号无效，降级为 mixed。
- 没有证据却写 R/E，降级为 mixed。

守卫统计写入运行日志的 `RAG_GUARD` 行，并汇总到评测报告。

## 4. 运行流程

```text
Neo4j 场景图
  → closure：从 POI 反向抽取候选边
  → PreFilter：静态只读初筛
  → 束划分：程序 + 关系 + 系统调用 + 对象类别
  → 规则检索：Motif/Hop（当前折）
  → 技术检索：BehaviorObservable → Technique（全局）
  → 大模型判定：四选一 all / none / mixed / unknown
  → 引用守卫：规则跳号、技术编号
  → DebrisPrune + 报告：edges / unexcluded / excluded
  → score_report_product：召回按步骤、查准按边
```

## 5. 离线知识构建

离线部分保留，不参与运行时：

1. 从 9 个训练场景蒸馏 Motif、Hop、逐规则统计；
2. 写入 `output/navigator-baseline/distill/fold-libraries/`；
3. 构建 Rule KG JSON：`tools/build_rule_kg.py`；
4. ATT&CK 快照与行为观测：`tools/build_attack_kg.py`；
5. 写入 Neo4j 规则库：`tools/build_rule_kg_neo4j.py`。

规则库 `trace-rules-kg-v1` 的结构：

- 全局节点：867 Technique、15 Tactic、45 BehaviorObservable；
- 按折节点：10 折合计 1,454 Motif、2,362 Hop、90 Case；
- 关系：HAS_HOP、NEXT_HOP、IMPLEMENTS、DERIVED_FROM、BELONGS_TO、OBSERVES。

折隔离：测场景 k 时，规则检索只读第 k 折的 Motif/Hop/Case；技术、战术、行为观测是全局知识。

## 6. 代码结构

```text
provenance-navigator/
├── main.py                 # 单场景 CLI：RAG v2
├── navigator/              # 正式运行时包
│   ├── pipeline.py         # 主流程：闭包 → 束划分 → 证据 → 判定 → 报告
│   ├── decoder.py          # 基模解码
│   ├── render.py           # 规则证据 + 技术证据两段渲染
│   └── guard.py            # 规则/技术引用守卫
├── rag/                    # 证据检索与规则知识库
│   ├── graph_retrieve.py   # retrieve_rules / retrieve_techniques
│   ├── neo4j_kg.py         # Rule KG 入库
│   ├── build_kg.py         # 从折库构建 Rule KG JSON
│   ├── stats.py            # 逐规则训练折统计
│   ├── attack.py、link.py、schema.py
│   └── embed.py、index.py、rerank.py、query.py  # 向量实验模块，未接入主路径
├── closure/                # 反向闭包抽取
├── domain/                 # 边、候选池、角色分类
├── llm/                    # 束判定、模型接入、结论解析
├── rules/                  # 离线蒸馏与角色编码（rules 运行模式已退出）
├── routing/                # prepare/filters/report 供运行时使用；route/channels 仅离线 LOO
├── config/                 # 场景、提示词、行为观测种子
├── tests/                  # 单元测试
└── tools/                  # 规则库维护
```

## 7. 快速开始

```bash
# 单场景正式运行
.venv/Scripts/python.exe provenance-navigator/main.py --scenario 1_Web_Exploit_Ransomware \
  --output output/navigator-runs/1_Web_Exploit_Ransomware_rag.json

# 官方评分
.venv/Scripts/python.exe tools/score_report_product.py \
  --report output/navigator-runs/1_Web_Exploit_Ransomware_rag.json \
  --gt groundtruth/1_Web_Exploit_Ransomware.groundtruth.json
```

离线规则库维护（仅重建折库/规则 KG 时使用，不参与日常评测）：

```bash
.venv/Scripts/python.exe provenance-navigator/run_loo_folds.py --mode rules \
  --out output/navigator-runs/loo --keep-reports tmp/loo_rules_reports
.venv/Scripts/python.exe provenance-navigator/tools/rebuild_library.py --from-scratch
```

## 8. 正式基线

正式基线由 `tools/promote_v2_baseline.py` 生成，包含 10 份压缩报告、`summary_v2.json`、`OVERVIEW.md` 和代码指纹。

当前统一提示词口径基线：**77.37% 召回、59.66% 查准**（701/906 步，19540/32751 条边，221 次调用，单次运行）。

基线的逐场景数字、微平均、代码版本与复现命令统一见：

👉 [output/navigator-baseline/OVERVIEW.md](../output/navigator-baseline/OVERVIEW.md)

评分口径：`tools/score_report_product.py`；召回按步骤、查准按边；同一条边多次发生只计一次。

## 9. 边界与限制

1. **运行时没有向量检索和重排。** `rag/embed.py`、`index.py`、`rerank.py`、`query.py` 是早期文本向量实验模块，主路径不调用；规则和技术都通过 Neo4j 图查询获得。
2. **证据是束级，不是边级。** 没有逐边证据卡、逐边引用和引用忠实度测量。
3. **没有增量知识演化。** 新场景、新 ATT&CK 版本的增量摄入、版本回滚未实现。
4. **ATT&CK 映射不完整。** 45 条人工行为观测覆盖 45 个技术；867 个技术里绝大多数没有行为观测。
5. **技术答案键是人工草稿。** 技术级命中率在复核前不是最终结论。
6. **规则正确性没有直接标准答案。** 评测用离线技术链接做代理，需配合人工抽检。
7. **折库来自 9 个训练场景。** 规则库覆盖范围受训练场景限制；未命中的行为不等于没有攻击。
8. **当前基线为单次运行。** 没有重复运行，波动范围未知。

## 10. 历史说明

旧的 `rules`、`hybrid`、`llm-only` 运行模式已退出导航器入口。离线蒸馏代码（`rules/offline.py`、`admission.py`、`coverage.py`、`roles.py`、`library.py`、`run_loo_folds.py`）保留，用于构建折库和规则 KG；`pipeline.py`、`routing/route.py`、`routing/channels.py` 仅保留给离线 LOO，不在 RAG 运行时路径上。
