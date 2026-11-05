# RAG 全量替换 B1 交接文档

> **2026-11-05 更新**：本文件描述的是 v2 扶正前的实验实现，其中的旧入口和命令已删除。
> 当前正式入口为 `provenance-navigator/main.py --scenario <场景>`；运行时模块位于
> `provenance-navigator/navigator/`（`pipeline.py`、`decoder.py`、`render.py`、`guard.py`）；
> 正式基线为 `output/navigator-baseline/OVERVIEW.md`（10 场景 76.93% / 60.02%，混合提示词口径）。
> 旧 `experiments/run_rag.py`、`run_b1_real_2hop.py`、`run_frozen_pair.py`、`rag_judge.py`
> 以及边级原型已删除；离线蒸馏代码保留。

- 文档版本：RAG-Handover-1.0
- 生成日期：2026-11-05
- 适用对象：接手 RAG 全量替换实验的后续 agent
- 相关文档：`docs/HANDOVER_B1.md`（B1 冻结与 B0/B1 对比）、`AGENTS.md`（最高工程法则）

---

## 0. 先读这一段：当前真实结论

**全量 RAG 替换在结构上已经成立，但没有证明优于 B1。**

- 10 场景对比（RAG 全量替换 vs B1，同一评分器）：RAG 76.93% / 56.70%，B1 78.37% / 58.97%；召回 −13 步，查准 −2.27 点，正确边 −246，上报边 +892，LLM 调用同为 219。
- 这次 10 场景对比是在「层级路由 + 规则子图证据 + 技术候选 + T1105 包管理器观测」的版本上跑的；它仍然包含提示词先验 A1–A3/A5，不是完全干净的对照，但比后续的 97% 结果干净。
- 之后又做了三个优化（去掉查准/背景统计、关闭 `hot_guard`、补父进程/`请判 all`），只重跑了场景 1 和 4：
  - 场景 1：97.0% / 76.5%，B1 95.05% / 75.62%；
  - 场景 4：61.9% / 7.48%，B1 66.67% / 7.66%。
- **场景 1 的 97.0% 不能作为 RAG 有效的证据。** 它同时受到 A1–A7 的硬编码提示、标签效应、关闭结构守卫和统计先验移除的影响。后续 agent 不得把 97.0% 写进论文成绩。
- 场景 1 的 97.0% 也还没有重复运行；此前 RAG 在场景 1 上跑过 86.1% 和 91.1%，单次波动很大。

**一句话：RAG 机制可运行，知识图谱已入库，但目前没有净增益；最近一次 97% 是提示词调参产物，不能当方法结论。**

**创新点与当前实现的差距见 0.1。后续 agent 不得把当前实现当成完整创新点的验证，也不得用当前负结果否定完整创新点。**

---

## 0.1 创新点与当前实现的差距（必读）

### 0.1.1 你要做的创新点（原始设想）

把离线蒸馏出的溯源图基模（Motif）组织成知识图谱，借鉴 LightRAG 的双层检索与增量更新机制，在因果图慢速通道判定时检索匹配的**规则子图**，作为先验上下文注入大语言模型；让符号规则的语义上下文与大模型裁决真正对齐，并建立能够吸收 MITRE ATT&CK 外部威胁情报、未来自动化攻击智能体生成数据、可随知识库持续演进扩充的神经符号协同溯源体系。

拆成四个可独立验证的创新点：

1. **溯源基模知识图谱**：Motif、Hop、ATT&CK Technique/Tactic、历史 Case、BehaviorObservable 统一到可版本化的图 schema；每条规则带攻击命中、背景命中、忽略命中、查准率；按折隔离。
2. **LightRAG 式混合检索**：符号精确匹配 + 向量语义召回 + 重排 + 图谱邻域扩展，检索结果是规则子图，不是文本片段。
3. **边级证据绑定与引用约束裁决**：把证据从「束标签」改成「边-跳证据卡」；模型必须逐边引用规则编号与跳号；没有引用不成立。目标是解决 B1 的标签效应和规则-LLM 割裂。
4. **增量知识演化**：新场景、ATT&CK 版本、未来自动化攻击数据按「挖掘→去重→统计→重嵌入→发布」增量进入 KG，并保留版本与回滚。

### 0.1.2 当前实现覆盖了哪一部分

| 创新点 | 当前状态 | 说明 |
|---|---|---|
| 1. 溯源基模知识图谱 | **部分实现** | 1,454 Motif / 2,362 Hop / 867×10 Technique 已入 Neo4j；逐规则统计已算；ATT&CK 只做了 45 项 BehaviorObservable，不是完整 867 技术映射；技术答案键是人工草稿 |
| 2. LightRAG 式混合检索 | **只实现了图查询部分** | 主路径是 Cypher Hop/技术入口 + 图谱扩展；**Qwen3-Embedding FP8 与 Reranker FP16 没有接入主路径**；向量检索只在早期文本实验里跑过，未与图检索融合 |
| 3. 边级证据与引用约束 | **只实现了束级** | 当前证据挂在层级束上，不是边-跳级；引用守卫只检查束级 `all` 是否引用 R 编号；没有真正的逐边证据卡、逐边引用、引用忠实度 |
| 4. 增量知识演化 | **未实现** | `rag/` 下没有 `evolve.py`；没有版本化增量摄入、没有新场景/新 ATT&CK 的合并流程 |

因此，**当前的 10 场景对比测的不是完整创新点**。它测的是：

> 层级路由 + 图查询（Cypher）+ 束级规则子图证据 + 提示词先验 + 部分 ATT&CK 观测。

这既没有向量检索，也没有边级绑定，也没有增量演化；它还包含第 4 节的 A1–A3/A5 提示词先验。**不能用这个负结果否定完整创新点，也不能用 97.0% 肯定它。**

### 0.1.3 研究问题与假设

- **RQ1（检索层）**：规则知识图谱的混合检索，能否在符号匹配不可达的 GT 攻击边上，把正确规则/技术排进 top-k？
- **RQ2（内容层）**：在 B1 的标签效应之上，图检索证据能否带来额外增量？即 `R_hyb − B1` 是否稳定为正？
- **RQ3（协议层）**：边级证据 + 强制引用，能否降低 B1 的标签效应和误报，同时不损失召回？
- **RQ4（演化层）**：把留出场景/新 ATT&CK 增量加入 KG 后，该场景的检索命中是否上升，且不需要重训？

对应假设：

- H1：混合检索在符号不可达边上的条件 hit@k 高于纯符号；
- H2：`R_hyb` 相对 B1 的微平均查准提升 ≥1 点，召回下降不超过 1 步；
- H3：增益在 `R_no_prior`（不显示统计先验）、`R_bundle`（束级而不是边级）、`R_no_cite`（不强制引用）消融中会消失或显著下降，证明增益来自「图检索内容 + 边级引用」，不是标签；
- H4：增量加入场景 k 后，场景 k 的检索 hit@k 上升，且旧场景不退化。

### 0.1.4 什么结果才算证明了创新点

- 检索层：在 695 条符号不可达边上，条件 hit@k 显著高于纯符号；必须报全量、可达子集、技术级三组数。
- 内容层：`R_hyb − B1` 的逐场景配对差值稳定为正，不是只靠某一个场景；必须附差分边清单。
- 协议层：引用合规率 ≥90%，引用忠实度可测；人工审计 20–50 条变化边。
- 演化层：留出场景加入 KG 后，该场景检索命中上升；旧场景不退化。
- 如果四项都做不到，按零假设写负结果；不得调提示词凑数。

### 0.1.5 与最接近工作 OMNISEC 的差异

- OMNISEC 用「正常行为知识库 + CTI 文本」做 RAG，让 LLM 判断异常行为是否攻击；候选来自异常检测/稀有路径。
- 本工作用「离线蒸馏 Motif/Hop + ATT&CK + Case」的规则子图做检索；候选来自 POI 因果闭包 + 静态初筛 + 符号匹配；证据是边-跳级规则子图，不是文本片段；要求逐边引用规则编号与跳号；知识库可增量演化。
- 论文摘要、引言、相关工作必须写清这个差异；不能只说「我们也用 RAG」。

### 0.1.6 当前实现为什么不能证明创新点

1. 主路径没有向量检索与重排，LightRAG 式混合检索只完成了图查询一半。
2. 证据是束级，不是边-跳级；引用守卫是束级 `all`，不是逐边引用。
3. 提示词先验 A1–A5 和第 4 节的硬编码，使 97.0% 不能归因给知识库。
4. 技术答案键是人工草稿，技术级数字不是最终结论。
5. 增量演化没有实现。

**后续 agent 的第一件事不是继续调提示词，而是先决定：是否按 0.1.1 的完整创新点补齐缺失层；如果只做当前束级图查询，就必须按零假设写负结果。**

---

## 1. 已经确认有效的部分

### 1.1 B0/B1 冻结与评分修复

- 冻结代码：`provenance-navigator/experiments/run_v4_frozen.py`
- 源 commit：`9c11503c2c80daee95a604f561606295f1621d59`
- 解码器：`provenance-navigator/experiments/experiment_engine.py`
- 评分器：`tools/score_report_product.py`（已修 `effect/effects` 四元组口径）
- 10 场景重跑（`tmp/frozen_runs/summary_b1.json`）：
  - B0：77.92% / 58.94%，219 次调用；
  - B1：78.37% / 58.97%，219 次调用；
  - B1 − B0：+4 步、+0.03 点，内容效应接近零。
- 报告：`tmp/frozen_runs/G0_REPORT.md`

### 1.2 本地检索模型可行性（G1）

- `D:\local_models\Qwen3-Embedding-4B`：torchao `Float8WeightOnlyConfig`，CUDA，2560 维，峰值 4.419GB；
- `D:\local_models\Qwen3-Reranker-0.6B`：FP16，CUDA，峰值 1.148GB；
- 报告：`tmp/frozen_runs/G1_REPORT.md`
- 注意：当前 RAG 全量替换的主路径**没有使用** embedding/reranker；它用的是 Neo4j 图查询。embedding/reranker 只用于早期的文本检索实验。

### 1.3 Rule KG v1 与 Neo4j

- 独立数据库：`trace-rules-kg-v1`（企业版 2026.07.1，支持多数据库）。
- 规模：1,454 Motif、2,362 Hop、8,670 Technique（867×10 折）、150 Tactic、90 Case、450 BehaviorObservable；
  - 边：2,362 `HAS_HOP`、908 `NEXT_HOP`、6,266 `IMPLEMENTS`、1,799 `DERIVED_FROM`、10,990 `BELONGS_TO`、450 `OBSERVES`。
- 每折用 `fold` 属性隔离；测场景 k 只用 `KG_k`。
- 图检索器：`provenance-navigator/rag/graph_retrieve.py`
  - Hop 入口与在线符号匹配逐场景一致；
  - 技术入口：`BehaviorObservable → Technique → IMPLEMENTS → Motif`；
  - 扩展：`HAS_HOP` / `IMPLEMENTS` / `DERIVED_FROM`。
- 入库代码：`provenance-navigator/rag/neo4j_kg.py`；入口 `tools/build_rule_kg_neo4j.py`。

### 1.4 图检索机制已验证

- 场景 7：Hop 入口命中 3/71，与 `MatchIndex` 在线可达一致；技术入口取回 70/71 条边的规则子图。
- 场景 1：Hop 入口 34/99，与在线可达一致；技术入口取回 97/99。
- 技术级覆盖是**测量值，不是 LLM 判定增益**；答案键是人工草稿，见第 8 节。

---

## 2. 10 场景对比（当前最干净的 RAG 全量替换结果）

| 场景 | B1 召回 | B1 查准 | RAG 召回 | RAG 查准 | Δ召回 | Δ查准 | 调用 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 Web Exploit | 95.05% | 75.62% | 86.14% | 76.90% | −9 | +1.27 | 29 |
| 2 SSH Spray | 98.15% | 50.00% | 98.15% | 50.79% | 0 | +0.79 | 23 |
| 3 Phishing Beacon | 100.00% | 6.64% | 100.00% | 6.87% | 0 | +0.24 | 28 |
| 4 Repo Poisoning | 66.67% | 7.66% | 60.71% | 11.59% | −5 | +3.93 | 38 |
| 5 Service Pivot | 93.87% | 39.43% | 93.87% | 36.43% | 0 | −3.00 | 23 |
| 6 Web SQLi | 91.30% | 1.09% | 100.00% | 0.86% | +4 | −0.24 | 1 |
| 7 DB Bruteforce | 87.67% | 98.63% | 87.67% | 98.78% | 0 | +0.15 | 5 |
| 8 FTP WebShell | 95.24% | 81.67% | 92.06% | 84.05% | −2 | +2.38 | 11 |
| 9 Container Escape | 13.55% | 29.31% | 13.55% | 29.31% | 0 | 0.00 | 1 |
| 10 Tomcat DNS | 97.89% | 9.70% | 96.84% | 8.35% | −1 | −1.35 | 60 |
| **微平均** | **78.37%** | **58.97%** | **76.93%** | **56.70%** | **−13 步** | **−2.27** | 219 |

产物：`tmp/rag-pilot/summary_rag.json`、`tools/compare_rag_b1.py`、`tmp/rag-pilot/logs/*.log`。

**注意**：这张表是在三个优化之前生成的；它包含 A1–A3/A5 和 B4，但不包含 A4/A6/A7。后续 1/4 的 97.0%/61.9% 是另一版，不能混入这张表。

---

## 3. 当前 RAG 主路径的代码结构

| 文件 | 作用 |
|---|---|
| `provenance-navigator/experiments/run_rag.py` | RAG 全量替换入口；设置 `RENDER_HOOK`、RAG 系统提示词、`all` 引用守卫、`cfg.none_guard="off"` |
| `provenance-navigator/experiments/rag_render.py` | 在 B1 层级束标题后插入规则子图证据卡；父进程/上游执行环境/`请判 all` 上下文 |
| `provenance-navigator/experiments/run_v4_frozen.py` | 冻结 B1 主流程；暴露 `CURRENT_MATCHER`、`CURRENT_PARENT_MAP`、`RENDER_HOOK` |
| `provenance-navigator/experiments/rag_judge.py` | 旧的 40 个小束判定器；**当前 `run_rag.py` 不使用它**，不要混淆 |
| `provenance-navigator/rag/graph_retrieve.py` | 图优先检索器 |
| `provenance-navigator/rag/neo4j_kg.py` | Rule KG 入库与计数 |
| `provenance-navigator/config/prompts/judge_bundle_rag.md` | RAG 层级束系统提示词 |
| `provenance-navigator/config/attack-observables.seed.json` | 45 项 BehaviorObservable |
| `groundtruth/attack-technique-map.json` | 技术级答案键，人工草稿 |

当前 `run_rag.py` 的流程：

1. 设置 `m.USE_MOTIF_EVIDENCE=False`、`m.VARIANT="v5_rag_hier"`；
2. 用 `judge_bundle_rag.md` 覆盖 `judge_mod.BUNDLE_SYSTEM`；
3. 用 `guarded_judge_bundles` 检查 `all` 是否有合法 R 引用；
4. 设置 `cfg.none_guard = lambda: "off"`；
5. 设置 `m.RENDER_HOOK = rag_render.render`；
6. 调用 `run_single_scenario`，闭包/初筛/图公理/评分沿用冻结 B1。

---

## 4. 必须清理的硬编码与场景特化（最高优先级）

以下 A/B 项**违反 AGENTS.md 第 1 条**（判据必须脱离测试场景独立成立）。C 项是从 B1 继承的，不是新增，但必须记录并固定。

### A. 我在 RAG 方法里新增的硬编码先验

| # | 位置 | 内容 | 处理 |
|---|---|---|---|
| A1 | `config/prompts/judge_bundle_rag.md:12-18` | 「外部大流量、爆破入口、下载/临时目录、持久化、删除/加密、命令执行 → 应判 all」 | 删除或改为消融 |
| A2 | `config/prompts/judge_bundle_rag.md:20-24` | 「覆盖 1/1000 也可能判 all」 | 删除或改为消融 |
| A3 | `config/prompts/judge_bundle_rag.md:61-64` | 「没有可引用规则时不得判 all」 | 删除或改为消融 |
| A4 | `experiments/rag_render.py:178-181` | 「请判 all，不得因程序本身是常见 Linux 命令而误判为 none」 | **删除** |
| A5 | `experiments/rag_render.py:154` | 证据卡写「本束命中攻击基模」 | 改为中性描述，或作为消融 |
| A6 | `experiments/rag_render.py:143-157` | 删掉了查准率、攻击/背景命中数 | 恢复统计，或作为 `R_no_prior` 消融 |
| A7 | `experiments/run_rag.py` | `cfg.none_guard = lambda: "off"` | 作为显式消融，不作主方法默认 |

### B. 观测种子里的工具名/场景名

| # | 位置 | 内容 | 处理 |
|---|---|---|---|
| B1 | `config/attack-observables.seed.json:438` | T1496 的 `xmrig`、**`kswapd0`**、`miner` | **删除 `kswapd0`**；`xmrig` 是工具名，应改为矿池连接行为 |
| B2 | `config/attack-observables.seed.json:555` | T1572 的 **`dnscat`**、iodine、socat | 删除工具名，改为 DNS 隧道行为（UDP 53、重复查询） |
| B3 | `config/attack-observables.seed.json:307-308` | T1505 的 `.war`、php-fpm/nginx/httpd/tomcat | 审查；`.war` 是场景 10 载荷格式 |
| B4 | `config/attack-observables.seed.json:5-9` | T1105 的 `dpkg/apt-get/apt-helper`、`/var/lib/dpkg`、`/var/cache/apt` | 通用技术映射，但为救场景 5 加的；需消融 |
| B5 | `config/attack-observables.seed.json:204/217` | T1595/T1046 的 `nmap/nc/curl/socat` | 工具名，需审查/消融 |
| B6 | `config/attack-observables.seed.json:164` | T1005 的 `/srv` | 审查 |
| B7 | `config/attack-observables.seed.json:412` | T1090 的 `socat/nc/ncat` | 工具名，需审查 |
| B8 | `config/attack-observables.seed.json:386` | T1195 的 `apt-get/apt/dpkg` | 通用供应链映射 |

**未实现的提议**：在对话中我提出过「apt/dpkg 工具安装链判 all」的提示词先验，**没有写入任何文件**，已撤回。后续 agent 不得把它加回来。

### C. 从 B1 继承的硬编码（保持固定，单独消融）

| # | 位置 | 内容 |
|---|---|---|
| C1 | `experiments/run_v4_frozen.py:250` | `has_shell_parent` 子串匹配 + 「请判 all」 |
| C2 | `experiments/run_v4_frozen.py:510` | token 过滤：`unit-root/dpkg/apt/systemd-timedated/fstrim/update-notifier/motd/fwupdmgr/system-generators` |
| C3 | `settings.py:261/266` | prune managers 与内部 sink 路径 |
| C4 | `routing/filters.py:66` | `apt-get` 特殊分支 |
| C5 | `domain/taxonomy.py` | 可执行名列表、共享守护进程列表 |

C1–C5 在 B1 和 RAG 中应保持一致；如果要做消融，必须同时改变两侧，不能只改 RAG。

### D. 不算违规

- `config/scenarios.json` 的 POI/IP：外部输入，只作调查起点。
- 通用 ATT&CK 行为（unlink、execve、sendto、mmap）的 syscall/role 模式：外部知识，必须声明。
- 证据卡的「本束主体：程序/动作/对象」：从图字段读出，不是提示。

---

## 5. 复现命令

### 5.1 Rule KG JSON

```bash
cd E:/Work/TraceSage
.venv/Scripts/python.exe tools/build_rule_kg.py \
  --out output/rule-kg/v1 --version kg-v1
```

### 5.2 ATT&CK 快照

```bash
.venv/Scripts/python.exe tools/build_attack_kg.py
```

### 5.3 Neo4j 入库

```bash
.venv/Scripts/python.exe tools/build_rule_kg_neo4j.py
```

- 创建/使用数据库 `trace-rules-kg-v1`；
- 需要 Neo4j 管理员权限；如果失败，先报告权限问题，不要改用 `attack-*-v2` 场景库。

### 5.4 冻结 B1

```bash
.venv/Scripts/python.exe provenance-navigator/experiments/run_b1_real_2hop.py <场景全名>
# 或全 10 场景
.venv/Scripts/python.exe provenance-navigator/experiments/run_frozen_pair.py --group b1
```

输出：`tmp/frozen_runs/b1/<场景>_b1.json`；B1 汇总：`tmp/frozen_runs/summary_b1.json`。

### 5.5 RAG 单场景

```bash
.venv/Scripts/python.exe provenance-navigator/experiments/run_rag.py <场景全名>
```

输出：`tmp/rag-pilot/<场景>_rag.json` 和 `<场景>_rag.trace.jsonl`。

### 5.6 10 场景对比

```bash
.venv/Scripts/python.exe tools/compare_rag_b1.py
```

读取 `tmp/frozen_runs/summary_b1.json` 与 `tmp/rag-pilot/logs/<场景>.log` 的 `RAG_RESULT`。

### 5.7 图检索评测

```bash
.venv/Scripts/python.exe tools/eval_graph_retrieval.py --scenario <场景全名>
```

### 5.8 诊断

```bash
.venv/Scripts/python.exe tools/diagnose_rag_gain.py --scenario <场景全名>
.venv/Scripts/python.exe tools/diagnose_rag_pilot.py <场景全名>
.venv/Scripts/python.exe tools/sample_evidence_audit.py
```

### 5.9 单元测试

```bash
.venv/Scripts/python.exe -m unittest discover -s provenance-navigator/tests -t provenance-navigator
```

当前基线：88 个测试全部通过。

---

## 6. 当前未解决的问题

1. **没有净增益**：最干净的 10 场景对比是 RAG −13 步、−2.27 点。后续 97.0% 是提示词调参产物，不可归因给知识库。
2. **场景 1 波动大**：RAG 在场景 1 上跑过 86.1%、91.1%、97.0%，单次结果不能当结论。
3. **场景 4 仍差 4 步**：apt/dpkg/mmap `/etc` 安装链被模型判成例行动态库加载，B1 判 all。
4. **场景 5 查准下降**：RAG 上报边更多，查准 −3.00 点。
5. **技术答案键未复核**：`groundtruth/attack-technique-map.json` 是人工草稿，49 个技术，未逐条核验；技术级数字会随答案键变化。
6. **图检索精度仍低**：20 条 top-3 证据卡中，top-1 逐跳精确对齐 6/20，top-1 技术正确 2/20，top-3 技术正确 9/20。
7. **B1 继承的 token 过滤**：场景 4 的 apt/dpkg 链被硬编码 token 过滤删除；B1 和 RAG 都受影响。不能把这一损失算成 RAG 的增益或损失。

---

## 7. 建议的下一步（按顺序）

1. **清理 A1–A4、B1、B2**：删除 `请判 all`、同质大束 prior、无引用不得 all 的硬约束、`kswapd0`、`dnscat`；A6 恢复统计或做消融；A7 改为显式消融。
2. **重跑场景 1 和 4**，用清理后的提示词/观测；确认 97.0% 是否还存在。
3. 如果场景 1 回落到 B1 附近或以下，按零假设写「RAG 全量替换无净增益」；不要再用提示词补。
4. 如果仍有稳定增益，重复 3 次，再跑全 10 场景与消融。
5. 复核技术答案键；所有技术级数字标注「人工草稿」。
6. 任何新规则/观测必须满足：能脱离 10 个测试场景独立成立；不能使用测试场景的进程名、路径、IP、载荷名作为规则键。

---

## 8. 交接检查清单

- [ ] 读 `AGENTS.md` 和本文件。
- [ ] 确认 `trace-rules-kg-v1` 可连接，且 `fold` 隔离正确。
- [ ] 确认 B1 汇总 `tmp/frozen_runs/summary_b1.json` 的 10 场景数字。
- [ ] 确认 10 场景 RAG 汇总 `tmp/rag-pilot/summary_rag.json`。
- [ ] **不要引用场景 1 的 97.0% 作为 RAG 增益**。
- [ ] 清理 A1–A4、B1、B2；恢复 A6；A7 改为消融。
- [ ] 重跑场景 1/4，记录 prompt、原始 verdict、R 引用、bundle id。
- [ ] 如果无增益，写负结果，不扩 10 场景。
- [ ] 如果增益稳定，重复 3 次并做消融（去 ATT&CK、去向量、去引用、去先验）。

---

## 9. 禁止事项

- 禁止把测试场景的 GT 写进检索库或提示词。
- 禁止用测试场景的进程名、路径、IP、载荷名作为规则键或提示词条件。
- 禁止把 `KG_all` 用于单场景评测；只能用 `KG_k`。
- 禁止把 `hot_guard` 关闭、统计先验移除、`请判 all` 当成主方法默认；这些只能是消融。
- 禁止在 GPU/FP8 失败时自动迁 CPU 或降精度；按 AGENTS.md 停机汇报。
- 禁止把运行产物 `output/engine-runs/`、`output/navigator-runs/`、`tmp/rag-pilot/` 当正式基线。
- 禁止覆盖 `output/engine-baseline/` 与 `output/navigator-baseline/`。

---

## 10. 关键产物路径

| 类别 | 路径 |
|---|---|
| B0/B1 汇总 | `tmp/frozen_runs/summary_b0.json`、`summary_b1.json` |
| G0/G1 报告 | `tmp/frozen_runs/G0_REPORT.md`、`G1_REPORT.md` |
| G3/G4 报告 | `tmp/frozen_runs/G3_REPORT.md`、`G4_REPORT.md` |
| Rule KG JSON | `output/rule-kg/v1/`（`manifest.json`、`attack.json`、`folds/*.json`） |
| Neo4j KG | 数据库 `trace-rules-kg-v1` |
| RAG 运行 | `tmp/rag-pilot/`（报告、trace、logs、summary） |
| 精度核验 | `tmp/frozen_runs/PRECISION_AUDIT_20.md` |
| 技术答案键 | `groundtruth/attack-technique-map.json` |
| 观测种子 | `provenance-navigator/config/attack-observables.seed.json` |
| RAG 提示词 | `provenance-navigator/config/prompts/judge_bundle_rag.md` |
