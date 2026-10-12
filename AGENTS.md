# TraceSage 项目说明

## 工作纪律与沟通约定（最高优先级；与下文冲突时以本节为准）

违反任一条，该次交付返工。

**权限与指令**

1. **默认只读**：有副作用（写盘、改配置、动进程、花资源）先报备「做什么、多大代价、多久」，同意再动；「看一下 / 说明 / 分析」只输出文字。
2. **不可逆先拿许可**：覆盖、删除、改名、对外提交、发布、花钱先问一句，催促不放宽；许可只对具体对象生效（先列清单），备份不算许可。
3. **既定口径优先**：先把已明确的要求（命名、范围、起点、边界、口径）列成检查表；偏离先说明再动，不自创标准；答过的问题不重复问，必须问时一次一件并给默认值。
4. **先认对象**：对象取当前话题，不凭动词断定；动手前一句话写出对象（定义 / 形式 / 数据 / 产物）放在最前面，关键词与对象冲突以对象为准；出现具体文件 / 目录 / 「落盘」才按改产物理解；全句要能安置、不自补理由，安置不上就问。
5. **紧迫性不降标准**：可少讲过程、先给数字、分批交付；不许省确认、跳自检；越做越需要自编理由就停下核对前提。

**交付**

6. **先交付后加工**：第一段就是成品（结论、清单、方案、数字）；过程与背景只在被问时展开。
7. **要清单就穷举**：按「哪些 / 全部」提问 → 逐条编号列全，不用「共 N 条 / 分几类」代替；没逐项枚举不宣称完整。
8. **数字有源**：说清哪一次、哪一步、什么口径；说不出来不写；口径或版本一变，旧数字作废。
9. **交付默认是可执行方案**：不给选择菜单；必须对方决策时一次一件并给默认值；不造概念区分，每句自问「删掉是否丢信息」。

**执行与出错**

10. **复杂动作先写脚本**：多步 / 嵌套命令落脚本；长任务后台跑 + 秒级轮询进度 + 明确超时，退出条件只依赖自己的产物；停止 / 清理按进程号、端口，不用名字匹配。
11. **出错先停先报**：错在哪 / 影响什么（哪些产物、哪些数字作废）/ 怎么回退；然后等指示，不等对方发现。
12. **答问一次列全维度**：定义与口径类问题一次列全判定维度（单位、粒度、边界、多实例、失败与重试、聚合、否定事实、阈值、上限、退化等）逐项定，不分轮挤；可说明「这一维没想清」。
13. **排除项不回流**：已排除的因素不再出现在任何产物里；认为相关就先说明再问。
14. **删就是删**：不留「原 X」「已移出」痕迹；改完按当前顺序重排编号，并同步所有交叉引用。
15. **改产物先列校验清单**：内容（数字、引用、编号连续）/ 格式（换行、编码、缩进）/ 一致性（计数、无悬空引用），改完逐项跑并报结果。

**讲解与沟通**

- 默认用户没看过代码、看不懂代码 / 公式 / 符号、不懂术语：提到文件 / 函数 / 变量先说它是干什么的，否则不点名；术语首次出现当场定义（是什么、取值、用途），全文同名，用描述性词不造比喻；行业通用词（召回、查准、候选集、判定）可直接用。
- 不写代码块、公式与符号、英文缩写当术语；数字带单位与口径；机制按「第一步、第二步」讲；改动按「现在怎么做 → 出什么问题（带实测数字）→ 改成什么 → 怎么验证」讲。

## 0. 设计泛用性（绝对要求）

**任何设计 / 机制 / 规则 / 阈值 / 名单，都不允许专门为 `input/sysdig/` 下的实验场景而做**：判据必须能脱离这些场景的答案独立成立，换没见过的场景仍有效；做不到就是换场景失效，是**作弊 / 造假**，不是「效果不好」，绝对不允许。

**禁止**：用场景标注挑判据（如按标注挑零命中类别桶、整桶剔除）；判据来自「这些场景恰好没有攻击内容」的分布结论而非结构事实（路径形状、端点标签、事件方向、时间先后、系统调用语义）；按场景定制路径/进程名单、时间窗、阈值；在某场景调阈值 / 名单到分数最好再在同一批场景报该分数。

**约束**：

1. 默认档只放结构判据（能从数据本身说清，能回答「换新攻击为什么仍成立」）。
2. 人工标注核对出的名单即使零命中，也只能作为**按数据集启用、启用前重新核对**的可选项；写明来源与局限，不得把「标注一条不丢」当有效证据（同义反复）。
3. 「整类活动可以丢掉」的新机制必须跨场景验证：挑判据时排除被检验场景，压缩量与标注流失量分开报。
4. 违反按 §9 禁止清单第 1、3 条处理：立即停下并报告哪些规则照答案挑、哪些数字与结论作废。

## 1. 项目目标

TraceSage 用 Sysdig 的 JSONL 日志构建主机级溯源图并写入 Neo4j：三类顶点（Process / File / Network）、五种方向化事件边、顶点与边属性。仅限**单主机日志**；未经用户明确提出，不引入多主机、`host_id`、跨主机关联。字段与数据模型（真实实现口径）见 `docs/字段与数据模型详细设计.md`。

## 2. 目录与资料

```
TraceSage/
├── AGENTS.md                 # 项目约定与说明
├── requirements.txt          # Python 依赖（pipreqs 生成）
├── .env                      # 数据库连接配置
├── .gitignore
├── input/sysdig/             # 5 个攻击场景的 JSONL 日志（GB 级）
├── output/                   # 产出结果（规则见本节末）
├── tmp/                      # 临时文件区
├── tools/                    # 独立小工具
├── attack/                   # 最小数据集构建：AGENTS.md（任务约束）、scenario-0N.md（场景说明）、data/<n>/（capture.scap + JSONL）
├── sysdig-parser/            # 溯源图解析导入器
│   ├── main.py               # 入口
│   └── parsers/              # pipeline 解析管线（主循环/进出配对/实体注册/边缓冲）、model 纯图模型
│                             # （顶点/EntityNode/EventEdge）、jsonl 行级解析（记录解码、args 字段抽取）、
│                             # dispatch 系统调用分发（Fingerprint/SystemCall、动作注册）、storage 批量写入、
│                             # config.py（.env 配置）+ reporting.py（进度/跳过行上报）（横切）
├── provenance-agent/         # 溯源调查 agent（三层：结构可达 / 判定 / 表达）
│   ├── main.py               # 入口：命令行 + 文件落盘
│   ├── config/agent.toml     # 全部参数（唯一真源）
│   ├── config/scenarios.json # POI 唯一来源（库名 + POI；新场景附入口定义）
│   ├── tests/                # dry_run.py（整链路干跑）、l1_ablation.py / l2_repeat.py（测量）、unit/（单测）
│   └── pagent/               # 包
│       ├── app.py            # 装配（依赖容器 + 流程顺序）
│       ├── contracts.py      # 层间数据结构与共享小助手
│       ├── core/             # 横切：settings/scenarios/db/llm/record/prompts/rules/trace + graph_facts（边方向与端点标签真源）
│       ├── prompts/          # 逐波判定提示词
│       ├── rules/            # l1_judgments.json（第 1 层判据：对象角色 / 事件判定 / 常驻服务 / 条目剔除）
│       ├── orchestration/    # intake / expand_closure / judging（含整批重试）/ register
│       └── layers/           # 各层一包（只许下游读上游，包内按用途分文件）
│           ├── l1_reach/     # graph_index 顶点-时间索引 / walk 闭包+取数 / table+judgments 判据表与唯一求值入口 / process_info 进程静态属性 / candidates 实例范围+折叠
│           ├── l2_judge/     # context / batching / waves / first_pass / decide（后两项调模型）
│           └── l3_express/   # report / narrative / evidence
├── progql-local/             # 调查引擎（Java）：src/main/java 的 gql（GQL 求值）/ main（入口）/ model / neo4j / util
│                             # / traversal（neo4jserver：Bolt 数据源 + 查询别名兼容层）；baseline/ 基线运行器
│                             # （run-baseline.sh、BaselineRunner.java、progql-llm.properties 排名权重、stub 编译桩）
├── groundtruth/              # 5 个场景人工标注 GT（`<场景>.groundtruth.json`）
├── docs/                     # 设计/口径文档：字段模型、攻击路径评分口径、第一层召回上限
├── sysdig.wiki/              # Sysdig 日志格式与字段语义参考
└── paper/                    # 参考资料论文
```

- **`output/` 只放产出结果**（会被文档引用、被后续运行复用或需跨机器保留的产物）：
  - `inventory/` 日志/图清单；`coverage/` 缺口报告（`<场景>.coverage-gap.json/.md` + `SUMMARY.md` + `FULL-REPORT.md`）；
  - `baseline/<场景>/` 引擎基线（`baseline.json` + `groundtruth-eval.txt`，见 `progql-local/baseline/README.md`）；
  - `agent/<场景>.json` agent 报告（`--all` 另有 `SUMMARY.json`，`metrics.json` 为 GT 评分；字段见 `provenance-agent/README.md` 的 schema 一节）；
  - 按日期命名的目录为历史归档。

## 3. 运行环境与依赖

- Python 命令都在项目 venv 执行：`.venv/Scripts/activate`（Windows / Git Bash）、`pip install -r requirements.txt`；新依赖写回 `requirements.txt`（`pipreqs . --ignore .venv,__pycache__ --force`），不要只装本机。
- 数据库连接从环境变量或根 `.env` 读，禁止硬编码：`NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE`。
- 本机 Neo4j 已装 GDS 2026.07.0（471 个过程）与 APOC 2026.07.1（174 个过程）；优先用插件、不在客户端重造：图算法（度数、连通分量、中心性、可达性、最短路等）用 `gds.*`；服务器端批量作业 `apoc.periodic.*`、拉子图 `apoc.path.*`、元数据与工具函数用 `apoc.*`。
- 边界：GDS/APOC 表达不了逐跳时间因果谓词；带时序的因果遍历在客户端实现，插件只做预筛与标准图计算。

## 4. Neo4j 导入约定

- 用官方 Python 驱动 + 参数化 Cypher；禁止拼接日志内容成 Cypher。
- 先建唯一约束/索引；顶点与事件边用 `MERGE` 幂等写入、分批事务（批大小走配置）不逐条提交；失败可定位批次、重试不重复。
- 每个场景一个独立库，库名 = 前缀 + 场景名（小写，`_` 归一化为 `-`；只允许字母/数字/点/横线）。当前数据集前缀 `attack-`：

  | 场景 | JSONL 日志 | Neo4j 数据库 |
  |---|---|---|
  | `1_Web_Exploit_Ransomware` | `1_Web_Exploit_Ransomware.jsonl` | `attack-1-web-exploit-ransomware` |
  | `2_SSH_Spray_Lateral_Exfiltration` | `2_SSH_Spray_Lateral_Exfiltration.jsonl` | `attack-2-ssh-spray-lateral-exfiltration` |
  | `3_Phishing_Beacon_Cryptomining` | `3_Phishing_Beacon_Cryptomining.jsonl` | `attack-3-phishing-beacon-cryptomining` |
  | `4_Repo_Poisoning_Backdoor` | `4_Repo_Poisoning_Backdoor.jsonl` | `attack-4-repo-poisoning-backdoor` |
  | `5_Exposed_Service_Pivot` | `5_Exposed_Service_Pivot.jsonl` | `attack-5-exposed-service-pivot` |

- 库优先级：`--neo4j-database` > `.env`/环境 `NEO4J_DATABASE` > 默认 `neo4j`。导入器不建库（当前 5 个场景库均已在线）；多库需 Enterprise，Community 只有 `neo4j`、只能逐场景导入（换场景前先清库）。建库：对 `system` 库执行 `CREATE DATABASE`（带 `IF NOT EXISTS`），库名照上表、用反引号包裹。
- 单场景用 `--neo4j-database`；批量用 `--input-dir input/sysdig --all`（按文件名排序、event_id 每场景从 1、fail-fast）。批量库名前缀默认 `attack-`（当前数据集），可用 `--neo4j-database-prefix` 覆盖，库名必须与上表一致。event_id 仅库内唯一，不要把多场景导入同一库；重复导入同一日志幂等（配合 MERGE）。
- 导入前后输出顶点/关系/跳过/异常/未匹配数和耗时；大日志处理必须可观察。

## 5. 性能与可维护性

- 大文件流式 JSON 解析、有限缓冲、分批写入；解析/建模/导入间可用有界队列或分阶段批处理，但保留顺序/配对所需上下文。
- 不为并行破坏进出配对、事件时间顺序或统计确定性。
- 性能优化须有可重复的计数/耗时/内存指标；先语义正确，再优化吞吐。

## 6. 修改边界

- 改前先读相关模块和资料；不覆盖用户未提交改动。
- 临时文件（草稿、扫描中间产物、诊断输出、比对 dump；含工具 `-o` / `--out`）写 `tmp/`，不写 `output/`；`output/` 只放产出结果（判定标准见 §2）。
- `AGENTS.md` 只写当前确定的事实（现状、约定、口径、不变式）；过程叙述（何时改了什么、改前改后）不写入。

## 7. 常用命令与工具

### 检查 / 导入

```bash
# 导入前体检（识别被 -p 格式串静默过滤的导出）
python tools/check_sysdig_export.py input/sysdig/1_Web_Exploit_Ransomware.jsonl

# 单场景导入（--dry-run 只解析不写库）
python sysdig-parser/main.py input/sysdig/1_Web_Exploit_Ransomware.jsonl neo4j 1 \
  --neo4j-database attack-1-web-exploit-ransomware
python sysdig-parser/main.py input/sysdig/1_Web_Exploit_Ransomware.jsonl neo4j 1 --dry-run

# 批量导入（每场景一个库；要求各库已存在）
python sysdig-parser/main.py --input-dir input/sysdig --all --neo4j-database-prefix attack-
python sysdig-parser/main.py --input-dir input/sysdig --all --dry-run
```

### 采集命令

```bash
sudo sysdig -w capture.scap

# 每个场景单独导出为 <场景名>.jsonl：
sudo sysdig -r capture.scap -j -p '*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' > attack.jsonl
```

### 覆盖度缺口（原始日志 vs 图）

```bash
python tools/run_coverage.py                # GB 级日志扫描耗时长
python tools/run_coverage.py --only 1,2 --force
python tools/coverage_summary.py

# 单跑某一步（其余参数见各脚本 --help）
python tools/log_inventory.py input/sysdig/2_SSH_Spray_Lateral_Exfiltration.jsonl -o output/inventory/2_SSH_Spray_Lateral_Exfiltration.log-inventory.json
python tools/db_inventory.py attack-2-ssh-spray-lateral-exfiltration -o output/inventory/2_SSH_Spray_Lateral_Exfiltration.db-inventory.json
python tools/coverage_gap.py --log output/inventory/2_SSH_Spray_Lateral_Exfiltration.log-inventory.json --database attack-2-ssh-spray-lateral-exfiltration --out-dir output/coverage
```

- 口径见 `tools/coverage_spec.json`；报告在 `output/coverage/`。
- 事件类型是否"已建模"运行时调 `handlers.build_handlers()` 反查，不手写清单。
- `data=` 载荷按不透明值统计（默认 snaplen 80，日志里本就 ≤80 字节）。
- `fcntl` **不建边是设计决策**：证据在 `tools/coverage_spec.json` 的 `declared_no_edge_events`，报告归 A1c、不计哨兵；代码在 `sysdig-parser/parsers/dispatch/handlers.py` 的 `_fcntl_action`；**全部场景库实测 0 条**。

### tools/ 脚本

| 脚本 | 用途 |
|---|---|
| `check_sysdig_export.py` | 导入前体检：记录数/事件类型，识别被 `-p` 静默过滤的导出 |
| `dump_parser_counters.py` | 解析等价性：dry-run 全量计数，`--baseline` 逐项 diff（`diff()` 按**键名**忽略 `file`，连带跳过 `stats.vertices.file`） |
| `dump_neo4j_content.py` | 图内容等价性：全库顶点/边（含属性与端点身份）规范化 JSON，`--baseline` diff |
| `log_inventory.py` | 日志侧全量清单（顶层键 / `evt.args` 参数名 / fd 类型符 / errno / 事件×方向×fd 矩阵），`unclassified` 必须为 0 |
| `db_inventory.py` | 图侧清单：labels / 关系类型 / 属性填充率 / `syscall` / `event_id` 连续性 / 孤立顶点 |
| `coverage_gap.py` | 日志 vs 图 vs `coverage_spec.json` → 缺口报告（A 事件 / B 参数 / C 实体 / D JSONL 键 / E 属性 / F 完整性）+ 哨兵列（声明建模但 0 条边，附原因） |
| `coverage_summary.py` | 跨场景报告合并为 `output/coverage/SUMMARY.md` |
| `run_coverage.py` | 批量驱动：清单 → 图清单 → 缺口报告；已有清单默认复用（`--force` / `--only`）；GB 级日志慢 |
| `l1_index.py` | 构建/重建第 1 层顶点-时间索引（缺失/过期自动重建；本命令为手工预建/强制重建） |
| `evaluate_gt.py` | 引擎评分：`baseline.json` vs GT（顶点按内容、边按 `(src, syscall, dst)` 三元组；**召回按步骤**＝必须条目 + 可能集合规则，**查准按边**）；`--window` 模拟 POI 时间窗 |
| `eval_agent_attack_path.py` | agent 报告 vs GT（同 `evaluate_gt.py` 口径、无豁免清单）；`--all`、`--json-out` |
| `rules_match.py` | 规则（可能集合）判定模块：端点条件、且/或/非组合、方向、边属性条件；供上面两个评分脚本调用（口径见 `docs/攻击路径评分口径.md`） |

## 8. 场景测试标准流程（provenance-agent）

触发：用户说“测试 / 跑一下某个场景”。**跳过一切预检直接执行**（不探测环境、不先跑 `tests/dry_run.py`、不做只读连通性验证；除非用户明确要求或第 1 步报错）。

```bash
# 1. 直接跑（单场景实测 20~60 秒，受网关延迟影响；模型调用 2~30 次）
.venv/Scripts/python.exe provenance-agent/main.py --scenario <场景全名>

# 2. 立刻打分
.venv/Scripts/python.exe tools/eval_agent_attack_path.py \
  --report output/agent/<场景全名>.json --gt groundtruth/<场景全名>.groundtruth.json
```

- 第一轮只报：召回（按步骤：必须条目 + 规则）/ 查准（按边）、引擎基线对照（`output/baseline/<场景>/`）、报告路径、停止原因、确认边数、LLM 调用数；漏报与多出边只列清单。**数字没报完不许做根因分析。**
- 深挖（`tmp/provenance-agent/logs/` 的 trace / 查询日志 / 判定明细 / `llm-*.jsonl`、`state/record-*.json`）只在数字对完后做，且仅当用户要求或数字异常。
- 场景名用 `provenance-agent/config/scenarios.json` 的**全名**（如 `1_Web_Exploit_Ransomware`），不接受简称；`--all` 跑配置里的全部场景（当前 5 个）。
- 自写读库脚本先 `pagent.core.settings.load_dotenv()`（`.env` 只在 `main.py:main()` 加载）；凭据不硬编码。
- 诊断产物写 `tmp/`；报告只写 `output/agent/<场景>.json`。
- 报错先归「库不存在 / POI 不存在 / 网关不可达」三类；只有这三类才回退环境排查。

## 9. 验证新方案 / 新机制 / 新功能的流程

> 仅在用户明确要求时启用；**测的必须是新方案本身**——用现有代码加参数改出来的数不算。

1. **动手前**：待测对象拆成组件清单并标注来源（新写 / 复用 / 只改参数 / 未实现）给用户看；一句话写清本次测量要回答的问题；把方法里禁止出现的东西写进方法说明。
2. **未实现不许顶替**：关键组件尚未实现就先实现；替代品（规则、人工标注、现有代码输出、上限推算）不算数，超范围就说明「需先实现 X」并给估计，由用户决定。
3. **对照只读已有产物**：`output/agent/`、`output/baseline/`（见 §2），**禁止重跑基线**；确需重跑必须先问用户，新数字不得与已有产物混表。
4. **过程**：先跑 1 个场景，逐阶段报输入 / 输出 / 砍掉条数及原因、抽 3~5 例核对，无误再跑其余；中间产物落盘 `tmp/`，每阶段能回答「进来多少、出去多少、为什么砍」；测错立即停（见「工作纪律」）。
5. **汇报**：三类数字分表——实测（真跑出来的）/ 上限（标准答案推算）/ 对照（旧方法、基线）；对照分数注明来源产物与代码版本，耗时 / 模型调用数见报告 `stats`；主动交代测量局限。

**禁止（报告前逐条自查）**：① 人工标注或任何形式的答案进方法输入；② 用「改参数跑现有代码」冒充新方案；③ 在测试场景上调规则 / 阈值 / 名单再报分数；④ 把上限推算写成方案性能；⑤ 只给表格、不给数字来源；⑥ 关键组件未实现用替代品顶着测。
