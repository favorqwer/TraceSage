# TraceSage 项目说明

## 讲解与沟通约定

### 一、默认前提

1. **默认用户没看过项目代码。** 任何提到某个文件、某个函数、某个变量名的地方，先用一句话说明它是干什么的；如果只是讲原理，就不提名字，直接说「程序里负责某某的那一部分」。
2. **默认用户看不懂任何代码、公式、符号。** 不写 Python、不写数据库查询语句、不写类似「p2f」「E001」「S:进程编号:时间」这种拼装格式、不写带大于小于号和绝对值的表达式。
3. **默认用户不知道任何内部术语。** 凡是术语，第一次出现时当场定义。

### 二、语言规则

**不写的东西：**

- 代码块（不管是 Python 还是数据库查询语句）。
- 数学公式和符号。要用中文说，比如不写「差距不超过 W 秒」，而写「相差不超过设定的秒数（默认 300 秒）」。
- 自己造的比喻式说法。比如「骨架」「心脏」「漂移」「饿死」「光环」「天花板」这类，一律不用。
- 英文缩写当术语用。比如不写「off」，写「关闭」；不写「auto」，写「自动读取」。

**要写的东西：**

- 每个机制用「第一步做什么、第二步做什么」的方式按顺序讲完。
- 每个数字都要带单位，并且说清它的口径。比如不写「436,000 条」，而写「从数据库取回 436,000 条数据」；不写「0.73」，而写「标准答案里 73% 的记录进了候选集」。
- 讲一个改动时，按这个顺序：现在是怎么做的 → 这样做出了什么问题（带实测数字）→ 改成什么 → 改完怎么验证。

### 三、术语规则

1. 术语第一次出现时，按三件事定义：它是什么 → 它的取值是什么 → 它用来干什么。
   - 例子：参照时刻——是一个时间值，取「当初把这一步拉进来的那个动作发生的时刻」，用来决定「往过去找多远」。
2. 同一个东西，全文只用一个名字，不能前面叫「参照时刻」、后面叫「锚点」。
3. 如果一个概念必须要一个名字，优先用描述性的名字，不要用比喻性的名字。
4. 行业里本来就在用的词（召回、查准、候选集、判定）可以直接用。

## 1. 项目目标

TraceSage 使用 Sysdig 导出的 JSONL 日志构建主机级溯源图，并将溯源图写入 Neo4j。图由三类顶点（Process / File / Network）、五种方向化事件边，以及顶点和事件边属性组成。当前范围是**单主机日志**；除非用户明确提出，不要引入多主机、`host_id` 或跨主机关联模型。字段与数据模型的详细设计（真实实现口径）见「字段与数据模型详细设计」。

## 2. 目录与资料

```
TraceSage/
├── AGENTS.md                 # 项目约定与说明
├── requirements.txt          # Python 依赖清单（pipreqs 生成）
├── .env                      # 数据库连接配置
├── .gitignore                
│
├── input/sysdig/             # 输入数据：6 个攻击场景的 JSONL 日志 + 同名 .query 场景查询
├── output/                   # 产出结果
├── tmp/                      # 临时文件区
├── tools/                    # 独立小工具
│
├── sysdig-parser/            # 溯源图解析导入器
│   ├── main.py               # 入口
│   └── parsers/              # 解析器包
│       ├── pipeline/         # 解析管线：主循环、进出配对、实体注册、边缓冲
│       ├── model/            # 纯图模型：顶点（Process/File/Network）、EntityNode、EventEdge
│       ├── jsonl/            # Sysdig JSONL 行级解析：记录解码、args 字段抽取
│       ├── dispatch/         # 系统调用分发：Fingerprint/SystemCall、动作注册
│       ├── storage/          # Neo4j 批量写入
│       ├── config.py         # 环境变量/.env 配置（横切）
│       └── reporting.py      # 进度与跳过行上报（横切）
│
├── provenance-agent/         # 溯源调查 agent（Python；分层：结构可达 / 判定 / 表达）
│   ├── main.py               # 入口：命令行 + 文件落盘
│   ├── config/agent.toml     # agent 的全部参数（唯一真源）
│   ├── config/scenarios.json # POI 唯一来源（库名 + POI 签名）
│   ├── tests/                # dry_run.py（整链路干跑）+ unit/（每层单测）+ fixtures/
│   └── pagent/               # 包
│       ├── app.py            # 装配：依赖容器 + 流程顺序
│       ├── contracts.py      # 层间数据结构与共享小助手
│       ├── core/             # 横切：settings / scenarios / db / llm / record / prompts / rules / trace
│       │                     #      + vertices（顶点表：文件角色 + 进程类别）/ graph_facts（边方向表）
│       ├── prompts/          # 提示词文本（逐波判定）
│       ├── rules/            # 判据表（对象角色 / 进程类别 / 剔除条目 / 相位关键词）
│       ├── orchestration/    # 编排：intake / expand / judging（含整批重试）/ register
│       └── layers/           # 各层各占一个包（只允许下游读上游；包内按用途分文件）
│           ├── l1_reach/       # 第 1 层 结构可达与折叠：closure / fold / siblings / output_filter / sources / snapshot / process_attributes
│           ├── l2_judge/       # 判定层（原第 2、3 层合并）：context / batching / waves / first_pass / decide（后两项调模型）
│           └── l3_express/     # 第 3 层 表达：report / phases / narrative / evidence
│
├── progql-local/             # 调查引擎（Java）
│   ├── src/main/java/        # gql（GQL 求值）/ main（入口）/ model / neo4j / util，
│   │                         # 以及 traversal/（neo4jserver：Bolt 数据源 + 查询别名兼容层）
│   └── baseline/             # 基线运行器：run-baseline.sh、BaselineRunner.java、
│                             # progql-llm.properties（排名权重）、stub/（编译桩）
│
├── groundtruth/              # 6 个场景的人工标注 GT（<场景>.groundtruth.json + 场景说明 .md）
├── docs/                     # 设计与问题分析文档：缺陷清单、覆盖度方法、数据集复核、逐主题报告
├── sysdig.wiki/              # Sysdig 日志格式与字段语义参考资料
└── paper/                    # 参考资料论文
```

- **`output/`**：**只允许存放产出结果**——会被文档引用、会被后续运行复用、或需要跨机器保留的产物。现有子目录：
  - `output/inventory/`：日志侧/图侧清单（覆盖度对账的输入，见「覆盖度缺口」命令）；
  - `output/coverage/`：缺口报告（6 份单场景报告 + `SUMMARY.md` + `FULL-REPORT.md`）；
  - `output/baseline/<场景>/baseline.json`：调查流程的回归基线/引擎产物（同目录可放 `<场景>/groundtruth-eval.txt` GT 评分明细）；六场景汇总为 `output/baseline/SUMMARY-six-scenarios.md` 与 `metrics-six-scenarios.json`（见 `progql-local/baseline/README.md`）；
  - `output/agent-vs-engine/`：引擎与 LLM agent 的对比报告；
  - `output/agent/<场景>.json`：`provenance-agent` 的溯源报告（schema 见该目录 README），
    可直接被 `tools/eval_agent_attack_path.py` 评分；`SUMMARY.json` 为多场景汇总，
    `metrics.json` 为同一次运行对 GT 的评分（`tools/eval_agent_attack_path.py --json-out` 的产物）。

## 3. 运行环境与依赖

- 全部 Python 命令都应在项目虚拟环境中执行：

  ```bash
  .venv/Scripts/activate        # Windows / Git Bash
  pip install -r requirements.txt
  ```

- 新增依赖时同步更新 `requirements.txt`，不要把依赖只安装在本机而不记录；重新生成（自动扫描项目 import）：`pipreqs . --ignore .venv,__pycache__ --force`。
- 数据库连接信息从环境变量或根 `.env` 读取，禁止硬编码：Neo4j 用 `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE`。
- 本机 Neo4j 服务器已安装 GDS（Graph Data Science）与 APOC 插件，版本 2026.07.1，与服务器一致（可用 `SHOW PROCEDURES` 验证：`gds.*` 约 471 个过程、`apoc.*` 约 174 个过程）。
- 写代码时优先复用这两个插件的现有能力，不要在客户端重复实现：图算法（度数、连通分量、PageRank/特征向量中心性、BFS/DFS 可达性、最短路径等）用 `gds.*` 过程；服务器端批量作业（`apoc.periodic.*`）、路径展开拉子图（`apoc.path.*`）、元数据与工具函数用 `apoc.*` 过程。
- 边界：GDS/APOC 无法表达逐跳的时间因果谓词；带时序语义的因果遍历仍在客户端实现，插件侧只承担预筛与标准图计算。

## 4. Neo4j 导入约定

- 优先使用官方 Python Neo4j 驱动和参数化 Cypher；禁止拼接用户日志内容形成 Cypher。
- 先建立唯一约束/索引，再使用 `MERGE` 做顶点和事件边的幂等写入。
- 顶点和关系采用分批事务，批大小通过配置控制；不要逐条提交事务。
- 事务失败时要能定位批次范围，并避免在重试时产生重复数据。
- 每个攻击场景对应一个**独立 Neo4j 数据库**，库名 `tracesage-<场景名小写，_ 归一化为 ->`（Neo4j 库名只允许字母/数字/点/横线，统一小写）：

  | 场景 | JSONL 日志 | Neo4j 数据库 |
  |---|---|---|
  | 1 Multi-Stage Data Exfiltration | `1_Multi_Stage_Data_Exfiltration.jsonl` | `tracesage-1-multi-stage-data-exfiltration` |
  | 2 Masquerade Data Exfiltration | `2_Masquerade_Data_Exfiltration.jsonl` | `tracesage-2-masquerade-data-exfiltration` |
  | 3 SSH Spray | `3_SSH_Spray.jsonl` | `tracesage-3-ssh-spray` |
  | 4 Site Defacement | `4_Site_Defacement.jsonl` | `tracesage-4-site-defacement` |
  | 5 User Timer Resource Hijack | `5_User_Timer_Resource_Hijack.jsonl` | `tracesage-5-user-timer-resource-hijack` |
  | 6 SQLite Pipeline Pollution | `6_SQLite_Pipeline_Pollution.jsonl` | `tracesage-6-sqlite-pipeline-pollution` |

- 数据库选择优先级：`--neo4j-database` > `.env`/环境的 `NEO4J_DATABASE` > 默认 `neo4j`。导入器不建库，目标库必须已存在；多数据库需要 Neo4j Enterprise，Community 版只有默认 `neo4j` 库，只能逐场景导入（换场景前先清库）。建库示例（对 `system` 库执行，横线开头的名字需反引号包裹）：

  ```cypher
  CREATE DATABASE `tracesage-1-multi-stage-data-exfiltration` IF NOT EXISTS
  CREATE DATABASE `tracesage-2-masquerade-data-exfiltration` IF NOT EXISTS
  CREATE DATABASE `tracesage-3-ssh-spray` IF NOT EXISTS
  CREATE DATABASE `tracesage-4-site-defacement` IF NOT EXISTS
  CREATE DATABASE `tracesage-5-user-timer-resource-hijack` IF NOT EXISTS
  CREATE DATABASE `tracesage-6-sqlite-pipeline-pollution` IF NOT EXISTS
  ```

- 单场景导入用 `--neo4j-database`，批量导入用 `sysdig-parser/main.py --input-dir input/sysdig --all`（按文件名排序、每场景 event_id 从 1 开始、fail-fast；完整命令见「检查 / 导入」）。event_id 仅在场景库内唯一，不要把多个场景导入同一个库；重复导入同一日志到同一库是幂等的（配合上文 MERGE 约定）。
- 导入前后输出顶点数、关系数、跳过数、异常数、未匹配数和耗时；大日志处理必须可观察。

## 5. 性能与可维护性

- 对大文件使用流式 JSON 解析、有限大小缓冲和分批写入。
- 可在解析、建模、导入之间使用有界队列或分阶段批处理，但必须保留顺序/配对所需的上下文。
- 不要为了并行而破坏进入/退出配对、事件时间顺序或统计结果的确定性。
- 任何性能优化都应以可重复的计数、耗时和内存指标验证；先保证语义正确，再优化导入吞吐。

## 6. 修改边界

- 修改前先阅读相关模块和现有资料；不要覆盖用户已有的未提交改动。
- **临时文件（草稿、扫描中间产物、一次性诊断输出、比对 dump）一律写 `tmp/`，不要写进 `output/`**；`output/` 只放产出结果（判定标准见「目录与资料」）。
- **`AGENTS.md` 只写“当前确定的事实”**（现状、约定、口径、不变式）；“什么时候改了什么、改前改后是多少”这类过程叙述不属于本文件的内容。

## 7. 常用命令与工具

### 采集命令

```bash
sudo sysdig -w capture.scap

# 每个攻击场景单独采集并保存为 <场景名>.jsonl，例如：
sudo sysdig -r capture.scap -j -p '*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' > attack.jsonl
```

### 检查 / 导入

```bash
# 1. 检查 sysdig 导出是否完整（防止 -p 格式串问题导致事件被静默丢弃）
python tools/check_sysdig_export.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl

# 2a. 单场景导入（目标库默认取 NEO4J_DATABASE，可用 --neo4j-database 显式指定；--dry-run 只解析不写库）
python sysdig-parser/main.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl neo4j 1 \
  --neo4j-database tracesage-1-multi-stage-data-exfiltration
python sysdig-parser/main.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl neo4j 1 --dry-run

# 2b. 六个场景批量导入：input/sysdig 下全部 *.jsonl 按文件名排序逐个导入，
#     每个场景写入独立数据库 tracesage-<场景名小写>（要求各库已存在）；fail-fast
python sysdig-parser/main.py --input-dir input/sysdig --all --neo4j-database-prefix tracesage-
python sysdig-parser/main.py --input-dir input/sysdig --all --dry-run
```

### 覆盖度缺口（原始日志 vs 图）

```bash
python tools/run_coverage.py                # 六场景：日志清单 -> 图清单 -> 缺口报告（已有清单复用；单场景扫描 3-10 分钟）
python tools/run_coverage.py --only 1,2 --force
python tools/coverage_summary.py            # 跨场景汇总 -> output/coverage/SUMMARY.md

# 单跑某一步（其余参数见各脚本 --help）
python tools/log_inventory.py input/sysdig/3_SSH_Spray.jsonl -o output/inventory/3_SSH_Spray.log-inventory.json
python tools/db_inventory.py tracesage-3-ssh-spray -o output/inventory/3_SSH_Spray.db-inventory.json
python tools/coverage_gap.py --log output/inventory/3_SSH_Spray.log-inventory.json --database tracesage-3-ssh-spray --out-dir output/coverage
```

- 口径与结论见 `docs/log-db-coverage-gap.md`；六场景汇总 `output/coverage/SUMMARY.md`。
- 事件类型是否"已建模"由运行时调 `handlers.build_handlers()` 反查，不手写清单。
- 已知边界：`data=` 载荷按不透明值统计（默认 snaplen 80，日志里本就 ≤80 字节）；`evt.num` 有少量缺口（场景 1 缺 0.51%）。
- `fcntl` **不建边是设计决策**（不是缺陷）：口径与实测证据写在 `tools/coverage_spec.json` 的 `declared_no_edge_events`，报告归入 A1c、不计哨兵；代码侧见 `sysdig-parser/parsers/dispatch/handlers.py` 的 `_fcntl_action`。**六库实测 fcntl 边 0 条**。

### tools/ 脚本

| 脚本 | 用途 |
|---|---|
| `check_sysdig_export.py` | 导入前体检：统计记录数与事件类型，识别被 `-p` 格式串静默过滤的导出 |
| `dump_parser_counters.py` | 解析等价性验证：dry-run 导出全部可观测计数（stats/逐理由跳过/配对/fd 表），`--baseline` 逐项 diff。注意其 `diff()` 按**键名**忽略 `file`，会连带跳过 `stats.vertices.file` |
| `dump_neo4j_content.py` | 图内容等价性验证：导出指定库全部顶点/边（含属性与端点身份）为规范化 JSON，`--baseline` 逐项 diff |
| `log_inventory.py` | 日志侧全量信息清单：一次流式扫描把顶层 JSON 键、`evt.args` 参数名、fd 类型符、errno/注解枚举、事件×方向×fd 矩阵全部落成确定性 JSON；分段自证 `unclassified` 必须为 0。是覆盖度对账的日志侧基准 |
| `db_inventory.py` | 图侧清单：labels/关系类型/每标签与每关系的属性填充率/`syscall` 取值/`event_id` 连续性/孤立顶点 |
| `coverage_gap.py` | 日志清单 vs 图清单 vs `coverage_spec.json` 契约 → 缺口报告（A 事件类型 / B 参数名 / C 实体种类 / D JSONL 键 / E 属性填充 / F 完整性）；含哨兵列"声明建模但 0 条边"并给出原因（设计上不建边 / 端点种类未建模 / 端点注记不完整 / 可疑） |
| `coverage_summary.py` | 六场景缺口报告合并成 `output/coverage/SUMMARY.md` |
| `run_coverage.py` | 批量驱动：清单 → 图清单 → 缺口报告，已有清单默认复用（`--force` 重跑，`--only` 选场景） |
| `evaluate_gt.py` | 引擎评分：BaselineRunner 的 `baseline.json` vs GT 的召回/查准（顶点按内容比对、边按 `(src, syscall, dst)` 精确三元组）；`--window` 可模拟 POI 时间窗 |
| `eval_agent_attack_path.py` | agent 溯源报告（`results/<场景>.json`，见 REPORT-FORMAT 口径）vs GT 的召回/查准评估；与 `evaluate_gt.py` 同口径（边三元组精确匹配、无豁免清单），支持 `--all` 批量、`--json-out` 指标落盘 |

注：工具命令的 `-o` / `--out` **只在产出结果时指向 `output/`**（如 `output/inventory/`、`output/coverage/`）；仅用于本次比对/验证的中间 dump 一律指向 `tmp/`（见「目录与资料」）。

## 8. 字段与数据模型详细设计

> 下面按 `TraceSage设计方案.md` 的「日志采集与字段」「数据模型（Neo4j）」样式，记录**当前代码实现**的真实口径（以 `sysdig-parser/parsers/` 为准）。
> 与设计方案文档的三处关键差异，引用时必须按下面口径：
> 1. 日志导出只有 **12 个 JSONL 键**；设计稿列出的 `fd.type` / `fd.name` / `fd.lip` / `fd.lport` / `fd.rip` / `fd.rport` / `evt.arg.filename` / `evt.res` **不是独立采集列**，全部从 `evt.args` 文本恢复（见「字段恢复关系」）。
> 2. `:File` 顶点**不写 `type` 属性**（值域仅 `file`，与标签完全冗余，已移除）。
> 3. `Process` 增加 `args` 属性，`Network` 的端点属性名固定为 `lip` / `lport` / `rip` / `rport`。

### 8.1 导出字段与规范记录字段（JSONL 原始键 -> `jsonl/record.py:parse_jsonl_entry` 规范键）

| JSONL 键 | 规范记录键 | 作用 / 说明 | 是否一定存在 |
|---|---|---|---|
| `evt.num` | `eventno` | 事件编号；规范键为字符串形式 | 必填，非整数则整行无效跳过 |
| `evt.rawtime` | `_ns` | Unix epoch 起始的绝对纳秒时间；规范键为 int 纳秒，时间戳派生值缓存 | 必填，非整数则整行无效跳过 |
| `evt.dir` | `direction` | 事件方向：`>` 进入，`<` 退出 | 必填，非 `>`/`<` 则整行无效跳过 |
| `evt.type` | `event` | Sysdig 事件类型（系统调用名，边 `syscall` 的原始值）；规范键为**原始**事件名，未归一 | 必填 |
| `evt.args` | `args` | 该事件全部参数拼接后的原始字符串（**字段恢复的唯一来源**），即规范键的参数原文 | 必填 |
| `evt.latency` | `_latency_ns` / `latency` | 进入→退出耗时（ns），进入/退出配对用；规范键 `_latency_ns` 为 int 纳秒（配对派生值缓存），`latency` 为字符串形式（兼容旧接口） | 必填，非整数则整行无效跳过 |
| `proc.pid` | `pid` | 进程/线程 ID（同时用作配对 tid） | 必填，JSON null 则按精确理由跳过 |
| `proc.name` | `process` | 可执行文件名（不含路径）；规范键为进程名 | 必填，JSON null 则按精确理由跳过 |
| `proc.exepath` | `exepath` | 可执行文件完整路径 | 必填，值可为空或 `<NA>` |
| `proc.cwd` | `cwd` | 事件发生时进程的当前工作目录 | 必填，值可为空 |
| `proc.args` | `proc_args` | 启动进程时传入的参数（命令行） | 可选；缺失/空 -> `Process.args` 不写 |
| `fd.l4proto` | `l4proto` | socket 四层协议（`tcp`/`udp`/…） | 可选；缺失/空/`<NA>` -> `Network.protocol` 不写 |
| （无 JSONL 键） | `raw` | 原始行 bytes；仅在写跳过样例日志时懒解码 | —（不在必填键集合内） |

- 前 10 项即 `jsonl/record.py` 的 `_REQUIRED_JSONL_KEYS`：缺任一键的整行无效、跳过并计数；后两项为可选映射（不加入必填集合，旧日志缺这两个键仍可解析）。`raw` 不由 JSONL 键映射，直接取原始行。
- JSON `null` 一律映射为空串，**绝不产生 `'None'` 字面量**；无进程上下文（`proc.pid`/`proc.name` 为 null，典型如内核调度 switch 事件）的行精确跳过。
- `proc.exeline`（`exepath + args`）**不采集、不存储**；`proc.args` 单独写入 `Process.args`。
- **多主机字段一律不存在**：没有 `host_id`、`container.id` 等列。
- 除上表规范键外，还有按需写入的派生缓存键：`_size`（`args` 的 `res=` -> `extract_size`）、`_res`（-> `extract_res`，`None` 表示字段缺失）、`_fs`（`args` 的 fd token -> `extract_file_and_socket`）。记录 dict 每事件新建、不跨事件复用，缓存安全。

### 8.2 字段恢复关系（`evt.args` 文本 -> 图字段）

```text
# --- fd 注记（fields.extract_file_and_socket，只取 args 中第一个 fd= token）---
File.path           <- fd=<f>path
                       （剥内核对已删除文件的标准后缀 " (deleted)"；其余括号视为路径字符）
File 合成键          <- fd=<p>pipe:[N]
                       （裸 <p> 无名字：由 (pid,fd) 管道表还原为 pipe:[<ino>]；
                        还原失败回落按事件秒分桶的 pipe:[anonymous@<sec>]）
Network.lip/lport    <- fd=<4t|4u|6|...>lip:lport->rip:rport 的本地端点
Network.rip/rport    <- 同上的远端端点
fd_type              <- 尖括号内的原始类型符（f/p/4/4t/6u/u…），仅调试与将来目录顶点用，不入库
fd_num               <- fd 编号，供管道表还原裸管道身份
# 四元组不全 / 内核 fd 地址（ffff…->ffff…）-> 只留 socket 串，不建 Network 顶点，计入 incomplete network

# --- 退出记录字段 ---
rel.bytes            <- res=（非负整数；extract_size：字段缺失或为负 -> -1）
调用是否失败          <- res=（extract_res：None=字段缺失；record_failed：字段存在且 <0）
File.path            <- 生命周期家族 path= / name=（*at 变体）/ linkpath=（symlink）
File.path            <- rename 家族 oldpath= / newpath=
Network 四元组        <- connect 的 tuple=src->dst（进入记录 fd 不带端点）
Network 监听端点      <- bind 的 addr=host:port（远端未知记 0.0.0.0:0）
管道身份             <- pipe()/pipe2() 的 fd1= / fd2= / ino=

# --- 双 fd / unix socket 通道 ---
File.path            <- sendfile 进入记录的 in_fd=（源文件）
Network 四元组        <- sendfile 进入记录的 out_fd=（目标 socket）
File.path(unix)      <- fd=<u> 注记尾部的文件系统路径（`<u>/path` 或 `<u>ffff…->ffff… /path`）；
                        connect 的路径在退出记录 tuple=<addr>-><addr> /path；
                        deny 抽象命名空间 `@name`（不建模）
fd 表身份            <- (pid,fd) → unix 路径，登记于 connect/bind/sendmsg/recvmsg 记录，
                        close 失效、dup/clone 传播；裸 `<u>` 由此回填

# --- 进入记录字段 ---
File.path            <- execve 的 filename=（按空格切 token；此处不做括号剥壳）
父进程               <- execve 的 ptid=(parent)
CLONE_THREAD 过滤    <- clone 的 flags=N(A|B|…)
```

- **路径身份归一**只在 `pipeline/entity_registry.get_or_create_file()` 这一个 chokepoint 做：先剥内核 `原始名(/绝对路径)` 注记（`strip_path_annotation`），再 `posixpath.normpath`（`normalize_file_path`）；`pipe:[…]`/`socket:[…]`/`netlink:[…]`/空串不喂 `normpath`，POSIX 行首 `//` 原样保留。**`unix:[…]` 例外地只归一括号内的路径**（合成前缀保真、内部真路径折叠），使 `unix:[/a/b/../c]` 与 `unix:[/a/c]` 是同一顶点。
- **失败判据**：`record_failed()`（`res` 存在且 `res < 0`）用于 accept / connect / bind / rename / 生命周期 / chmod 族的「失败则不建边」（`fcntl` 也会调用它，但只用于「socket 注记无四元组」审计，它本身不建边，见 §8.4）；数据流族（read/write/send/recv）用 `record_size()`（拿不到 `res` 就没有 `bytes`，不建边）；`execve` 仅在 `record_size(end_rec) == 0` 时算成功；非阻塞 `connect` 的 `EINPROGRESS(-115)` 经 `record_connect_failed()` 视为已发起、照常建边。

### 8.3 顶点（Node）

| Label | 去重键 / MERGE 键（唯一约束） | 属性（写入 Neo4j） | 说明 |
|---|---|---|---|
| `Process` | `process_id` = `proc.pid + proc.name`（**无分隔符拼接**） | `process_id`(str), `pid`(str), `name`(str), `exepath`(str, 可空), `args`(str, 可空), `cwd`(str, 可空) | 身份 = `(pid, name)`；`exepath`/`args`/`cwd` 是描述属性，**不参与身份**，同一个键「首个非空值 wins」 |
| `File` | `file_id` = 归一后的路径 | `file_id`(str), `path`(str) | **无 `type` 属性**（已移除）；管道建为合成 File 顶点，键形如 `pipe:[<ino>]` 或 `pipe:[anonymous@<sec>]` |
| `Network` | `network_id` = `lip:lport->rip:rport` | `network_id`(str), `lip`(str), `lport`(str), `rip`(str), `rport`(str), `protocol`(str, 可空) | 仅在四元组齐全时创建；`protocol` 取首个非空值，同四元组出现不同协议时保留首个并计数 |

- `process_id` / `file_id` / `network_id` 对应代码里的 `Process.pid_and_name` / `FileEntity.path` / `NetworkEntity.src_and_dst_ip`，不是旧实现的整型自增 `uniq_id`。
- 属性可空性是真实语义：`SET n.x = null` 在 Neo4j 中等价于「不设置/移除该属性」，因此图上不会出现空串占位属性。
- **只有参与过事件边的顶点才入库**（`pipeline/parser.py` 的 `_edge_vertex_keys` 过滤）：在实体抽取阶段创建、但从未出现在任何边上的孤立顶点会被丢弃，并在最终 flush 打印 `Edge-less vertices not written` 计数。
- 不构造 Unknown 顶点；无 File/Network 对象时只保留可识别的 Process 顶点或直接不建边（计入 `no object` / `incomplete network` 审计）。

### 8.4 关系（EventEdge）——五种事件边 = 五种关系名

| 关系名 | 方向（固定端点标签） | 系统调用（`evt.type`，原始名 -> 边 `syscall`） | 说明 |
|---|---|---|---|
| `p2p` | Process → Process | `execve`（父进程→子进程）；`clone` / `vfork` / `fork`（父→子） | `execve` 父进程取退出记录 `ptid=`；`clone` 家族跳过 `CLONE_THREAD`（与父共享顶点，建边即自环） |
| `p2f` | Process → File | `write` / `writev` / `pwrite` / `pwritev` / `pwritev2`；`rename` / `renameat` / `renameat2`（新路径侧）；`unlink` / `unlinkat`；`rmdir`；`mkdir` / `mkdirat`；`symlink` / `symlinkat`；`chmod` / `fchmod` / `fchmodat` / `fchmodat2`；`send` / `sendto` / `sendmsg` / `sendmmsg`（fd 为 unix socket 合成 File）；`connect`（unix socket 路径）；`sendfile`（`out_fd` 为普通文件时） | write/send 族仅当 fd 实体为 File 时落此 |
| `f2p` | File → Process | `read` / `readv` / `pread` / `preadv` / `preadv2`；`rename` / `renameat` / `renameat2`（旧路径侧）；`execve`（可执行文件→子进程）；`recv` / `recvfrom` / `recvmsg` / `recvmmsg`（fd 为 unix socket 合成 File）；`sendfile`（`in_fd`） | read/recv 族仅当 fd 实体为 File 时落此 |
| `p2n` | Process → Network | `send` / `sendto` / `sendmsg` / `sendmmsg`；`write` / `writev` / `pwrite` / `pwritev` / `pwritev2`（fd 为 Network）；`connect`（IP 四元组）；`bind`；`sendfile`（`out_fd` 为 socket） | write/send 族仅当 fd 实体为 Network 时落此 |
| `n2p` | Network → Process | `recv` / `recvfrom` / `recvmsg` / `recvmmsg`；`read` / `readv` / `pread` / `preadv` / `preadv2`（fd 为 Network）；`accept` | read 族仅当 fd 实体为 Network 时落此；`fcntl` **只注册不建边**（见下） |

- 边的 `syscall` 属性写**家族基本名**（`CANONICAL_SYSCALL_MAP`）：`readv/pread/preadv/preadv2 -> read`、`writev/pwrite/pwritev/pwritev2 -> write`、`send/sendmsg/sendmmsg -> sendto`、`recv/recvmsg/recvmmsg -> recvfrom`、`renameat/renameat2 -> rename`、`unlinkat -> unlink`、`mkdirat -> mkdir`、`symlinkat -> symlink`、`chmod` 族（`fchmod/fchmodat/fchmodat2 -> chmod`）、`fork/vfork -> clone`、`openat/openat2/creat -> open`、`sendfile64 -> sendfile`。事件分发与进入/退出配对仍用原始 `evt.type`。**handler 注册表从本表反查派生**（`handlers._family()`）：家族变体只要进归一表就自动注册，不再手写事件名名单（手写事件名名单会与归一表脱节、导致整族静默丢边，禁止）。（注：`open` 族（含裸名 `open`）虽在归一表中，但只延长 `p2p` 不建边，不会产生带这些名字的边。）
- 一个系统调用可产生多条边：`rename` -> 旧路径 `f2p` + 新路径 `p2f`；`execve` -> 父→子 `p2p` + 可执行文件→子进程 `f2p`；`sendfile` -> `File(in_fd) --f2p--> Process` + `Process --p2n|p2f--> 目标`（两端点同在进入记录 `in_fd=` / `out_fd=`，`bytes` 两侧同取退出记录 `res=`）。`accept` 只产生单向 `n2p`。**不生成合成反向边**（只表示实际发生的单向事件，避免假外发与重复计数）。
- **unix socket**：`<u>` 注记带文件系统路径时建**合成 File 顶点** `unix:[<path>]`（沿用 File 标签，与 `pipe:[ino]` 同构，不塞 Network 四元组）。路径来源两种形态：`fd=N(<u>/path)` 与 `fd=N(<u>ffff…->ffff… /path)`；`connect` 的路径在退出记录 `tuple=<addr>-><addr> /path`。裸 `<u>` 由 `fd_table` 的 `(pid,fd) → unix 路径` 回填（登记在 connect/bind/sendmsg/recvmsg 记录，close 失效，dup/clone 传播），回填不到只计数；抽象命名空间（`@name`）与 netlink 不建模。
- **只注册、不建边**：`open` / `openat` / `openat2` / `creat` 的指纹仍注册（不计入 unmatched），动作只延长 `p2p` 边活跃期；读意图 open 由 read 族覆盖、写意图由 write 族覆盖。`fcntl` 同样只注册、**不建边**（已决策：不搬数据、无 `bytes`、边模型分不出查状态与加锁；口径与实测见 `coverage_spec.json` 的 `declared_no_edge_events`），但它的指纹参与 fd 记账与「socket 注记无四元组」审计。
- `ftruncate` / `utimensat` / `chown` / `setxattr` 在当前采集中进入/退出 args 均为空，无路径可提取，**未注册**；未注册的 `evt.type` 落入 `Unmatched fingerprint` 跳过统计。
- 端点标签由关系名唯一决定，对比/查询不得按 `optype` 猜方向（见「关系（EventEdge）」）。

### 8.5 关系属性

| 属性 | 类型 | 来源 | 说明 |
|---|---|---|---|
| `event_id` | int | `next_event_id()` | 全局（单次导入内）自增，每生成一条边递增 1；**同一条记录对生成的多条边拥有各自独立的 event_id**；批量导入时每个场景库从 1 开始 |
| `starttime` | int (ns) | 进入记录 `_ns` | `>` 进入时间 |
| `endtime` | int (ns) | 退出记录 `_ns` | `<` 退出时间，即事件真正完成时间；`p2p` 的 `execve`/`clone` 边会被父进程后续被追踪事件延长到最终 flush |
| `syscall` | str | `canonical_syscall(evt.type)` | 家族基本名（见「关系（EventEdge）」） |
| `bytes` | int | 退出记录 `res=` | 数据流族填充实际字节量（非负）；元数据类与关联边（`connect`/`bind`/`accept`/`rename`/`chmod`/生命周期/进程创建/`execve`）填 `0` |

- 事件只保留 `bytes`，**不保留 `res`**：`res` 仅用于成败判断与字节量取值。
- 关系不存 `host`（单主机），不做多主机字段。

### 8.6 Schema 与写入不变式

- **唯一约束**：顶点 3 个 —— `Process.process_id`、`File.file_id`、`Network.network_id`；关系属性 5 个 —— `event_id_p2p` / `event_id_p2f` / `event_id_f2p` / `event_id_p2n` / `event_id_n2p`（**按关系类型分别命名**；同名约束会让后续 `IF NOT EXISTS` 静默 no-op，因此必须分别命名）。建库时会先 `DROP CONSTRAINT event_id IF EXISTS` 清理遗留旧约束。
- **写入顺序**：先 MERGE 顶点（分批），再写边（按 5 个方向各一批）；边通过端点 MERGE 键 MATCH 端点，缺任一端点则跳过并计入 `skippedMissing`（可审计，不静默丢边）。
- **幂等**：顶点 MERGE 在 id 键上；边用 `MERGE (a)-[r:rel {event_id}]->(b)`（即端点 + 关系类型 + `event_id`），配合上述约束，重复导入同一日志不产生重复数据。
- **批量与 flush**：Neo4j 批量事务批大小 `PROGQL_NEO4J_BATCH_SIZE`（默认 5000）；解析侧边的 flush 阈值 `PROGQL_SYSDIG_FLUSH_EDGE_LIMIT`（默认 50000，只统计 p2f/f2p/p2n/n2p）；`p2p` 只在导入结束的最终 flush 写入。
- **导入可观察计数**（`parser.py` / `reporting.py`）：处理行数、逐理由跳过数、进入/退出配对各档、五类边计数、三类顶点数、`incomplete network`、`no object`、`connect EINPROGRESS`、`network protocol conflicts`、管道 fd 表统计、`Edge-less vertices not written`。

---

## 9. 溯源调查 agent（`provenance-agent/`）

在 `sysdig-parser` 导入的图上做**反向追踪**的 agent。设计决策与架构见 `provenance-agent/README.md`；本节只记录不可变口径。

- **架构**：确定性展开（纯代码，不调模型）→ **逐波判定**（模型调用只在这里）→ 代码定结论与报告。各层各占 `pagent/layers/` 下一个包（`l1_reach` / `l2_judge` / `l3_express`），编排在 `pagent/orchestration/`。没有调度用的 LLM，没有状态机框架。
- **任务范围**：只从 POI 往回走（反向追踪）；不引入"往前看"查询、不做多主机、不引入 `host_id`。
- **参数唯一来源**：`provenance-agent/config/agent.toml`（agent 的全部参数都在这一份文件里，程序启动时读一次；
  每项旁边写明它管什么与为什么是这个值）。凭据与连接信息不在其中，仍走环境变量或根 `.env`。
  容错口径：某项没写、类型不对或小于下限，都用代码内置默认值并在启动时打印一行说明，不报错。
- **POI 唯一来源**：`provenance-agent/config/scenarios.json`（库名 + POI 签名；实例数/时间范围由 intake 现算，不写进配置）。
  `input/sysdig/*.query`（含引擎方法描述）**不得进入 agent 的任何可见上下文**。
- **模型调用不先思考**（默认）：每次请求显式带 DeepSeek 官方接口字段 `thinking = {"type": "disabled"}`。
  官方默认是 `enabled`（先内部推理再回答），而推理文字由网关返回、代码只读正文，因此那些词只占生成时间
  与额度、不进判定文本（实测同一场景同一候选集：输出词 7,453 → 26,446、判定 74.6 秒 → 231.1 秒，
  并让场景 3 有 200 条候选因网关超时记未判定）。参数文件里把 `judge.thinking` 置真恢复官方默认，仅用于对照实验。
- **表示层**：一条边归一个进程（**进程身份摘要只用于判定时的上下文渲染与分组，不参与可达性计算**）。边归属规则：进程写文件/网络归源进程，文件/网络被进程读写归目标进程，进程派生归子进程；每条边恰好归属一个进程。
- **只读**：`pagent/core/db.py:ReadOnlyGraph` 是访问 Neo4j 的唯一入口（`execute_read` + 写关键字黑名单 + 禁多语句 + 不截断返回 + 查询审计日志）。
- **反向闭包（第 1 层，唯一引擎）**：事件级、时间门限、单调推进（`pagent/layers/l1_reach/closure.py`）。三条因果规则：同进程（先发生的可能影响后发生的）、同顶点交付（写入侧 → 读取侧；**只对能承载内容的通道生效**：非交付通道（内核现生成的伪文件、设备节点（含终端）、系统运行目录及其中的系统级套接字）只收边、不展开；`/proc/进程号/` 下的读边连边都不收，判据表 `pagent/rules/vertices.json`（文件段））、派生（父进程 → 子进程）。**派生那条带子进程把关**（`pagent/layers/l1_reach/siblings.py`）：先用“不带子进程”跑一遍定出主干（被展开过的进程 + 它们的直接子进程），主干里的进程无条件带走子进程，第二层起要“和主干有过一次写-读配对”（读的东西主干写过，或写的东西主干读过；非交付通道与 connect/bind 不算），因此正式流程是两遍。门限只减不增：每个顶点只完整展开一次，门限变高时只补取新增区间（实测六场补取占展开总数 0~7.5%；扫到的记录数是闭包的 1.2~1.3 倍，其中已收进闭包的边在来源侧直接跳过、真正进判定的行数约等于闭包大小）。
- **展开侧不设任何条数上限**：待考察顶点数、收进闭包的边数、查询返回行数全部不设限；闭包的终止条件是“待考察清单耗尽”。任何条数上限都是按数据分布随机丢边——实测子进程上限 8 让场景 4 的标注覆盖从 100% 掉到 74.6%；判定漏抄 id / 调用失败 → 进 `unjudged`（**不得当成排除**）并记缺口。
- **报告口径**：`output/agent/<场景>.json` 的 `edges[]` 为 `(src, syscall, dst)` + `event_id`（**没有 `mitre_technique`**，也**没有模型自报的把握**）。**判定只有一轮**：判为相关 → 确认，否则排除；模型没给结论 → 未判定（不等于排除）。模型在结论里多写的字段（含旧版要求的“把握”）**一律忽略**：不进报告、不进日志、不参与判断与评分（旧版“相关且把握达阈值才确认”已删除）。实体内容口径与 GT 一致（`Process=coalesce(exepath,name)`、`File=path`、`Network=lip:lport->rip:rport`）。**影响往回走的判定都在第 1 层取边时完成**（对象角色在顶点表文件段 `core/vertices.py`，内容形状在 `core/edge_rules.py`），后果只有一档：命中就不收这条边（两端也不会被推进待考察清单），逐类计数进报告里的 `stats.expand.dropped`（`r1` / `r2` / `prefilter` / `kernel_pid_file` / `nondelivery_write`）；**子进程把关挡下的派生边不属于规则剔除**，单独记 `stats.expand.gate_blocked`。**终点事件不受规则约束**，永远交给模型判定（展开结束的日志打印「规则残留 N 条（终点事件除外，应为 0）」）。**候选表 = 闭包输出折叠之后的内容三元组**（第 1 层尾部的 `fold.py` 只合并不删边），也就是交给模型的那一堆、召回上限的口径。折叠还会给记录两端各存一份**身份**（进程→进程标识、文件→路径、网络→四元组），并在折叠之后用 `l1_reach/sessions.py` 算出服务会话的**命令活动**与**会话一览**（连接端点 / 服务进程 / 活动条数 / 候选条数；会话＝一个进程接受一次远端连接，活动＝这次会话里由非常驻服务进程留下的候选记录条数，**没有阈值**）；身份只用于给「上游交接明细」定位，命令活动写在边行行尾，会话一览进状态摘要——三者都**只用于渲染**，不参与收边、不过滤候选（不变式：上下文只增不减）。第 1 层的确定性判据只有两张表（`pagent/rules/`）：**顶点表**（`vertices.json`，判定在 `core/vertices.py`：文件段三种文件角色——普通交付 / 系统提供 / 非交付通道，非交付通道那一条是**顶点的判定**，命中的文件顶点只收边、不往回找写入者、不算写-读配对；进程段三个进程类别——常驻系统进程 / shell / 普通命令）、**剔除表**（`filters.json`，判定在 `core/edge_rules.py`：`traversal` 段取边时剔、`output` 段闭包后剔——`output` 段的条件写全“属主类别 + 对象类别 + 方向（读/写）”，派生边不参与对象分类；`stats.expand.scope` 与 `stats.expand.routine` 是输出期一次遍历里两组过滤的计数，见 `pagent/layers/l1_reach/output_filter.py`）。边的方向与两端标签由关系类型唯一决定，统一在 `core/graph_facts.py`（闭包、折叠、索引构建、判定层渲染共用）。判定层**逐波推进**：按「离终点最少几跳」把所有候选边分波（一跳一波）；波内按参数文件 `judge.batch`（默认 70 条）切批，**同一波的所有批共用同一份冻结的双层滚动上下文、并发投递**，整波判完才更新状态。双层上下文：第 1 层「上游交接明细」列出这条边的上层顶点（第 1 层折叠留下的 `via_kind` / `via_key`）上**已经判过**的边及其结论（`JudgeState.upstream`，**按顶点身份查**：进程→进程标识、文件→路径、网络→四元组，身份在第 1 层折叠时随候选记录存下；只取确实以这个身份为一端的已判记录、优先给属主就是这个进程实例的记录。按内容（可执行文件路径）查会把同名进程的历史混在一起——场景 3 有 191 个进程都叫 `/usr/sbin/sshd`，实测给模型看的 2,713 条「以前判过的记录」里只有 2.5% 真的关于那个进程；每条边最多 `judge.upstream_limit` 条，默认 3）；第 2 层「调查状态摘要」由纯代码逐波更新，写已确认链片段、服务会话一览（被服务进程接受过的连接及其命令活动条数与已判计数；按活动从多到少，有活动的最多列 8 行、其余合并成一行；不设字符上限）。每次调用渲染顺序：任务说明（目标事件 = 配置里的 POI 签名、发生次数与时间原点、调查方向、清单口径；**只含任务定义**，不含标准答案、`.query` 与场景特化判据；通用字段口径（折叠事件数、字节与时间的含义、对象端点写法、相关边标签）写在系统提示词里）→ 调查状态摘要 → 进程身份表 → 本波边（本批标题标出「离终点第几跳、第几/共几波」；属于某次服务会话的记录在行尾附「本会话命令活动=N 条记录」——这次会话里由非服务进程（shell、命令等）产生的候选记录条数，0 表示这次会话除连接本身与自身读写之外没有命令活动；每条下面缩进列出**相关边**：上层顶点明细与同一对象邻居**合并成一块**、同一条边只出现一次；同对象邻居取前/后各 `judge.neighbor_per_side` 条（优先与这条边方向相反的：读边优先列写它的、写边优先列读它的；设为 0 就不列同一对象邻居），前侧或后侧为空时按 `render.overlap_neighbor` 补时间重叠的；已判过的带结论，没轮到判的标「尚未判到」；网络端点有协议记录时显示成「端点（协议）」）。**上下文不压缩**：每次投递都是完整上下文（一条边不少、相关边一条不少）。编号在整次调查里全局唯一。报告 `stats.judge` 里记 `waves` / `wave_details`（每波条数、批数、输入字符、确认/排除/缺失）等可审计计数。
- **运行态产物**：`tmp/provenance-agent/`（查询日志 `queries-*.jsonl`、逐条判定 `verdicts-*.jsonl`、原始输出度量 `llm-*.jsonl`、轨迹 `trace-*.jsonl`、调查记录 `state/record-*.json`、第 1 层测量结果 `l1-ablation/`、第 2 层重复运行结果 `l2-runs/`（当前方案每场景重复多轮、含评分）、顶点-时间索引 `l1-index/`），不进 `output/`。
- **评分**：`tools/eval_agent_attack_path.py`，与 `tools/evaluate_gt.py` 同口径。
## 10. 场景测试标准流程（provenance-agent）

用户说"测试 / 跑一下某个场景"时，**跳过一切预检，直接按下面顺序执行**；不要先探测环境、不要先跑 `tests/dry_run.py`、不要先做只读连通性验证（除非用户明确要求，或第 1 步本身报错）。

```bash
# 1. 直接跑（单场景实测 20~60 秒，墙钟受网关单次延迟影响；模型调用 2~30 次）
.venv/Scripts/python.exe provenance-agent/main.py --scenario <场景全名>

# 2. 跑完立刻打分（与引擎同口径）
.venv/Scripts/python.exe tools/eval_agent_attack_path.py \
  --report output/agent/<场景全名>.json \
  --gt groundtruth/<场景全名>.groundtruth.json
```

3. **先报数字，再谈深挖**：第一轮回复只给——召回 / 查准 / F1、引擎基线对照（`output/baseline/<场景>/groundtruth-eval.txt`）、报告路径、停止原因、确认边数、LLM 调用数；漏报与多出边只列清单。**数字没报完不许做根因分析。**
4. 深挖（`tmp/provenance-agent/logs/` 的 trace / 查询日志 / 判定明细 / `llm-*.jsonl` 的原始输出度量、`state/record-*.json`）只在对完数字之后做，且仅当用户要求或数字异常时才做。

硬约束：
- 场景名必须用 `provenance-agent/config/scenarios.json` 的**全名**（`2_Masquerade_Data_Exfiltration` 等），不接受简称。
- 自写读库脚本必须先 `pagent.settings.load_dotenv()`（`.env` 只在 `main.py:main()` 加载）；凭据一律不硬编码。
- 诊断产物写 `tmp/`；只有报告写 `output/agent/<场景>.json`。
- 报错时先判断是否属于「库不存在 / POI 不存在 / 网关不可达」三类，只有这三类才允许回退到环境排查。

## 11. 验证新方案 / 新机制 / 新功能的流程

> 仅在用户明确要求「测试 / 验证某个新方案（新机制、新功能）」时启用；不要主动触发（与全局规则「只做当前指令」一致）。
>
> **核心要求：测的必须是新方案本身。** 用现有代码加参数改出来的数，不能叫「测新方案」。

### 11.1 动手前（五项，缺一不可）

**（1）把待测对象拆成组件清单，逐项标注来源。**

| 标注 | 含义 |
|---|---|
| 新写 | 本次新实现的代码路径 |
| 复用 | 直接调用现有代码 |
| 只改参数 | 复用现有代码，只改常量 / 环境变量 / 配置 |
| 未实现 | 还没写 |

清单必须先给用户看。

**（2）关键组件处于「未实现」时，先实现，不许用别的东西顶替。**

替代品（规则、人工标注、现有代码的输出、上限推算）不能代表未实现的组件。若工作量超出本次范围，直接说明「需先实现 X」并给出工作量估计，由用户决定是否继续。

**（3）写清方法里禁止出现的东西。**

至少包括：人工标注、标准答案、目标结果，以及在本次测试场景上调出来的规则 / 阈值 / 名单。

**（4）写清本次测量要回答的问题，一句话。** 写不出来说明还没想清楚，先想清楚再动手。

**（5）对照数据只取仓库里已有的产物，禁止重跑基线。**

- agent 基线在 `output/agent/`：`metrics.json` 是评分，`<场景>.json` 是报告，报告里的 `stats` 有判定耗时与模型调用次数；引擎基线在 `output/baseline/`。做对照就读这些文件，**不要重新运行基线**。
- 只有当已有产物缺失、或确实要比较同一代码版本时，才允许重跑，**且必须先问用户**。
- 重跑得到的新数字不得与已有产物混在同一张表里。每个分数必须注明来源产物与代码版本。
- **当前工作区代码与 `output/agent/` 那批产物不是同一版本**（同一场景、同一条代码路径，已发布产物给出 32 条，当前代码给出 727 条），引用分数时必须写清是哪一版。

### 11.2 动手时（三项）

**（5）先跑 1 个场景，检查中间产物。** 逐阶段列出输入条数 / 输出条数 / 砍掉条数及原因；抽 3~5 个具体例子人工核对。核对无误再跑其余场景。

**（6）分阶段留证据。** 中间产物落盘 `tmp/`（见「修改边界」）；每个阶段都要能回答「进来多少、出去多少、为什么砍」。

**（7）中途发现测错，立即停下并报告**，不要一边发现不对一边继续跑完。

### 11.3 汇报时（三项）

**（8）三类数字分表呈现，不许混在一张表里。**

| 类别 | 定义 |
|---|---|
| 实测 | 方法真实跑出来的结果 |
| 上限 | 用标准答案推算、方法本身达不到的数 |
| 对照 | 旧方法 / 基线 |

**（9）每个数字必须能回答「它是怎么算出来的」**（来自哪一步、用了什么、排除了什么）。写不清的数字不许进表。

**（10）主动交代本次测量的局限**（例如：进程判断用规则代替模型；某条规则在本次测试场景上调过，分数偏高）。

### 11.4 禁止清单

1. 用人工标注（或任何形式的答案）作为方法的输入。
2. 用「改参数跑现有代码」冒充「测新方案」。
3. 在测试场景上调规则 / 阈值 / 名单，然后在同一批场景上报告分数。
4. 把「上限推算」写成「方案性能」。
5. 只给表格、不给数字来源。
6. 关键组件未实现时，用替代品顶替着测。

### 11.5 报告前自查（五问）

1. 把输入里的某样东西换成「正确答案」，结果会不会变好？会 → 方法里漏了东西。
2. 这个数字里有没有用到人工标注？用了 → 只能叫上限。
3. 跑的是新写的代码路径，还是现有代码路径？现有 → 不能叫「测新方案」。
4. 表里每个数字都能说清是哪一步算出来的吗？
5. 本次漏掉的东西，用户不发现的话我会不会主动说？

### 11.6 已测错时的处置

立即停止，主动说明：测错了什么、错在哪一步、哪些数字作废。**不得等用户发现。**

---

## 12. 设计泛用性（绝对要求）

**任何设计 / 机制 / 规则 / 阈值 / 名单，都不允许是专门为 `input/sysdig/` 下那六个实验场景做出来的。**判据必须能脱离「这六个场景的答案」独立成立，换一个没见过的场景仍然有效。做不到这一点，就等于换个场景就失效——这是**作弊 / 造假**，不是「效果不好」，绝对不允许。

**什么算「专门针对六个场景的设计」**（出现即禁止）：

- 用六个场景的人工标注挑判据：某类活动在标注里没出现，就把这整类写进剔除名单（例如「按标注挑出零命中的类别桶、再整桶剔除」这种写表方式）。
- 判据来自「在这六个场景里恰好没有攻击内容」这种分布结论，而不是日志与图的结构事实（路径形状、端点标签、事件方向、时间先后、系统调用语义）。
- 按场景定制路径名单、进程名单、时间窗、阈值：同一个机制要换一套参数才能在另一个场景成立。
- 在某个场景上调阈值 / 名单直到分数最好，然后在同一批场景上报这个分数。

**约束**：

1. 默认档只放结构判据：判据能从数据本身说清，并能回答「换一个没见过的攻击，为什么它仍然成立」。
2. 靠人工标注核对出来的名单，即使已验证「零命中」，也只能作为**按数据集启用、启用前重新核对**的可选项；文档与报告要写明它的来源与局限，不得把「六个场景标注一条不丢」当作有效证据（那是同义反复）。
3. 涉及「整类活动可以丢掉」的新机制，必须做跨场景验证：挑判据时排除被检验的场景，压缩量与标注流失量分开报。
4. 违反按 §11.4 禁止清单第 1、3 条处理：立即停下并主动报告哪些规则是照答案挑的、哪些数字与结论作废，不得继续使用。
