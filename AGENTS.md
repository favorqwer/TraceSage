# TraceSage 项目说明

## 1. 项目目标

TraceSage 使用 Sysdig 导出的 JSONL 日志构建主机级溯源图，并将溯源图写入 Neo4j。图由三类顶点（Process / File / Network）、五种方向化事件边，以及顶点和事件边属性组成。当前范围是**单主机日志**；除非用户明确提出，不要引入多主机、`host_id` 或跨主机关联模型。字段与数据模型的详细设计（真实实现口径）见「字段与数据模型详细设计」。

## 2. 目录与资料

```
TraceSage/
├── AGENTS.md                 # 项目约定与说明
├── CHANGELOG.md              # 改动记录
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
├── provenance-agent/         # 溯源调查 agent（Python + LangGraph）
│   ├── main.py               # 入口：单场景 / --all / --dry-run
│   ├── config/scenarios.json # POI 唯一来源（库名 + POI 签名 + 采集窗口）
│   └── pagent/               # 包
│       ├── settings.py       # 路径/模型/预算/.env（横切）
│       ├── scenarios.py      # 场景与 POI 配置加载
│       ├── db.py             # 只读 Neo4j：写守卫 + 有界返回 + 查询审计日志
│       ├── steps.py          # 行为步骤层：摘要 / 机械枚举 / 四类前驱
│       ├── collapse.py       # 折叠成内容三元组 + R1/R2 结构性伪边剔除
│       ├── state_store.py    # 调查状态图（SQLite：三类节点四类边）
│       ├── llm.py            # 模型工厂 + JSON 调用自校正 + token 记账
│       └── graph/            # LangGraph 装配（state / nodes / build）
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
    可直接被 `tools/eval_agent_attack_path.py` 评分；`SUMMARY.json` 为多场景汇总。

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
- **`AGENTS.md` 只写“当前确定的事实”**（现状、约定、口径、不变式）；任何“什么时候改了什么、改前改后是多少、验证结论如何”的叙述一律写入 `CHANGELOG.md`，不要写进本文件。

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
- `fcntl` **不建边是设计决策**（不是缺陷）：口径写在 `tools/coverage_spec.json` 的 `declared_no_edge_events`，报告归入 A1c、不计哨兵；理由与实测证据见 `docs/log-db-coverage-gap.md` §5.1。

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
| `eval_agent_attack_path.py` | agent 溯源报告（`results/<场景>.json`，见 REPORT-FORMAT 口径）vs GT 的召回/查准评估；与 `evaluate_gt.py` 同口径（边三元组精确匹配、无豁免清单），支持 `--all` 批量、`--min-confidence` 过滤、`--json-out` 指标落盘 |

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
- **失败判据**：`record_failed()`（`res` 存在且 `res < 0`）用于 accept / fcntl / connect / bind / rename / 生命周期 / chmod 族的「失败则不建边」；数据流族（read/write/send/recv）用 `record_size()`（拿不到 `res` 就没有 `bytes`，不建边）；`execve` 仅在 `record_size(end_rec) == 0` 时算成功；非阻塞 `connect` 的 `EINPROGRESS(-115)` 经 `record_connect_failed()` 视为已发起、照常建边。

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

在 `sysdig-parser` 导入的图上做**反向追踪**的 LangGraph agent。设计决策与架构见 `provenance-agent/README.md`；本节只记录不可变口径。

- **任务范围**：只从 POI 往回走（反向追踪）；不引入"往前看"查询、不做多主机、不引入 `host_id`。
- **POI 唯一来源**：`provenance-agent/config/scenarios.json`（库名 + POI 签名 + 采集窗口）。
  `input/sysdig/*.query`（含引擎方法描述）**不得进入 agent 的任何可见上下文**。
- **表示层**：一个步骤 = 一个进程实例。边归属规则与 `docs/溯源图agent调查-创新点与效果.md` 的"进程子图"一致（p2f/p2n→源进程，f2p/n2p→目标进程，p2p→子进程）；每条边恰好归属一个进程。
- **只读**：`pagent/db.py:ReadOnlyGraph` 是访问 Neo4j 的唯一入口（`execute_read` + 写关键字黑名单 + 禁多语句 + 有界返回 + 查询审计日志）。
- **有界且不静默**：通用查询 `PAGENT_MAX_ROWS`（默认 1000）；步骤层单进程 `PAGENT_MAX_PROCESS_EDGES`（默认 200000），超限必须显式暴露 `edges_truncated`。
- **报告口径**：`output/agent/<场景>.json` 的 `edges[]` 为 `(src, syscall, dst)` + `confidence` + `event_id`；实体内容口径与 GT 一致（`Process=coalesce(exepath,name)`、`File=path`、`Network=lip:lport->rip:rport`）。
- **运行态产物**：`tmp/provenance-agent/`（查询日志、轨迹、状态图、checkpoint、步骤缓存），不进 `output/`。
- **评分**：`tools/eval_agent_attack_path.py`，与 `tools/evaluate_gt.py` 同口径。