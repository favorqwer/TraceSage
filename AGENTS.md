# TraceSage 项目说明

## 第一部分：四大通用工程法则（最高优先级；任何情况下绝对压倒速度与格式）

违反任一条，该次交付无效并返工。

1. **声明边界法则（系统能力与输入真实性）**
   - 汇报、评估或设计任何系统能力时，必须严格区分「系统自主计算范围」与「外部前置输入范围」。严禁将下游组件、人工标注、人工启发式预选池、已知答案分布伪装为系统自主端到端能力。
   - 判据必须能脱离特定实验场景独立成立。严禁针对测试场景的答案挑选规则、白名单、时间窗或阈值（严禁过拟合伪装与测试作弊）。

2. **阻断诚实法则（未就绪即停与诚实阻断）**
   - 关键依赖未就绪、前置条件不满足或执行出错时，必须立即原地停止并主动说明缺失环节、影响范围与回退方案。
   - 严禁使用任何形式的替代品（如硬编码规则、假数据、人工补丁、上游阶段产物缓存）顶替测量。明确拒绝一切为了交差而制造的虚假数字。

3. **独立可验证法则（闭环复现与数字溯源）**
   - 所有性能、耗时、召回率、查准率数字必须能够通过完整代码闭环直接独立复现，必须说清测量口径、代码版本、输入来源与耗时。
   - 严禁擅自覆盖基线数据，严禁推算上限冒充实测结果。输入口径或代码版本一旦变更，旧数字立即作废。

4. **真实绝对压倒形式法则（本质真实优先于交付形式）**
   - 当「快速给出结果 / 满足交付第一段出数要求」与「系统完整正确运行 / 诚实报告未实现」发生冲突时，本质真实性拥有无限最高优先级。
   - 宁可停下报阻断，绝不允许为了快速交差而走捷径伪造全流程。

## 第二部分：操作安全与交互交付底线

### 权限与物理安全
1. **默认只读**：有副作用（写盘、改配置、动进程、花资源）先报备「做什么、多大代价、多久」，同意再动；「看一下 / 说明 / 分析」只输出文字。
2. **不可逆先拿许可**：覆盖、删除、改名、对外提交、发布先列清单明确确认；许可只对具体对象生效，备份不算许可。
3. **复杂动作先写脚本**：多步或长耗时任务必须编写独立脚本；后台执行配秒级进度与明确超时；停止清理按具体进程号，不用通配名字匹配。

### 交付质量与规范
4. **既定口径优先**：先把已明确的要求（命名、范围、起点、边界、口径）列成检查表；偏离先说明再动，不自创标准；答过的问题不重复问，必须问时一次一件并给默认值。
5. **要清单就穷举**：按「哪些 / 全部」提问时逐条编号列全，不用「共 N 条 / 分几类」代替；没逐项枚举不宣称完整。
6. **交付默认是可执行方案**：不给选择菜单；必须对方决策时一次一件并给默认值；不造多余概念，每句自问「删掉是否丢信息」。
7. **答问一次列全维度**：定义与口径类问题一次列全判定维度（单位、粒度、边界、多实例、失败与重试、聚合、否定事实、阈值、上限、退化等）逐项定，不分轮挤；可说明「这一维没想清」。
8. **排除项不回流**：已排除的因素不再出现在后续任何产物中；认为相关需重新提请说明。
9. **删就是删**：不留「原 X」「已移出」等历史痕迹；修改完毕按当前顺序重排编号并同步所有交叉引用。
10. **改产物先列校验清单**：修改关键产物先列内容（数字、引用、编号连续）、格式（换行、编码、缩进）与一致性清单，改完逐项跑并报结果。

### 算法验证与对比实验底线（防作弊、防伪增益）
11. **主干同构基线（起点真）**：对照组必须 100% 运行既有验证的主干完整流程，严禁自写“简化版/旁路流程”替代基线；启动对比前必须复核对照组数据，偏离已知历史基准立即阻断排查，严禁在漂移基线上算增益。
12. **实体差分归因（过程真）**：任何指标提升必须附带具体的差分清单（Diff List，列出具体多召回或精准剔除了哪些对象），严禁仅凭宏观总数增长宣称有效；必须确认差分对象确实由新机制产生，严禁将系统中既有能力的衍生副产物冒充为新收益。
13. **零假设首段直报（终点真）**：算法验证默认秉持零假设（默认无效甚至有害）；若实测增益为 0、恶化或被既有机制覆盖，必须在交付第一段直接汇报无效结论与物理瓶颈，严禁调参凑数，严禁粉饰交付。

### 讲解与沟通约定
- 默认用户没看过代码、看不懂代码、公式、数学符号及缩写：提到文件、函数、变量先用自然语言说清它是干什么的；专业术语首次出现当场定义（是什么、取值、用途），全文同名；通用行业词（如召回率、查准率、候选集）可直接用。
- **绝对禁止比喻（最高优先级禁令）**：讲解、汇报、回复里一律不得使用比喻、类比、打比方、拟人或生活化例子（如「一屋子人」「倒查三楼」「安检」之类）。一律直接写机制、对象、数字与出处（文件、函数、行号、查询语句）；需要解释概念时用该概念自身在图或代码里的定义说明。违反即本次交付无效，立即重写。

## 第三部分：项目目标、核心边界与图模型

TraceSage 使用 Sysdig 生成的主机系统调用事件流（SCAP 二进制文件直接流式解析）构建溯源图并存入 Neo4j 图数据库。图模型以 `provenance-parser` 代码为准，完整字段口径见 `provenance-parser/README.md`，建模公理见 `docs/PROVENANCE_GRAPH_MODELING_AXIOMS.md`。

- 核心边界：系统默认面向企业级多主机环境建模；节点以 `host_id` 作为命名空间属性与复合主键最高前缀，支持单机独立溯源。跨主机场景下 Network 顶点同样按 `host_id` 隔离，两端因果连接需要网络端点（IP、端口、时间）对齐；当前解析器只负责单次 capture 的图，不做跨主机对端自动合并。

### 图模型

顶点 3 类，主键均以 `host_id` 开头：

| 顶点 | 主键（Neo4j MERGE 键） | 主要属性 | 说明 |
|---|---|---|---|
| `Process` | `host_id, container_id, pid, start_ns` | `exe_path`、`cmdline`、`ppid`、`uid`、`euid`、`container_privileged`、`container_host_root_rw` | `start_ns` 是进程实例的出生时刻；同一 `pid` 不同 `start_ns` 代表 exec 前后的两个进程，`0` 表示出生时刻未知。`ppid` 是父进程的 pid 数字，不是父节点键。 |
| `File` | `host_id, container_id, path` | `file_type` | `path` 是规范化后的路径；`file_type ∈ {file, directory, pipe, unix, memfd, unknown}`。unix 套接字与 memfd 也建 `File` 节点，网络套接字不建。 |
| `Network` | `host_id, endpoints` | `proto` | `endpoints` 是 Sysdig 的连接元组字符串（形如 `lip:lport->rip:rport`）；`proto` 可能是 tcp/udp 等，也可能缺失；主键不含 `container_id`。 |

匿名 IPC（`event`、`timerfd`、`signalfd`、`inotify`、`eventpoll`、`netlink`、`bpf`、`other`）没有可区分名字，不建节点。容器属性 `container_privileged` / `container_host_root_rw` 缺失表示未知，不是 false。

关系边 5 类。关系类型只表示两端是哪种顶点，不表示数据流向；具体动作由边属性 `action` 给出。

| 关系类型 | 方向 | 典型 `action` |
|---|---|---|
| `ProcessToProcess` | 进程 → 进程 | `clone`、`exec`、`exit`、`signal`、`ptrace`、`wait`、`mem_read`、`mem_write`、`pidfd_getfd` |
| `ProcessToFile` | 进程 → 文件 | `create`、`write`、`mmap_write`、`rename`、`link`、`unlink`、`truncate`、`chmod`、`mount`、`umount`、`chroot`、`setns`、`ioctl`、`connect`（unix）、`send`（unix） |
| `FileToProcess` | 文件 → 进程 | `read`、`stat`、`mmap_read`、`mmap_exec`、`exec`、`rename`（源端）、`recv`（unix） |
| `ProcessToNetwork` | 进程 → 连接 | `connect`、`bind`、`listen`、`send` |
| `NetworkToProcess` | 连接 → 进程 | `accept`、`recv` |

边属性：`event_id`、`action`、`start_ns`、`end_ns`、`syscall`、`result`、`payload_b64`、`to_path`、`mode`。

- 写库以 `(event_id, action)` 作为关系唯一约束；同一事件可以产生多条边（如 `exec` 出 `ProcessToProcess` + `FileToProcess`，`rename` 出 `FileToProcess` + `ProcessToFile`）；自环不落图。
- `result` 是单字段三语义：数据类为字节数、失败为负错误码、`0` 为实测零；未观测时不写该属性。`fd` 号与 `mmap` 成功返回的地址不写入 `result`。
- `syscall` 是系统调用家族名（如 `sendmsg -> sendto`），原始 `evt.type` 用 `event_id` 回原始捕获核对。
- `payload_b64` 是载荷前 N 字节的 base64，不是可打印文本；`to_path` 只用于 `link` 的目标路径；`mode` 只用于 `chmod` 的权限模式。
- 方向约定：`read`/`recv`/`stat`/`mmap_read`/`mmap_exec`/`exec` 是「文件或连接 → 进程」；`write`/`send`/`create` 等是「进程 → 文件或连接」。unix 域套接字的 `connect`/`send`/`recv` 走 `ProcessToFile`/`FileToProcess`，不建 `Network` 节点；unix `accept` 只登记 fd，不建边。

跨主机关联不属于 `provenance-parser` 的职责；当前仓库没有对端流量对齐模块，跨主机关联只能作为外部前置步骤，不得在能力汇报中算作系统自主能力。

## 第四部分：主干资产全景

```
TraceSage/
├── AGENTS.md                 # 项目最高工程法则与操作约定
├── requirements.txt          # Python 依赖清单
├── .env                      # 数据库连接环境配置
├── attack/data/              # 各攻击场景 capture.scap 原始二进制捕获
├── input/sysdig/             # 历史场景 JSONL 日志备份
├── groundtruth/              # 10 个攻击场景人工标注标准答案
├── docs/                     # 图模型公理、攻击清单等设计文档
├── gt-annotator/             # groundtruth 标注与校验工具
├── output/                   # 产出结果（严格分类，不可混淆）
│   ├── navigator-baseline/   # 导航器基线与 OVERVIEW.md
│   ├── engine-baseline/      # 调查引擎基线与 OVERVIEW.md
│   ├── parser-v2/            # 解析器当次报告（含历史运行）
│   ├── engine-runs/          # 引擎当次运行产物（不得当基线）
│   ├── navigator-runs/       # 导航器当次运行产物（不得当基线）
│   └── agent-vs-engine/      # score_report_product.py 默认结果目录（按需生成）
├── tmp/                      # 临时文件与诊断数据区（随时可清）
├── tools/                    # 评测与检查工具（如 score_report_product.py）
├── provenance-parser/        # SCAP 流式解析与 Neo4j 溯源图构建入库
├── provenance-navigator/     # 神经符号因果拓扑与离线蒸馏双向因果导航系统
├── provenance-engine/        # 调查引擎（基于 Neo4j 与 GQL 的纯图路径遍历）
├── server/                   # TraceSage-Studio 工作台后端（FastAPI，复用导航器闭包提取与双向路由）
├── web/                      # TraceSage-Studio 工作台前端（Vite + React 因果图交互界面）
└── paper/                    # 参考论文
```

## 第五部分：数据库规范与评测协议

### 数据库命名规范
每个场景对应独立的 Neo4j 数据库（小写字母与连字符，前缀统一为 `attack-`，默认全部采用 `-v2` 标准物理规范 Schema 数据库）

- **默认使用 -v2 库底线**：历史无 `-v2` 后缀的库（如 `attack-1-web-exploit-ransomware`）缺少必需的边属性（`action`、`start_ns`、`result` 等），属于早期遗留非标准库，严禁使用；系统调用图分析、基线评测与标注默认且必须连接 `-v2` 结尾的标准库。
- 数据库操作严格使用官方驱动与参数化 Cypher，禁止字符串拼接构造 Cypher。

### 常用核心工具
| 脚本 | 用途 |
|---|---|
| `tools/score_graph_product.py` | 引擎产出 vs 标准答案评分（召回按步骤、查准按边）；产物未内藏 syscall 时按 `-v2` 库反查补全，反查不到即阻断 |
| `tools/score_report_product.py` | 智能体 / 导航器报告 vs 标准答案评分（与上一条同一口径） |
| `tools/rules_match.py` | 评分公共模块：可能集合规则与端点条件判定，动作名 ↔ syscall 词表 |
| `tools/run_all_engine_v2.py` | 批量在 `-v2` 库上跑调查引擎并自动评分 |
| `tools/promote_navigator_baseline.py` | 导航器留一交叉（10 场景逐折）结果校验后写成正式基线报告 |
| `tools/l1_index.py` | 手动建 / 重建导航器第 1 层顶点-时间索引 |
| `tools/neo4j_desktop_start.*` / `neo4j_desktop_stop.*` | 本机 Neo4j 桌面版启停 |

### 场景测试标准流程

用户触发测试时，直接在项目虚拟环境下运行对应系统的入口脚本。场景名以 `groundtruth/<场景全名>.groundtruth.json` 的文件名为准（大小写敏感）；`attack/data/<序号>/` 下的 `.jsonl` 文件名只作历史备份，不得作为 `--scenario` 的取值依据。

**图数据流式导入：**
```bash
python provenance-parser/main.py \
  --scap attack/data/<序号>/capture.scap \
  --scenario <场景全名> \
  --neo4j-database attack-<场景名小写连字符>-v2
```

**导航器评测：**
```bash
python provenance-navigator/main.py --scenario <场景全名>
# 或全量留一交叉
python provenance-navigator/run_leave_one_out.py
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

### 基线产物落盘位置
- 调查引擎（provenance-engine）的基线一律写 `output/engine-baseline/<场景名>/`：`baseline.json` 是引擎交付的最终图，`groundtruth-eval.txt` 是 `tools/score_graph_product.py` 对同一份产物的完整评分输出；汇总与口径写在 `output/engine-baseline/OVERVIEW.md`。
- 导航器（provenance-navigator）的基线一律写 `output/navigator-baseline/`（三模式逐场景结果与 `OVERVIEW.md`），由 `tools/promote_navigator_baseline.py` 校验后落盘。
- 当次用的运行产物写 `output/engine-runs/`、`output/navigator-runs/`；这两处不得当作基线，也不得被引用为成绩来源。
- `tools/run_all_engine_v2.py` 与 `provenance-engine/baseline/run-baseline.sh` 不带输出目录参数时都会写 `output/engine-baseline/`：前者用于批量重跑基线，后者只用于基线复跑；当次测试必须显式传 `output/engine-runs/<场景名>`，否则会覆盖正式基线。

### 多场景汇总口径（合并平均）
- 跨场景汇总一律用合并平均（又称加权平均、微平均）：先把所有场景的命中数相加、所有场景的判定对象数相加，再相除；禁止先算每个场景的比率再取算术平均（每个场景一票）当总成绩。
  - 召回 = Σ命中步骤 / Σ标注步骤；每个必须条目算 1 步，每条可能集合规则算 1 步。
  - 查准 = Σ命中边数 / Σ报告去重四元组数；四元组 = `(源, 系统调用, 目标, 成败)`，同一条边发生多次只计 1 个四元组。
  - 成败判等：两侧都有值时必须相等（图上 `result<0` 为 failure、`result≥0` 为 success）；任一侧无成败证据时按三元命中，并在输出里披露出「成败未核」的条数。
- 合并值必须与逐场景表同时给出，并披露三项分布：最小值、中位数、最大值；以及合并分母中各场景的占比（避免合并值被单一大输出场景主导而不被发现）。
- 禁止用调和平均当总成绩（它只反映最差场景的严重度，不是任何量的估计）；需要表达严重度时直接报最差场景。
- 召回与查准的分母不同，禁止合成单一的 F1 或「综合分」。
- 两套系统对比时，两侧必须使用同一汇总口径与同一分母，并额外给出逐场景配对差值（新方法减基线），不得只比合并值。

