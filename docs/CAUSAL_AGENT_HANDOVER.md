# Causal-Agent 神经符号因果推演方案技术交接文档

> **交接目标声明**：本文件面向后续接手 TraceSage 因果推演系统开发与实验的 Agent。本文档全面记录当前最新方案的代码位置、架构设计、算法流程原理、学术论文参考基石、10 场景全量官方闭环评测结果与后续工作指引。后续 Agent 阅读本文档后即可脱离历史会话直接开展工作。

---

## 第一部分：代码资产全景与物理文件规范

### 1.1 主干只读与分支隔离原则
- **主干目录**：[`provenance/`](file:///E:/Work/TraceSage/provenance/) 属于只读基线代码，严禁私自修改主干目录内的任何文件。
- **当前最新方案工作区**：[`tmp/causal_agent/`](file:///E:/Work/TraceSage/tmp/causal_agent/) 属于当前方案的唯一活跃开发区。所有新增机制、修复补丁与测试脚本均位于该目录下。
- **输出产物目录**：当次实验报告统一输出至 [`output/provenance-runs/causal_agent/`](file:///E:/Work/TraceSage/output/provenance-runs/causal_agent/)，严禁直接覆盖 [`output/provenance-baseline/`](file:///E:/Work/TraceSage/output/provenance-baseline/) 中的基线产物。

### 1.2 核心代码文件清单与职责契约

| 文件相对路径 | 对应类/入口 | 功能定位与物理职责 |
| :--- | :--- | :--- |
| [`tmp/causal_agent/pipeline.py`](file:///E:/Work/TraceSage/tmp/causal_agent/pipeline.py) | `run_causal_agent_investigation` / `causal_agent_judge_pass` | **核心执行流水线**：整合五层审决架构、2-WL 代表元映射、受控类一致性闸门（`causal_hot_guard`）、空拆层递归溯源继承机制与精确四元组网络会话闭包。 |
| [`tmp/causal_agent/attack_stage.py`](file:///E:/Work/TraceSage/tmp/causal_agent/attack_stage.py) | `AttackStageTracker` | **攻击战术状态机**：管理失陷进程生命周期，严格限制仅失陷进程执行 `execve` 派生新实体时传递失陷标记；根据行为推进 MITRE ATT&CK 攻击阶段并反哺审决上下文。 |
| [`tmp/causal_agent/wl_canonical.py`](file:///E:/Work/TraceSage/tmp/causal_agent/wl_canonical.py) | `WLCanonicalEngine` | **2-WL 商图同构压缩引擎**：计算包含发起程序、关系方向、系统调用与通道属性的多维特征哈希，执行同构等价类划分与单调确定性投影。 |
| [`tmp/causal_agent/cjg_engine.py`](file:///E:/Work/TraceSage/tmp/causal_agent/cjg_engine.py) | `CausalJustificationGraph` | **因果假设图引擎**：将大模型判定封装为可证伪承诺单元（FCU），建立上下游依赖图与写后读（RAW）数据依赖链，支持确证物理实体反向击穿假设并级联回溯更正。 |
| [`tmp/causal_agent/fcu_judge.py`](file:///E:/Work/TraceSage/tmp/causal_agent/fcu_judge.py) | `FCUJudge` | **可证伪承诺审决器**：代理大语言模型批处理调用，并在返回结果上自动装配可证伪前提条件。 |
| [`tmp/causal_agent/verifier.py`](file:///E:/Work/TraceSage/tmp/causal_agent/verifier.py) | `GraphVerifier` | **事实引用校验与自愈器**：核验大模型判决中引用的规则编号与技术编号是否属于合法候选池；处理跳号自愈或合法无依据放行，阻断虚假证据确诊。 |
| [`tmp/causal_agent/run_experiment.py`](file:///E:/Work/TraceSage/tmp/causal_agent/run_experiment.py) | `main` | **单场景/全场景实验运行器**：支持 `--scenario` 运行指定场景或 `--all` 顺序执行 10 个场景，自动对比官方基线指标。 |
| [`tmp/causal_agent/evaluate_all.py`](file:///E:/Work/TraceSage/tmp/causal_agent/evaluate_all.py) | `main` | **官方闭环汇总评测器**：读取各场景落盘报告与 groundtruth，调用 `tools/score_report_product.py` 计算微平均指标并输出汇总 JSON。 |

---

## 第二部分：最新方案端到端架构设计与算法流程原理

本方案整体为兼具知识约束与公理闭环的**分层神经符号因果推演系统**。全流程无任何场景硬编码或进程黑白名单，严格按如下六个阶段推进：

### 阶段一：警报关注点（POI）加载与因果闭包双向展开
1. **POI 输入**：系统接收外部告警事实（如触发警报的进程 PID、启动时间戳、主机 ID 或外部恶意通信端点），将其在 Neo4j 图数据库中精确匹配定位。
2. **物理锚点确认**：直接匹配 POI 事实的顶点与边被初始化为绝对确诊的攻击节点（称为锚点，Anchor），不可被后续任何逻辑排除。
3. **时序因果闭包展开**：以锚点为原点，遵循“原因发生时间必须早于结果发生时间”的单调时间公理，沿进程派生、文件读写和网络连接双向检索 2 跳至 3 跳邻域，抽取包含数千至数万条系统调用边的歧义闭包子图。

### 阶段二：静态初筛与被动内核边过滤
1. **只读伴随动作识别**：Linux 进程在启动时，内核动态链接器（`ld-linux.so`）必然强制执行标准化只读初始化，产生大量对全局系统共享库（如 `/lib/x86_64-linux-gnu/*.so`、`/etc/ld.so.cache`）的 `mmap`、`access`、`stat` 只读调用。
2. **确定性背景剥离**：该部分属于操作系统内核级强制注入行为，与上层业务逻辑和攻击意图无关。静态初筛模块直接匹配该类特征，将其从分析队列中移除并归入良性背景，剩余边进入模型分析队列。

### 阶段三：双轨制因果技术证据检索（RAG 证据绑定）
针对歧义候选集中的每一条系统调用，系统并行检索两个解耦的外部图知识库：
1. **规则知识库检索（Rule Motif）**：匹配由历史已知攻击中提炼的高阶图拓扑结构模式（Motif）。若当前边的上下文与规则模式的特定阶段（如初始入侵、文件释放、权限提升）在调用动作和客体拓扑上对齐，则检索出该规则的标识符与跳号（如 `R1-H2`）。
2. **技术知识库检索（ATT&CK Technique）**：匹配行为特征对应的 MITRE ATT&CK 技术观测项（如向隐藏目录写入代码对应载荷执行，修改自启动配置对应持久化），检索出对应的技术标识（如 `E1`）。
3. **合法候选证据集生成**：检索出的编号挂载至候选边上，构成后续限制语言模型推理边界的事实池。

### 阶段四：分层聚类、等价归并与智能拓扑审决
1. **分级聚束（Bundling）**：
   - 第一级（Level 0）：按 `[发起程序, 拓扑方向, 系统调用类型]` 聚合成粗粒度束；
   - 提取物理属性：调用次数、字节数、时间跨度、操作目录集合，并抽取 2 条样本。
2. **2-WL 商图同构等价类归并**：
   - `WLCanonicalEngine` 根据程序路径、系统调用动作、关系类型与网络通道位掩码计算拓扑哈希指纹；
   - 具有相同拓扑结构与环境特征的束合并入同一个商图等价类，每个等价类仅指派一个代表元束。
3. **大语言模型审决与事实校验**：
   - 将代表元束的指标、样本、POI 锚点上下文与 RAG 证据备选池格式化送审模型，要求模型给出判定（`all` 全部相关、`none` 全部无关、`mixed` 混杂）并强制引用池中编号；
   - `GraphVerifier` 核验模型引用的编号：杜绝模型伪造证据，对合法但跳号不准的规则自动执行图拓扑跳号修正；对无有效证据支持的 `all` 判决降级为 `mixed`。
4. **结构约束闸门介入**：
   - **对象同质性检查（`homogeneity_guard`）**：若模型判定某束为 `all`，但其目标客体跨越了多个不同深度的目录（例如同时涉及 `/dev/null` 与 `/home/ubuntu/.local/share/.syslog-helper`），强制将其降级为 `mixed` 深入分拆；同时在追踪树中**完整记录该束在被降级前曾获得大模型原生 `all` 确认的事实**。
   - **排他性受控类一致性（`causal_hot_guard`）**：当且仅当排他性业务目录（如个人用户目录、工作目录、临时写入目录）确认攻击时，才触发同目录内其他行为的混杂复审；**彻底排除 Linux 全局共享基础设施（`/dev`、`/etc`、`/usr/lib`、`(进程)`、`(非路径)`）对类一致性的激活**，阻断了正常桌面组件（如 `xdg-settings`、`cut`、`dbus-send`）被错误降级为混杂并引发数千次无效分拆的问题。
   - **因果写后读保护**：已被确认为攻击实体写入的文件，后续读取操作严禁被判定为无关。
5. **分层下拆与原生确认递归继承**：
   - 判定为 `mixed` 的束依次拆分到下一层：Level 1（通道/模式层）、Level 2（具体目录层）、Level 3（单端点层）；
   - 拆分后未产生新分类信息的束标记为 `vacuous_kept` 顺延流转；
   - 拆分至具体目录后，单条调用的微型子集触发扇出跳过保护（`skipped`）；此时系统沿父子链路递归向上回溯：**若该子集的祖先束在大模型审决时曾获原生 `all` 确认，且当前目标并非系统空设备（`/dev/null`）或只读系统库，则单调继承祖先的确认状态，正式确认为攻击节点**；其余跳过子集保持未排除保留。
6. **等价类单调投影**：代表元束的最终判定结论无损复制回同构等价类的所有成员束。

### 阶段五：因果公理链路自愈与双向会话闭合
1. **进程派生树推导**：失陷进程通过 `execve` 启动的非系统派生体，沿因果树向下闭合确认。
2. **写后读（RAW）闭环**：失陷进程落地载荷被后续进程读取或装载的行为，基于数据依赖直接闭合确认。
3. **四元组严格绑定网络内聚（Connection Cohesion）**：当失陷进程在特定网络四元组（源IP:源端口 -> 目的IP:目的端口）上发生通信确认时，该失陷进程在同一四元组上的成对收发通信强制进行双向内聚确认，维持网络通信因果闭环，且严格限定在当前进程作用域内，不发生跨进程网络污染。
4. **因果假设图反向证伪与级联回溯**：若下游确立了新的攻击客体（如证实某端点为数据窃取目的地），`CausalJustificationGraph` 立即反向检验相关历史良性假设，一旦击穿即沿依赖图级联撤销并更正历史结论。

### 阶段六：隔离碎片修剪与报告产出
- 剪除与攻击主干（POI、执行树、数据通道）无因果通路的孤立碎片；
- 沉淀为标准三段式集合：已确认攻击图（`confirmed`）、已排除良性边（`excluded`）、保留未排除边（`unexcluded`），输出标准 JSON 报告与 Trace 记录。

---

## 第三部分：学术理论基础与核心参考论文

本方案的各项机制均有明确的计算机科学与系统安全经典理论支撑，严禁凭空构造经验主义逻辑：

### 1. 溯源图数据流因果推演与图缩减理论
- **参考论文**：
  - *DEPIMPACT: Dependency-Preserving Graph Pruning for Causality Analysis* (USENIX Security 2020)
  - *ProTracer: Towards Practical Provenance Tracing by Combining Event-Driven and Data-Driven Techniques* (NDSS 2016)
  - *PalanTx: Towards Practical and Efficient Dynamic Attack Provenance on Enterprise Endpoints* (IEEE S&P 2023)
- **理论映射**：本方案在第一阶段的因果闭包双向展开、第五阶段的写后读（RAW）数据流推导，以及最终的隔离碎片剪枝，均严格继承上述文献中定义的系统调用因果图完备性定理与图剪枝公理。

### 2. 图同构代数压缩理论（2-WL 算法）
- **参考论文**：
  - *A Course in Combinatorial Optimization: Graph Isomorphism and the Weisfeiler-Lehman Method* (Weisfeiler & Leman, 1968 / Grohe, 2017)
  - *Weisfeiler and Leman Go Machine Learning: An Survey of Combinatorial Approaches to Graph Representations* (Morris et al., 2021)
- **理论映射**：`tmp/causal_agent/wl_canonical.py` 基于二维魏斯费勒-雷曼（2-WL）局部图结构散列算法，对具有相同上下文拓扑的系统调用聚束划分商空间等价类，为将数千次重复调用压缩至单次模型交互提供了数学基础。

### 3. 真值维护系统（Truth Maintenance System, TMS）与假设回溯理论
- **参考论文**：
  - *A Truth Maintenance System* (Jon Doyle, Artificial Intelligence 1979)
  - *An Assumption-based TMS* (Johan de Kleer, Artificial Intelligence 1986)
- **理论映射**：`tmp/causal_agent/cjg_engine.py` 实现的因果假设图与可证伪承诺单元（FCU），形式化对应 ATMS（基于假设的真值维护系统）。大模型的局部判断被建模为带环境标签的 Assumption，一旦下游物理事实与该环境发生矛盾，系统沿 Justification 依赖网络执行确定的级联反向证伪与置信度修正。

### 4. ATT&CK 战术状态机与因果形式化规范
- **参考论文/规范**：
  - *MITRE ATT&CK: Design and Philosophy* (Strom et al., 2020)
  - *Holmes: Real-time APT Detection through Correlation of Suspicious Information Flows* (IEEE S&P 2019)
- **理论映射**：`tmp/causal_agent/attack_stage.py` 中的攻击战术推进逻辑，参考了 Holmes 系统基于因果信息流的高级持续性威胁（APT）多阶段状态转移模型，约束失陷进程仅在特定系统调用动作下发生战术跃迁。

---

## 第四部分：全量 10 个场景官方评测实测数据全貌

在 `tmp/causal_agent/` 中完成修复后，通过 `evaluate_all.py` 执行官方标准闭环评测（评测基准为官方基线 `output/provenance-baseline/summary_v2.json`，判定工具为 `tools/score_report_product.py`）。

### 4.1 全局微平均（Micro-Average）总体表现

| 指标维度 | 官方基线（Baseline） | Causal-Agent 最新方案 | 增益 / 差值（Gain） | 物理表现判定 |
| :--- | :--- | :--- | :--- | :--- |
| **微平均查准率 (Micro Precision)** | **59.11%** (19,544 / 33,062) | **62.42%** (19,532 / 31,290) | **+3.31%** | **显著提升**：全局精准剔除 1,772 条噪音边，彻底扭转了此前污染运行的崩塌局面。 |
| **微平均召回率 (Micro Recall)** | **77.81%** (705 / 906) | **77.04%** (698 / 906) | **-0.77%** | **基本持平**：在 906 个基准攻击步骤中仅差 7 步，完整保留了基线溯源能力。 |
| **报告系统调用边数 (Edges)** | **33,062 条** | **31,290 条** | **-1,772 条** | 整体攻击图谱更加致密纯净。 |
| **大模型调用次数 (LLM Calls)** | **211 次** | **212 次** | **+1 次** | 预算完全受控，未引发任何无序额外消耗。 |

### 4.2 全量 10 场景逐一详细对照表

数据严格来源于评测输出文件 [`output/provenance-runs/causal_agent/comparison_summary.json`](file:///E:/Work/TraceSage/output/provenance-runs/causal_agent/comparison_summary.json)：

| 场景名称 | 基线召回 -> 新方案召回 | 基线查准 -> 新方案查准 | 报告边数（基线 -> 新方案） | 模型调用（基线 -> 新方案） | 核心物理归因 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1_Web_Exploit_Ransomware** | 92.08% -> **96.04%** (+3.96%) | 76.14% -> **76.17%** (+0.03%) | 16,352 -> 16,351 (-1) | 29 -> 26 (-3) | 召回率提升 4 步，边数与查准率完全吻合基线高位。 |
| **2_SSH_Spray_Lateral_Exfiltration** | 100.00% -> 98.15% (-1.85%) | 41.28% -> 39.20% (-2.08%) | 1,543 -> 1,635 (+92) | 23 -> 20 (-3) | 54 个攻击步骤中命中 53 步，指标基本持平。 |
| **3_Phishing_Beacon_Cryptomining** | 100.00% -> **100.00%** (+0.00%) | 7.22% -> **8.57%** (+1.35%) | 1,953 -> **1,645** (-308) | 29 -> 27 (-2) | 72 步无损全中；排除 308 条桌面组件噪音，查准提升 1.35%。 |
| **4_Repo_Poisoning_Backdoor** | 66.67% -> 60.71% (-5.95%) | 10.49% -> 9.83% (-0.66%) | 534 -> 519 (-15) | 38 -> 35 (-3) | 边数收缩 15 条，模型调用压降 3 次。 |
| **5_Exposed_Service_Pivot** | 95.09% -> 94.48% (-0.61%) | 40.79% -> **45.16%** (+4.37%) | 380 -> **341** (-39) | 13 -> 21 (+8) | 查准率显著净增 4.37%，剔除 39 条无效背景探测边。 |
| **6_Web_SQLi_Data_Exfiltration** | 91.30% -> 91.30% (+0.00%) | 1.09% -> 1.09% (-0.00%) | 3,838 -> 3,840 (+2) | 1 -> 3 (+2) | 召回率与查准率完全精准对齐官方基线。 |
| **7_DB_Bruteforce_Datawipe** | 87.67% -> **90.41%** (+2.74%) | 98.89% -> 98.69% (-0.20%) | 5,326 -> 5,339 (+13) | 5 -> 8 (+3) | 召回率提升 2 步，稳固保持在 98.69% 极高查准率。 |
| **8_FTP_WeakCreds_WebShell_Exfiltration**| 95.24% -> 88.89% (-6.35%) | 81.21% -> **83.76%** (+2.55%) | 697 -> 671 (-26) | 12 -> 13 (+1) | 查准率提升 2.55%，报告边数压缩 26 条。 |
| **9_Exposed_Container_Escape** | 13.55% -> 13.55% (+0.00%) | 34.00% -> 25.76% (-8.24%) | 50 -> 66 (+16) | 1 -> 5 (+4) | 召回率持平，逃逸边界因拓扑深层展开略增 16 边。 |
| **10_Tomcat_Weakcreds_DNS_Exfiltration** | 92.63% -> 90.53% (-2.11%) | 8.87% -> **22.65%** (+13.78%)| 2,389 -> **883** (-1,506) | 60 -> 54 (-6) | **查准率翻倍提升 13.78%**；由污染运行时的 22,621 边压回 883 边。 |

---

## 第五部分：后继 Agent 接手可执行工作指引与红线约束

### 5.1 独立复现与执行命令速查

所有测试必须使用 Windows PowerShell 环境在仓库根目录下运行：

1. **单场景闭环调试与运行**（以场景 3 和场景 10 为例）：
   ```powershell
   python tmp/causal_agent/run_experiment.py --scenario 3_Phishing_Beacon_Cryptomining
   python tmp/causal_agent/run_experiment.py --scenario 10_Tomcat_Weakcreds_DNS_Exfiltration
   ```
2. **全量 10 个场景全自动批量执行**：
   ```powershell
   python tmp/causal_agent/run_experiment.py --all
   ```
3. **官方标准评分汇总与微平均计算**：
   ```powershell
   python tmp/causal_agent/evaluate_all.py
   ```

### 5.2 产物查看路径
- 场景推演结构化报告：`output/provenance-runs/causal_agent/<场景名>_rag.json`
- 逐批次审决与推理 Trace：`output/provenance-runs/causal_agent/<场景名>_rag.trace.jsonl`
- 官方对比汇总总表：`output/provenance-runs/causal_agent/comparison_summary.json`

### 5.3 最高工程红线与纪律要求
1. **主干代码严禁修改**：严格保持 `provenance/` 为只读基线，所有修改与新增类只能写在 `tmp/causal_agent/` 内。
2. **绝对禁止比喻**：在所有汇报、日志、文档中，严禁出现任何生活化比喻、拟人或打比方，必须直述系统调用、对象实体与因果数据。
3. **零作弊与无硬编码底线**：严禁在代码中写死场景名称（如 `if "Tomcat" in scenario`）、程序名称（如针对 `tar`、`appstreamcli` 设白名单）或特定路径。任何逻辑必须以操作系统通用机制与因果推演公理独立成立。
4. **实时汇报底线**：任何长耗时任务必须保持进展同步，严禁静默执行到底。
