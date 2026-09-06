# TraceSage 项目说明

## 1. 项目目标

TraceSage 使用 Sysdig 导出的 JSONL 日志构建主机级溯源图，并将溯源图写入 Neo4j。图由三类顶点、五种方向化事件边，以及顶点和事件边属性组成。当前范围是**单主机日志**；除非用户明确提出，不要引入多主机、`host_id` 或跨主机关联模型。

## 2. 目录与资料

- `README.md`：项目目录说明与常用命令。
- `input/sysdig/`：输入数据，包含 JSONL 日志（如 `attack.jsonl`）、sysdig 纯文本导出和攻击场景查询（`*.llm.query`）。
- `output/`：解析、建模、导入或质量检查产生的输出（日志、对比报告、SQL 备份、统计结果）。
- `sysdig.wiki/`：Sysdig 日志格式和字段语义的参考资料。优先阅读其中的 User Guide 和 Quick Reference Guide。
- `tools/`：独立小工具与一次性诊断脚本（导出健全性检查、PG/Neo4j 诊断对比）。
- `analyze_attack_log/`：日志统计工具。 `analyze_attack_log.py` 按 JSONL 流式读取日志，统计原始字段、派生字段、解析异常、事件类型、进程名、FD 类型和统一系统调用类型。
- `sysdig-parser/`：溯源图解析导入器（单主机 Sysdig JSONL 日志 → Neo4j）。
- `requirements.txt`：当前 Python 依赖清单。
- `.venv/`：项目虚拟环境。
- `input/`、`output/` 中的日志可能很大，处理时应采用流式或分块方式，避免一次性载入内存。

## 3. 运行环境与依赖

- 全部 Python 命令都应在项目虚拟环境中执行。
- 新增依赖时同步更新 `requirements.txt`，不要把依赖只安装在本机而不记录。
- 本机 Neo4j 服务器已安装 GDS（Graph Data Science）与 APOC 插件，版本 2026.07.1，与服务器一致（可用 `SHOW PROCEDURES` 验证：`gds.*` 约 471 个过程、`apoc.*` 约 174 个过程）。
- 写代码时优先复用这两个插件的现有能力，不要在客户端重复实现：图算法（度数、连通分量、PageRank/特征向量中心性、BFS/DFS 可达性、最短路径等）用 `gds.*` 过程；服务器端批量作业（`apoc.periodic.*`）、路径展开拉子图（`apoc.path.*`）、元数据与工具函数用 `apoc.*` 过程。
- 边界：GDS/APOC 无法表达逐跳的时间因果谓词；带时序语义的因果遍历仍在客户端实现，插件侧只承担预筛与标准图计算。

## 4. Neo4j 导入约定

- 优先使用官方 Python Neo4j 驱动和参数化 Cypher；禁止拼接用户日志内容形成 Cypher。
- 先建立唯一约束/索引，再使用 `MERGE` 做顶点和事件边的幂等写入。
- 顶点和关系采用分批事务，批大小通过配置控制；不要逐条提交事务。
- 事务失败时要能定位批次范围，并避免在重试时产生重复数据。
- 数据库连接信息从环境变量或 `.env` 读取，禁止硬编码。
- 导入前后输出顶点数、关系数、跳过数、异常数、未匹配数和耗时；大日志处理必须可观察。
- 导入结果的正确性对比，固定以 PostgreSQL 库 `1_Multi_Stage_Data_Exfiltration`（第一个攻击场景）为基准库；对比工具为 `sysdig-parser/compare_pg_neo4j.py`；完整对比记录与差异归因见 `output/neo4j-pg-comparison-20260904.md`。
- 对比时进程顶点数差异（PG 约 560 vs Neo4j 约 433）及含进程端点的边键差异属**预期**：PG 基准库以 tid 记录进程，本解析器以 pid 建顶点。不要将其视为错误，也不要试图"修复"。
- 其余已知的良性差异（2026-09-04 对比确认）：PG 中 46 条 p2p 为旧版合成反向边（f4ec524 已按设计移除）；PG 中 152 条 rename 边 File 路径为空串（旧解析器未提取路径，现解析器已提出真实路径）。

## 5. 性能与可维护性

- 对大文件使用流式 JSON 解析、有限大小缓冲和分批写入。
- 可在解析、建模、导入之间使用有界队列或分阶段批处理，但必须保留顺序/配对所需的上下文。
- 不要为了并行而破坏进入/退出配对、事件时间顺序或统计结果的确定性。
- 任何性能优化都应以可重复的计数、耗时和内存指标验证；先保证语义正确，再优化导入吞吐。

## 6. 修改边界

- 修改前先阅读相关模块和现有资料；不要覆盖用户已有的未提交改动。

## 7. 调查流程基线

- 基线定义：对 Neo4j 溯源库（sysdig-parser 导入，`NEO4J_DATABASE` 指定，默认 `neo4j`）按 `input/sysdig/1_Multi_Stage_Data_Exfiltration.query` 描述的流程执行一次完整调查（POI 反向因果遍历 → CPR 因果窗口合并 → projection 三特征加权与声誉传播 → 入口候选 `count(in(n))=0 ORDER BY n.rel DESC LIMIT 5` → 逐入口正向扩展 UNION → 与反向图 INTERSECT），产出的结果即为回归基线。数据源为 `traversal.neo4jserver.Neo4jServerTraversal`（Bolt 连接；连接参数取自环境变量或根 `.env`）。2026-09-06 之前基线跑在 PostgreSQL 库 `1_Multi_Stage_Data_Exfiltration` 上，旧产物保留在 `output/baseline/1_Multi_Stage_Data_Exfiltration/`。
- 运行方法：`bash progql-local/baseline/run-baseline.sh`（用 javac 编译引擎与 `baseline/BaselineRunner.java`，编译时排除引用已删除 ProGQL 解析器的 `main/Main.java`，以 `progql-local/baseline/stub/main/Main.java` 作为引擎所需静态成员的编译桩；Bolt 驱动 neo4j-java-driver 4.1.1 在类路径中必须排在嵌入式 neo4j-3.5.11 jar 之前，并补充 reactive-streams/netty）。Neo4j 图无数字顶点 id，`Neo4jNodeRegistry` 按（标签, MERGE 键）升序枚举分配确定性 id 1..N，同库内容跨机器可得相同产物。
- 入口排名权重是全项目约定：影响 **0.55** / 最早因果时间 **0.45**，固定在 `progql-local/baseline/progql-llm.properties`；基线脚本通过 `-Dprogql.llm.config` 传入，其他环境运行该流程时也应使用同一配置，避免排名结果漂移。
- 基线产物：`output/baseline/neo4j-1_Multi_Stage_Data_Exfiltration/baseline.json`（不含时间戳，可逐字节 diff）。字段分四类：`meta`（参数：POI 模式、entry_limit、排名权重、CPR 窗口、数据源连接串）、`poi`（POI 事件标识与时间）、阶段规模（`stages`、`entry_candidates`、`forward_per_entry`）、结果明细（`entry_ranking`、`entry_candidate_lists` 全部候选名单、`final_vertices`/`final_edges`、`b_score_edges` 含权重、`b_raw_edge_keys`、`forward_union_edge_keys`、`final_vertex_mix`/`final_event_distribution`）。注意 `output/` 被 `.gitignore` 忽略，基线产物不入库，跨机器或重装环境时需手动保留。
- 对比方法：任何可能影响调查流程的修改（引擎、解析器、权重/传播逻辑、图操作）之后重跑同一命令，与基线 JSON 做 diff；`stages`、`entry_ranking`、`entry_candidate_lists`、`final_edges`、`b_score_edges`、`b_raw_edge_keys`、`forward_union_edge_keys` 任一变化都必须归因（预期改进或回归）。
- 确定性：2026-09-06 先后以 0.7/0.3 与 0.55/0.45 两种权重各连跑多次，`baseline.json` 均逐字节一致（权重融合的 multiKMeans 在该数据上收敛同一划分）；若未来数据集触发 KMeans 不稳定，优先排查权重阶段的 NaN/Infinity。
- 独立运行对比记录（2026-09-06）：与另一环境引擎产物的对比（`output/baseline/1_Multi_Stage_Data_Exfiltration-1_Multi_Stage_Data_Exfiltration-20260906-124338`）确认——各阶段图规模、最终图顶点/边、事件分布、候选集合、声誉值完全一致；入口排序差异经反解验证源于该环境的排名权重为 0.55/0.45（残差 ≤1e-9），据此将 0.55/0.45 定为标准并重新生成基线。
- 引擎修复记录（2026-09-06）：`GQLBackwardPropagate.getFeatureWeight` 的 time 特征在事件边与 POI 边 endtime 相同时求值为 `1/0` → Infinity，经出边归一化变为 NaN 并导致 KMeans 空簇异常（`ConvergenceException`）。已在该分支增加非有限结果回落到引擎自带的 `getTimeWeight` 伪最小差处理（`pseudoMinDiff=1e-10`）。
- Neo4j 数据源切换与对比记录（2026-09-06）：基线数据源由 PostgreSQL 切换为 sysdig-parser 导入的 Neo4j 溯源库。两次运行逐字节一致（确定性成立）。与旧 PG 基线的内容级对比（剥离 id 空间，映射到 实体内容+syscall+ns 时间戳，工具 `tools/compare_baseline_pg_neo4j.py`，详见 `output/neo4j-baseline-comparison-20260906.md`）：POI 事件两边同源（同 ns 时间戳与字节数）；b_raw 内容边 common 87（PG 160 / Neo4j 185）；主干攻击链（bash→.system_service.sh→nc→POI socket write、su/sudo 链）两边一致且时间戳相同。差异全部源于两代解析器对同一日志的不同建模，不是引擎语义变化：① 新解析器记录 clone（PG 无）与 p2n connect（PG 无）；② sudo/su 进程拓扑不同（PG 以 tid 建顶点且 sudo 的父是 su，新解析器以 pid+name 建顶点且 sudo 的父是 bash），连带 tty/ptmx/utmp 终端分支只在 Neo4j 进入反向窗口；③ 旧解析器 execve 配对的 endtime 到进程退出（个别边 endtime 相差数百 μs），使 PG 反向窗口扩进 wget 下载链而 Neo4j 收紧在前；④ PG rename 边 File 路径为空串（已知良性差异），新解析器有真实路径并新增 AT_FDCWD 顶点。entry top5 与 final 图随之不同（PG 25v/46e vs Neo4j 20v/45e），声誉值不可跨图比较。
