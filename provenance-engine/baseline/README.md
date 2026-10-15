# 调查流程基线（baseline runner）

本目录包含对一条 ProGQL 调查流程的**确定性复现工具**（逐阶段复现查询语言层描述的
调查流程），以及它产出的回归对比基线。

## 背景

ProGQL 查询语言层（语法/解析器/AST 构建器）已从本仓库删除，`main/Main.java` 因仍引用
已删除的解析器而无法编译。`BaselineRunner` 以**程序化构造** gql AST 对象的方式驱动剩余
引擎（Neo4jServerTraversal + GQLBackwardPropagate + 图操作），逐阶段复现查询文件描述的
流程：

1. 定位 POI（`NetworkEvent{optype:"write"}` 写往外传地址，映射到 Neo4j 的
   `p2n {syscall:"write"}`）并以因果约束
   `r.starttime<max(collect(vout IN out(v) | vout.endtime))` 反向遍历 → `b_raw`
2. `CausalityPreserve.mergeEdgeFallInTheRange2(10.0)` 因果窗口边合并 → `b_cpr`
3. `SET e.weight=projection(...)` 三特征（amount/time/structure）加权 +
   `SET u.rel=reduce(...)` 声誉传播（`GQLBackwardPropagate`）→ `b_score`
4. 入口候选 `WHERE count(in(n))=0 ORDER BY n.rel DESC LIMIT 5`（复合分 = 影响力 0.55
   + 最早因果时间 0.45，权重由 `baseline/progql-llm.properties` 固定，网络/文件/进程
   按配额分配）→ top 5
5. 从每个入口以 `re.endtime>min(collect(uin IN in(u) | uin.starttime))` 正向扩展并
   UNION → `forward_union`
6. 最终结果 `INTERSECT(b_score, forward_union)` → `final`

## 运行

```bash
bash provenance-engine/baseline/run-baseline.sh 1_Web_Exploit_Ransomware \
  output/engine-baseline/1_Web_Exploit_Ransomware --poi-file /srv/data/README_RESTORE.txt
# 参数: run-baseline.sh <场景名> [outDir] [--poi-... / --poi-file <路径> / --entry-limit ...]
# （POI 没有默认值，必须显式给；各场景的 POI 见 provenance-agent/config/scenarios.json）
```

- 数据源：**Neo4j 服务器**（scap-parser 导入的溯源图；`bolt://localhost:7687/neo4j`，
  连接参数取自环境变量或仓库根 `.env` 的 `NEO4J_URI` / `NEO4J_USER` /
  `NEO4J_PASSWORD` / `NEO4J_DATABASE`，不硬编码）。`dbName` 参数仅作为场景名写入
  产物的 `meta.scenario`；图库本身由 `NEO4J_DATABASE` 决定。
- POI 参数（没有默认值，必须显式给）：`--poi-srcip/--poi-srcport/--poi-dstip/--poi-dstport/--poi-optype`
  描述 Network POI；`--poi-file <绝对路径>` 切换为 File POI
  （`(p:Process)-[st:FileEvent{optype:"..."}]->(f:File{name:"..."})`），
  `name` 经兼容层映射到 `File.path`。入口限额默认 5，用 `--entry-limit N` 覆盖。
  各场景的 POI 见 `provenance-agent/config/scenarios.json`。
- 场景范围：当前五场景各自一个独立库（前缀 `attack-`，命名约定见根 AGENTS.md），
  跑某个场景时用 `NEO4J_DATABASE` 指向对应场景库，并用 `run-baseline.sh` 的场景名与
  产物目录参数区分场景；产物落 `output/engine-baseline/<场景>/`（`baseline.json` +
  `groundtruth-eval.txt`）。流程与对比方法不变，但不同场景的基线产物之间不可比。
- 顶点 id：Neo4j 图没有数字顶点 id，`Neo4jNodeRegistry` 在启动时按
  （标签, MERGE 键）升序枚举全部顶点分配 1..N，同一份库内容在任何机器上得到相同
  id，保证产物可复现。
- 事件语义映射：五种方向化关系 p2p/p2f/f2p/p2n/n2p 与查询侧别名
  （`optype→syscall`、`amount→bytes`）对应，由 `Neo4jServerTraversal` 兼容层翻译；
  Network 顶点的 ip 属性（lip/lport/rip/rport）不带 `/32` cidr 后缀，匹配时自动剥离。
- 入口排名权重通过 `-Dprogql.llm.config` 指向 `baseline/progql-llm.properties`
  （impact 0.55 / time 0.45）固定，与运行目录无关；这是全项目约定，见 AGENTS.md 第 7 节。
- 产物：`output/engine-baseline/<outDir>/baseline.json`（该目录被 `.gitignore` 忽略，
  不随仓库版本化，跨机器需手动保留）。
- 依赖：JDK 17+ 与本机 `~/.m2/repository` 中的依赖 jar（清单见脚本内 `CP`；
  Bolt 驱动 neo4j-java-driver 4.1.1 必须排在嵌入式 neo4j-3.5.11 jar 之前，
  并补充 reactive-streams 与 netty 运行时）。
- 编译方式：javac 直接编译 `src/main/java` 全部源码**排除** `main/Main.java` 与
  `traversal/neo4j/BreadthFirstIterator.java`（与 pom 的编译排除一致），并加入
  `stub/main/Main.java`（提供引擎读取的 `Main.poiEdge/getNodeById` 等静态成员的
  编译桩）与本运行器。

## 产物与对比方法

`baseline.json` 的可 diff 字段（不含任何时间戳/耗时）：

- `stages`：b_raw / b_cpr / b_score / forward_union / final 各阶段顶点数与边数；
- `poi`：POI 事件签名、类型与起止时间；
- `entry_candidates` 与 `entry_ranking`：候选数量与 top-5 入口的排名、复合分、声誉；
- `entry_candidate_lists`：三类入口候选的完整名单（id/签名/声誉/复合分/最早因果时间）；
- `forward_per_entry`：每个入口的正向扩展规模；
- `final_vertex_mix`、`final_event_distribution`：最终图构成；
- `final_vertices` / `final_edges`：最终图全部顶点（含声誉）与边；每条边含规范化边键、
  融合权重，以及内嵌的 `syscall` 与 `starttime`/`endtime`（秒，浮点，取自事件边）；
  因此 `tools/evaluate_gt.py` 可直接用产物评分，不必回库反查；
- `b_raw_edge_keys`：反向遍历结果全部规范化边键（CPR 合并前的原始内容）；
- `b_score_edges`：b_score 阶段全部规范化边键及融合权重；
- `forward_union_edge_keys`：正向扩展合并图的全部规范化边键。

修改项目后重跑同一命令，与基线 `baseline.json` 做文本 diff：上述任一字段变化都
意味着行为变化，必须归因（预期改进或回归）。

## 确定性

2026-09-06 在基准库上连跑 3 次，`baseline.json` 逐字节一致。权重融合内部的
`multiKMeansPlusPlus`（20 次 KMeans，随机初始化）在该数据上收敛到同一划分；若未来
数据集使 KMeans 不稳定，优先排查权重阶段的 NaN/Infinity（见
`GQLBackwardPropagate.getFeatureWeight` 的 time 特征非有限回落处理）。
