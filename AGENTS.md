# TraceSage 项目说明

## 1. 项目目标

TraceSage 使用 Sysdig 导出的 JSONL 日志构建主机级溯源图，并将溯源图写入 Neo4j。图由三类顶点（Process / File / Network）、五种方向化事件边，以及顶点和事件边属性组成。当前范围是**单主机日志**；除非用户明确提出，不要引入多主机、`host_id` 或跨主机关联模型。字段与数据模型的详细设计（真实实现口径）见第 9 节。

## 2. 目录与资料

```
TraceSage/
├── AGENTS.md                 # 项目约定与说明（本文件：目录结构、导入约定、常用命令、对比基准）
├── requirements.txt          # Python 依赖清单（pipreqs 生成）
├── .env                      # 数据库连接配置（不入库）
├── input/sysdig/             # 输入数据：6 个攻击场景的 JSONL 日志与同名 .query 场景查询
├── output/                   # 运行产物：导入日志、对比报告、SQL 备份、统计输出
├── tools/                    # 独立小工具与一次性诊断脚本（用途见第 8 节）
├── sysdig-parser/            # 溯源图解析导入器（单主机 Sysdig JSONL 日志 → Neo4j）
│   ├── main.py               # 入口
│   ├── compare_pg_neo4j.py   # PG 基准库 vs Neo4j 正确性对比
│   └── parsers/              # 解析器包（按层分子包）
│       ├── pipeline/         # 解析管线：主循环、进出配对、实体注册、边缓冲
│       ├── model/            # 纯图模型：顶点（Process/File/Network）、EntityNode、EventEdge
│       ├── jsonl/            # Sysdig JSONL 行级解析：记录解码、args 字段抽取
│       ├── dispatch/         # 系统调用分发：Fingerprint/SystemCall、动作注册
│       ├── storage/          # Neo4j 批量写入
│       ├── config.py         # 环境变量/.env 配置（横切）
│       └── reporting.py      # 进度与跳过行上报（横切）
└── sysdig.wiki/              # Sysdig 日志格式与字段语义参考资料（优先阅读 User Guide 和 Quick Reference Guide）
```

- `input/sysdig/` 中每个攻击场景为一对 `<场景名>.jsonl` 与 `<场景名>.query`；每个场景导入独立 Neo4j 数据库（见第 4 节）。
- `output/`：解析、建模、导入或质量检查产生的输出（日志、对比报告、SQL 备份、统计结果）；配对算法改造（改前/改后）统计对比见 `output/pairing_comparison/README.md`。
- `.venv/`：项目虚拟环境。
- `input/`、`output/` 中的日志可能很大，处理时应采用流式或分块方式，避免一次性载入内存。

## 3. 运行环境与依赖

- 全部 Python 命令都应在项目虚拟环境中执行：

  ```bash
  .venv/Scripts/activate        # Windows / Git Bash
  pip install -r requirements.txt
  ```

- 新增依赖时同步更新 `requirements.txt`，不要把依赖只安装在本机而不记录；重新生成（自动扫描项目 import）：`pipreqs . --ignore .venv,__pycache__ --force`。
- 数据库连接信息从环境变量或根 `.env` 读取，禁止硬编码：Neo4j 用 `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE`；PG 对比工具另用 `PG_USER` / `PG_HOST` / `PG_PORT` / `PG_PASSWORD`。
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

- 单场景导入用 `--neo4j-database`，批量导入用 `sysdig-parser/main.py --input-dir input/sysdig --all`（按文件名排序、每场景 event_id 从 1 开始、fail-fast；完整命令见第 8 节）。event_id 仅在场景库内唯一，不要把多个场景导入同一个库；重复导入同一日志到同一库是幂等的（配合上文 MERGE 约定）。
- 导入前后输出顶点数、关系数、跳过数、异常数、未匹配数和耗时；大日志处理必须可观察。
- 导入结果的正确性对比：单场景严格对比用 `sysdig-parser/compare_pg_neo4j.py`（固定以第 1 个场景为基准库）；六场景全量详细对比用 `tools/compare_pg_neo4j_scenarios.py`。两者键空间一致（Process=`(pid, 可执行路径)`、File=路径、Network=四元组），但新工具修正了旧工具两个方法错误：① 旧工具按 `optype=='write'` 猜边方向，会把 PG `rename` 的 Process→File 半边错标成 File→Process（PG 的 process/file/network 三表共用一个 id 序列，实测六库跨表 id 交集为 0，方向应由端点类型唯一决定）；② 旧工具不做系统调用家族名归一，会把 PG 的 `recvmsg/sendmsg/writev/renameat` 误判成“PG 独有的边”。
- 对比分层判据（新工具）：`L1` 结构 `(src,dst,syscall)` / `L1x` 同 L1 但进程端点忽略 pid / `S1` = L1 去重集合 / `L2` 结构+starttime / `L2x`、`L3`（+endtime+bytes）、`L3x`。**带 x 的级别才是真实语义差异**，非 x 与 x 之差即进程身份口径的量化影响。
- 完整对比记录：`output/neo4j-pg-comparison-20260904.md`（单场景，历史）、`output/reimport-20260910/REPORT.md` + `compare/<场景>.md`（六场景，含 accept 修复复验）。
- **总口径(2026-09-10 六场景复核)**:Neo4j 是 PG 基准库的严格超集。PG 六库共 1,518,182 条边,按 `L2x`(结构+starttime、进程忽略 pid)只剩 **107** 条在 Neo4j 找不到(0.007%);Neo4j 另有 1,935,775 条 PG 没有的结构边。六库顶点总数 64,572、边 3,453,850。下列四条原因覆盖全部差异。**2026-09-15（G3/G4 重导后）复核**：同一工具重跑六场景，`L2x 仅PG` 变为 **156**（逐库 4/32/32/42/35/11）——其中 −1 条是场景 2 的 `f2p/execve` 真缺口被 G3 修好，+50 条是对比工具的口径假象：PG 基准库保留 sysdig 原始拼写（`…/fontconfig//x.cache-9`），而新图已按 G4 折叠为单斜杠，字符串相等判据失效（已反证：三库归一后残留内部 `//` 顶点数 = 0，对应单斜杠顶点存在）。给 PG 侧套同一个 `normalize_file_path` 后应为 **106**。
- 原因 1——进程身份口径（**预期，不要“修复”**）：PG 基准库以线程号建进程实体，本解析器以 `(pid, name)` 建顶点。实测六库：PG 独有 pid 合计 8,639 个、Neo4j 独有 pid 仅 15 个（PG 的 pid 空间基本包含 Neo4j）；这批“边键差异”在按可执行路径对齐（L1x/L2x）后全部消失。旧文档里的“PG 约 560 vs Neo4j 约 433”是场景 1 的四个不同口径（PG process 行 560 / 解析器注册顶点 433 / 实际入库 Process 顶点 235 / 归一到 `(pid,exepath)` 154），引用时必须说明口径。
- 原因 2——read/write 全量逐次记录（**预期，新图信息更全**）：旧导入器对“同一进程反复访问同一文件/套接字”只保留部分记录，本解析器每次系统调用建一条边；两边结构键集合几乎相同，差别在每个键的重复次数（场景 1 `f2p/read` 单键最大重复：PG 2,823 次 vs Neo4j 58,197 次）。Neo4j 多出的结构边里 1,907,999 条（98.6%）属此类，且这类的“仅 PG”为 0——旧图有的时刻新图全有。
- 原因 3——本解析器建模更多系统调用（**预期**）：旧导入器完全没有 clone(9,840)、connect(7,472)、unlink(4,902)、mkdir(2,840)、symlink(1,011)、rmdir(783)、chmod(568)、bind(243)；`rename` 多出 116 个结构键来自把 `renameat/renameat2` 归入 `rename`（场景 3 日志实测 `renameat` 31 对，正好等于多出的 31 个键，其余六场景同构）。
- 原因 4--套接字四元组不完整(**不是"PG 噪声",而是解析口径差异 + 一个待改进项**):剩下 107 条"仅 PG"边里 106 条是 sendmsg/recvmsg/sendto 事件,sysdig 的进入记录只给出**单端点/半绑定 fd 注记**(如 `fd=13(<4u>127.0.0.53:53)`、`fd=125(<4>0.0.0.0:0)`),无 `ip:port->ip:port`;本解析器对数据流族只读 fd 注记,不产出 NetworkEntity 就不建边(计入 `incomplete network` 审计),而旧导入器把缺失的一端填 0 建成全零/半零顶点并保留边。实测:六库 Network 顶点"仅 PG 且被事件引用"共 13 个,**全部是退化四元组(非退化 0 个)**;另 1 条是场景 2 的 `f2p/execve`，新图把 filename 记成 `./update_patch.sh(/tmp/update_patch.sh)` 而未归一为绝对路径（**已修复：2026-09-15 G3/G4，见下文**）。改进方向(**未完成**):数据流族在 fd 注记不含四元组时回退到同一记录的 `tuple=` 字段(`connect`/`accept` 已如此做,可复用 `_CONNECT_TUPLE_PATTERN`)。已按 starttime 回查日志逐条实测(106 条全部命中):全是单端点注记,其中 **94 条的同一记录 `tuple=` 带真实远端、可兜底恢复**(如 `fd=59(<4>0.0.0.0:0) size=2504 tuple=0.0.0.0:52744->220.181.184.97:443`),剩下 12 条无四元组可用(属采集限制,需要导出时补 `%tuple`/`%fd.name`);恢复后 PG→Neo4j 结构层复现率可达 99.9991%。证据见 `output/reimport-20260910/logs/residual-forms.log` 与 `check_residual_fd_forms.py`。注意 `0.0.0.0:0->0.0.0.0:0` 这类顶点在新图里是由 connect/bind 正常建立的,所以"顶点是否存在"不能当判据。
- 旧导入器合成的反向边不在对比范围内：PG 里 processevent 6,877 条 + networkevent 122 条 `is_synthetic_reverse=true`（f4ec524 已按设计从本解析器移除），`tools/compare_pg_neo4j_scenarios.py` 默认剔除并单独计数（`--keep-synthetic` 可关）。
- **更正一条过时结论**：旧记录称“PG 中 152 条 rename 边 File 路径为空串”。实测当前六库 `file.name` 为空的顶点数为 **0**，指向空路径的 rename 边也为 0；该条已不成立，不要再作为已知差异引用。
- **已修复（2026-09-10）accept 整类丢边**：修前 PG 有 122 条 `n2p/accept`（场景 3 为 110、场景 4 为 12），Neo4j 为 0。根因：`extract_size()` 把“`res=` 字段缺失”与“res<0”合并返回 -1，而 handler 用它判调用失败；本导出格式下 accept 的退出记录只给 `fd=N(<4t>ip:port->ip:port) tuple=...`、不带 `res=`（场景 3 实测 12,208 条 accept 退出记录带 `res=` 的为 0 条），于是整类被无差别丢弃。现由 `fields.extract_res()`（仅在字段缺失时返回 None）+ `record.record_res()/record_failed()` 区分二者，6 处“失败则不建边”判据改用 `record_failed()`；`_make_edge_action`（read/write 族，res 即 bytes）与 `_execve_action`（res=0 才算成功）仍用 `record_size()`。修后场景 3 `n2p` 8,322→8,432、场景 4 11,847→11,859，其余四类边一字不变；改前改后全量计数器 diff 仅 `edges.n2p` 一项（切片 A/B 已验证），场景 1/2/5/6 全量 dry-run 复验与入库值逐项一致，故基线不受影响。
- **已修复（2026-09-11）connect EINPROGRESS 整类丢边**：非阻塞 connect 的退出记录为 `res=-115(EINPROGRESS)`（连接已发起、四元组已由内核分配，语义上不是失败），但“失败则不建边”判据 `record_failed`（`res<0` 即失败）把它当失败丢弃，导致外传 socket 在图中只剩 sendto 一条边、出度 0（场景 2 的 `curl→192.168.122.128:4444` 即此类）。修法：新增 `record.record_in_progress()/record_connect_failed()`，仅 `connect` 家族改用后者（`record_failed` 本体与其余 6 处调用不动），并在 `entity_registry` 加 `connect_in_progress_count` 审计计数。实测六个场景 `EINPROGRESS` 只出现在 connect 退出记录中（45/306/95/248/732/305 条，无例外），`-101/-111/-2/-13` 仍是真失败不建边。场景 2 全量计数器 diff 仅 `edges.p2n 6467→6773` 与新增计数 `connect_in_progress=306`，其余逐项相同。
- **已重导(2026-09-11,connect 修复后)**:6 个库 DROP/CREATE 后重导,新增边 45/306/95/248/732/305 条全部是 `p2n/connect`(合计 +1,731,删除 0),新增 Network 顶点 3/152/1/85/468/158(合计 +867),Process/File 内容与其余边多重集完全一致(工具 `output/connect-fix-20260911/compare_content.py`,含改前内容快照 `pre/`)。场景 1 基线重跑(`output/baseline/tracesage-1_Multi_Stage_Data_Exfiltration-connectfix-20260911/`)与 `-postfix-20260909` **内容级完全一致**(剥 id 前缀后逐字段对比,工具 `compare_baseline.py`),GT 评分 21/24=87.5%、查准 21/75=28.0% 不变,故 2026-09-09 基线记录继续有效。
- **已修复（2026-09-15）G3/G4 顶点身份归一**：`filename=` 通道此前不剥内核 `原始名(/绝对路径)` 注记、且 File 键未做词法归一（`docs/graph-defects-20260913.md` 的 G3/G4）。修法：新增 `jsonl/fields.py` 的 `strip_path_annotation()`（判据与旧实现逐字一致：括号内以 `/` 开头才剥）与 `normalize_file_path()`（剥壳 + `posixpath.normpath`；`pipe:[…]`/`socket:[…]`/`unix:[…]`/空串不喂 normpath），并挂在 `pipeline/entity_registry.get_or_create_file()` 这个**唯一 chokepoint**（File 的 MERGE 键就是 `path`，所以键与实体属性一起归一）；`dispatch/handlers.py` 的 `_normalize_exit_path`/`_normalize_rename_path` 收敛为调用共用函数（三份近似实现曾导致“某条通道忘了归一”）。六库 DROP/CREATE 重导后核验：边多重集（按 关系类型×syscall 的条数/字节和/最早最晚时间）逐库 **0 差异**；File 顶点 40,381→40,318（−63，与预测逐库吻合：sc2 −1、sc3 −26、sc4 −23、sc5 −13、sc1/sc6 0）；括号注记 3→0、`/./` 1→0、内部 `//` 100→0、尾斜杠 1→0，**行首 `//` 1,085 个保持不变**（POSIX 保留行首双斜杠，snap-confine 顶点未被误并）。产物：`output/g34-fix/`（`check_impact.py`、`snapshot_db.py`、`db-snapshot-{pre,post}.json`、`reimport.log`、`cmp/`）；GT 已同步改写（场景 2/4/5 各 1 行括号路径）。
- **已修复（2026-09-15）家族变体整类未注册（裸 `chmod` / `symlinkat`）**：`handlers.py` 按手写事件名名单注册家族，而 `CANONICAL_SYSCALL_MAP` 已把 `chmod`、`symlinkat` 归到 `chmod`/`symlink`，注册表没跟上 → 这两类退出记录落入 `Unmatched fingerprint`，边整类丢失（实测场景 3/4/5/6 共 **5,138** 条 `p2f`）。修法：新增 `handlers._family(canonical...)` 从归一表反查家族全部事件名，`_CHMOD_FAMILY/_RENAME_FAMILY/_SPAWN_FAMILY/_EXIT_PATH_FAMILY` 全部改为派生（生命周期按 canonical 家族给基准字段、`unlinkat`/`mkdirat` 保留字段序覆盖）；同时给归一表补 `fchmodat2 -> chmod`（内核 6.5+/glibc 2.39 起 `fchmodat()` 走它，否则同一 bug 会在新主机重现）。实测（dry-run 逐场景计数器，场景 1→6）：新增边 0/0/1,396/2,512/1,224/6（=5,138，全部 `p2f`：chmod 209 + symlink 4,929）、File 顶点 +0/0/1,212/2,278/1,190/0（=4,680），`p2p/f2p/p2n/n2p` 与 Process/Network 顶点计数逐项不变；unmatched 跳过行相应减少 1,459/2,525/1,231/10；场景 1 逐项与修前完全一致（日志里无这两类记录）。GT 不受影响：GT 的 chmod/symlink 边本就由 `fchmod`/`fchmodat`/`symlink` 产出且已在图中（逐条查库确认）。**状态：已清库全量重导（2026-09-15）**——六个库 DROP/CREATE 后批量全量重导（`--input-dir input/sysdig --all`，event_id 各库从 1 开始、密编号），六库逐库 `batchErrors=0`、`skippedMissing=0`、无重复 `event_id`。逐库核对：sc1/sc2 内容与重导前**逐字节一致**（含 event_id；两者日志里无这两类记录，不受修复影响），sc3/4/5/6 与中间“增量追加”阶段的内容多重集**完全一致**、仅有 event_id 重新密编号；`p2f/chmod` 与 `p2f/symlink` 现为 2/2、11/1、582/2,065、144/2,564、20/1,289、18/19（= 日志侧独立期望值）。场景 1 调查基线重跑（`output/baseline/tracesage-1_Multi_Stage_Data_Exfiltration-variants-20260915/`）与 `-g34-20260914` **内容级完全一致**（b_raw 167v/1975e、b_cpr 167v/344e、entry candidates network=1/file=46/process=0、final 52v/94e），故 GT 与基线记录继续有效。产物：`output/reimport-20260915-variants/reimport.log`。

## 5. 性能与可维护性

- 对大文件使用流式 JSON 解析、有限大小缓冲和分批写入。
- 可在解析、建模、导入之间使用有界队列或分阶段批处理，但必须保留顺序/配对所需的上下文。
- 不要为了并行而破坏进入/退出配对、事件时间顺序或统计结果的确定性。
- 任何性能优化都应以可重复的计数、耗时和内存指标验证；先保证语义正确，再优化导入吞吐。

## 6. 修改边界

- 修改前先阅读相关模块和现有资料；不要覆盖用户已有的未提交改动。

## 7. 调查流程基线

- 基线定义：对 Neo4j 溯源库（sysdig-parser 导入，`NEO4J_DATABASE` 指定，默认 `neo4j`）按 `input/sysdig/1_Multi_Stage_Data_Exfiltration.query` 描述的流程执行一次完整调查（POI 反向因果遍历 → CPR 因果窗口合并 → projection 三特征加权与声誉传播 → 入口候选 `count(in(n))=0 ORDER BY n.rel DESC LIMIT 5` → 逐入口正向扩展 UNION → 与反向图 INTERSECT），产出的结果即为回归基线。数据源为 `traversal.neo4jserver.Neo4jServerTraversal`（Bolt 连接；连接参数取自环境变量或根 `.env`）。2026-09-06 之前基线跑在 PostgreSQL 库 `1_Multi_Stage_Data_Exfiltration` 上，旧产物保留在 `output/baseline/1_Multi_Stage_Data_Exfiltration/`。
- 运行方法:`bash progql-local/baseline/run-baseline.sh [dbName] [outDir] [POI 选项...]`(可选 POI 覆盖:`--poi-srcip/--poi-srcport/--poi-dstip/--poi-dstport/--poi-optype`,属性名沿用 PG 写法、由兼容层翻译,默认 = 场景 1 的 `nc write 192.168.122.129:49580→192.168.122.128:4444`;用 javac 编译引擎与 `baseline/BaselineRunner.java`,编译时排除引用已删除 ProGQL 解析器的 `main/Main.java`,以 `progql-local/baseline/stub/main/Main.java` 作为引擎所需静态成员的编译桩;Bolt 驱动 neo4j-java-driver 4.1.1 在类路径中必须排在嵌入式 neo4j-3.5.11 jar 之前,并补充 reactive-streams/netty）。

  **两个必踩的坑（2026-09-15 实测）**：① 第一个参数是**场景名**（如 `1_Multi_Stage_Data_Exfiltration`），引擎据此推导 `input/sysdig/<场景>.query` 与 `tracesage-<场景>` 库名；传库名会得到错误结果（场景 1 会静默跑在 `.env` 默认的 `neo4j` 库上、场景 2 直接 POI 找不到）。② 目标库由环境变量/根 `.env` 的 `NEO4J_DATABASE` 决定，跑非默认库必须先导出它（例：`NEO4J_DATABASE=tracesage-2-masquerade-data-exfiltration bash progql-local/baseline/run-baseline.sh 2_Masquerade_Data_Exfiltration <outDir> <POI 选项>`）；`tools/evaluate_gt.py` 同理只读 `.env`，要用 `output/connect-fix-20260911/run_evaluate_gt.py`（`GT_DB` 变量）跑指定库。Neo4j 图无数字顶点 id,`Neo4jNodeRegistry` 按(标签, MERGE 键)升序枚举分配确定性 id 1..N,同库内容跨机器可得相同产物。
- 入口排名权重是全项目约定：影响 **0.55** / 最早因果时间 **0.45**，固定在 `progql-local/baseline/progql-llm.properties`；基线脚本通过 `-Dprogql.llm.config` 传入，其他环境运行该流程时也应使用同一配置，避免排名结果漂移。
- 基线产物：`output/baseline/neo4j-1_Multi_Stage_Data_Exfiltration/baseline.json`（不含时间戳，可逐字节 diff）。字段分四类：`meta`（参数：POI 模式、entry_limit、排名权重、CPR 窗口、数据源连接串）、`poi`（POI 事件标识与时间）、阶段规模（`stages`、`entry_candidates`、`forward_per_entry`）、结果明细（`entry_ranking`、`entry_candidate_lists` 全部候选名单、`final_vertices`/`final_edges`、`b_score_edges` 含权重、`b_raw_edge_keys`、`forward_union_edge_keys`、`final_vertex_mix`/`final_event_distribution`）。注意 `output/` 被 `.gitignore` 忽略，基线产物不入库，跨机器或重装环境时需手动保留。
- 对比方法：任何可能影响调查流程的修改（引擎、解析器、权重/传播逻辑、图操作）之后重跑同一命令，与基线 JSON 做 diff；`stages`、`entry_ranking`、`entry_candidate_lists`、`final_edges`、`b_score_edges`、`b_raw_edge_keys`、`forward_union_edge_keys` 任一变化都必须归因（预期改进或回归）。
- 确定性：2026-09-06 先后以 0.7/0.3 与 0.55/0.45 两种权重各连跑多次，`baseline.json` 均逐字节一致（权重融合的 multiKMeans 在该数据上收敛同一划分）；若未来数据集触发 KMeans 不稳定，优先排查权重阶段的 NaN/Infinity。
- 独立运行对比记录（2026-09-06）：与另一环境引擎产物的对比（`output/baseline/1_Multi_Stage_Data_Exfiltration-1_Multi_Stage_Data_Exfiltration-20260906-124338`）确认——各阶段图规模、最终图顶点/边、事件分布、候选集合、声誉值完全一致；入口排序差异经反解验证源于该环境的排名权重为 0.55/0.45（残差 ≤1e-9），据此将 0.55/0.45 定为标准并重新生成基线。
- 引擎修复记录（2026-09-06）：`GQLBackwardPropagate.getFeatureWeight` 的 time 特征在事件边与 POI 边 endtime 相同时求值为 `1/0` → Infinity，经出边归一化变为 NaN 并导致 KMeans 空簇异常（`ConvergenceException`）。已在该分支增加非有限结果回落到引擎自带的 `getTimeWeight` 伪最小差处理（`pseudoMinDiff=1e-10`）。
- 三项修复后基线重跑记录（2026-09-09）：解析器三项修复（第 5 节）后重导六场景库，重跑基线到 `output/baseline/tracesage-1_Multi_Stage_Data_Exfiltration-postfix-20260909/baseline.json`，与旧基线（`tracesage-1_Multi_Stage_Data_Exfiltration/`）**内容级完全一致**：final 52v/94e、POI、entry ranking、全部候选名单、b_score 内容+权重、b_raw、forward_union 逐项相同；差异仅为数字 id 空间移位（25 个新顶点按（标签，MERGE 键）插入排序后顶点 id 整体后移，event_id 在队列插入点 204775 之后 +1，而全部调查产物引用的 event_id 均小于该点，不受影响）。GT 复核（`tools/evaluate_gt.py`）：召回 21/24=87.5%、查准 21/75=28.0% 与旧基线完全相同，3 条未召回为 GT known_gaps 已记录的单侧边——恢复的 5286 条环境边无一条进入最终调查图。注意：signature 字段自带数字 id 前缀，跨基线对比必须剥前缀后再比。
- Neo4j 数据源切换与对比记录（2026-09-06）：基线数据源由 PostgreSQL 切换为 sysdig-parser 导入的 Neo4j 溯源库。两次运行逐字节一致（确定性成立）。与旧 PG 基线的内容级对比（剥离 id 空间，映射到 实体内容+syscall+ns 时间戳，工具 `tools/compare_baseline_pg_neo4j.py`，详见 `output/neo4j-baseline-comparison-20260906.md`）：POI 事件两边同源（同 ns 时间戳与字节数）；b_raw 内容边 common 87（PG 160 / Neo4j 185）；主干攻击链（bash→.system_service.sh→nc→POI socket write、su/sudo 链）两边一致且时间戳相同。差异全部源于两代解析器对同一日志的不同建模，不是引擎语义变化：① 新解析器记录 clone（PG 无）与 p2n connect（PG 无）；② sudo/su 进程拓扑不同（PG 以 tid 建顶点且 sudo 的父是 su，新解析器以 pid+name 建顶点且 sudo 的父是 bash），连带 tty/ptmx/utmp 终端分支只在 Neo4j 进入反向窗口；③ 旧解析器 execve 配对的 endtime 到进程退出（个别边 endtime 相差数百 μs），使 PG 反向窗口扩进 wget 下载链而 Neo4j 收紧在前；④ PG rename 边 File 路径为空串（已知良性差异），新解析器有真实路径并新增 AT_FDCWD 顶点。entry top5 与 final 图随之不同（PG 25v/46e vs Neo4j 20v/45e），声誉值不可跨图比较。
- connect EINPROGRESS 修复后的基线复核（2026-09-11）：见第 4 节末两条。场景 1 基线内容级不变,新增的 45 条环境 connect 边(firefox 44、NetworkManager 1)未进入 b_raw/b_cpr/final 任一阶段;场景 2 基线已按 POI 参数化产出(`output/baseline/tracesage-2_Masquerade_Data_Exfiltration-connectfix-20260911/`,POI = `curl sendto 192.168.122.129:47160→192.168.122.128:4444`):b_raw 67v/446e → b_cpr 67v/98e → forward_union 88v/149e → final 23v/39e,用场景 2 GT(32 条,含修复后恢复的 `curl --connect-->...:4444` 与载荷 read 边)评分召回 23/32=71.9%、查准 23/34=67.6%;9 条未召回中 6 条集中在 P3 自我复制/时间规避支支(副本 `/tmp/.sys_kernel_check_v2` 与 sleep 无出边,正向不可达)与两条 `/etc/passwd --read-->`(passwd 无入边),均为已知"单侧边被 INTERSECT 切除"机制;多出 12 条为终端/配置读取/clone/孪生边等噪声类。
- G3/G4 归一后的基线复核（2026-09-15）：场景 1 基线（`output/baseline/tracesage-1_Multi_Stage_Data_Exfiltration-g34-20260914/`）与 09-11 基线**内容级完全一致**（工具 `output/connect-fix-20260911/compare_baseline.py`；b_raw 167v/1975e、final 52v/94e、GT 召回 29/32=90.6%、查准 29/75=38.7% 全不变，因场景 1 无 G3/G4 触发点）。场景 2 基线（`output/baseline/tracesage-2_Masquerade_Data_Exfiltration-g34-20260914/`）的差异全部可归因本次修复、无回归：b_raw/b_cpr 67→**66** 顶点（孤立括号顶点并入）、final 39→**40** 边、`final_event_distribution.execve` 7→**8**（原挂在孤立顶点上的 `/tmp/update_patch.sh --execve--> update_patch.sh` 进入最终图）、forward_union 149→150、入口候选 file 6→**5**（假入口 `./update_patch.sh(/tmp/update_patch.sh)` 并入后不再满足 `count(in(n))=0`）；GT 重评（32 条）召回 23/32→**24/32=75.0%**、查准 23/34→**24/35=68.6%**。其余变化为数值漂移（声誉值因顶点/边数小幅变动、`poi.sink_signature` 的 event_id 3785→3784 属 id 空间移位）。
- GT 补齐两处载荷/数据链缺口（2026-09-11，口径：与攻击者 IP 之间的全部网络事件边均收录（`connect`、请求 `write`、载流 `read`/`recvfrom`/`sendto`/`write`，每场景 6 条）；数据经管道传递时收录管道上下游两条边，并把管道生产/消费者的 execve 链补全）：
  - 场景 2（`groundtruth/2_Masquerade_Data_Exfiltration.groundtruth.json`，31→32 条）：补回 `192.168.122.129:54720->192.168.122.128:80 --read--> /usr/bin/wget`——它携带 886B 载荷本体（`recvfrom` 只有 186B 响应头），字节守恒链 `net--read-->wget`(886B) → `wget--write-->/tmp/update_patch.sh`(886B)；同时决定 P1 的 `wget--write-->net`（145B HTTP 请求）**保留不删**；重评召回 22/31→**23/32=71.9%**、查准 22/34→**23/34=67.6%**。
  - 场景 1（`groundtruth/1_Multi_Stage_Data_Exfiltration.groundtruth.json`，24→32 条）：同样补回载荷 `read` 边（236B），并补 `/usr/bin/tar--write-->pipe:[94889]`、`pipe:[94889]--read-->/usr/bin/gzip`、`/usr/bin/tar--execve-->/bin/sh`、`/bin/sh--execve-->/usr/bin/gzip`、`/usr/bin/cat--write-->pipe:[97589]`、`pipe:[97589]--read-->/usr/bin/nc`（tar|gzip 与 cat|nc 两条数据链，10240B/1168B），以及 `wget--write-->net`（148B HTTP 请求）；32 条在库逐条验证存在，重评召回 21/24→**29/32=90.6%**、查准 21/75→**29/75=38.7%**（补的 8 条全在引擎最终图内，3 条未召回仍为 INTERSECT 单侧边）。
  - 场景 1 另有 6 条痕迹清理边（`rm --execve-->` ×2、`unlink .system_service.sh/target_data.txt/.hidden_dir/stolen_data.tar.gz` ×4）**未收录**，与场景 2 GT 删除 P7 的口径保持一致。

## 8. 常用命令与工具

### 采集命令

```bash
sudo sysdig -w capture.scap

# 每个攻击场景单独采集并保存为 <场景名>.jsonl，例如：
sudo sysdig -r capture.scap -j -p '*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' > attack.jsonl
```

### 检查 / 导入 / 对比

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

# 3. 与 PostgreSQL 基准库严格对比（单场景，基准库固定为第 1 个场景）
python sysdig-parser/compare_pg_neo4j.py --pg-db 1_Multi_Stage_Data_Exfiltration

# 4. 六场景逐份详细对比（分层判据 L1/L1x/S1/L2/L2x/L3/L3x，单场景约 12–55 秒）
#    PG 库名 = 场景名，Neo4j 库名自动映射为 tracesage-<场景名小写>；输出 md+json
python tools/compare_pg_neo4j_scenarios.py --scenario 1 --out-dir output/cmp
python tools/compare_pg_neo4j_scenarios.py --scenario all --out-dir output/cmp
```

### tools/ 脚本

| 脚本 | 用途 |
|---|---|
| `check_sysdig_export.py` | 导出文件健全性检查：统计记录数与事件类型，识别被过滤的导出 |
| `dump_parser_counters.py` | 解析等价性验证：dry-run 导出全部可观测计数（stats/逐理由跳过/配对/fd 表），`--baseline` 逐项 diff，性能重构前后必须全部一致。注：其 `diff()` 按**键名**忽略 `file`，会连带跳过 `stats.vertices.file`（File 顶点数变化需另用 `output/g34-fix/snapshot_db.py` 类工具核对，2026-09-15 已踩过） |
| `dump_neo4j_content.py` | 图内容等价性验证：导出指定库全部顶点/边（含属性与端点身份）为规范化 JSON，`--baseline` 逐项 diff |
| `compare_pg_neo4j_scenarios.py` | 六场景逐份 PG vs Neo4j 详细对比：统一键空间、按端点类型定边方向、PG 侧系统调用家族名归一，输出 L1/L1x/S1/L2/L2x/L3/L3x 分层差异与差异样本（md+json）；默认剔除 PG 的合成反向边（`--keep-synthetic` 保留）。注：PG 侧 File 路径**未做 G4 同款词法归一**，图归一后会出现拼写类假差异（2026-09-15：L2x 仅PG 107→156，+50 条全为 `fontconfig//…` 拼写口径；需先对 PG 侧套 `normalize_file_path` 再比，则应为 106） |

## 9. 字段与数据模型详细设计

> 本节按 `TraceSage设计方案.md` 的「日志采集与字段」「数据模型（Neo4j）」样式，记录**当前代码实现**的真实口径（以 `sysdig-parser/parsers/` 为准）。
> 与设计方案文档的三处关键差异，引用时必须按本节：
> 1. 日志导出只有 **12 个 JSONL 键**；设计稿列出的 `fd.type` / `fd.name` / `fd.lip` / `fd.lport` / `fd.rip` / `fd.rport` / `evt.arg.filename` / `evt.res` **不是独立采集列**，全部从 `evt.args` 文本恢复（见 9.4）。
> 2. `:File` 顶点**不写 `type` 属性**（值域仅 `file`，与标签完全冗余，已移除）。
> 3. `Process` 增加 `args` 属性，`Network` 的端点属性名固定为 `lip` / `lport` / `rip` / `rport`。

### 9.1 采集命令（现行）

```bash
sudo sysdig -w capture.scap

# 单场景导出：格式串前缀的 * 必带（裸 * 才会让「缺任一字段的行」照常输出），
# 否则缺 %fd.l4proto 等字段的事件被静默丢弃；用 tools/check_sysdig_export.py 校验。
sudo sysdig -r capture.scap -j \
  -p '*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' \
  > attack.jsonl
```

### 9.2 导出字段（JSONL 原始键，共 12 项）

| JSONL 键 | 作用 | 是否一定存在 |
|---|---|---|
| `evt.num` | 事件编号 | 必填，非整数则整行无效跳过 |
| `evt.rawtime` | Unix epoch 起始的绝对纳秒时间 | 必填，非整数则整行无效跳过 |
| `evt.dir` | 事件方向：`>` 进入，`<` 退出 | 必填，非 `>`/`<` 则整行无效跳过 |
| `evt.type` | Sysdig 事件类型（系统调用名，边 `syscall` 的原始值） | 必填 |
| `evt.args` | 该事件全部参数拼接后的原始字符串（**字段恢复的唯一来源**） | 必填 |
| `evt.latency` | 进入→退出耗时（ns），进入/退出配对用 | 必填，非整数则整行无效跳过 |
| `proc.pid` | 进程/线程 ID（同时用作配对 tid） | 必填，JSON null 则按精确理由跳过 |
| `proc.name` | 可执行文件名（不含路径） | 必填，JSON null 则按精确理由跳过 |
| `proc.exepath` | 可执行文件完整路径 | 必填，值可为空或 `<NA>` |
| `proc.cwd` | 事件发生时进程的当前工作目录 | 必填，值可为空 |
| `proc.args` | 启动进程时传入的参数（命令行） | 可选；缺失/空 -> `Process.args` 不写 |
| `fd.l4proto` | socket 四层协议（`tcp`/`udp`/…） | 可选；缺失/空/`<NA>` -> `Network.protocol` 不写 |

- 前 10 项即 `jsonl/record.py` 的 `_REQUIRED_JSONL_KEYS`：缺任一键的整行无效、跳过并计数；后两项为可选映射（不加入必填集合，旧日志缺这两个键仍可解析）。
- JSON `null` 一律映射为空串，**绝不产生 `'None'` 字面量**；无进程上下文（`proc.pid`/`proc.name` 为 null，典型如内核调度 switch 事件）的行精确跳过。
- `proc.exeline`（`exepath + args`）**不采集、不存储**；`proc.args` 单独写入 `Process.args`。
- **多主机字段一律不存在**：没有 `host_id`、`container.id` 等列。

### 9.3 规范记录字段（`jsonl/record.py:parse_jsonl_entry` 输出）

| 规范键 | 来源 JSONL 键 | 说明 |
|---|---|---|
| `eventno` | `evt.num` | 字符串形式 |
| `cpu` | （无） | JSONL 导出无此列，固定占位 `"0"` |
| `_ns` | `evt.rawtime` | int 纳秒；时间戳派生值缓存 |
| `_latency_ns` | `evt.latency` | int 纳秒；配对派生值缓存 |
| `process` | `proc.name` | 进程名 |
| `pid` | `proc.pid` | 进程/线程 ID |
| `direction` | `evt.dir` | `>` / `<` |
| `event` | `evt.type` | **原始**事件名，未归一 |
| `cwd` | `proc.cwd` | 工作目录 |
| `latency` | `evt.latency` | 字符串形式（兼容旧接口） |
| `exepath` | `proc.exepath` | 可执行文件路径 |
| `args` | `evt.args` | 参数原文 |
| `proc_args` | `proc.args` | 可选字段 |
| `l4proto` | `fd.l4proto` | 可选字段 |
| `raw` | 原始行 | bytes；仅在写跳过样例日志时懒解码 |

- 此外还有按需写入的派生缓存键：`_size`（`args` 的 `res=` -> `extract_size`）、`_res`（-> `extract_res`，`None` 表示字段缺失）、`_fs`（`args` 的 fd token -> `extract_file_and_socket`）。记录 dict 每事件新建、不跨事件复用，缓存安全。

### 9.4 字段恢复关系（`evt.args` 文本 -> 图字段）

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

# --- 进入记录字段 ---
File.path            <- execve 的 filename=（按空格切 token；此处不做括号剥壳）
父进程               <- execve 的 ptid=(parent)
CLONE_THREAD 过滤    <- clone 的 flags=N(A|B|…)
```

- **路径身份归一**（G3/G4，2026-09-15 已修）只在 `pipeline/entity_registry.get_or_create_file()` 这一个 chokepoint 做：先剥内核 `原始名(/绝对路径)` 注记（`strip_path_annotation`），再 `posixpath.normpath`（`normalize_file_path`）；`pipe:[…]`/`socket:[…]`/`unix:[…]`/空串不喂 `normpath`，POSIX 行首 `//` 原样保留。
- **失败判据**：`record_failed()`（`res` 存在且 `res < 0`）用于 accept / fcntl / connect / bind / rename / 生命周期 / chmod 族的「失败则不建边」；数据流族（read/write/send/recv）用 `record_size()`（拿不到 `res` 就没有 `bytes`，不建边）；`execve` 仅在 `record_size(end_rec) == 0` 时算成功；非阻塞 `connect` 的 `EINPROGRESS(-115)` 经 `record_connect_failed()` 视为已发起、照常建边。

### 9.5 顶点（Node）

| Label | 去重键 / MERGE 键（唯一约束） | 属性（写入 Neo4j） | 说明 |
|---|---|---|---|
| `Process` | `process_id` = `proc.pid + proc.name`（**无分隔符拼接**） | `process_id`(str), `pid`(str), `name`(str), `exepath`(str, 可空), `args`(str, 可空), `cwd`(str, 可空) | 身份 = `(pid, name)`；`exepath`/`args`/`cwd` 是描述属性，**不参与身份**，同一个键「首个非空值 wins」 |
| `File` | `file_id` = 归一后的路径 | `file_id`(str), `path`(str) | **无 `type` 属性**（已移除）；管道建为合成 File 顶点，键形如 `pipe:[<ino>]` 或 `pipe:[anonymous@<sec>]` |
| `Network` | `network_id` = `lip:lport->rip:rport` | `network_id`(str), `lip`(str), `lport`(str), `rip`(str), `rport`(str), `protocol`(str, 可空) | 仅在四元组齐全时创建；`protocol` 取首个非空值，同四元组出现不同协议时保留首个并计数 |

- `process_id` / `file_id` / `network_id` 对应代码里的 `Process.pid_and_name` / `FileEntity.path` / `NetworkEntity.src_and_dst_ip`，不是旧实现的整型自增 `uniq_id`。
- 属性可空性是真实语义：`SET n.x = null` 在 Neo4j 中等价于「不设置/移除该属性」，因此图上不会出现空串占位属性。
- **只有参与过事件边的顶点才入库**（`pipeline/parser.py` 的 `_edge_vertex_keys` 过滤）：在实体抽取阶段创建、但从未出现在任何边上的孤立顶点会被丢弃，并在最终 flush 打印 `Edge-less vertices not written` 计数。
- 不构造 Unknown 顶点；无 File/Network 对象时只保留可识别的 Process 顶点或直接不建边（计入 `no object` / `incomplete network` 审计）。

### 9.6 关系（EventEdge）——五种事件边 = 五种关系名

| 关系名 | 方向（固定端点标签） | 系统调用（`evt.type`，原始名 -> 边 `syscall`） | 说明 |
|---|---|---|---|
| `p2p` | Process → Process | `execve`（父进程→子进程）；`clone` / `vfork` / `fork`（父→子） | `execve` 父进程取退出记录 `ptid=`；`clone` 家族跳过 `CLONE_THREAD`（与父共享顶点，建边即自环） |
| `p2f` | Process → File | `write` / `writev` / `pwrite` / `pwritev` / `pwritev2`；`rename` / `renameat` / `renameat2`（新路径侧）；`unlink` / `unlinkat`；`rmdir`；`mkdir` / `mkdirat`；`symlink` / `symlinkat`；`chmod` / `fchmod` / `fchmodat` / `fchmodat2` | write 族仅当 fd 实体为 File 时落此 |
| `f2p` | File → Process | `read` / `readv` / `pread` / `preadv` / `preadv2`；`rename` / `renameat` / `renameat2`（旧路径侧）；`execve`（可执行文件→子进程） | read 族仅当 fd 实体为 File 时落此 |
| `p2n` | Process → Network | `sendto` / `sendmsg` / `sendmmsg`；`write` / `writev` / `pwrite` / `pwritev` / `pwritev2`（fd 为 Network）；`connect`；`bind` | write 族仅当 fd 实体为 Network 时落此 |
| `n2p` | Network → Process | `recvfrom` / `recvmsg` / `recvmmsg`；`read` / `readv` / `pread` / `preadv` / `preadv2`（fd 为 Network）；`accept`；`fcntl` | read 族仅当 fd 实体为 Network 时落此 |

- 边的 `syscall` 属性写**家族基本名**（`CANONICAL_SYSCALL_MAP`）：`readv/pread/preadv/preadv2 -> read`、`writev/pwrite/pwritev/pwritev2 -> write`、`sendmsg/sendmmsg -> sendto`、`recvmsg/recvmmsg -> recvfrom`、`renameat/renameat2 -> rename`、`unlinkat -> unlink`、`mkdirat -> mkdir`、`symlinkat -> symlink`、`chmod` 族（`fchmod/fchmodat/fchmodat2 -> chmod`）、`fork/vfork -> clone`、`openat/openat2/creat -> open`。事件分发与进入/退出配对仍用原始 `evt.type`。**handler 注册表从本表反查派生**（`handlers._family()`）：家族变体只要进归一表就自动注册，不再手写事件名名单（手写名单曾导致裸 `chmod`、`symlinkat` 整族未注册、静默丢 5,138 条边）。（注：`open` 族虽在归一表中，但只延长 `p2p` 不建边，不会产生带这些名字的边。）
- 一个系统调用可产生多条边：`rename` -> 旧路径 `f2p` + 新路径 `p2f`；`execve` -> 父→子 `p2p` + 可执行文件→子进程 `f2p`。`accept` / `fcntl` 只产生单向 `n2p`。**不生成合成反向边**（只表示实际发生的单向事件，避免假外发与重复计数）。
- **只注册、不建边**：`openat` / `openat2` / `creat` 的指纹仍注册（不计入 unmatched），动作只延长 `p2p` 边活跃期；读意图 open 由 read 族覆盖、写意图由 write 族覆盖。
- `ftruncate` / `utimensat` / `chown` / `setxattr` 在当前采集中进入/退出 args 均为空，无路径可提取，**未注册**；未注册的 `evt.type` 落入 `Unmatched fingerprint` 跳过统计。
- 端点标签由关系名唯一决定，对比工具/查询不得按 `optype` 猜方向（见第 4 节）。

### 9.7 关系属性

| 属性 | 类型 | 来源 | 说明 |
|---|---|---|---|
| `event_id` | int | `next_event_id()` | 全局（单次导入内）自增，每生成一条边递增 1；**同一条记录对生成的多条边拥有各自独立的 event_id**；批量导入时每个场景库从 1 开始 |
| `starttime` | int (ns) | 进入记录 `_ns` | `>` 进入时间 |
| `endtime` | int (ns) | 退出记录 `_ns` | `<` 退出时间，即事件真正完成时间；`p2p` 的 `execve`/`clone` 边会被父进程后续被追踪事件延长到最终 flush |
| `syscall` | str | `canonical_syscall(evt.type)` | 家族基本名（见 9.6） |
| `bytes` | int | 退出记录 `res=` | 数据流族填充实际字节量（非负）；元数据类与关联边（`connect`/`bind`/`accept`/`fcntl`/`rename`/`chmod`/生命周期/进程创建/`execve`）填 `0` |

- 事件只保留 `bytes`，**不保留 `res`**：`res` 仅用于成败判断与字节量取值。
- 关系不存 `host`（单主机），不做多主机字段。

### 9.8 Schema 与写入不变式

- **唯一约束**：顶点 3 个 —— `Process.process_id`、`File.file_id`、`Network.network_id`；关系属性 5 个 —— `event_id_p2p` / `event_id_p2f` / `event_id_f2p` / `event_id_p2n` / `event_id_n2p`（**按关系类型分别命名**；同名约束会让后续 `IF NOT EXISTS` 静默 no-op，曾导致只有 p2p 真正生效）。建库时会先 `DROP CONSTRAINT event_id IF EXISTS` 清理遗留旧约束。
- **写入顺序**：先 MERGE 顶点（分批），再写边（按 5 个方向各一批）；边通过端点 MERGE 键 MATCH 端点，缺任一端点则跳过并计入 `skippedMissing`（可审计，不静默丢边）。
- **幂等**：顶点 MERGE 在 id 键上；边用 `MERGE (a)-[r:rel {event_id}]->(b)`（即端点 + 关系类型 + `event_id`），配合上述约束，重复导入同一日志不产生重复数据。
- **批量与 flush**：Neo4j 批量事务批大小 `PROGQL_NEO4J_BATCH_SIZE`（默认 5000）；解析侧边的 flush 阈值 `PROGQL_SYSDIG_FLUSH_EDGE_LIMIT`（默认 50000，只统计 p2f/f2p/p2n/n2p）；`p2p` 只在导入结束的最终 flush 写入。
- **导入可观察计数**（`parser.py` / `reporting.py`）：处理行数、逐理由跳过数、进入/退出配对各档、五类边计数、三类顶点数、`incomplete network`、`no object`、`connect EINPROGRESS`、`network protocol conflicts`、管道 fd 表统计、`Edge-less vertices not written`。

### 9.9 当前未建模的边界（已知，勿误当 bug）

- **非 IP 传输端点（G1，未修）**：unix socket（`fd=<u>ffff…->ffff… /path`）、netlink（`fd=<n>`）、无名 pty slave（`fd=1(<u>)`）不建顶点也不建边，计入 `incomplete network` / `no object`。
- **`sendfile` 零拷贝（G2，未修）**：双 fd 系统调用，未注册 handler，不产生任何边（场景 4 nginx 的读边因此为 0）。
- **失败的生命周期调用（G5，未修）**：`mkdir` 等返回 `res<0` 时既无顶点也无边（场景 6 的 `mkdir -p` 逐级 `EEXIST` 导致持久化根目录连顶点都不存在）；`docs/graph-defects-20260913.md` 建议「失败也建顶点、不建边」。
- **数据流族四元组不全（未修）**：fd 注记只给单端点/半绑定（如 `fd=13(<4u>127.0.0.53:53)`）时不产出 Network 顶点、不建边；改进方向是回退到同一记录的 `tuple=` 字段。
- 以上缺口的完整证据、影响面与验收判据见 `docs/graph-defects-20260913.md`；PG↔Neo4j 残差口径见第 4 节。
