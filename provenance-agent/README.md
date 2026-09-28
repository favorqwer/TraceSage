# provenance-agent — 基于溯源图的反向追踪 agent

在 `sysdig-parser` 导入的 Neo4j 溯源图上，从 POI 出发**反向追踪**攻击因果链，产出可被
`tools/eval_agent_attack_path.py` 评分的溯源报告。

## 1. 已锁定的设计决策

| 决策 | 取值 | 含义 |
|---|---|---|
| D1 任务定义 | **A 反向追踪** | 只从 POI 往回找入口；不含 POI 之后的活动与平行分支 |
| D2 表示层 | **B 进程身份** | 一条边归一个进程（写文件/网络归源进程，被读写归目标进程，派生归子进程）；进程身份摘要只用于渲染与分组 |
| D3 创新点 | **候选 1 + 候选 2** | ①进程级表示与机械枚举（折叠 + 五条结构式规则）；②调查状态显式化 + **硬约束读回** |
| D4 知识库 | **暂不做** | 无 CTI / MITRE RAG；战术链由**规则**从图上事实推导 |
| D5 POI | **配置文件指定** | `config/scenarios.json` 是 POI 唯一来源；`.query` 文件不进 agent 上下文 |
| D6 数据外发 | 允许 | 走 `.env` 的 `OPENAI_BASE_URL` / `OPENAI_MODEL` |
| D7 改图 | **不允许** | 不修 G1/G2/G5；agent 侧只能记录缺口 |
| D8–D10 | 默认 | macro F1 主指标、全自动批量 + 可选交互、单主机 |

## 2. 架构：三层（原四层；第 2、3 层已合并为一个判定层）

各层各占 `pagent/layers/` 下的一个包（包内按用途分文件），只允许下游读上游；编排在
`pagent/orchestration/`，装配与流程顺序在 `pagent/app.py`，横切基础设施在 `pagent/core/`，
提示词与规则表分别是 `pagent/prompts/`、`pagent/rules/` 下的数据文件。
模型调用只出现在判定层；展开、折叠、上下文渲染与报告全部是纯代码。

```
起点定位（第 1 层）
  │
  ├─ 反向闭包（第 1 层：闭包 + 折叠，纯代码）
  │    从终点事件出发，按三条因果规则往回走（规则与门限见下）
  │    门限只减不增：每个顶点只完整展开一次，门限变高时补取新增区间
  │    → 规则判定（取边时，五条命中就不收边）→ 折叠（内容三元组）= 候选表
  │
  ├─ 判定驱动（判定层：分波与上下文、逐波判定）
  │    按「离终点几跳」分波 → 波内按批大小切批 → 同一波共用冻结上下文并发投递
  │    逐波更新双层滚动上下文（纯代码）→ 按阈值定结论
  │    → 一批失败整批重试（编排器）
  │
  └─ 报告（表达层，纯代码）：时间线 / 规则推导相位 / 入口点 / 缺口
```

| 层 | 作用 | 代码 |
|---|---|---|
| 1 结构可达与折叠 | 从终点事件往回走算出**反向闭包**，再折叠成内容三元组（= 候选表 = 召回上限） | `pagent/layers/l1_reach/` |
| 2 判定（原第 2、3 层合并） | 分波、双层滚动上下文、按批大小切批、提示词渲染、逐波判定（后两项调模型）、按阈值定结论 | `pagent/layers/l2_judge/` |
| 3 表达 | 报告装配与证据编号回填（纯代码） | `pagent/layers/l3_express/` |
| 编排 | 起点定位 → 展开与折叠 → 判定驱动（波 → 判定层，含整批重试）→ 登记 | `pagent/orchestration/` |
| 装配 | 依赖容器与流程顺序 | `pagent/app.py` |
| 横切 | 配置 / 场景 / 图访问 / 模型 / 记录 / 提示词加载 / 规则加载 / 轨迹 | `pagent/core/` |

> 包名数字与上表层号一致（`l2_judge` 是合并后的判定层，数字沿用原第 2 层）。

| 环节 | 职责 | 实现 |
|---|---|---|
| `orchestration.intake` | 回库核对 POI、算实例数与时间范围、定位起点 | 纯代码（第 1 层） |
| `orchestration.expand` | 逐轮展开前沿候选，直到耗尽；再折叠成候选表并准备进程身份摘要 | 纯代码（第 1 层 + 判定层的上下文准备） |
| `l1_reach.run_closure` + `l1_reach.fold` | 事件级时间门限闭包（五条规则均在取边时判定）+ 折叠（纯合并） | 纯代码（第 1 层） |
| `l2_judge`（波次 / 状态 / 渲染 / 逐波判定 / 定结论） | 分波与双层上下文、按批大小切批、渲染提示词、逐波判定、按阈值定结论 | 纯代码 + LLM（判定层） |
| `orchestration.register` / `record` | 把结论登记进内存记录表（实体 + supports/refutes） | 纯代码（编排） |
| `l3_express.build_report` | 确定性报告，已确认边**默认全选** | 纯代码（表达层） |

**为什么把"取证员"删了**（实测）：旧版每轮派一个带工具的模型去展开进程，但它只是照抄控制器给它的
进程标识；实测场景 1 的 15 轮里 14 轮模型自报"取不到数据"（工具结果被上下文清理清空 + 撞工具调用上限），
而**100% 的候选边其实是工具函数自己收走的**。它占 42% 的调用、61% 的提示词字符、50% 的墙钟，还漏展开 19% 的指令目标。

**为什么"判定去波化"**：旧版"展开一点→判一点"把 82 个批切成 13 波，每波时长等于最慢那一批
（20~46s），而判定调用累计 547.6s ÷ 并发 12 = 45.6s 才是理想值。现在展开完再一次并行判定。

### 第 1 层（`pagent/layers/l1_reach/`）

- **表示层没有“步骤 / 进程实例”这一层**：每条边带归属进程的标识，进程身份摘要（程序、命令行、工作目录、
  来源、活动时间范围）只用于判定时的上下文渲染与分组，**不参与可达性计算**（上下文由判定层准备，见下）。
- 归属规则：进程写文件/网络归源进程，文件/网络被进程读写归目标进程，进程派生归子进程。
- **折叠**（本层尾部，紧接闭包）：按 `(src 内容, syscall, dst 内容)` 归并，记录实例数/累计字节/首末时间/
  全部 event_id/来源成员。折叠是**有损**的：实例间的相对时序、各自的时间与字节量会丢；同一三元组只有
  一个判定结论。折叠不删任何边，它的输出就是候选表。

### 反向闭包（第 1 层，默认引擎 `closure`）

**事件**＝图上一条边（两个端点、操作名、字节数、起始与结束时刻）。事件甲可能影响事件乙，当且仅当：

1. **同进程**：两者都以同一进程为端点，甲的起始时刻不晚于乙的起始时刻；
2. **同顶点交付**：甲写入同一文件/网络顶点、乙从该顶点读取，且甲的起始时刻不晚于乙的结束时刻
   （**且只对能承载内容的通道生效**：见下面“机制”里那条共享/虚拟通道）；
3. **派生**：甲是派生事件（父→子），乙是该子进程在甲之后的事件；**子进程要不要算上游，按下面那条
   子进程口径定**（主干里无条件收，第二层起要"和主干有过一次写-读配对"）。

**反向闭包**＝能沿上面三条走回终点事件的**全部事件**（即这套规则下的最小集合）。推进方式：
到达一个顶点时带一个**门限**（时刻）——进程顶点取"起始不晚于门限"的全部入射事件，文件/网络顶点
只取**写入侧**。同一顶点门限变高时只补取新增区间 ⇒ 每个顶点只被完整展开一次、少量顶点补取一次
（实测占展开总数 0~7.5%）⇒ **取回行数与闭包大小同阶**（实测：扫到的记录数是闭包的 1.2~1.3 倍；
其中已经收进闭包的边在来源侧直接跳过、不再重造内部表示，所以真正进判定的行数约等于闭包大小）。

展开跑**两遍**（第一遍只定主干名单、不带子进程，第二遍带把关；口径见 `l1_reach/siblings.py`）：
两遍都读同一个本地索引，中间没有东西会改它，所以两遍看到的是同一份数据。第一遍的大小等于主干
的大小，主干远小于结果时两遍合起来反而更快——六场景整层墙钟（含取数、折叠、进程身份摘要）：
场景 3 从 1.93 秒降到 0.68 秒、场景 4 从 1.5 秒降到 0.13 秒；主干接近最终结果的场景 5 从 2.24 秒
升到 2.37 秒（多一成）；峰值内存场景 3 从 317 兆降到 155 兆、场景 5 从 385 兆降到 372 兆。

**机制（写死，不是开关）**：文件/网络顶点只回溯**写入侧**（读不会把内容送回顶点）；**共享/虚拟通道
只收边、不展开**——终端以外的设备节点、内核现生成的伪文件（`/proc`、`/sys`）、系统运行目录及其中的
套接字（表在 `pagent/rules/shared_channels.json`），从它们读的那条边照收，但不往回找写入者
（口径与实测：六场景候选减 42%、事件减 68%、标注覆盖仍为 100%）；**子进程口径**：同一主体在门限之前
派生出去的其它子进程也算上游（有意识的超集口径），但主干里无条件收、第二层起要"和主干有过一次
写-读配对"（读的东西主干写过，或写的东西主干读过；共享/虚拟通道与连接建立不算）——
口径与实测见 `l1_reach/siblings.py` 与 CHANGELOG（六场景候选减 69.5%、事件减 38.5%、进程减 64.4%、
标注覆盖仍为 100%）；五条结构式规则（结构性伪边与系统例行文件、内核按进程现生成的伪文件、写进共享通道）在**取边时**就判定，命中的边根本不进闭包（同一份判定，`core/edge_rules.py`）；读取事件给写入者的
门限取读取的**结束**时刻（允许边写边读）；进程状态不设时间窗、上界取**终点事件时刻**（终点事件之后的
自身活动不算）；**不设任何条数上限**，终止条件只有"待考察清单耗尽"。

本层没有开关：语义口径全部写死，**取数方式也只有一种**——读本地顶点-时间索引快照（按顶点分块、
块内按时间排序，取数就是读本地文件），缺失或损坏或过期就重建。换成读索引的理由：直查数据库
按行计价，实测每行约 27~39 微秒，大闭包场景要取回几十万到上百万行；同一个闭包读索引只花几秒。
代价是每个库**第一次**跑会先建索引（一次性 7~37 秒、19~93 兆字节，放在
`tmp/provenance-agent/l1-index/<库名>/`），之后只要库的边总数、最大事件编号与规则表内容都没变
就直接复用；索引建不出来（磁盘、权限）就报错停下，不做隐式降级。直查数据库那条路只在单测里
作为参考实现保留（`DbSource`），不参与正式流程。

索引的定长记录里除了端点与时刻，还存着**这条边的结构性伪边判定结果**（由源内容、操作名、
目标内容、源标签唯一决定）：建索引时按当时的规则表算一次，遍历时只看这一个整数、不再重算。
顶点表里同样存着**文件顶点是不是共享/虚拟通道**（值是该通道的类别名）：遍历时只看这个字段，
不再重算路径前缀。正因为如此，**规则表内容在被复用的判据里**（`meta.json` 存规则文件校核值）——
规则改了就重建，不会拿旧规则算出来的标记当判定。

指标表见 `tests/l1_ablation.py`（`--all` 跑六场景，看候选边/命中标注/事件数/进程数/顶点数是否与
改前逐项相同；`--report` 打印汇总表）；单测见 `tests/unit/test_closure.py`、
`tests/unit/test_snapshot.py`、`tests/unit/test_shared_channels.py` 与 `tests/unit/test_sibling_gate.py`。

### 判定层与判定驱动（`l2_judge/` / `orchestration/judging.py`）

1. **候选表就是交给模型的清单**：五条结构式规则在**第 1 层遍历期取边时一处判定**（同一个规则模块
   `core/edge_rules.py`），后果只有一档：**命中就不收这条边**（两端也不会被推进待考察清单），逐类计数进
   报告里的 `stats.expand.dropped`；**终点事件不受规则约束**，永远交给模型判定。展开结束的日志会打一行
   「规则残留 N 条（终点事件除外，应为 0）」。
   - 规则表：动态库读取与自我执行（`pseudo_edges.json`）、系统例行文件读（`prefilter.json`）、
     内核按进程现生成的伪文件与写进共享 / 虚拟通道（`candidate_drops.json` + `shared_channels.json`）。
     这些表逐条核对过六个场景的 GT（零命中）；`/etc/passwd`、`/dev/urandom`、`/proc/cpuinfo`
     等**故意不列入**；**读取**共享通道的边也不剔（它是链条上进程的输入，例如 `dd` 读 `/dev/urandom`）。
   - 实测（六场景）：这两类结构式规则在取边时剔掉 14,857 条边实例，闭包收进 316,040 条边
     （旧口径 330,897 条），候选表 2,771 条、人工标注 356/356 —— 候选表与进程数与旧口径逐条相同。
2. **波次、状态与渲染**（判定层，纯代码）：先把闭包产出的事件行整理成每个进程的身份摘要（命令行、工作目录、
   来源、活动区间）与按对象的时间索引；再按「离终点最少几跳」把候选边分波（一跳一波），波内按 70 条
   （`PAGENT_JUDGE_BATCH`）切批。**同一波的所有批共用同一份冻结的双层滚动上下文、并发投递**，
   整波判完才更新状态：
   - 第 1 层「上游交接明细」：这条边的上层顶点（第 1 层折叠时留下的 `via_kind` / `via_key`）上
     **已经判过**的边及其结论，每条边最多 `PAGENT_UPSTREAM_LIMIT` 条（默认 3）；
   - 第 2 层「调查状态摘要」：已确认链片段、本波工作面、相关顶点状态、计数，逐波由纯代码更新，
     上限 `PAGENT_STATE_MAX_CHARS`（默认 2500）。
   每次调用的文本顺序：**任务说明**（目标事件、时间原点、调查方向、清单口径；只含任务定义，
   不含标准答案、`.query` 与场景特化判据）→ **调查状态摘要** → **进程身份表** → **本次要判的边**
   （每条一行，下面挂上游明细与「同一对象上的接触者」；接触者已判过的带结论）。
   单次文本超过 `PAGENT_CALL_MAX_CHARS`（默认 80000）时逐级压局部上下文（先接触者、后上游明细），
   **一条边都不少**。
3. **定结论**（判定层，纯代码）：整次调查的边统一编号（`E001` 形式、跨波全局唯一），**要求原样回抄**；
   判为相关且置信度达到阈值（`--min-confidence`，默认 0.5）→ 确认；否则排除；
   漏抄/抄错的边不会被当成"无关"，直接记 `unjudged` + 缺口。**没有第二轮复核**。
4. **失败处理**（编排器 `orchestration/judging.py`）：一批调用失败（网关 504/超时）→ **该批重试**
   （`PAGENT_WAVE_ATTEMPTS`，默认 2 次）；仍失败则该批全部边记缺失（未判定）。

## 3. 运行

```bash
# 干跑测试：假判定模型驱动整条流水线，不调真实 LLM（改代码后先跑）
python provenance-agent/tests/dry_run.py
python provenance-agent/tests/dry_run.py 2_Masquerade_Data_Exfiltration
DRY_JUDGE_DROP_ID=keep python provenance-agent/tests/dry_run.py   # 默认故意漏一条 id（测未判定）；=keep 时不漏

# 每层单测：不需要数据库、不需要模型
python -m unittest discover -s provenance-agent/tests/unit -t provenance-agent

# 只跑确定性层（POI → 反向闭包），不调 LLM；报告写 tmp/
python provenance-agent/main.py --scenario 1_Multi_Stage_Data_Exfiltration --dry-run

# 第 1 层指标表（六个场景；不调模型；结果写 tmp/provenance-agent/l1-ablation/）
python provenance-agent/tests/l1_ablation.py --all
python provenance-agent/tests/l1_ablation.py --report

# 第 2 层重复运行与汇总（当前方案；每场景重复 N 轮；自动评分与归因分解；结果写 tmp/provenance-agent/l2-runs/）
python provenance-agent/tests/l2_repeat.py --repeats 2
python provenance-agent/tests/l2_repeat.py --scenarios 4_Site_Defacement 5_User_Timer_Resource_Hijack 6_SQLite_Pipeline_Pollution --repeats 2
python provenance-agent/tests/l2_repeat.py --report      # 只按已有结果重算汇总，不跑模型

# 顶点-时间索引快照（第 1 层唯一的取数方式；缺失或过期会自动重建，这个命令用于手工预建）
python -m pagent.layers.l1_reach.snapshot --database tracesage-3-ssh-spray

# 单场景 / 批量
python provenance-agent/main.py --scenario 6_SQLite_Pipeline_Pollution
python provenance-agent/main.py --all

# 评分（与引擎同口径）
python tools/eval_agent_attack_path.py --report output/agent/1_Multi_Stage_Data_Exfiltration.json \
    --gt groundtruth/1_Multi_Stage_Data_Exfiltration.groundtruth.json
```

| 旋钮 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| 判定批大小 | `PAGENT_JUDGE_BATCH` | 70 | 波内投递的每批条数上限 |
| 判定并发 | `PAGENT_MAX_CONCURRENCY` | 12 | 同一波的批的并发上限（网关实测限流是 20） |
| 模型调用上限 | `PAGENT_MAX_LLM_CALLS` | 150 | 超限的批显式记 `unjudged` |
| 阈值 | `--min-confidence` | 0.5 | 判定为相关的最低置信度 |
| 边上下文 | `PAGENT_EDGE_CONTEXT` | 1 | 置 0 时不给每条边附「同一对象上的接触者」；只用于对照实验 |
| 同对象接触者 | `PAGENT_OBJECT_HANDOFF` | 1 | 置 0 时只关「同一对象上的接触者」一项（其余局部上下文不变） |
| 命令表 | `PAGENT_COMMAND_TABLE` | 0 | 置 1 时图顶点没记命令行就沿派生链往上补，并写明来源 |
| 派生链层数 | `PAGENT_COMMAND_INHERIT_DEPTH` | 5 | 命令表往上找的最大层数（超过就记“派生链断”，不猜） |
| 任务说明 | `PAGENT_TASK_HEADER` | 1 | 置 0 时不向模型给“本次调查的任务”（目标事件 / 时间原点 / 清单口径）；**只用于同一份代码的对照实验**，正常跑保持开启 |
| 波内重试 | `PAGENT_WAVE_ATTEMPTS` | 2 | 一批调用失败时整批重试次数 |
| 上游明细条数 | `PAGENT_UPSTREAM_LIMIT` | 3 | 每条边最多列几条「上层顶点上已判过的边」 |
| 状态摘要上限 | `PAGENT_STATE_MAX_CHARS` | 2500 | 第 2 层调查状态摘要的字符上限 |
| 链片段条数 | `PAGENT_STATE_CHAIN_LIMIT` | 20 | 状态摘要里「已确认链片段」最多列几条 |
| 单次文本上限 | `PAGENT_CALL_MAX_CHARS` | 80000 | 超过就逐级压局部上下文（先接触者、后上游明细），不丢边 |

**展开侧没有任何旋钮**：上游候选、子进程、管道组成员、待处理清单、单进程边数、查询返回行数全部不设上限。
任何条数上限都是按数据分布随机丢边——上限只要小于真实链长就会掉召回，而真实链长事先不知道。
实测：子进程上限 8 让场景 4 的标注覆盖从 100% 掉到 74.6%、场景 5 从 100% 掉到 94.1%；
取消上限后两者都回到 100%。展开的终止条件只有一个：待考察清单（前沿）耗尽。

## 4. 产物

| 路径 | 内容 |
|---|---|
| `output/agent/<场景>.json` | 溯源报告（见下） |
| `tmp/provenance-agent/dry-run/<场景>.json` | `--dry-run` 的报告（诊断产物，**不写 output/**） |
| `tmp/provenance-agent/logs/queries-<run_id>.jsonl` | 每次查询的 Cypher/参数/行数/耗时/是否截断 |
| `tmp/provenance-agent/logs/verdicts-<run_id>.jsonl` | **逐条判定明细**（排查"这条真边为什么被排"的唯一依据） |
| `tmp/provenance-agent/logs/llm-<run_id>.jsonl` | 每次模型调用的提示词字符 / 原始输出字符 / 输出 token / 耗时 + 文本样本 |
| `tmp/provenance-agent/logs/trace-<run_id>.jsonl` | 阶段轨迹（intake / 每轮展开 / 每批判定 / 报告） |
| `tmp/provenance-agent/state/record-<run_id>.json` | 调查记录（实体 / 假设 / 缺口 + 四类边） |
| `tmp/provenance-agent/l1-ablation/<场景>.json` | 第 1 层指标表结果（`--report` 汇总成同目录的 `SUMMARY.md` / `SUMMARY.json`） |
| `tmp/provenance-agent/l2-runs/` | 第 2 层重复运行结果（`runs/` 逐轮报告、`eval/` 逐轮评分、`metrics.json` 与 `SUMMARY.md` 汇总，见 §3 的 l2_repeat 命令） |
| `tmp/provenance-agent/l1-index/<库名>/` | 顶点-时间索引快照（可重建的派生数据，不是测量结果；第 1 层唯一的取数方式，缺失或过期自动重建） |

> `tmp/` 是临时区：**只保留最近一次测量的结果文件**，历史运行记录（日志、旧的测量结果、调查记录）
> 确认不再需要后直接删除；需要长期保留的结论写进 `CHANGELOG.md`。删除 `state/` / `logs/` / `dry-run/`
> 不会影响运行，下次跑会自动重建。

报告 schema：

```json
{"scenario": "...", "run_id": "...", "poi": {"kind": "...", "rel": "...", "syscall": "...", "key": "..."},
 "edges": [{"src": "...", "syscall": "...", "dst": "...", "confidence": "high|medium|low",
            "confidence_value": 0.85,
            "event_id": 123, "instances": 4, "bytes": 1024, "reason": "...",
            "process_id": "..."},
           {"src": "...", "syscall": "...", "dst": "...", "confidence": "low|medium|high",
            "confidence_value": 0.6,
            "event_id": 456, "instances": 1, "bytes": 0, "reason": "...", "process_id": "..."}],
 "narrative": "（确定性时间线，非 LLM 生成）", "tactics": ["Execution", "Exfiltration"], "entry_point": "...",
 "gaps": [{"label": "...", "next_action": "...", "status": "open"}],
 "hypotheses": [{"key": "POI", "label": "...", "status": "confirmed"}],
 "reflection": {"sufficient": false, "confidence": 0.6, "missing_phases": [...], "derived_by": "rules"},
 "selection_note": "确定性报告：确认边 30 条全部保留（相关且达到判定阈值的边）",
 "generated_by": "deterministic_reporter",
 "stop_reason": "frontier_exhausted|candidates_failed|dry_run",
 "event_id_resolved": 30, "event_id_unresolved": 0,
 "stats": {"expand": {"rounds": 0, "fold": {...}, "dropped": {"r1": 0}, "gate_blocked": 0},
           "judge": {"waves": 0, "calls": 0, "wave_details": []},
           "llm": {...}, "queries": 0, "query_rows": 0, "wall_seconds": 0,
           "confirmed_triples": 0, "excluded_triples": 0, "unjudged_triples": 0,
           "state": {...}}}
```

`edges` 装**确认边**：判为相关且置信度达到阈值；判定只有一轮，没有第二批复核。
每条边同时给置信度档位（`confidence`）与数值（`confidence_value`）：以前只有档位，低分的边与高分的边
在报告里长得一模一样。

`stats.unjudged_triples` 是“模型没给出可解析结论、或被调用上限熔断”的候选边数；**未判定 ≠ 排除**。

## 5. 不变式（改动时不得破坏）

1. **只读**：`db.ReadOnlyGraph` 是唯一访问点；`execute_read` + 写关键字黑名单（先剔字符串字面量再匹配）+ 禁多语句。
2. **不截断、不静默**：展开侧不设任何条数上限（上游候选、子进程、管道组成员、待处理清单、
   单进程边数、查询返回行数）；**判定未完成**必须显式记进 `unjudged`。
3. **POI 只来自配置**：`.query` 文件不得进入提示或工具输出。
4. **端点内容只从工具输出复制**：报告边的 `src`/`dst` 来自图上内容，不允许模型凭记忆写。
5. **假设必须收尾、缺口必须带后继动作**：`record.close_unclosed()` 与 `record.add_gap()` 强制。
6. **未判定 ≠ 排除**：漏 id / 调用失败 / 预算熔断的边进 `unjudged`，既不静默丢也不当成无关。
7. **报告默认全选已确认边**：不做模型挑选；相关且达到阈值的边全部计入（判定只有一轮）。
8. **只有判定调 LLM**：干跑测试断言"除判定外没有任何模型调用"。

## 6. 已知问题（未修，按优先级）

| # | 问题 | 影响 |
|---|---|---|
| 1 | 无「往前看」查询（D1=A 的直接后果） | 结构性拿不到 POI 之后 / 平行分支的边 |
| 2 | 未做知识库（D4） | 相位靠关键词规则推导，覆盖有限；`Initial Access` 基本恒缺（攻击机进程不在图里） |
| 3 | ~~兄弟/子进程仍受 top-K 限制~~（已修：取消全部条数上限） | — |
| 4 | 批内“上下文光环” | 同一批里既有明显恶意边、又有同一脚本的模糊边时，模糊边更容易被判相关；逐波方案把取舍点整体移向召回（场景 4/5 召回 100%、查准下降；场景 6 多报 121 条），见 `CHANGELOG.md` |
| 5 | ~~一次性判定丢掉了跨波上下文~~（已修：逐波 + 双层滚动上下文） | — |
| 6 | 判定稳定性 | 没有第二轮复核；模型仍非确定性（同一配置不同次运行的结论有波动），用 `tests/l2_repeat.py` 多轮重复度量 |
| 7 | 长命 shell 进程的边很多（如 `gnome-terminal` 上千条边） | 展开与判定成本高且多为噪声；无确定性预筛 |
