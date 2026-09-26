# provenance-agent — 基于溯源图的反向追踪 agent

在 `sysdig-parser` 导入的 Neo4j 溯源图上，从 POI 出发**反向追踪**攻击因果链，产出可被
`tools/eval_agent_attack_path.py` 评分的溯源报告。

## 1. 已锁定的设计决策

| 决策 | 取值 | 含义 |
|---|---|---|
| D1 任务定义 | **A 反向追踪** | 只从 POI 往回找入口；不含 POI 之后的活动与平行分支 |
| D2 表示层 | **B 行为步骤** | 一个步骤 = 一个进程实例（无超参，不按时间切分） |
| D3 创新点 | **候选 1 + 候选 2** | ①步骤化表示与机械枚举（折叠 + R1/R2）；②调查状态显式化 + **硬约束读回** |
| D4 知识库 | **暂不做** | 无 CTI / MITRE RAG；战术链由**规则**从图上事实推导 |
| D5 POI | **配置文件指定** | `config/scenarios.json` 是 POI 唯一来源；`.query` 文件不进 agent 上下文 |
| D6 数据外发 | 允许 | 走 `.env` 的 `OPENAI_BASE_URL` / `OPENAI_MODEL` |
| D7 改图 | **不允许** | 不修 G1/G2/G5；agent 侧只能记录缺口 |
| D8–D10 | 默认 | macro F1 主指标、全自动批量 + 可选交互、单主机 |

## 2. 架构：五层

五层各占 `pagent/layers/` 下的一个包（包内按用途分文件），只允许下游读上游；编排在
`pagent/orchestration/`，装配与流程顺序在 `pagent/app.py`，横切基础设施在 `pagent/core/`，
提示词与规则表分别是 `pagent/prompts/`、`pagent/rules/` 下的数据文件。
模型调用只出现在第 3、4 层；展开、压缩、报告全部是纯代码。

```
起点定位（第 1 层）
  │
  ├─ 反向闭包（第 1 层 + 第 2 层折叠与摘要，纯代码）
  │    从终点事件出发，按三条因果规则往回走（规则与门限见下）
  │    门限只减不增：每个顶点只完整展开一次，门限变高时补取新增区间
  │    → 规则在遍历期剔除 → 折叠（内容三元组）→ 步骤上下文（只用于渲染）
  │
  ├─ 判定驱动（第 2 层装批 → 第 3 层第一轮 → 第 4 层复核与合并）
  │    所有边按步骤打包成大批 → 一个并发池 → 合并结论
  │    粗筛（第 2 层，纯代码）→ 第一轮逐条判定（第 3 层）→ 边界边/漏 id 二次对抗复核（第 4 层）
  │    → 整批失败二分拆批重试（编排器）
  │
  └─ 报告（第 5 层，纯代码）：时间线 / 规则推导相位 / 入口点 / 缺口
```

| 层 | 作用 | 代码 |
|---|---|---|
| 1 结构可达 | 从终点事件往回走，算出**反向闭包**（决定上限） | `pagent/layers/l1_reach/` |
| 2 压缩与准备 | 折叠、剔两类结构性伪边、步骤摘要、确定性粗筛、切批、提示词渲染（不许降低上限） | `pagent/layers/l2_prepare/` |
| 3 语义判别 | 第一轮逐条判定（模型调用） | `pagent/layers/l3_semantic/` |
| 4 全局校验 | 复核不确定的边、合并结论（模型调用；当前口径 = 同批内复核） | `pagent/layers/l4_verify/` |
| 5 表达 | 报告装配与证据编号回填（纯代码） | `pagent/layers/l5_express/` |
| 编排 | 起点定位 → 展开 → 判定驱动（批 → 第 3 层 → 第 4 层，含二分拆批重试）→ 登记 | `pagent/orchestration/` |
| 装配 | 依赖容器与流程顺序 | `pagent/app.py` |
| 横切 | 配置 / 场景 / 图访问 / 模型 / 记录 / 提示词加载 / 规则加载 / 轨迹 | `pagent/core/` |

| 环节 | 职责 | 实现 |
|---|---|---|
| `orchestration.intake` | 回库核对 POI、算实例数与时间范围、定位起点步骤 | 纯代码（第 1 层） |
| `orchestration.expand` | 逐轮展开前沿候选，直到耗尽 | 纯代码（第 1、2 层） |
| `l1_reach.run_closure` + `l2_prepare.fold` | 事件级时间门限闭包（规则在遍历期生效）+ 折叠 | 纯代码（第 1、2 层） |
| `orchestration.judging` / `l3_semantic.judge_first_pass` / `l4_verify.verify` | 粗筛后装批、第一轮判定、边界边与漏 id 的复核、合并结论 | LLM（第 3、4 层） |
| `orchestration.register` / `record` | 把结论登记进内存记录表（实体 + in-step/supports/refutes） | 纯代码（编排） |
| `l5_express.build_report` | 确定性报告，已确认边**默认全选** | 纯代码（第 5 层） |

**为什么把"取证员"删了**（实测）：旧版每轮派一个带工具的模型去展开步骤，但它只是照抄控制器给它的
step_key；实测场景 1 的 15 轮里 14 轮模型自报"取不到数据"（工具结果被上下文清理清空 + 撞工具调用上限），
而**100% 的候选边其实是工具函数自己收走的**。它占 42% 的调用、61% 的提示词字符、50% 的墙钟，还漏展开 19% 的指令目标。

**为什么"判定去波化"**：旧版"展开一点→判一点"把 82 个批切成 13 波，每波时长等于最慢那一批
（20~46s），而判定调用累计 547.6s ÷ 并发 12 = 45.6s 才是理想值。现在展开完再一次并行判定。

### 第 1、2 层（`pagent/layers/l1_reach/` / `pagent/layers/l2_prepare/`）

- **一个步骤 = 一个进程实例**，键 `S:<process_id>:<该进程最早一条被收进闭包的边的 starttime>`。
  步骤只用于判定时的上下文渲染与分组，**不参与可达性计算**。
- 归属规则：进程写文件/网络归源进程，文件/网络被进程读写归目标进程，进程派生归子进程。
- **折叠**（第 2 层）：按 `(src 内容, syscall, dst 内容)` 归并，记录实例数/累计字节/首末时间/全部 event_id/来源成员。
  折叠是**有损**的：实例间的相对时序与各自字节量会丢。

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
的大小，主干远小于结果时两遍合起来反而更快——六场景整层墙钟（含取数、折叠、步骤摘要）：
场景 3 从 1.93 秒降到 0.68 秒、场景 4 从 1.5 秒降到 0.13 秒；主干接近最终结果的场景 5 从 2.24 秒
升到 2.37 秒（多一成）；峰值内存场景 3 从 317 兆降到 155 兆、场景 5 从 385 兆降到 372 兆。

**机制（写死，不是开关）**：文件/网络顶点只回溯**写入侧**（读不会把内容送回顶点）；**共享/虚拟通道
只收边、不展开**——终端以外的设备节点、内核现生成的伪文件（`/proc`、`/sys`）、系统运行目录及其中的
套接字（表在 `pagent/rules/shared_channels.json`），从它们读的那条边照收，但不往回找写入者
（口径与实测：六场景候选减 42%、事件减 68%、标注覆盖仍为 100%）；**子进程口径**：同一主体在门限之前
派生出去的其它子进程也算上游（有意识的超集口径），但主干里无条件收、第二层起要"和主干有过一次
写-读配对"（读的东西主干写过，或写的东西主干读过；共享/虚拟通道与连接建立不算）——
口径与实测见 `l1_reach/siblings.py` 与 CHANGELOG（六场景候选减 69.5%、事件减 38.5%、进程减 64.4%、
标注覆盖仍为 100%）；结构性伪边与
系统例行文件在**遍历期**就剔除（与第 2 层共用同一份判定，`core/edge_rules.py`）；读取事件给写入者的
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

指标表见 `tests/l1_ablation.py`（`--all` 跑六场景，看候选边/命中标注/事件数/步骤数/顶点数是否与
改前逐项相同；`--report` 打印汇总表）；单测见 `tests/unit/test_closure.py`、
`tests/unit/test_snapshot.py`、`tests/unit/test_shared_channels.py` 与 `tests/unit/test_sibling_gate.py`。

### 第 2、3、4 层与判定驱动（`l2_prepare/` / `l3_semantic/` / `l4_verify/` / `orchestration/judging.py`）

1. **确定性粗筛**（第 2 层）：两类边直接判无关、不进模型。
   - **遍历期就剔除**（第 1 层与第 2 层共用同一份判定）：动态库读取、系统自带程序的自我执行、
     系统例行文件（本地化/字符集、名字解析/服务配置）；这些表逐条核对过六个场景的 GT（零命中）；
     `/etc/passwd`、`/dev/urandom`、`/proc/cpuinfo` 等**故意不列入**。
   - **只在候选集层面剔除**（`pagent/rules/candidate_drops.json`，第 1 层照收这些边）：内核按进程现生成的
     伪文件（`/proc/<进程号>/`、`/proc/self/` 下，被 `ps`、`ss`、`systemd` 这类工具成批例行读取）、
     以及**写进**共享 / 虚拟通道的边（内容流向一个永不追溯的通道）。**读取**共享通道的边不去掉
     （它是链条上进程的输入，例如 `dd` 读 `/dev/urandom`）。两类的理由与实测见 CHANGELOG：
     六场景候选边 5,114 → 2,771（少 46%），人工标注 356/356 不变。
2. **切批**（第 2 层）：按步骤分组后**装填到批大小**（默认 50，可跨步骤），每批独立渲染每个步骤的上下文块。
3. **第一轮**（第 3 层）：每条边带 `E001` 形式 id，**要求原样回抄**；漏抄/抄错的边不会被当成"无关"，
   而是进第二轮复核，两轮都不行则记 `unjudged` + 缺口。
4. **第二轮（对抗复核）**（第 4 层）：只针对"危险边"（第一轮没给结论的 + 置信度贴着阈值 ±0.1 的），
   用相反口气提问（先假设无害）；两轮不一致 → 取低值、**保留**并标 `contested`。
5. **失败处理**（编排器 `run.py`）：整批调用失败（网关 504/超时）→ **二分拆批重试**，拆到单条仍失败才记 `unjudged`。

## 3. 运行

```bash
# 干跑测试：假判定模型驱动整条流水线，不调真实 LLM（改代码后先跑）
python provenance-agent/tests/dry_run.py
python provenance-agent/tests/dry_run.py 2_Masquerade_Data_Exfiltration
DRY_JUDGE_DROP_ID=always python provenance-agent/tests/dry_run.py   # 测"两轮都漏 id → 未判定"

# 每层单测：不需要数据库、不需要模型
python -m unittest discover -s provenance-agent/tests/unit -t provenance-agent

# 只跑确定性层（POI → 反向闭包），不调 LLM；报告写 tmp/
python provenance-agent/main.py --scenario 1_Multi_Stage_Data_Exfiltration --dry-run

# 第 1 层指标表（六个场景；不调模型；结果写 tmp/provenance-agent/l1-ablation/）
python provenance-agent/tests/l1_ablation.py --all
python provenance-agent/tests/l1_ablation.py --report

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
| 判定批大小 | `PAGENT_JUDGE_BATCH` | 50 | **太小会掉召回**（缺同批上下文），太大顶网关超时；失败会自动二分拆批 |
| 判定并发 | `PAGENT_MAX_CONCURRENCY` | 12 | 网关实测限流是 20，超了会 429 |
| 模型调用上限 | `PAGENT_MAX_LLM_CALLS` | 150 | 超限的批显式记 `unjudged` |
| 阈值 | `--min-confidence` | 0.5 | 判定为相关的最低置信度 |
| 步骤内存缓存 | `PAGENT_STEP_CACHE` | 1 | 只用于验证"缓存不改变结果"，正常跑不要关 |

**展开侧没有任何旋钮**：上游候选、子进程、管道组成员、待处理清单、单进程边数、查询返回行数全部不设上限。
任何条数上限都是按数据分布随机丢边——上限只要小于真实链长就会掉召回，而真实链长事先不知道。
实测：子进程上限 8 让场景 4 的标注覆盖从 100% 掉到 74.6%、场景 5 从 100% 掉到 94.1%；
取消上限后两者都回到 100%。展开的终止条件只有两个：前沿耗尽、同一个步骤连续失败两次。

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
| `tmp/provenance-agent/l1-index/<库名>/` | 顶点-时间索引快照（可重建的派生数据，不是测量结果；第 1 层唯一的取数方式，缺失或过期自动重建） |

> `tmp/` 是临时区：**只保留最近一次测量的结果文件**，历史运行记录（日志、旧的测量结果、调查记录）
> 确认不再需要后直接删除；需要长期保留的结论写进 `CHANGELOG.md`。删除 `state/` / `logs/` / `dry-run/`
> 不会影响运行，下次跑会自动重建。

报告 schema：

```json
{"scenario": "...", "run_id": "...", "poi": {"kind": "...", "rel": "...", "syscall": "...", "key": "..."},
 "edges": [{"src": "...", "syscall": "...", "dst": "...", "confidence": "high|medium",
            "event_id": 123, "instances": 4, "bytes": 1024, "reason": "...",
            "step_key": "S:...", "contested": true}],
 "narrative": "（确定性时间线，非 LLM 生成）", "tactics": ["Execution", "Exfiltration"], "entry_point": "...",
 "gaps": [{"label": "...", "next_action": "...", "status": "open"}],
 "hypotheses": [{"key": "POI", "label": "...", "status": "confirmed"}],
 "reflection": {"sufficient": false, "confidence": 0.6, "missing_phases": [...], "derived_by": "rules"},
 "selection_note": "确定性报告：已确认 30 条全部保留（无 LLM 选择、无剔除）",
 "generated_by": "deterministic_reporter",
 "stop_reason": "frontier_exhausted|candidates_failed|dry_run",
 "event_id_resolved": 30, "event_id_unresolved": 0,
 "stats": {"expand": {"rounds": 0, "fold": {...}}, "judge": {"batches": 0, "calls": 0},
           "llm": {...}, "queries": 0, "query_rows": 0, "wall_seconds": 0,
           "confirmed_triples": 0, "excluded_triples": 0, "unjudged_triples": 0,
           "prefiltered_triples": 0, "contested_triples": 0, "state": {...}}}
```

`stats.unjudged_triples` 是"两轮都没给出可解析结论、或被调用上限熔断"的候选边数；
`edges[].contested=true` 表示这条边两轮判定不一致（取低值后仍达阈值）。

## 5. 不变式（改动时不得破坏）

1. **只读**：`db.ReadOnlyGraph` 是唯一访问点；`execute_read` + 写关键字黑名单（先剔字符串字面量再匹配）+ 禁多语句。
2. **不截断、不静默**：展开侧不设任何条数上限（上游候选、子进程、管道组成员、待处理清单、
   单进程边数、查询返回行数）；**判定未完成**必须显式记进 `unjudged`。
3. **POI 只来自配置**：`.query` 文件不得进入提示或工具输出。
4. **端点内容只从工具输出复制**：报告边的 `src`/`dst` 来自图上内容，不允许模型凭记忆写。
5. **假设必须收尾、缺口必须带后继动作**：`record.close_unclosed()` 与 `record.add_gap()` 强制。
6. **未判定 ≠ 排除**：漏 id / 调用失败 / 预算熔断的边进 `unjudged`，既不静默丢也不当成无关。
7. **报告默认全选已确认边**：不做模型挑选。
8. **只有判定调 LLM**：干跑测试断言"除判定外没有任何模型调用"。

## 6. 已知问题（未修，按优先级）

| # | 问题 | 影响 |
|---|---|---|
| 1 | 无「往前看」查询（D1=A 的直接后果） | 结构性拿不到 POI 之后 / 平行分支的边 |
| 2 | 未做知识库（D4） | 相位靠关键词规则推导，覆盖有限；`Initial Access` 基本恒缺（攻击机进程不在图里） |
| 3 | ~~兄弟/子进程仍受 top-K 限制~~（已修：取消全部条数上限） | — |
| 4 | 大批判定的"上下文光环" | 同一批里既有明显恶意边、又有同一脚本的模糊边时，模糊边更容易被判相关（场景 2 实测多出 3 条来自恶意脚本的边，GT 未收录）。批 25~50 是实测的折中 |
| 5 | 一次性判定丢掉了跨波上下文 | 旧版多波之间会累积"已确认时间线 / 已排除负例"，现在没有。若 GT 回归显示查准下降，可改成按 depth 的两阶段判定 |
| 6 | 判定稳定性 | 边界边二次对抗复核 + 争议默认保留；但模型仍非确定性（实测同一配置连跑三次结果一致，但不同批大小会改变结论） |
| 7 | 长命 shell 步骤很大（如 `gnome-terminal` 上千条边） | 展开与判定成本高且多为噪声；无确定性预筛 |
