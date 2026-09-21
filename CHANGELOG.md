# 改动记录（CHANGELOG）

本文件**只记录效果尚未证实的改动**：改了什么、为什么还没证实、需要做什么才算证实。
已实测证实有效/正向的改动不留档（查 git 历史）。`AGENTS.md` 只写当前确定的事实。

- 条目按新→旧排列，不标日期；同一主题被后续改动覆盖时只保留最新一条。
- 产物只写当前仍存在的 `output/` 或 `docs/` 路径；临时文件写 `tmp/`，不在此引用其路径。

---

## 待决项

未解决、需要决定或重做的问题；不随「只记录未证实改动」的约定删除。

**1. `output/agent-vs-engine/` 快照未按新 GT 重算（待用户决定）**

它是 2026-09-17 的单轮快照、**GT=407 口径**（含 agent 与引擎对照表与逐相位命中），
不被 `docs/溯源图agent调查-创新点与效果.md` 引用。重写会破坏那一轮记录，故未动。重算命令已存在：

```bash
python tools/eval_agent_attack_path.py --all --results-dir output/agent-vs-engine/normalized \
  --gt-dir groundtruth --json-out <新文件>
```

**2. 时间尊重可达性判据未做出：场景 4 的 P0 15 条（POI 之前但不在回溯路上）仍留在 GT 里**

- 它时间上早于 POI，按时间筛选抓不到，需要「时间尊重的可达性」计算。
- 尝试失败：`p2p` 边的 `endtime` 被延长到父进程末尾，破坏了 `writer.endtime <= reader.starttime` 的链接条件；
  改用 `starttime` 后仍不够稳，本次未采用，文档已声明该部分待重做。
- 量化影响（按 GT=375 口径算）：若一并删除，场景 4 的 F1 变成 **M1 0.776 > 基线 0.711 > E2 0.657**，
  即「两个臂都在场景 4 回退」只对 E2 成立。
- **顺带的方法论结论**：严格「依赖祖先」可达性（`A.dst == B.src` 且 `A.start ≤ B.start`，从 POI 反向可达）
  **不可用**——场景 4 只剩 5/78、场景 6 只剩 18/120 条被判为祖先。根因：这套溯源图**不建模「目录包含文件」
  与「同一脚本内的命令顺序」**（如 `mkdir` 建目录与之后往该目录写文件在图上没有路径）。
  → **判据必须是语义的，不是纯图可达性。**

**3. GT 里「痕迹清理」边是否收录未定口径**

场景 1 的 md 写了「删除入口/暂存文件」这一步（`rm /tmp/.system_service.sh` 等 4 条 unlink）、
场景 2 同理（`rm /tmp/update_patch.sh` 等 2 条）：库里 `unlink` 边存在、GT 从未登记，
场景 1 的 md 又自述该步为「增加额外的文件操作噪音」。**是否入 GT 需先定口径**，故未补。

**4. 图缺陷未修（unix / sendfile 之外的遗留）**

- 场景 4 审计链仍不连通（符号链接别名 + rsyslogd 线程名分叉）；
- 场景 6 终端面 / pty；
- netlink、抽象命名空间。

详见 `docs/graph-defects-20260913.md`。

**5. 引擎基线低召回机制未修**

场景 4/6 的低召回集中在 POI 反向锥之外的 GT 阶段（同会话但非 POI 数据流祖先的 tar/cp/归档/回显边），
机制为 `INTERSECT(b_cpr, forward_union)` 单侧切除；证据（场景 4 final 图无任何 tar/cp/nginx 顶点）与逐条未召回边见
`output/baseline/<场景>/`。

---

## 记录

### `provenance-agent` 改用 Supervisor 套路（4+3+6），并新增干跑测试

**背景**：用户指出上一轮拿"pi 框架 + 自由探索"与"LangGraph FSM"对比是**控制变量不对齐**的
（框架不同、工具层不同、GT 版本不同），据此推结论不成立；且 pi test 的 M1 臂状态图**从未被读回**，
那个实验本身也没真正测到机制。因此废弃"拿 pi test 数字推 FSM 更优"的说法。

**口径修正（必须按这个说）**

- pi test 的 E2/M1 数字与本次数字**不可直接比较**；要比较必须**同框架、同工具层、同模型、同 GT 版本**。
- 已把三种套路实现在**同一代码库、同一工具层**上，作为可对比的臂：
  `--mode supervisor`（默认）/ `--mode react` / `--mode fsm`。
- 目前**只有 fsm 臂跑过场景 1**（见下一条），supervisor 臂的结果见本条目末尾。

**改动**

- 新增 `pagent/tools.py`：14 个工具（步骤查询 / 机械枚举 / 四类前驱 / 空白区审计 / 只读 Cypher /
  实体存在性验证 / 状态图读写 / 提交报告），用 `@tool` + Pydantic schema。
  **工具层与套路无关**——三种臂共用同一批工具，这正是控制变量的关键。
- 新增 `pagent/graph/workers.py` + `supervisor.py`：主管 + 五个 worker（researcher / judge / memory /
  reflect / reporter）；`Send` 把候选边切成 N 批**并行**判定；`reflect` 自审；`reporter` 出报告。
- 新增 `pagent/prompts.py`：图 schema 与建模缺口共享片段（避免多处漂移）。
- 新增 `pagent/react_agent.py`：ReAct 臂（`create_agent` + TodoList/Summarization/ContextEditing/
  ToolCallLimit/ModelRetry 等 middleware）。
- 新增 `pagent/tests/dry_supervisor.py`：**假模型干跑整张图**，7—12 秒跑完，检查 12 项不变式。
- `llm.py`：新增 `BudgetCallback`（callback 记账，子 agent 内部的 LLM 调用也能记到）；
  `LlmBudget` 增加**每次调用耗时**（`by_node_ms` / `slowest`）。

**三项优化（用户指定）**

1. **memory 条件调用**：本轮无新确认/排除且无新考察步骤时**不叫 LLM**（旧版每轮都叫，24 次里一半空转）。
2. **judge 并行**：`Send` 扇出，批大小 `PAGENT_JUDGE_BATCH`（默认 20）。干跑实测：15 条候选 → 3 批、
   70 条 → 7 批，且完成顺序乱序（3/1/2），确认真并行。
3. **每调用耗时记账**：`stats.llm.by_node_ms` / `slowest`；`act` 节点归因耗时与 Neo4j 耗时已可分开看。

**这一轮挖出并修掉的 9 个真缺陷**（每一个都有实测现象，不是推测）

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | researcher 连续 4 轮"展开了步骤却带回 0 条边" | 审计日志多线程 `open(...,'a')` 在 Windows 报共享冲突，异常从 `finally` 冒出来打挂工具调用 | `ReadOnlyGraph` 加可重入锁 + 审计失败不抛出 |
| 2 | 同上（第二处） | 步骤缓存多线程写同一文件 | 缓存写入加锁 + 临时文件原子替换 |
| 3 | 主管连续 6 轮全派 judge、空转到预算耗尽 | 判完后 `pending_edges` 未清空 | 切批节点同时清空 `pending_edges`，扇出改读 `judge_batches` |
| 4 | 状态图 `edges: 0`、所有确认边被拒收 | `expand_step` 默认不返回 `event_ids`（省上下文），而 memory 硬约束要求 event_id | 侧信道**始终**取含 event_ids 的全量边，只给 LLM 精简视图 |
| 5 | `SQLite objects created in a thread can only be used in that same thread` | 子 agent 工具跑在别的线程，`StateStore` 连接绑定创建线程 | `check_same_thread=False` + 可重入锁包住全部读写 |
| 6 | researcher 去查不存在的 `:Step` 标签 | worker 自己的 system prompt 里没有图 schema | 新增 `prompts.GRAPH_SCHEMA`，注入所有 agent |
| 7 | 一个错 `step_key` 把整个 worker 调用打挂，丢掉整轮取证 | 工具直接抛 `KeyError` | 工具返回可自校正的错误（附该进程真实步骤列表） |
| 8 | **memory worker 12 轮一次都没被派过** | 主管提示词里"judge 有新结论→派 memory"被无视 | **路由级硬约束**：`judge_dirty` 未登记则强制转 memory |
| 9 | `reflect` 说证据不足 → researcher 零收获 → 再派 → 无限打转 | 无"零收获"终止判据 | 路由级硬约束：连续 2 次零收获强制转 reporter |

缺陷 8/9 是**路由级硬约束**，不是提示词——它们必须在 `route_supervisor()` 里用代码拦，
这与 pi test 得出的"工具的可用性 ≠ 工具会被使用"是同一个道理。

**干跑测试（新增，这是本轮的流程改进）**

上一轮的错误做法是"改一个 bug 就跑一次 35 分钟的真实跑测"。现在改为：

```bash
python provenance-agent/tests/dry_supervisor.py [场景名]
```

用两个脚本化假模型（按角色返回预置 JSON / 按脚本发工具调用）驱动整张图，**7—12 秒**跑完，
断言 12 项不变式：memory 被调用、judge 多批并行、报告非空且每条边带 event_id、状态图有边、
假设全收尾、零收获不超 2 连、审计日志每行合法 JSON、轮次不超上限等。
实测：场景 1（3 批）与场景 6（7 批）**全部通过**。

**场景 1 结果：同框架、同工具层、同模型、同 GT 的受控对比**

这是目前**唯一**口径对齐的对比（只有控制流不同）：

| 臂（`--mode`） | 召回 | 查准 | F1 | LLM 调用 | LLM 总耗时 |
|---|---|---|---|---|---|
| `fsm`（固定流程） | 30/32 = 93.8% | 30/31 = **96.8%** | **0.952** | 63 | 22.8 min |
| `supervisor`（4+3+6） | 30/32 = 93.8% | 30/34 = 88.2% | 0.909 | 52 | **11.1 min** |

- 两者**漏的边完全相同**（都是 P3 的 `mkdir` 两条）。
- 差异全在查准：supervisor 多报了 4 条，全是 `bash → sudo → su → bash` 这条**提权父链**
  （fsm 臂在 bash 处就收了）；这四条在图上真实存在，只是 GT 未收录。
- **三项优化的效果**：LLM 总耗时 **22.8 → 11.1 min（−51%）**，调用数 63 → 52。
  分节点：judge 280s / researcher 155s / supervisor 100s / memory 75s / reflect 12s / reporter 44s。
- 状态图：134 节点 / 188 边；假设 12 条**全部收尾**；自动登记缺口 15 条（fsm 臂为 0——这是路由硬约束带来的差别）。
- 主管 13 轮；`reflect` 最终仍判定不足（conf 0.72，缺 Initial Access/Discovery/Lateral Movement/Impact），
  最终由"连续零收获"硬约束收尾（`supervisor_concluded`）。

**一个仍存在的观测缺陷**：本轮跑测时 `BudgetCallback` 拿到的 token 数是 0
（回调收到的是 `LLMResult` 而非 ChatModel 响应），**已修**（`_usage()` 兼容三种返回形态，单调用实测 108 token），
但上表的两行数字**尚未带 token**，需重跑才能补上。

**产物**：`provenance-agent/`（tools.py / prompts.py / react_agent.py / graph/workers.py /
 graph/supervisor.py / tests/dry_supervisor.py）、`output/agent/<场景>.json`。

---
### 新增 `provenance-agent/`：基于溯源图的 LangGraph 攻击溯源 agent（首个可运行骨架）

**为什么效果未证实**：只有场景 1 跑通端到端，**其余五场景与全部消融未做**，
所以「这套 agent 是否普适」尚无证据。

**已锁定的决策**（D1–D10，详见 `provenance-agent/README.md` §1）

| 决策 | 取值 |
|---|---|
| D1 任务定义 | A 反向追踪（不含 POI 之后/平行分支） |
| D2 表示层 | B 行为步骤（一个步骤 = 一个进程实例，`GAP=0`） |
| D3 创新点 | 候选 1（步骤化表示+机械枚举）+ 候选 2（状态显式化+硬约束读回） |
| D4 知识库 | 暂不做（无 CTI/MITRE RAG） |
| D5 POI | 配置文件指定（`config/scenarios.json`） |
| D6 数据外发 | 允许 |
| D7 改图 | 不允许（不修 G1/G2/G5） |
| D8–D10 | 默认（macro F1 主指标、批量+可选交互、单主机） |

**新增内容**

- `provenance-agent/`：`main.py`（单场景 / `--all` / `--dry-run`）、`pagent/{settings,scenarios,db,steps,collapse,state_store,llm}.py`、`pagent/graph/{state,nodes,build}.py`、`config/scenarios.json`。
- 主图 FSM：`intake → plan → act → judge → memory → tick → gate →(plan | close_out → report)`。
- 只读层：`execute_read` + 写关键字黑名单（先剔字符串字面量再匹配）+ 禁多语句 + 有界返回 + 查询审计 JSONL。
- 步骤层：三 UNION 取进程自有边、磁盘缓存、摘要（含命令行原文）、折叠成内容三元组、R1/R2 伪边剔除、四类前驱。
- 状态图：SQLite 三类节点 + 四类边；相对 pi test 的 M1 臂把「可选工具」升级为**硬约束**（状态快照强制注入 planner、假设不得以 `tracing` 离场、gap 必须带 `next_action`、确认边必须带 `event_id`）。
- `requirements.txt`：新增 `langchain` / `langchain-core` / `langchain-openai` / `langgraph` / `langgraph-checkpoint-sqlite`。

**未做 / 已知问题（不得当作已完成）**

- 其余五场景完整跑测与消融：**未做**（仅场景 1 完成）。
- 「往前看」查询、空白区审计强制化、知识库（MITRE/CTI）、对抗判定、机器粗筛：未实现或未启用。
- 缺口登记率低：planner 极少主动 `close_gap`（场景 1 最终 `gaps` 为空）。
- planner 收尾前会漂到长命 shell 的无害子进程（`lesspipe` / `dircolors` / `basename` / `gnome-terminal`），每轮一个、直到前沿耗尽，浪费轮次。
- 叙事文本与最终报告可能不同步（`fine.narrative` 在最后一轮判定前生成）。
- 判定稳定性：同一批边两次判定结论可能不同（温度已为 0，中转网关仍可能非确定）。
- 过程中修掉的缺陷（步骤层被通用行上限静默截断、四类前驱漏线索、文件来源漏元数据路径、LLM 传输层无容错）已在场景 1 上验证修复有效，按本文件约定不留档。

**产物**：`provenance-agent/`（含 README）、`provenance-agent/config/scenarios.json`、`output/agent/<场景>.json`（冒烟产物）。

---

### 移除 GAP（时间聚类阈值）：机制改为「一个步骤 = 一个进程实例」

**为什么效果未证实**：端到端数字（E2/M1 臂 macro F1、池覆盖、查准）**仍来自 GAP=2 s 的 `E2-1` / `M1-1` 运行**，
无 GAP 的重跑（`E2-2` / `M1-2`）**未做**；下面只有池口径的估计代价。

| 口径 | GAP=2 s | GAP=∞（= 无 GAP） | 变化 |
|---|---|---|---|
| 可达上限（oracle） | 0.797 | **0.792** | −0.6% |
| 展开池三元组 | 2834 | **3546** | **+25%** |
| 池召回 | 94.7% | **96.1%** | +1.4 pp |
| **池查准** | 11.9% | **9.7%** | **−18%（相对）** |

**改动**

| 文件 | 改前 | 改后 |
|---|---|---|
| `tools/steps.py` | `DEFAULT_GAP_MS = 2000` | **`0`**（0 = 不切）；`process_bundle` 增加 `clusters = [rows] if (gap_ms <= 0 and rows) else _cluster(...)` |
| `tools/steps.py` 文件头 | 「时间聚类…GAP 默认 2000 ms」 | 「**步骤 = 进程实例（无时间聚类）**」 |
| `tools/set_arm.py` | `cur.get("step_gap_ms", 2000)` | **`0`**（不再从旧 run.json 继承） |
| `arms/E1-steps-expand.md` | 「按时间切段，间隔超过 GAP（默认 2000 ms）」 | 「**一个步骤 = 一个进程实例**，无超参」 |
| `run.json` | `step_gap_ms: 2000` | **`0`**；`run_id` → `E2-2`（arm `E2-steps-filtered`） |
| `docs/溯源图agent调查-创新点与效果.md` | 1.1.2(3) 时间聚类小节 + GAP 敏感性/边界条目/参数/产物 | **全部删除**；步骤定义改为「一个步骤 = 一个进程实例」，原 (4)(5)(6) 顺延为 (3)(4)(5) |

`--gap-ms` 保留（仅供分析脚本做阈值敏感性扫描），默认 0。

**行为级验证（非效果）**：`PI_RUN_ID=smoke` 下 `5144sshd` 默认不切 → **1 步 / 330 边**；`--gap-ms 2000` → **95 步**（与改前一致）。

**待办**：重跑 `E2-2` / `M1-2`（需开新 pi 会话），拿无 GAP 的端到端数字替换文档。
风险：池 +25%，单次 `expand` 可能涨 10 倍（`5144sshd` 实测 50 → 492 三元组），工具结果体积与上下文压力明显上升。

**顺带否掉的替代方案**：「改成结构边界（进程每 execve 出子进程就切一刀）」**不等价**——
六场景步骤数 315（GAP=2 s）vs 283（结构），**场景 3 差 5 倍（106 vs 21）**：`sshd` 几乎不派生子进程，
有的是会话之间的大段空闲，两种切法切的是不同的东西。

---

### `send` / `recv` / `open` 家族基本名登记（真实日志效果未证实）

**为什么效果未证实**：六场景日志里这三类事件**记录数为 0**，改动对现有六库**零影响**；
`send` / `recv` 在 sysdig 事件表里的形态只能靠同族（`sendto`/`recvfrom`/`sendmsg`/`recvmsg`）推断，本机无网络可核对。

**问题**：`CANONICAL_SYSCALL_MAP` 与家族元组只收录了带后缀的变体（`sendto`/`sendmsg`/`sendmmsg`、`recvfrom`/`recvmsg`/`recvmmsg`），
裸名 `send`/`recv` 未登记 —— 直连内核调 `send(2)`/`recv(2)` 的主机上这两类数据流会整类落 `Unmatched fingerprint` 丢边；
`open` 同样未登记（按设计不建边，但会落 unmatched、且不延长 `p2p`，与 `openat` 口径不一致）。

**改动**

- `dispatch/meta_config.py`：`CANONICAL_SYSCALL_MAP` 增 `"send": "sendto"` / `"recv": "recvfrom"`；`_SEND_FAMILY` / `_RECV_FAMILY` 补裸名。
- `dispatch/handlers.py`：`_OPEN_NO_EDGE_EVENTS` 增 `"open"`。
- 方向与动作**零新增代码**（由家族元组派生）；`AGENTS.md` §8.4 同步。
- handler 指纹数 68 → **73**（5 个新指纹，与既有键 **0 冲突**）。

**合成日志验证（6 对事件）**：边计数 p2n/p2f/n2p/f2p = 0/0/0/0 → **1/1/1/1**（边 `syscall` = `sendto`/`recvfrom`）；
`open` **0 条边、不落 unmatched、把 `p2p` 边 `endtime` 从 clone 退出时间延长到 open 退出时间**。

**待办**：首份含这两类事件的真实日志到手后，用 `tools/check_sysdig_export.py` + `tools/run_coverage.py` 复核；
若其 fd 注记出现在**退出**记录而非进入记录，需再补 `(send/recv, None, Entity)` 指纹 + 一个从退出记录取端点的动作。

**验证脚本**：`tmp/verify_bug3.py`（合成 5 用例，含「模拟修复前」对照）、`tmp/verify_bug3_slice.py`（六日志零命中 + 切片计数器等价）。**产物**：无（不改图）。
