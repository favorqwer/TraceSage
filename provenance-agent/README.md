# provenance-agent — 基于溯源图的反向追踪 agent

在 `sysdig-parser` 导入的 Neo4j 溯源图上，从 POI 出发**反向追踪**攻击因果链，产出可被
`tools/eval_agent_attack_path.py` 评分（与引擎 `tools/evaluate_gt.py` 同口径）的溯源报告。

## 2. 架构

三层，各占 `pagent/layers/` 下一个包（包内按用途分文件），只允许下游读上游；编排在
`pagent/orchestration/`，装配与流程顺序在 `pagent/app.py`，横切基础设施在 `pagent/core/`，
提示词与规则表是 `pagent/prompts/`、`pagent/rules/` 下的数据文件。**只有判定层调模型**；
展开、折叠、上下文渲染与报告全是纯代码。

```
起点定位 intake
  → 展开与折叠 expand_closure：反向闭包 → 实例范围 → 折叠 → 两道固定剔除 = 候选表
  → 判定驱动 judging：按「离终点几跳」分波 → 波内按批切批、同一波共用冻结上下文并发投递
     （一批失败整批重发）→ 逐波更新双层滚动上下文 → 按布尔定结论
  → 登记 register → 报告 build_report（时间线 / 入口点 / 缺口）
```

| 组件 | 作用 | 代码 |
|---|---|---|
| 第 1 层 结构可达与折叠 | 从终点事件往回算**反向闭包**，经实例范围过滤后折叠成内容三元组（= 候选表 = 召回上限） | `pagent/layers/l1_reach/` |
| 判定层 | 分波、双层滚动上下文、切批、提示词渲染、逐波判定（后两项调模型）、按布尔定结论 | `pagent/layers/l2_judge/` |
| 表达层 | 报告装配与证据编号回填（纯代码） | `pagent/layers/l3_express/` |
| 编排 | 起点定位 → 展开与折叠 → 判定驱动（含整批重试）→ 登记 | `pagent/orchestration/` |
| 装配 / 横切 | 依赖容器与流程顺序 / 配置、场景、只读图访问、模型、记录、提示词与规则加载、轨迹 | `pagent/app.py` / `pagent/core/` |

### 第 1 层：结构可达与折叠（`layers/l1_reach/`）

包内六个文件各管一件事：`graph_index.py`（顶点-时间索引，唯一的取数方式）、`walk.py`（闭包引擎
`run_closure`）、`table.py` + `judgments.py`（判据表的加载校验与唯一求值入口）、`process_info.py`
（进程静态属性缓存）、`candidates.py`（实例范围 `filter_output_rows` + 折叠 `fold`）。

**反向闭包**（`walk.run_closure`）：从终点事件出发按三条因果规则往回走，算出能影响它的**全部事件**：
① 同进程（先发生的可能影响后发生的）；② 同顶点交付（写入侧的起始不晚于读取侧的结束，只对能承载
内容的通道生效）；③ 派生（父→子，以及同一主体在门限之前派生出的其它子进程；有意的超集口径）。
推进用只增不减的时间门限（进程顶点取"起始不晚于门限"的全部入射事件，且门限至少抬到终点事件时刻；
文件/网络顶点只取写入侧），**不设任何条数上限**，终止条件只有"待考察清单耗尽"。

闭包之后依次：**实例范围过滤**（只留"做出终点事件的那一次执行"里的进程，开关 `judge.output_filter`，
默认开）→ **折叠**（按 `(src 内容, syscall, dst 内容)` 合并实例，只合并不删边、不做判定）→ **两道固定
剔除**（`item.proc_state_numeric_unlisted`、`item.all_instances_empty_read`）= **候选表**（召回上限口径）。
每条边归一个进程（写文件/网络归源进程，被读写归目标进程，派生归子进程），进程身份摘要只用于渲染
与分组、不参与可达性计算；边的方向与两端标签由关系类型唯一决定（`core/graph_facts.py`）。

全部会改变结果的判据都在一张表 `pagent/rules/l1_judgments.json`（对象 / 事件 / 进程 / 条目四段），
常驻服务进程也在同一张表里判定；取数只有本地顶点-时间索引一条路，规则改动不需要重建索引。
当前五场景的候选表规模、召回与查准、闭包收边与耗时见 `docs/第一层形式化与召回上限对照.md` §5
（指标表用 `tests/l1_ablation.py` 量，单测在 `tests/unit/`）。

### 判定层与判定驱动（`l2_judge/` / `orchestration/judging.py`）

1. **候选表就是交给模型的清单**：第 1 层取边时不按规则剔边，**终点事件不受规则约束**，永远交给
   模型判定；候选表的规模与标注覆盖逐场景见 `docs/第一层形式化与召回上限对照.md` §5。
2. **逐波判定**：按「离终点最少几跳」分波（一跳一波），波内按 `judge.batch`（默认 70 条）切批，
   **同一波的所有批共用同一份冻结的双层滚动上下文、并发投递**，整波判完才更新状态。上下文两层：
   ①「上游交接明细」＝上层顶点上已经判过的边及其结论（按**顶点身份**查，每条边最多
   `judge.upstream_limit` 条，默认 3）；②「调查状态摘要」＝已确认的上游活动（最近
   `judge.state_chain_limit` 条，默认 20）。每次调用的上下文完整不压缩，渲染顺序：任务说明 →
   调查状态摘要 → 进程身份表 → 本次要判的边（每条边下面列出上层顶点明细与同一对象上的邻居，
   已判过的带结论）。模型调用**不先思考**：请求显式带 `thinking = {"type": "disabled"}`
   （`judge.thinking` 默认 false）。
3. **定结论**（纯代码）：整次调查的边统一编号（`E001` 形式、跨波唯一），**要求原样回抄**；判为相关
   → 确认，否则排除；漏抄/抄错的边记 `unjudged` + 缺口。**没有第二轮复核**。
4. **失败处理**：一批调用失败（网关超时）→ 该批重发（一批最多尝试 `judge.wave_attempts` 次，默认
   2 = 首次 + 失败后一次）；仍失败则该批全部边记缺失（未判定）。

## 3. 运行

```bash
# 干跑测试：假判定模型驱动整条流水线，不调真实 LLM（改代码后先跑）
python provenance-agent/tests/dry_run.py
python provenance-agent/tests/dry_run.py 2_SSH_Spray_Lateral_Exfiltration
DRY_JUDGE_DROP_ID=keep python provenance-agent/tests/dry_run.py   # 默认故意漏一条 id（测未判定）；=keep 时不漏

# 每层单测：不需要数据库、不需要模型
python -m unittest discover -s provenance-agent/tests/unit -t provenance-agent

# 只跑确定性层（POI → 反向闭包），不调 LLM；报告写 tmp/
python provenance-agent/main.py --scenario 1_Web_Exploit_Ransomware --dry-run

# 第 1 层指标表（config/scenarios.json 里的全部场景；不调模型；结果写 tmp/provenance-agent/l1-ablation/）
python provenance-agent/tests/l1_ablation.py --all
python provenance-agent/tests/l1_ablation.py --report

# 判定层重复运行与汇总（每场景重复 N 轮；自动评分与归因分解；结果写 tmp/provenance-agent/l2-runs/）
python provenance-agent/tests/l2_repeat.py --repeats 2
python provenance-agent/tests/l2_repeat.py --scenarios 3_Phishing_Beacon_Cryptomining 5_Exposed_Service_Pivot --repeats 2
python provenance-agent/tests/l2_repeat.py --report      # 只按已有结果重算汇总，不跑模型

# 顶点-时间索引（第 1 层唯一的取数方式；缺失或过期会自动重建，这个命令用于手工预建）
python tools/l1_index.py --database attack-3-phishing-beacon-cryptomining   # --force 可强制重建

# 单场景 / 批量
python provenance-agent/main.py --scenario 3_Phishing_Beacon_Cryptomining
python provenance-agent/main.py --all

# 评分（与引擎同口径）
python tools/eval_agent_attack_path.py --report output/agent/1_Web_Exploit_Ransomware.json \
    --gt groundtruth/1_Web_Exploit_Ransomware.groundtruth.json
```

**全部参数在一份文件里**：`provenance-agent/config/agent.toml`（唯一真源，程序启动时读一次）。
每项旁边写明了它管什么、为什么是这个值；改完直接重跑就生效，没有第二个入口。
凭据与连接信息（数据库口令、接口密钥、模型名）**不在**这份文件里，仍然从环境变量或仓库根 `.env` 读。
容错口径：某项没写、类型不对或小于下限，都用代码内置的默认值，并在启动时打印一行说明；不报错、不崩。
**POI 唯一来源**：`provenance-agent/config/scenarios.json`（库名 + POI 签名；实例数与时间范围由 intake
现算，不写进配置）；`input/sysdig/*.query` 不得进入 agent 的任何可见上下文。

**展开侧没有任何旋钮**：上游候选、子进程、管道组成员、待处理清单、单进程边数、查询返回行数全部不设上限。
任何条数上限都是按数据分布随机丢边——上限只要小于真实链长就会掉召回，而真实链长事先不知道。
实测：子进程上限取 8 时，场景 4 的标注覆盖是 74.6%、场景 5 是 94.1%；不设上限时两者都是 100%。
展开的终止条件只有一个：待考察清单（前沿）耗尽。

## 4. 产物

| 路径 | 内容 |
|---|---|
| `output/agent/<场景>.json` | 溯源报告（schema 见下）；`SUMMARY.json` 为多场景汇总，`metrics.json` 为同一次运行对 GT 的评分（`tools/eval_agent_attack_path.py --json-out`：按步骤召回、按边查准、必须条目与规则各自的命中数） |
| `tmp/provenance-agent/dry-run/<场景>.json` | `--dry-run` 的报告（诊断产物，**不写 output/**） |
| `tmp/provenance-agent/logs/queries-<run_id>.jsonl` | 每次查询的 Cypher/参数/行数/耗时/是否截断 |
| `tmp/provenance-agent/logs/verdicts-<run_id>.jsonl` | **逐条判定明细**（排查"这条真边为什么被排"的唯一依据） |
| `tmp/provenance-agent/logs/llm-<run_id>.jsonl` | 每次模型调用的提示词字符 / 原始输出字符 / 输出 token / 耗时 + 文本样本 |
| `tmp/provenance-agent/logs/trace-<run_id>.jsonl` | 阶段轨迹（intake / 展开 / 每波判定 / 报告） |
| `tmp/provenance-agent/state/record-<run_id>.json` | 调查记录（实体 / 假设 / 缺口 + 关系列表与状态统计） |
| `tmp/provenance-agent/l1-ablation/<场景>.json` | 第 1 层指标表结果（`--report` 汇总成同目录的 `SUMMARY.md` / `SUMMARY.json`） |
| `tmp/provenance-agent/l2-runs/` | 判定层重复运行结果（`runs/` 逐轮报告、`eval/` 逐轮评分、`metrics.json` 与 `SUMMARY.md` 汇总） |
| `tmp/provenance-agent/l1-index/<库名>/` | 顶点-时间索引快照（可重建的派生数据，不是测量结果；缺失或过期自动重建） |

> `tmp/` 是临时区：**只保留最近一次测量的结果文件**，历史运行记录（日志、旧的测量结果、调查记录）
> 确认不再需要后直接删除。删除 `state/` / `logs/` / `dry-run/` 不会影响运行，下次跑会自动重建。

报告 schema（`output/agent/<场景>.json`）的用途：它是 agent 的唯一交付格式，字段固定供三方消费——
① 评分（`tools/eval_agent_attack_path.py` 读 `edges` 的内容三元组 `src`/`syscall`/`dst`，与 GT 的必须条目和
可能集合规则比对：召回按步骤（命中条目 + 命中规则）/（条目 + 规则）、查准按边（命中条目边 + 满足规则的边）/报告去重三元组；
`tests/l2_repeat.py` 另读 `stats.judge`/`stats.llm` 做重复性统计）；② 人工排查（`narrative` 时间线、
`entry_point` 入口点、`gaps` 缺口、`hypotheses` 假设）；③ 观测与审计（`stats` 各阶段计数、
`stop_reason` 停止原因，每条确认边的 `event_id`/`instances`/`bytes`/`reason`/`process_id` 可回溯证据）。

```json
{"scenario": "...", "run_id": "...", "poi": {"kind": "...", "rel": "...", "syscall": "...", "key": "..."},
 "edges": [{"src": "...", "syscall": "...", "dst": "...",
            "event_id": 123, "instances": 4, "bytes": 1024, "reason": "...",
            "process_id": "..."}],
 "narrative": "（确定性时间线，非 LLM 生成）", "entry_point": "...",
 "gaps": [{"label": "...", "next_action": "...", "status": "open"}],
 "hypotheses": [{"key": "POI", "label": "...", "status": "confirmed"}],
 "reflection": {"sufficient": true, "critique": "...", "expand_rounds": 5, "derived_by": "rules"},
 "selection_note": "确定性报告：确认边 30 条全部保留（判为相关的边）",
 "generated_by": "deterministic_reporter",
 "stop_reason": "frontier_exhausted|candidates_failed|dry_run",
 "event_id_resolved": 30, "event_id_unresolved": 0,
 "stats": {"expand": {"rounds": 5,
                      "fold": {"raw_instances": 450, "collapsed_triples": 110},
                      "scope": {"enabled": true, "rows_before": 450, "rows_after": 449,
                                "dropped": 0, "scope_processes": 24, "scope_rounds": 24,
                                "poi_kept": 1, "owner_missing": 0, "rows_judged": 449}},
           "judge": {"edges": 0, "calls": 0, "seconds": 0, "waves": 0, "wave_details": [],
                     "unjudged_waves": 0},
           "llm": {...}, "queries": 9, "query_rows": 40, "wall_seconds": 0.2,
           "expand_rounds": 5, "processes_examined": 24,
           "confirmed_triples": 0, "excluded_triples": 0, "unjudged_triples": 0,
           "state": {...}}}
```

口径补充：

- `event_id_resolved` / `event_id_unresolved` 只在真实运行（非 `--dry-run`）里出现：缺证据编号的边回库
  按内容三元组补编号。
- `edges` 装**确认边**：判为相关；判定只有一轮，没有第二批复核。模型在结论里多写的字段（如"把握"）
  **一律忽略**：不进报告、不进日志、不参与判断与评分。报告里没有 `mitre_technique`、没有模型自报的
  把握、也没有战术相位字段。
- `stats.unjudged_triples` 是"模型没给出可解析结论、或被调用上限熔断"的候选边数；**未判定 ≠ 排除**。
- 实体内容口径与 GT 一致：`Process=coalesce(exepath,name)`、`File=path`、`Network=lip:lport->rip:rport`。
- `stats.judge` 记 `waves` / `wave_details`（每波条数、批数、输入字符、确认/排除/缺失）等可审计计数；
  闭包与取数来源的逐项计数只在运行日志 `[expand] ...` 与轨迹文件 `trace-<run_id>.jsonl` 的
  `expand_closure` 事件里，报告里只有 `stats.expand` 的 `rounds` / `fold` / `scope`。