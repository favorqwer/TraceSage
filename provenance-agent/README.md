# provenance-agent — 基于溯源图的反向追踪 agent

在 `scap-parser` 导入的 Neo4j 溯源图上，从 POI 出发**反向追踪**攻击因果链，产出可被
`tools/eval_agent_attack_path.py` 评分（与引擎 `tools/evaluate_gt.py` 同口径）的溯源报告。

## 2. 架构

三层，各占 `pagent/layers/` 下一个包（包内按用途分文件），只允许下游读上游；编排在
`pagent/orchestration/`，装配与流程顺序在 `pagent/app.py`，横切基础设施在 `pagent/core/`，
提示词与规则表是 `pagent/prompts/`、`pagent/rules/` 下的数据文件。**只有判定层调模型**；
展开、折叠、上下文渲染与报告全是纯代码。

```
起点定位 intake
  → 展开与折叠 expand_closure：反向闭包 → 折叠 = 候选表（第 1 层不做任何尾部裁剪；来源保持打开，供前向补链重跑）
  → 判定驱动 judging：把候选边打成五级「束」→ 首层按风险分数排序 → 逐级四值判定
     （一级一次调用、批内并发；一批失败整批重发）→ 四道结构闸门限制删边权限
     → 前向补链（未排除的写入对象后来被谁读走）→ 新增三元组再判一轮
  → 登记 register → 报告 build_report（三段：已确认 / 未排除 / 已排除）
```

| 组件 | 作用 | 代码 |
|---|---|---|
| 第 1 层 结构可达与折叠 | 从终点事件往回算**反向闭包**，折叠成内容三元组（= 候选表 = 召回上限；不做任何尾部裁剪） | `pagent/layers/l1_reach/` |
| 判定层 | 束的定义与五级细分、条目与渲染（批头共享表）、束级四值判定（调模型）、四道结构闸门、来路 | `pagent/layers/l2_judge/` |
| 表达层 | 三段报告装配、机制类分栏与证据编号回填（纯代码） | `pagent/layers/l3_express/` |
| 编排 | 起点定位 → 展开与折叠 → 判定驱动（含整批重试）→ 前向补链 → 登记 | `pagent/orchestration/` |
| 装配 / 横切 | 依赖容器与流程顺序 / 配置、场景、只读图访问、模型、记录、提示词与规则加载、轨迹 | `pagent/app.py` / `pagent/core/` |

### 模块目录结构

```
provenance-agent/
├── main.py               # 入口：命令行 + 文件落盘
├── config/agent.toml     # 全部参数（唯一真源）
├── config/scenarios.json # POI 唯一来源（库名 + POI；新场景附入口定义）
├── tests/                # dry_run.py（整链路干跑）、l1_ablation.py / l2_repeat.py（测量）、unit/（单测）
└── pagent/               # 核心包
    ├── app.py            # 装配（依赖容器 + 流程顺序）
    ├── contracts.py      # 层间数据结构与共享小助手
    ├── core/             # 横切：settings/scenarios/db/llm/record/prompts/rules/trace + graph_facts
    ├── prompts/          # 束级判定提示词（judge_bundle.md）与前向补链闸门提示词（forward_gate.md）
    ├── rules/            # l1_judgments.json（第 1 层判据：对象角色 / 事件判定）
    ├── orchestration/    # intake / expand_closure / judging / forward_chain / register
    └── layers/           # 各层一包（只许下游读上游，包内按用途分文件）
        ├── l1_reach/     # graph_index / walk / table+judgments / process_info / candidates
        ├── l2_judge/     # bundles / context / items+rendering / judge / guards / state / outcome
        └── l3_express/   # report / narrative / evidence
```

### 第 1 层：结构可达与折叠（`layers/l1_reach/`）

包内六个文件各管一件事：`graph_index.py`（顶点-时间索引，唯一的取数方式）、`walk.py`（闭包引擎
`run_closure` / `run_causal_closure` 与受限前向补链 `find_forward_seeds`）、`table.py` + `judgments.py`
（判据表的加载校验与唯一求值入口，含生命周期与载体判据）、`process_info.py`（进程静态属性缓存）、
`candidates.py`（折叠 `fold` / `fold_records`）。

**因果闭包**（`walk.run_causal_closure`）：反向因果遍历 + 受限前向补链。从终点事件出发按因果规则往回走：
① 同进程（先发生的可能影响后发生的）；② 同顶点交付（写入侧的起始不晚于读取侧的结束，只对能承载
内容的通道生效）；③ 派生（父→子，以及同一主体在门限之前派生出的其它子进程；有意的超集口径）。
推进用只增不减的时间门限（进程顶点取"起始不晚于门限"的全部入射事件，且门限至少抬到终点事件时刻；
文件/网络顶点只取写入侧），**不设任何条数上限**，终止条件只有"待考察清单耗尽"。

闭包之后做**折叠**（按 `(src 内容, syscall, dst 内容)` 合并实例，并把各实例的**入闭包通道**按位合起来）=
**候选表**（召回上限口径）。折叠时依据进程生命周期仅剔除首次对外动作之前读入且未被篡改的环境标准共享库
（`judgments.is_startup_dependency`），完整保留真实运行阶段的侦察读取。
**本层不做任何针对实验场景的尾部裁剪**：会少收的只有取数阶段的两处结构判据（非交付通道不往回找写入者、
零字节读不再往下展开，边本身照样收）。
每条边归一个进程（写文件/网络归源进程，被读写归目标进程，派生归子进程），进程身份摘要只用于渲染
与分组、不参与可达性计算；边的方向与两端标签由关系类型唯一决定（`core/graph_facts.py`）。

全部会改变结果的判据都在一张表 `pagent/rules/l1_judgments.json`（对象段 / 事件段）；
取数只有本地顶点-时间索引一条路，规则改动不需要重建索引。
当前五场景的候选表规模、召回与查准、闭包收边与耗时见 `docs/第一层形式化与召回上限对照.md` §5
（指标表用 `tests/l1_ablation.py` 量，单测在 `tests/unit/`）。

### 判定层与判定驱动（`l2_judge/` / `orchestration/judging.py`）

判定单位是**束**（同一批边打包），不是单条边；**只有「整束无关」会删边**，其余一律继续拆或保留。

1. **束的五级细分**（`bundles.py`，纯代码）：程序集合+关系类型+系统调用 → +入闭包通道 →
   +对象类别（文件按目录、网络按两端主机） → +对象身份 → 单条边。每级都是同一个候选集合的划分，
   下一级是上一级的细化（单测 `tests/unit/test_bundles.py` 断言）。
2. **条目与渲染**（`items.py` / `rendering.py`，纯代码）：每个束给结构摘要 + 成员样本；
   批头列两张**共享表**（「同类规模」= 本批涉及的每个对象类别有多少个束、中位成员数；
   「上一级束」= 子束拆自哪个更大的束，含当时判定与理由），束行用 C/P 编号引用；
   已判相关的束留下的对象类别/程序痕迹渲染成「线索」行。
3. **四值判定**（`judge.py`，调模型）：每个束回一个结论——整束相关 / 整束无关 / 混杂 / 判不了；
   判「混杂」要给一正一反两个成员编号（只用于排查）。提示词 `pagent/prompts/judge_bundle.md`。
   模型调用**不先思考**：请求显式带 `thinking = {"type": "disabled"}`（`judge.thinking` 默认 false）。
4. **四道结构闸门**（`guards.py`，纯代码、零额外调用）：空拆（与上一级成员相同不重判）、
   扇出（拆分产生的单条边子束不判）、类一致性（同类已有相关时同类判无关要降级）、
   凭证（判无关的束命中已知误杀模式——全是派生边 / 同一进程已确认——就降级为要拆）。
5. **失败处理**：一批调用失败（网关超时）→ 该批重发（一批最多尝试 `judge.batch_attempts` 次，
   默认 2 = 首次 + 失败后一次）；仍失败则该批的束记「没给结论」——继续拆，最后一律保留。
   达到 `bundle.cap_calls` 的束同样按「未排除」处理。**未判定 ≠ 排除。**

## 3. 运行

```bash
# 干跑测试：假判定模型驱动整条流水线，不调真实 LLM（改代码后先跑）
python provenance-agent/tests/dry_run.py
python provenance-agent/tests/dry_run.py 2_SSH_Spray_Lateral_Exfiltration
DRY_JUDGE_DROP_ID=keep python provenance-agent/tests/dry_run.py   # 默认故意漏几条 id（测缺失路径）；=keep 时不漏

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
python tools/eval_agent_attack_path.py --report output/agent-runs/1_Web_Exploit_Ransomware.json \
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
| `output/agent-runs/<场景>.json` | 溯源报告（schema 见下）；`SUMMARY.json` 为多场景汇总。**每次运行的输出都写 `agent-runs/`**；成绩基线在 `output/agent-baseline-current/`（当前版本）与 `output/agent-baseline-archive/`（归档），运行不得写这两个目录。GT 评分用 `tools/eval_agent_attack_path.py`（`--json-out` 可另存） |
| `output/agent-baseline-current/OVERVIEW.md` | 当前基线的成绩总览表（本次 / 上一版逐场景对比：已确认召回查准、未排除召回查准、LLM 调用、token、判定耗时、LLM 累计耗时、墙钟）；归档基线 `agent-baseline-archive/OVERVIEW.md` 与引擎基线 `engine-baseline/OVERVIEW.md` 同格式，缺数据的列留空 |
| `tmp/provenance-agent/dry-run/<场景>.json` | `--dry-run` 的报告（诊断产物，**不写 output/**） |
| `tmp/provenance-agent/logs/queries-<run_id>.jsonl` | 每次查询的 Cypher/参数/行数/耗时/是否截断 |
| `tmp/provenance-agent/logs/bundles-<run_id>.jsonl` | **逐束判定明细**（四值结论、理由、闸门说明；判「无关」的束附结构凭证事实） |
| `tmp/provenance-agent/logs/llm-<run_id>.jsonl` | 每次模型调用的提示词字符 / 原始输出字符 / 输出 token / 耗时 + 文本样本 |
| `tmp/provenance-agent/logs/trace-<run_id>.jsonl` | 阶段轨迹（intake / 展开 / 每波判定 / 报告） |
| `tmp/provenance-agent/state/record-<run_id>.json` | 调查记录（实体 / 假设 / 缺口 + 关系列表与状态统计） |
| `tmp/provenance-agent/l1-ablation/<场景>.json` | 第 1 层指标表结果（`--report` 汇总成同目录的 `SUMMARY.md` / `SUMMARY.json`） |
| `tmp/provenance-agent/l2-runs/` | 判定层重复运行结果（`runs/` 逐轮报告、`eval/` 逐轮评分、`metrics.json` 与 `SUMMARY.md` 汇总） |
| `tmp/provenance-agent/l1-index/<库名>/` | 顶点-时间索引快照（可重建的派生数据，不是测量结果；缺失或过期自动重建） |

> `tmp/` 是临时区：**只保留最近一次测量的结果文件**，历史运行记录（日志、旧的测量结果、调查记录）
> 确认不再需要后直接删除。删除 `state/` / `logs/` / `dry-run/` 不会影响运行，下次跑会自动重建。

报告 schema（`output/agent-runs/<场景>.json`）的用途：它是 agent 的唯一交付格式，字段固定供三方消费——
① 评分（`tools/eval_agent_attack_path.py` 读 `edges` 的内容三元组 `src`/`syscall`/`dst`，与 GT 的必须条目和
可能集合规则比对：召回按步骤（命中条目 + 命中规则）/（条目 + 规则）、查准按边（命中条目边 + 满足规则的边）/报告去重三元组；
`unexcluded` / `excluded` 两段用同一个口径另行评分）；② 人工排查（`narrative` 时间线、
`entry_point` 入口点、`gaps` 缺口、`hypotheses` 假设）；③ 观测与审计（`stats` 各阶段计数、
`stop_reason` 停止原因，每条确认边的 `event_id`/`instances`/`bytes`/`reason`/`process_id` 可回溯证据）。

```json
{"scenario": "...", "run_id": "...", "poi": {"kind": "...", "rel": "...", "syscall": "...", "key": "..."},
 "edges": [{"src": "...", "syscall": "...", "dst": "...",
            "event_id": 123, "instances": 4, "bytes": 1024, "reason": "...",
            "process_id": "...", "origin": "confirmed", "class": "story|mechanism"}],
 "unexcluded": [{"src": "...", "syscall": "...", "dst": "...", "origin": "confirmed|kept"}],
 "excluded": [{"src": "...", "syscall": "...", "dst": "...", "origin": "excluded"}],
 "narrative": "（确定性时间线，非 LLM 生成）", "entry_point": "...",
 "gaps": [{"label": "...", "next_action": "...", "status": "open"}],
 "hypotheses": [{"key": "POI", "label": "...", "status": "confirmed"}],
 "reflection": {"sufficient": true, "critique": "...", "expand_rounds": 5, "derived_by": "rules"},
 "selection_note": "三段报告：已确认 30 条（解释链候选 25 / 机制类 5）；未排除 120 条；已排除 8 条",
 "generated_by": "deterministic_reporter",
 "stop_reason": "frontier_exhausted|dry_run",
 "event_id_resolved": 30, "event_id_unresolved": 0,
 "stats": {"expand": {"rounds": 5,
                      "fold": {"raw_instances": 450, "collapsed_triples": 110}},
           "judge": {"candidates": 110, "calls": 0, "seconds": 0, "levels": [], "passes": [],
                     "guards": {...}, "forward": {...}, "missing_bundles": 0},
           "llm": {...}, "queries": 9, "query_rows": 40, "wall_seconds": 0.2,
           "expand_rounds": 5, "processes_examined": 24, "candidates": 110,
           "confirmed_triples": 30, "story_triples": 25, "mechanical_triples": 5,
           "kept_triples": 72, "unexcluded_triples": 102, "excluded_triples": 8,
           "selfcheck": {...}, "state": {...}}}
```

口径补充：

- **三段报告**：`edges`（已确认）= 模型判「整束相关」的边；`unexcluded` = 已确认 + 其余未排除的边
  （含被闸门跳过、没轮到判、达到调用上限的），它是**覆盖可证明**的那一段；`excluded` = 只由
  「整束无关」产生的删边。除「整束无关」外，任何结论（混杂 / 判不了 / 没答 / 没判到）都不删边。
- `edges` 里每条边的 `class` 分两栏：`story`（解释链候选）与 `mechanism`（机制类：只读边 + 对象落在
  系统路径前缀里）。机制类**只分栏、不删除**（里面藏着读 `/etc/shadow` 这类凭据步骤）。
- `event_id_resolved` / `event_id_unresolved` 只在真实运行（非 `--dry-run`）里出现：缺证据编号的边回库
  按内容三元组补编号。
- 模型在结论里多写的字段（如“把握”、见证编号）**一律忽略**：不进报告、不进日志、不参与判断与评分。
  报告里没有 `mitre_technique`、没有模型自报的把握、也没有战术相位字段。
- `stats.selfcheck` 记三条恒等式（每条候选边都有来路、已确认 ⊆ 未排除、未排除 + 已排除 = 候选）。
  被闸门跳过 / 没轮到判的边都在未排除段里，**未判定 ≠ 排除**。
- 实体内容口径与 GT 一致：`Process=coalesce(exepath,name)`、`File=path`、`Network=lip:lport->rip:rport`。
- `stats.judge` 记 `levels`（每级束数、批数、四值计数、单批最大输入字符）/ `passes` / `guards` /
  `forward` 等可审计计数；闭包与取数来源的逐项计数在运行日志 `[expand] ...` 与轨迹文件
  `trace-<run_id>.jsonl` 的 `expand_closure` / `expand_forward` 事件里。