# 纯 LLM 溯源基线（plain_llm）

对照实验用的第三方基线：**只让大模型读溯源图的边，判断哪些边属于这起入侵**，不使用规则库、不做图遍历、不做向量检索、不加时间窗、不按场景调阈值。用于和下列两套已固化基线在同一批场景、同一份标准答案、同一个评分工具下比较：

| 系统 | 位置 |
|---|---|
| attack_graph（当前主线正式基线，零 Neo4j） | `output/attack-graph-baseline/` |
| provenance（历史冻结基线） | `output/provenance-baseline/` |
| engine（DEPIMPACT 纯图遍历，读取 `-v2` Neo4j） | `output/engine-baseline/` |
| 纯 LLM（本目录，读取 `-v2` Neo4j） | `output/plain-llm-runs/` |

提示词口径参考 `E:\Work\ProGQL` 的 LLM 用法：边以 `[类型|标识] --动作--> [类型|标识]` 文本给出，模型只回答"删/留"，温度 0，严格 JSON，按 200 条一批。**没有**移植 ProGQL 的查询引擎、入口预排序、子图切分和语义修复 Agent——这些属于额外机制，不属于"最普通的 LLM 用法"。

## 输入口径与边界（出数字前必须读）

1. **前置输入共用**：解析器建图、Neo4j `-v2` 图库、POI（调查起点）都不是 LLM 的自主发现能力；三方共用同一套图与同一个 POI（`provenance/config/scenarios.json`）。
2. **输入是去重边表**：模型看到的是全图按 `(源, 系统调用, 目标, 成败)` 去重后的边，带实例数、首末时间、载荷预览；不是原始 syscall 流。整图实例边合计约 842 万条，任何上下文都放不下，"一次性喂全图"不存在。
3. **去重的代价**：同一行为的多次发生被合并成一行，模型看不到"第几次"，只看到次数与首末时间。
4. **无其他机制**：没有规则库、embedding、图遍历、时间窗、白名单、按场景调整的阈值；十场景共用同一套提示词（`prompts/`）。
5. **评定只看边**：模型自报的 stage、why、入口判断都不参与评分；评分只看 `edges` 的 `(src, syscall, dst, effect)`。
6. **模型与温度**：默认沿用仓库根目录 `.env` 的 `OPENAI_MODEL`（当前 `deepseek-v4.1-flash`，与 provenance 基线同一模型），温度 0。
7. **产物归属**：本目录只写 `output/plain-llm-runs/`，不覆盖 `output/engine-baseline/` 与 `output/provenance-baseline/`。

## 端点注意事项

- 当前端点 `https://opencode.ai/zen/go/v1` 要求 `x-opencode-session` 请求头；端点包含 `opencode.ai` 时客户端自动补（默认 `ses_tracesage_plainllm`，可在 `config.yaml` 改）。缺这个头时服务端返回 400 `MissingSessionID`。
- 请求体默认带 `thinking: {"type": "disabled"}`，与 provenance 基线关闭思考模式的设置一致；换模型或换端点时按对方接口文档调整 `extra_body`。

## 目录结构

```
experiments/plain_llm/
├── config.yaml                 # 模型/端点/批大小/并发/载荷预览长度
├── prompts/                    # 冻结的两阶段提示词
├── run_scenario.py             # 单场景入口
├── run_all.py                  # 十场景批量入口
├── score_and_summarize.py      # 评分 + 三方对比表
└── plainllm/
    ├── settings.py             # 配置加载（.env + config.yaml）
    ├── client.py               # OpenAI 兼容客户端：重试/退避/用量记账
    ├── export_graph.py         # Neo4j → 内容去重边表 JSONL
    ├── chunking.py             # 稳定排序、切块、单行格式
    ├── poi.py                  # 场景/POI/锚点边解析
    ├── scan.py                 # 阶段一：全量边逐批判定
    ├── assemble.py             # 阶段二：候选边拼成攻击链
    ├── report.py               # 写 report.json（可被评分工具直接读）
    └── run_scenario.py         # 单场景编排 + manifest
```

## 运行

```bash
# 1. 单场景
python experiments/plain_llm/run_scenario.py --scenario 1_Web_Exploit_Ransomware

# 2. 十场景（场景逐个跑，场景内部按 concurrency 并发）
python experiments/plain_llm/run_all.py

# 3. 评分与三方汇总
python experiments/plain_llm/score_and_summarize.py
```

常用参数：

- `--chunk-size`：阶段一每批边数，默认 200。
- `--assemble-chunk`：阶段二每批候选边数，默认 150。
- `--concurrency`：阶段一并发数，默认 4。
- `--no-resume`：忽略已落盘的批次检查点，重新请求。
- `--reexport`：强制重新导出边表。
- `--skip-existing`：已有 `report.json` 的场景跳过。

## 产物

每个场景一个目录 `output/plain-llm-runs/<场景>/`：

| 文件 | 内容 |
|---|---|
| `edges.jsonl` | 全图内容去重边表（含实例数、首末时间、成败、载荷预览） |
| `stats.json` | 导出统计（实例边数、四元组数、顶点数、时间范围、文件哈希） |
| `scan/chunk200/chunk_*.json` | 阶段一每批的结论与原始摘要（断点续跑依据） |
| `assemble/chunk150/batch_*.json` | 阶段二每批保留清单、阶段号、脉络 |
| `calls.jsonl` | 每次模型调用的耗时、token、状态、完整提示词与响应原文（响应截断 4000 字符） |
| `report.json` | 交付报告，`edges` 可直接被 `tools/score_report_product.py` 评分 |
| `manifest.json` | 配置快照、提示词/代码哈希、输入指纹、调用与耗时汇总 |
| `metrics.json` | 评分工具对该场景的输出（`score_and_summarize.py` 生成） |

汇总：`output/plain-llm-runs/OVERVIEW.md`（三方对比表）、`summary.json`（机器可读）、`run_summary.json`（批量运行成本）。

## 规模实测（决定了切批数）

| 场景 | 图实例边 | 内容四元组 | 200 条/批 → 批数 |
|---|---:|---:|---:|
| 1_Web_Exploit_Ransomware | 1,219,143 | 37,756 | 189 |
| 2_SSH_Spray_Lateral_Exfiltration | 573,086 | 13,673 | 69 |
| 3_Phishing_Beacon_Cryptomining | 691,911 | 22,011 | 111 |
| 4_Repo_Poisoning_Backdoor | 377,701 | 26,247 | 132 |
| 5_Exposed_Service_Pivot | 123,144 | 20,626 | 104 |
| 6_Web_SQLi_Data_Exfiltration | 725,504 | 9,664 | 49 |
| 7_DB_Bruteforce_Datawipe | 142,087 | 6,560 | 33 |
| 8_FTP_WeakCreds_WebShell_Exfiltration | 1,381,898 | 9,471 | 48 |
| 9_Exposed_Container_Escape | 375,742 | 17,358 | 87 |
| 10_Tomcat_Weakcreds_DNS_Exfiltration | 2,810,673 | 129,879 | 650 |
| **合计** | **8,420,889** | **293,245** | **1,472** |

## 成本估算（未实测，按上一节边数推算）

- 阶段一：1,472 次调用（每批 200 条）。按每条边约 30 token、每次固定提示约 1,500 token 估算，输入约 1,100 万 token；输出按选中边数计，通常几十万 token。
- 阶段二：批次 = 阶段一选中边数 / 150，输入约为被选中边的全部文本。
- 墙钟：并发 4、单次 6 秒估算，阶段一约 40 分钟；阶段二与选中量成正比。
- 以上只是推算，实际数字以 `run_summary.json` 与各场景 `manifest.json` 为准（调用数、token、耗时都是实测落盘）。

## 调参纪律

- 提示词、切批大小、并发数在开跑前定稿；开跑后不得为了提升指标按场景修改。
- 任何改动都会改变 `manifest.json` 里的提示词/代码哈希与 `edges_sha256`，比对时必须先核对哈希。
- 结果的解释口径：召回与查准分母不同，禁止合成 F1；跨场景只用合并平均（按判定对象加权），同时给逐场景配对差值。

## 已知局限

- 每场景只跑一次，未测重复运行波动；服务端在温度 0 下仍可能非确定。
- 内容去重会合并不同进程实例的相同行为，模型无法区分"哪个进程实例"。
- 阶段一各批之间不共享上下文（只共享 POI 与全图规模），跨批的因果链只能靠阶段二拼接。
- 单批 200 条边里绝大多数是正常背景，模型逐批判定的召回与查准上限受这一形态限制；本基线不做任何"先筛后判"的优化，否则就引入了额外机制。
