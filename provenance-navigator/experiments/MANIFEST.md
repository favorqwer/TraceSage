# B1 冻结清单

- 冻结日期：2026-11-04
- 源文件：`tmp/run_all_v4_experiment.py`
- 冻结副本：`provenance-navigator/experiments/run_v4_frozen.py`
- 冻结时仓库 commit：`9c11503c2c80daee95a604f561606295f1621d59`
- 冻结时 commit 时间：2026-11-04 17:04:16 +0800
- 路径改动：仅 `REPO_ROOT` 由 `parent.parent` 改为 `parents[2]`，业务逻辑未改。

## 开关

| 开关 | 值 |
|---|---|
| `USE_MOTIF_EVIDENCE` | `True` |
| `VARIANT` | `v4_motif_evidence` |
| `REAL_2HOP` | `True`（B1）；`False`（B0） |
| `CONTENT_BINDING` | `False` |
| `COVERAGE_MIN` | `0.5`（未启用） |
| `SPLIT_EVIDENCE` | `False` |
| `ANCHOR_PAIR_CONFIRM` | `False` |
| `SUBGRAPH_EVIDENCE` | `False` |
| `STRUCTURED_OUTPUT` | `False` |

## 入口

| 入口 | 作用 |
|---|---|
| `run_b1_real_2hop.py` | B1：`REAL_2HOP=True`，真 2 跳证据 |
| `run_b0_empty_labels.py` | B0：`REAL_2HOP=False`，复现空 2 跳标签 |
| `run_frozen_pair.py` | 批量重跑 B0/B1，支持 `--resume`，写 `tmp/frozen_runs/` |
| `experiment_engine.py` | 固化解码器；`decode_motif(..., real_2hop=)` 支持 B0/B1 |

## 观测

- 每个场景写 `<报告名>.trace.jsonl`：
  - `kind=batch`：束元数据、完整提示词、原始输出、verdicts；
  - `kind=detail`：逐束 `detail`（bundle id、level、size、verdict、reason、witnesses、sample）。
- `llm/client.py:set_trace_raw(True)` 让 `call_json` 返回 `_raw_text`。
- `llm/judge.py:set_trace_sink(fn)` 是逐批旁路钩子，默认关闭。

## 评分口径

- `tools/score_report_product.py` 已修：优先单数 `effect`，其次复数 `effects`；多值展开为多个四元组。
- 因此同一份报告在修复前后的查准分母/成败核验会变化；G0 的 B0/B1 数字以修复后为准，逐场景与交接文件并列记录差异。

## 输入与模型

- 折库：`output/navigator-baseline/distill/fold-libraries/<场景>.json`
- GT：`groundtruth/<场景>.groundtruth.json`（仅评分）
- 判定模型：`.env` 中 `OPENAI_MODEL`（当前为 `deepseek-v4.1-flash`）
- 温度：`0.0`
- 思考模式：`False`

## 证据标题格式（冻结版）

```text
【离线攻击基模参考证据】(本束成员 M 条，命中 N 个攻击基模):
```

## 已知边界

- 本冻结版保留 `tmp/experiment_engine.py` 的 `decode_motif()` 依赖；该文件仍在 `tmp/`，未纳入版本管理。若后续需要长期复现，应把解码器一并固化。
- 本冻结版保留硬编码维护 token 过滤与 `has_shell_parent` 子串匹配，未在本轮修改。
- 研究对象是 B1 实验流程：符号匹配只产生证据，不直接确认边；与 `routing/route.py` 的符号快速通道不同。
