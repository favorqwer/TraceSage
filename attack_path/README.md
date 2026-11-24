# Attack Path：研究点二攻击路径推理主线

> **目录定位**：`attack_path/` 是 TraceSage **研究点二（基于静态贝叶斯网络的系统异常行为推理方法）** 的主开发目录，与研究点一主线目录 `attack_graph/` 并列。

## 1. 与 `attack_graph/` 及 `tsg/` 的依赖与耦合边界

- **零 Neo4j 复用边界**：`attack_path/` 通过 `_bridge.py` 将 `attack_graph/` 置于 `sys.path` 前端并引入仓库根路径，仅复用 `attack_graph/settings.py`（提供场景 POI 配置与 `graph_path()` 路径解析）、`baseline_events_path()` / `events_path_for_report()` 路径定位以及 `tsg.TSGReader` 只读访问封装（`open_graph()`）。运行期不连接 Neo4j，也不依赖已废除的 `tmp/provenance/l1-index/` 或 `temporal_events.pkl`。
- **单向只读消费主线产物**：第一至第三阶段通过 `attack_path/loader.py`（`load_scenario_events()`）直接只读消费 `output/attack-graph-baseline/`（或 `output/attack-graph-runs/`）中的聚合报告与伴生单事件明细 `events_v2/*.events.json.gz`，以及单文件图索引 `graphs/<场景名>.tsg`，不修改 `attack_graph/` 已有流程与正式基线。
- **第四阶段反馈联动**：反馈优化闭环（问题 24）需与 `attack_graph/` 配合，通过显式开关参数增量接入复核接口，保留原基线独立复现能力。

## 2. 阶段规划与目录归属

| 阶段 | 对应问题清单 | 主要代码归属 | 核心职责 |
|---|---|---|---|
| 第一阶段：图数据准备与无环化 | 问题 1（已完成）+ 问题 2 ～ 8 | `attack_graph/` + `tsg/`（问题 1 已解决）；`attack_path/`（问题 2 ～ 8） | 问题 1 已由单文件 `.tsg`（v2）全属性索引 + 伴生 `*.events.json.gz` 出口与 `attack_path/loader.py` 彻底完成；问题 2 ～ 8 负责事件级 DAG 构建、路径规约与物理断链诊断 |
| 第二阶段：真实攻击路径标注与评测 | 问题 9 ～ 16 | `attack_path/` | 路径级标准答案格式与校验器、10 场景人机路径标注、边传播训练标签派生、双阶段评分脚本 |
| 第三阶段：候选生成与静态贝叶斯推理 | 问题 17 ～ 23 | `attack_path/` | 受控候选路径生成、观测证据与边特征编码、证据相关性与共享证据处理、留一折参数估计、联合后验求解与 Top-K 排序 |
| 第四阶段：反馈优化闭环 | 问题 24 | `attack_path/` + `attack_graph/` | 高后验路径回传复核、受限误剪枝恢复与防误差累积 |

## 3. 基础校验测试

```powershell
& ./.venv/Scripts/python.exe -m unittest discover -s attack_path/tests -p "test_*.py"
```
