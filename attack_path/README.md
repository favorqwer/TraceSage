# Attack Path：研究点二攻击路径推理主线

> **目录定位**：`attack_path/` 是 TraceSage **研究点二（基于静态贝叶斯网络的系统异常行为推理方法）** 的主开发目录，与研究点一主线目录 `attack_graph/` 并列。运行期全程零 Neo4j 依赖，只读消费 `output/attack-graph-baseline/events_v2/*.events.json.gz` 与单文件全属性索引 `graphs/<场景名>.tsg`。

## 1. 与 `attack_graph/` 的依赖与耦合边界

- **复用基础规则与索引工具**：`attack_path/` 通过 `_bridge.py` 导入 `attack_graph` 的场景配置、`domain.network`、`core.filters` 与无状态公共枢纽清单，并通过 `tsg.format.TSGReader` 按需零拷贝只读访问 `graphs/<场景名>.tsg`。
- **单向只读消费主线产物**：第一至第三阶段严格只读消费 `output/attack-graph-baseline/` 下的 `events_v2/*.events.json.gz`（不修改 `attack_graph/` 已有流程与正式基线）。
- **第四阶段反馈联动**：反馈优化闭环（问题 24）需与 `attack_graph/` 配合，通过显式开关参数增量接入复核接口，保留原基线独立复现能力。

## 2. 第一阶段已落地模块（问题 1 ～ 8 已闭环）

| 模块 | 职责 | 对应问题 |
|---|---|---|
| `attack_path/loader.py` | 零数据库直接加载并校验 `events_v2/*.events.json.gz` 与去重实体属性表 | 问题 1 |
| `attack_path/preprocess.py` | 失败/零字节读/退出过滤、容器前缀保护的 POSIX 路径规约与安全 `chroot` 别名还原、无状态枢纽阻断、外网拆向（`NetworkIn`/`NetworkOut`）与 `poi` 反向线性裁剪（含 `unlink` 重建分代截断） | 问题 6 + 问题 8 前置 |
| `attack_path/dag.py` | 按需最小版本分裂构建实体版本有向无环图（0 环）、基于传递祖先位图的因果等价流/多轮往返折叠、同 `event_id` 成对双边组标注与紧邻伴随调用归并、文件删除/截断断开延续边及二次反向修剪、Kahn 拓扑排序 0 环硬校验 | 问题 2 + 3 + 4 + 5 |
| `attack_path/diagnose.py` | 入度为 0 的候选入口 4 类审计分类、研究点一 `confirmed` 差集连通分量物理断链体检（不造假边）与 10 场景命令行汇总 | 问题 7 + 问题 8 |

## 3. 阶段规划与目录归属

| 阶段 | 对应问题清单 | 主要代码归属 | 核心职责 |
|---|---|---|---|
| 第一阶段：图数据准备与无环化（已完成） | 问题 1 ～ 8 | `attack_path/` | 单事件字段零查库加载、清洗与 `poi` 反向裁剪、实体版本有向无环图（0 环）构建、候选入口与物理断链诊断 |
| 第二阶段：真实攻击路径标注与评测 | 问题 9 ～ 16 | `attack_path/` | 路径级标准答案格式与校验器、10 场景人机路径标注、边传播训练标签派生、双阶段评分脚本 |
| 第三阶段：候选生成与静态贝叶斯推理 | 问题 17 ～ 23 | `attack_path/` | 受控候选路径生成、观测证据与边特征编码、证据相关性与共享证据处理、留一折参数估计、联合后验求解与 Top-K 排序 |
| 第四阶段：反馈优化闭环 | 问题 24 | `attack_path/` + `attack_graph/` | 高后验路径回传复核、受限误剪枝恢复与防误差累积 |

## 4. 校验测试与 10 场景第一阶段诊断命令

```powershell
# 运行全部单元测试
& ./.venv/Scripts/python.exe -m unittest discover -s attack_path/tests -p "test_*.py" -v

# 零 Neo4j 运行 10 场景第一阶段完整构图、0 环校验与断链体检
& ./.venv/Scripts/python.exe -m attack_path.diagnose
```
