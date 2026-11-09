# FLEXIS/TraceSage 良性活动先验挖掘交接文档

> 交接对象：下一位继续处理本任务的 agent   
> 文档目的：完整说明当前已经做过的事情、当前产物、真实算法边界、如何在不调用 LLM 的情况下验证效果，以及后续工作顺序。  
> 当前文档版本：2026-11-06  16:30 左右（以工作区文件和产物为准）

## 1. 用户目标与当前结论

用户原始目标：

1. 找到论文 `FLEXIS: FLEXible Frequent Subgraph Mining using Maximal Independent Sets` 的开源代码并下载；
2. 不使用 10 个场景的 groundtruth，直接从训练集日志中离线提取高频系统活动模式；
3. 构建用于 RAG 导航辅助判断的良性系统活动先验规则库；
4. 每一步向用户反馈。

当前必须对用户保持的准确结论：

- FLEXIS 作者开源仓库已经找到并下载。
- 当前 TraceSage 工具是“受 FLEXIS 启发的流式适配器”，**不是 FLEXIS 完整算法复现**。
- 当前已完成 10 个解析图的无 GT、无 LLM 流式扫描。
- 当前生成了 7 条未标注的一跳活动先验规则。
- 当前没有把这些规则导入 Neo4j，也没有接入现有 RAG 导航器。
- 当前不能报告召回率、查准率或 RAG 导航提升数字。
- 当前不能把这 7 条规则称为已经证明的“良性白名单”。10 个输入场景本身都是攻击场景，跨场景高频只能说明重复出现，不能单独证明良性。

## 2. 上游 FLEXIS 代码

### 2.1 仓库信息

- 上游仓库：<https://github.com/akshit-sharma/flexis>
- 本地目录：`third_party/flexis/`
- 当前 commit：`9f260efa658bec39ffd514eec6765a94417ae9c9`
- commit 提交者：`akshit-sharma`
- commit 日期：`2025-06-23`
- 仓库构建方式：C++/CMake/Ninja/vcpkg
- 上游输入：FLEXIS 自定义 `vf3.bin` 图文件
- 上游 CLI 核心参数：`--input`、`--support`、`--max-size`、`--slider`

上游源码关键位置：

- `third_party/flexis/src/mining.cpp`：FLEXIS 主循环；初始边模式、匹配、候选扩展、循环终止。
- `third_party/flexis/src/generator.hpp`：Core Graph、Core Group、模式合并、clique 处理、Bliss 规范化相关代码。
- `third_party/flexis/src/matcher.hpp`：VF3Light 子图匹配、非重叠节点使用状态、mIS 相关匹配流程。
- `third_party/flexis/src/pattern.hpp`：模式图、图标签、Bliss canonical form、自动同构等。
- `third_party/flexis/Readme.md`：构建和运行说明。

### 2.2 论文方法的必要组成

论文文件：

`docs/paper/useful/2025_FLEXIS_FLEXible_Frequent_Subgraph_Mining_using_Maximal_Independent_Sets.pdf`

论文 PDF 内部标注为 `arXiv:2404.01585v1`，标题为：

`FLEXIS: FLEXible Frequent Subgraph Mining using Maximal Independent Sets`

论文 Algorithm 1 的流程是：

1. 从数据图生成所有 size-2 边模式；
2. 用阈值 `tau` 和 VF3 matcher 找频繁模式；
3. 将频繁的 `(k-1)` 顶点模式扩展为 `k` 顶点候选；
4. 循环执行匹配和扩展，直到候选为空。

论文 Algorithm 2 的候选生成不是简单二跳枚举，而是：

1. 从 `(k-1)` 模式拆出 Core Graph；
2. 按去掉标记顶点后的同构关系构建 Core Group；
3. 在同一 Core Group 中成对选取 Core Graph；
4. 枚举自动同构；
5. 合并两个 Core Graph 的标记顶点；
6. 对生成候选使用 Bliss canonical form 去重；
7. 对 clique 模式执行额外的 clique candidate 生成。

论文的支持度部分使用 mIS/最大独立出现集方向，并通过 `slider` 控制与 MIS 的重叠程度。上游 `matcher.hpp` 中的匹配过程会维护已使用数据图节点状态，避免选择共享节点的匹配。

## 3. 当前 TraceSage 实现

当前工具：

`tools/mine_flexis_benign_prior.py`

它的模块级说明已经明确写出：这是 “adapter inspired by FLEXIS”，不是直接调用上游 FLEXIS binary。

### 3.1 当前输入

当前默认输入不是原始 JSONL，也不是 groundtruth，而是已经由 TraceSage parser 生成的 `nodes.csv` 和 `edges.csv`：

| 场景 | 当前解析图目录 |
|---|---|
| `1_Web_Exploit_Ransomware` | `output/parser-v2/1_Web_Exploit_Ransomware-r3/` |
| `2_SSH_Spray_Lateral_Exfiltration` | `output/parser-v2/2_SSH_Spray_Lateral_Exfiltration-r3/` |
| `3_Phishing_Beacon_Cryptomining` | `output/parser-v2/3_Phishing_Beacon_Cryptomining-r3/` |
| `4_Repo_Poisoning_Backdoor` | `output/parser-v2/4_Repo_Poisoning_Backdoor-r3/` |
| `5_Exposed_Service_Pivot` | `output/parser-v2/5_Exposed_Service_Pivot-r3/` |
| `6_Web_SQLi_Data_Exfiltration` | `output/parser-v2/6_Web_SQLi_Data_Exfiltration-r3/` |
| `7_DB_Bruteforce_Datawipe` | `output/parser-v2/7_DB_BruteForce_DataWipe-r3/` |
| `8_FTP_WeakCreds_WebShell_Exfiltration` | `output/parser-v2/8_FTP_WeakCreds_WebShell_Exfiltration-r3/` |
| `9_Exposed_Container_Escape` | `output/parser-v2/9_Exposed_Container_Escape-r9/` |
| `10_Tomcat_Weakcreds_DNS_Exfiltration` | `output/parser-v2/10_Tomcat_Weakcreds_DNS_Exfiltration-r3/` |

脚本中的固定场景映射在 `tools/mine_flexis_benign_prior.py:33` 附近的 `SCENARIOS` 常量中。

### 3.2 当前处理流程

脚本按场景串行处理，每份 CSV 都是流式读取，不把全量边文件装进内存。

#### 第一遍扫描

对应 `first_scan()`，约在 `tools/mine_flexis_benign_prior.py:250`：

- 读取 `nodes.csv`，建立 parser 节点主键到整数 ID 的映射；
- 流式读取 `edges.csv`；
- 为每个节点记录入边动作和出边动作的 bit mask；
- 记录文件写入者集合，最多保留 3 个写入者用于角色分类；
- 不读取 groundtruth。

#### 角色分类

对应 `assign_roles()` 以及 `process_role()`、`file_role()`、`network_role()`，约在 `:194-248`：

- Process 角色形如 `P.<direction>.<spawn>.<instance>.<priv>`；
- File 角色形如 `F.<bits>.<writers>.<sensitivity>.<place>`；
- Network 角色形如 `N.<direction>.<peers>`；
- 角色只使用解析图节点属性和边动作，不使用 GT；
- 当前 process instance 分档使用固定阈值：`<3` 为 `single`，`3-55` 为 `few`，`>=56` 为 `many`；
- 当前网络 peers 角色固定输出 `single`，没有实现完整动态 peer 分档。

#### 第二遍扫描

对应 `second_scan()`，约在 `tools/mine_flexis_benign_prior.py:277`：

- 将每条实际边转换为 `(src_role, syscall, dst_role)` 一跳签名；
- 统计每个场景中该签名的原始出现次数；
- 对每个中间节点，用入签名和出签名构造有限的二跳候选；
- 每个节点的二跳类型组合最多保留 `--max-pairs-per-node` 个，默认 1000；
- 二跳候选总数最多保留 `--max-two-candidates` 个，默认 500。

#### 支持度计算

对应 `greedy_one_support()` 和 `greedy_two_support()`，约在 `:321-370`：

- 一跳规则：按 CSV 事件顺序扫描；同一候选的两个端点都未被该候选之前的匹配占用时，计为一次节点不重叠出现；
- 二跳规则：每个中间节点只使用首个入邻接代表和首个出邻接代表；
- 这是确定性的贪心 maximal node-disjoint occurrence set；
- 这不是精确 Maximum Independent Set；
- 没有实现论文的 `slider`，也没有实现论文 mIS 的完整阈值插值逻辑。

#### 候选准入

默认参数：

```text
min_scenario_support = 7
min_edge_count       = 100
min_mis_support      = 3
max_pairs_per_node   = 1000
max_two_candidates   = 500
```

含义：

- 至少在 7 个场景出现；
- 对每个实际出现该签名的场景，原始边出现数至少 100；
- 对每个实际支持场景，贪心节点不重叠支持度至少 3；
- 二跳候选数量受限以避免高连接度节点产生无界笛卡尔积。

## 4. 当前产物

输出目录：

`output/rule-kg/flexis-benign-v1/`

文件：

- `folds/global.json`：完整规则和候选诊断；
- `manifest.json`：与 `global.json` 基本相同，并附 `folds.global` 入口；
- `tmp/flexis-benign-v1.log`：最近一次全量运行日志。

主要元数据：

```json
{
  "version": "flexis-benign-v1",
  "groundtruth_used": false,
  "counts": {
    "motifs": 7,
    "admitted": 7,
    "hops": 7,
    "one_hop": 7,
    "two_hop": 0
  }
}
```

产物中还记录：

- 论文版本和上游仓库地址；
- 上游 FLEXIS commit；
- 输入场景及具体 `edges.csv`、`nodes.csv` 路径；
- 筛选阈值；
- 每条候选的原始出现数；
- 每个场景的 greedy MIS 支持度；
- 17 条一跳候选的淘汰诊断。

### 4.1 最终 7 条规则

| ID | 结构 | 场景数 | 各支持场景最低原始次数 | 各支持场景最低贪心独立支持 |
|---|---|---:|---:|---:|
| `FLEXIS_PRIOR_00001_1HOP` | `F.r.none.-.sys --read--> P.none.exec.few.-` | 8 | 131 | 4 |
| `FLEXIS_PRIOR_00002_1HOP` | `F.r.none.-.usr --read--> P.none.exec.few.-` | 10 | 119 | 3 |
| `FLEXIS_PRIOR_00003_1HOP` | `F.r.none.-.usr --read--> P.none.leaf.single.-` | 10 | 6699 | 7 |
| `FLEXIS_PRIOR_00004_1HOP` | `F.wr.single.-.usr --read--> P.none.leaf.single.-` | 10 | 128 | 3 |
| `FLEXIS_PRIOR_00005_1HOP` | `F.xr.none.-.sys --mmap--> P.both.exec.few.-` | 8 | 280 | 3 |
| `FLEXIS_PRIOR_00006_1HOP` | `P.both.leaf.single.- --sendto--> N.dial.single` | 10 | 224 | 3 |
| `FLEXIS_PRIOR_00007_1HOP` | `P.none.leaf.single.- --write--> F.wr.single.-.usr` | 10 | 128 | 3 |

### 4.2 当前结果的正确解释

这些规则表示：在当前 10 个攻击场景的解析图中，某些带角色和系统调用标签的活动类型重复出现，并且在当前贪心节点不重叠计数下达到设定阈值。

这些规则**不表示**：

- 规则已经被证明是良性；
- 规则不会覆盖攻击行为；
- 规则已经能提升 RAG 导航效果；
- 规则是论文 FLEXIS 完整算法的输出；
- 规则的 2-hop 结果为零意味着数据中没有频繁二跳模式。

## 5. 非常重要的已知限制

### 5.1 当前不是 FLEXIS 完整复现

当前代码没有实现：

- Core Graph；
- Core Group；
- 两个 `(k-1)` 频繁模式的逐层合并；
- clique candidate 生成；
- Bliss canonical form 去重；
- Bliss 自动同构枚举；
- VF3Light 子图同构匹配；
- 论文 `slider`；
- 论文 mIS 的完整阈值计算；
- 逐层 BFS 终止逻辑。

因此当前结果不能用于声称“复现 FLEXIS 论文实验”。

### 5.2 二跳结果存在明确的下采样问题

`second_scan()` 为每个节点的每个签名只保存一个首个邻接：

- `first_in[dst].setdefault(signature, src)`；
- `first_out[src].setdefault(signature, dst)`。

`greedy_two_support()` 后续只用这些首个代表构造二跳实例。因此：

- 二跳候选本身已经受每节点组合上限影响；
- 二跳实例又受首个邻接代表限制；
- 当前 `two_hop=0` 不能作为“没有频繁二跳活动模式”的结论；
- 若后续要研究二跳或严格复现 FLEXIS，必须重写二跳匹配和候选保存方式。

### 5.3 角色抽象会合并不同具体实体

当前签名只保留：

```text
源角色 + syscall + 目标角色
```

它不保留：

- 具体文件路径；
- 具体进程可执行路径；
- 具体网络端点；
- event_id；
- 时间间隔；
- result 成功/失败；
- edge class 的完整差异。

因此当前规则适合做粗粒度候选背景证据，不适合直接当作无条件白名单。

### 5.4 输入不是纯良性训练集

这 10 个场景是攻击场景。即使规则跨 10 个场景出现，也可能是：

- 系统基础活动；
- 攻击前后的常规服务活动；
- 多个攻击场景共有的攻击基础设施活动；
- 解析图中反复出现的后台程序活动。

要证明“良性”，需要独立的纯良性日志或人工审核标签；不能仅靠当前 10 个攻击场景的无监督频次。

### 5.5 当前没有 RAG/Neo4j 接入

现有 `output/rule-kg/v1` 是项目已有规则知识库，不是本次 FLEXIS 适配器产物。当前没有把 `flexis-benign-v1` 合并或导入 `trace-rules-kg-v1`，也没有修改在线检索代码使其读取这 7 条规则。

不要直接覆盖 `output/rule-kg/v1`，不要把 `flexis-benign-v1` 改名成正式基线。

## 6. 已知运行历史

第一次全量运行时使用了 `min_mis_support=10`，并且实现把未出现的场景按 0 纳入最低 MIS 判定，最终得到 0 条规则。该问题已修正：

- 最低 MIS 只在该候选实际出现的支持场景内计算；
- 默认 `min_mis_support` 调整为 3；
- 最终运行得到 7 条一跳规则、0 条二跳规则；
- 最近一次完整运行日志末尾为 `elapsed_seconds: 118.832`；
- 最近一次扫描所有场景的 `bad_edges=0`。

因此不要把第一次的 0 条结果当作当前最终结果。

## 7. 不调用 LLM 的验证方案

下一 agent 继续工作时，先完成以下离线验证，不调用任何模型接口，不运行 `provenance/main.py` 的 LLM 判定流程。

### 7.1 结构和来源验证

目标：确认产物确实来自指定输入，且没有偷偷读取 GT。

检查项：

1. `global.json` 中 `groundtruth_used == false`；
2. `source.upstream_commit` 与 `git -C third_party/flexis rev-parse HEAD` 一致；
3. `input_files` 的 10 组文件全部存在；
4. 每个输入文件都位于预期的 parser-v2 场景目录；
5. 输出 `motifs`、`hops`、`counts` 数量一致；
6. 每个 motif 的 hop 能重建其结构；
7. 每个 motif 的 `support_scenarios` 与 `raw_occurrences_by_scenario`、`greedy_mis_support_by_scenario` 的键一致；
8. `bad_edges` 全部为 0；
9. 工具源码中没有导入 `groundtruth` 文件的逻辑；
10. 运行日志没有 LLM、Neo4j 写入或在线导航调用。

### 7.2 确定性验证

同一输入重复运行两次，比较去掉以下运行时字段后的 JSON：

- `elapsed_seconds`；
- 如果后续增加时间戳，也要排除时间戳。

应比较：

- motif ID；
- motif 结构；
- 场景支持集合；
- 原始出现次数；
- greedy MIS 支持度；
- 输入文件列表；
- 筛选阈值。

如果两次结构结果不一致，应先阻断，不要继续接入 RAG。

### 7.3 无 GT 的活动频率验证

这只能验证“频繁”和“结构稳定”，不能验证“良性”：

1. 重新统计每条最终规则在每个场景中的原始出现数；
2. 重新统计每条最终规则的节点不重叠支持度；
3. 检查所有规则满足 `scenario_support >= 7`；
4. 检查所有规则在每个支持场景满足 `raw >= 100`；
5. 检查所有规则在每个支持场景满足 `greedy_mis >= 3`；
6. 抽取每条规则的实际端点样本，查看是否集中在单一固定节点；
7. 抽取每条规则涉及的 `edge_class`、`action`、`syscall`、`result` 分布，确认角色签名没有掩盖成功/失败差异。

### 7.4 使用 GT 的事后污染审计

GT 不参与规则生成，但可以在生成后用于独立审计。要明确标记为“事后审计”，不能称为训练过程的一部分。

对每条规则和每个场景计算：

- 规则匹配边总数；
- 匹配到 GT 攻击边的数量；
- 匹配到非 GT 攻击边的数量；
- 攻击污染率；
- 按 `(src, syscall, dst, effect)` 去重后的污染率；
- 规则覆盖的 GT 步骤数量。

建议至少输出：

```text
rule_id
scenario
all_matches
attack_matches
non_attack_matches
attack_contamination_rate
matched_gt_steps
```

不要把“非 GT 边”直接称为“良性边”。groundtruth 只标注已知攻击步骤，未标注部分仍可能是未标注攻击或背景。

### 7.5 独立良性数据验证

要把规则称为良性白名单，必须增加独立纯良性输入：

- 纯良性运行日志；
- 与当前 parser 相同 schema 的 `nodes.csv` / `edges.csv`；
- 明确采集时间、主机、软件和运行任务；
- 不得用攻击场景中人工挑出的“看起来正常”边代替。

在独立良性数据上测：

- 规则覆盖率；
- 每条规则的出现稳定性；
- 不同主机/不同时间段的稳定性；
- 规则命中的具体节点和路径分布。

没有独立良性数据，只能使用“未标注活动先验”这一名称。

### 7.6 RAG 价值验证，但仍不调用 LLM

在接入 LLM 之前，可以验证检索层是否有用：

1. 将 7 条规则转换为与现有 `Motif/Hop` 兼容的离线 JSON；
2. 写一个只做规则匹配的离线检索器；
3. 输入现有候选边或候选束；
4. 统计 exact/partial 命中率、每束证据数、空结果率；
5. 与现有 `output/rule-kg/v1` 的检索结果做并列比较；
6. 不修改正式 `output/rule-kg/v1`，单独输出实验目录。

只有在检索层结果稳定、污染审计完成后，才讨论是否允许调用 LLM 比较导航决策效果。

## 8. 后续工作建议顺序

### 阶段 A：先做当前适配器审计

1. 补结构校验脚本；
2. 补确定性比较；
3. 补 GT 事后污染审计；
4. 重新检查二跳实现是否需要修复；
5. 把结果明确命名为“未标注活动先验”。

### 阶段 B：决定是否严格复现 FLEXIS

如果用户要求严格使用论文方法，不能继续扩展当前简化脚本，而应选择以下路线之一：

- 将 TraceSage 图转换为上游 FLEXIS 可读的 `vf3.bin`，调用上游 C++ 程序；
- 或在 Python/C++ 中实现等价的 Core Group、模式合并、Bliss 去重、VF3 子图匹配和 mIS/slider。

必须先确定这些建模问题：

1. 10 个场景是分别挖掘还是组成一个不相连的联合图；
2. 顶点标签使用 Process/File/Network，还是使用当前结构角色；
3. 边标签使用 action、syscall，还是二者组合；
4. `result` 成功/失败是否进入边标签；
5. 不同场景中相同角色节点是否允许互相作为同一模式实例；
6. 支持度是按单场景计算、按场景数计算，还是联合图节点不重叠计算；
7. `slider` 取值以及频繁阈值如何确定。

这些问题没有确定前，不能把结果用于论文方法对比。

### 阶段 C：建立规则库实验版本

严格方法或当前适配器都应写到独立版本目录，例如：

```text
output/rule-kg/flexis-exact-v1/
output/rule-kg/flexis-adapter-v2/
```

不要覆盖：

```text
output/rule-kg/v1/
output/provenance-baseline/
output/engine-baseline/
```

### 阶段 D：最后才接 RAG

接入时需要：

- 使用独立规则版本号；
- 保存 source、commit、输入文件、阈值和生成时间；
- 规则和 ATT&CK 技术证据保持分离；
- 不把未验证的先验规则直接当作确认性白名单；
- 先做离线检索回放，再进行任何模型判定实验。

## 9. 当前工作区注意事项

当前 `git status` 中存在多项已有修改，包含：

- `AGENTS.md`；
- `docs/PROVENANCE_GRAPH_MODELING_AXIOMS.md`；
- `docs/agents/evaluation-protocol.md`；
- `docs/agents/test-runbook.md`；
- `provenance/README.md`；
- `provenance/main.py`；
- `provenance/rules/assembly.py`；
- `provenance/rules/route.py`；
- `provenance/settings.py`；
- `tools/promote_v2_baseline.py`；
- `docs/history/provenance-historical-modes.md`。

这些修改不是本次 FLEXIS 适配器交接文档创建时产生的，下一 agent 不得回滚、覆盖或擅自整理。

本次任务新增或产生的主要对象：

- `third_party/flexis/`：上游仓库 clone；
- `tools/mine_flexis_benign_prior.py`：当前简化适配器；
- `output/rule-kg/flexis-benign-v1/`：当前规则快照；
- `tmp/flexis-benign-v1.log`：最近一次运行日志。

当前没有执行 `git add` 或 `git commit`。下一 agent 也不要擅自提交。

## 10. 推荐的第一条接手命令

先只读检查，不调用 LLM：

```bash
python -m py_compile tools/mine_flexis_benign_prior.py
python tools/mine_flexis_benign_prior.py --help
python -c "import json; p='output/rule-kg/flexis-benign-v1/folds/global.json'; d=json.load(open(p,encoding='utf-8')); print(d['counts']); print(d['selection']); print(d['groundtruth_used'])"
```

重新生成当前适配器产物的命令：

```bash
python tools/mine_flexis_benign_prior.py \
  --edge-root output/parser-v2 \
  --node-root output/parser-v2 \
  --out output/rule-kg/flexis-benign-v1
```

如果后续改变任何阈值，必须使用新的输出目录或新的版本号，并在产物中记录改变后的阈值。不要覆盖旧快照后再声称结果可与旧结果直接比较。

## 11. 交接时必须保留的最终表述

向用户汇报时应使用以下口径：

> 已下载 FLEXIS 作者开源代码。当前 TraceSage 侧完成的是一个不读取 GT、也不调用 LLM 的流式频率先验适配器，借鉴了带标签活动图和节点不重叠支持度的思想，但没有实现 FLEXIS 的 Core Group 合并、Bliss 规范化、VF3Light 匹配和 slider/mIS 完整算法。对 10 个 parser-v2 场景扫描后，当前得到 7 条跨场景重复的一跳未标注活动先验规则；这些规则尚未证明为良性白名单，尚未接入 Neo4j/RAG，也没有产生召回率或查准率提升数字。
