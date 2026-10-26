# TraceSage 溯源端自适应协同演进设计方案 (第 2 版：内生免疫与策略强化架构)
## Autonomous Cyber-Immunity & Adaptive Investigation Policy Specification

---

## 1. 演进范式跃迁：从“被动规则打补丁”到“自主演进免疫系统”

### 1.1 现状技术悖论剖析
在第 1 版设计中，演进逻辑主要依赖“对齐攻击先验 ➔ 重新挖掘子图 ➔ 扩充规则库”。这种范式属于典型的**被动特征堆叠（Passive Signature Patching）**，存在根本性瓶颈：
1. **规则通胀与冲突困境**：规则数量单调递增，缺乏跨场景抽象能力与淘汰机制，势必在复杂系统背景中引发良性运维事件的级联误报；
2. **调查决策能力未进化**：演进只增加了通道二的模式数量，而通道三（LLM 仲裁）的束划分闸门、闭包前向/反向展开路径选择依然依赖静态启发式，面对海量拓扑噪声依然存在依赖爆炸与 Token 浪费；
3. **响应严重滞后**：必须等待未见攻击在受害机完整落地后才能被动收录，无法对攻击变种产生前瞻性防御。


## 2. 引擎 1：认知调查导航策略的强化演进 (Investigation Navigation Policy)

### 2.1 调查过程的图马尔可夫决策过程 (Graph MDP) 建模
TraceSage 面对数万条系统调用因果边时，核心挑战是在有限算力下逼近真实的攻击主干路径。将单次调查抽象为马尔可夫决策过程：
- **状态空间 $\mathcal{S}$**：当前闭包调查图 $\mathcal{G}_{\text{current}}$，包含已确诊节点集 $\mathcal{V}_{\text{confirmed}}$、候选边集 $\mathcal{E}_{\text{candidate}}$ 及通道二匹配状态；
- **动作空间 $\mathcal{A}$**：
  - $a_{\text{expand}}(v)$：沿顶点 $v$ 向前/向后展开因果流；
  - $a_{\text{prune}}(bundle)$：基于结构特征将特定边束直接置为白名单剪枝；
  - $a_{\text{escalate}}(bundle)$：将高歧义边束移送通道三 LLM 进行批判定；
- **收益函数（Pareto Reward）**：
  $$R = \text{Recall}(\mathcal{E}_{\text{GT}}) - \lambda_1 \cdot \text{Cost}_{\text{Token}} - \lambda_2 \cdot \text{ExpandedNodes} - \lambda_3 \cdot \text{FalsePositives}$$

### 2.2 调查注意力（Investigation Attention）的自我演进
在多次攻防对抗迭代中，TraceSage 记录调查轨迹日志：
1. **反向路径压缩学习**：分析已走通的 Ground Truth 路径，识别调查过程中的盲目分支（如被攻击者故意刷屏诱导的日志洪泛）；
2. **自适应前向展开权重更新**：
   - 动态调整 `extractor.py` 中的边遍历启发式权值：对频繁出现在历史成功攻击路径上的因果拓扑关系（如跨命名空间 IPC、非标目录动态库加载），赋予更高的优先展开权重；
   - 进化效果：在面对混淆图时，系统收敛到真正入口点的平均遍历步数持续单调下降。

---

## 3. 引擎 2：规则图拓扑的“达尔文代谢与抽象跃迁” (Rule Metabolism)

### 3.1 规则基因抽象跃迁 (Abstraction Lifting)
系统杜绝将字面量规则简单相加。当 `distiller.py` 挖掘到针对同一攻击阶段的多个同构具体规则时，触发**抽象提升算子（Lifting Operator）**：

```text
具象规则 1: (Process:curl) ──write──> (File:/tmp/exp.sh) ──execve──> (Process:sh)
具象规则 2: (Process:wget) ──write──> (File:/dev/shm/a.py) ──execve──> (Process:python)
具象规则 3: (Process:python) ──mmap_write──> (File:memfd:x) ──mmap_exec──> (Process:x)
                             │
                             ▼ [规则抽象提升 Lifting]
高阶因果图不变量公理 (High-Order Causal Invariant):
(Process{InboundActive}) ──[write|mmap_write]──> (File{NonStandardDir|memfd}) 
                         ──[execve|mmap_exec]──> (Process{SpawnedInterpreter})
```
- **机制**：通过在 Neo4j 图模式中提升实体角色的抽象层级，将 10 条脆弱的叶子特征规则压缩为 1 条高鲁棒性的**拓扑因果不变量（Topological Causal Invariant）**；
- **收益**：既防御了已见攻击，更具备跨场景捕获 PenAgent 未知变形手法的泛化能力。

### 3.2 基于适应度的规则代谢与淘汰机制 (Fitness Decay)
为防止规则膨胀导致的性能退化与误报率上升，每条规则在数据库中维护一个**动态生命周期属性**：
- **有效性加分**：在线或离线调查中，成功击中攻击必须边且经确诊验证，提升置信度权重 $W_{\text{rule}} \leftarrow W_{\text{rule}} + \Delta_{\text{pos}}$；
- **良性背景穿透惩罚**：在系统良性基线日志（Benign Noise Pool）中，每产生一次将正常系统调用误判为攻击边，实施重度惩罚 $W_{\text{rule}} \leftarrow W_{\text{rule}} - \Delta_{\text{neg}}$；
- **时效衰减机制**：若某规则连续 $N$ 轮对抗未被触发，其权重按半衰期衰减；
- **硬淘汰准则**：当 $W_{\text{rule}} < \theta_{\text{evict}}$ 时，该规则自动移出通道二核心规则库，沉淀归档至冷知识库。规则库规模始终动态收敛在信息密度最高的精炼集合中。

---

## 4. 引擎 3：反事实因果图主动扰动与虚拟免疫 (Counterfactual Vaccine Engine)

### 4.1 攻击前瞻性推演架构
系统无需等待 PenAgent 发起攻击才被动收集样本。TraceSage 在离线对抗间歇期，启动**反事实因果图扰动引擎（Counterfactual Graph Perturber）**：

```text
┌────────────────────────────────────────────────────────┐
│ 历史真实攻击因果子图 (GroundTruth Seed Subgraph)        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 虚拟红队扰动生成器 (Virtual Perturbation Generator)     │
│ · 扰动 1 (时间轴拉伸): 插入非均匀时延, 尝试破坏时序关联  │
│ · 扰动 2 (实体伪装): 将子进程替换为孤儿进程 (PPID=1)   │
│ · 扰动 3 (介质置换): 将持久化磁盘落地置换为匿名内存映射 │
└───────────────────────────┬────────────────────────────┘
                            │ 离线合成 100+ 虚拟变种攻击拓扑
                            ▼
┌────────────────────────────────────────────────────────┐
│ TraceSage 自我沙箱压力测试 (Self-Play Investigation)    │
│ · 运行调查流程，记录漏报/失控节点                      │
│ · 自动生成前瞻性补丁基模 (Preemptive Motifs)            │
└────────────────────────────────────────────────────────┘
```

### 4.2 免疫抗体前置固化
通过反事实推演发现的盲区，在真实攻击尚未发生时，即通过贝叶斯提升度检验（以良性噪声库为负样本母池），直接编译写入通道二规则集。  
当 PenAgent 以为自己进化出了“新型规避战术”发起实测攻击时，TraceSage 已经在离线反事实空间内完成针对该拓扑的免疫，实现**前瞻性防御（Zero-Day Preemption）**。

---

## 5. 引擎 4：神经-符号双向晶体化跃迁 (Neuro-Symbolic Crystallization)

### 5.1 从慢思考直觉到快反射规则的晶体化 (Crystallization)
通道三（LLM 仲裁通道）具有高维语义理解能力，但面临高延迟与 Token 成本：
- **捕获推理轨迹**：当通道三通过复杂的上下文分析，对一组原本无法被符号规则识别的边束（Bundle）做出高置信度判定时，系统记录大模型的判定逻辑链；
- **拓扑反编译为规则**：提取该边束及其上下文的有向图骨架（Roles + Actions + Topological Features），通过离线频繁子图提取器将其形式化为标准的 ProGQL 或 Matcher 基模；
- **快反射固化**：下一次遇到同构对抗拓扑时，通道二以 **0 延迟、0 Token 消耗** 瞬时确认攻击链路，高维认知直接转化为物理本能。

### 5.2 僵化规则的流体化柔性重审 (Fluidification)
当系统环境变更（如目标主机升级了新型系统守护进程），导致某条既有高阶符号规则在边界用例上产生置信度波动（边缘命中）：
- 系统自动降低该规则在通道二的执行优先级，将其**“融化（Fluidify）”**；
- 规则从“阻断型硬判定”转变为“提示型软约束（Soft Constraint）”，作为高价值上下文注入给通道三大模型；
- 大模型结合全局语义重新校准其边界，校准完毕后重新结晶。

---

## 6. 系统持续进化健康度度量指标 (Evolution Health Metrics)

为确保系统能力增长真实可复算，杜绝虚假自循环，定义如下进化健康度指标体系：

| 指标 | 物理定义 | 进化期望方向 |
|---|---|---|
| **调查能效比 ($\eta_{\text{investigation}}$)** | $\frac{\text{GroundTruth 检出边数}}{\text{调用 LLM 的总 Token 消耗}}$ | **持续单调递增**（越查越省算力） |
| **规则泛化比 ($\mathcal{R}_{\text{generality}}$)** | $\frac{\text{反事实变种拓扑识别数}}{\text{通道二符号规则总数}}$ | **持续提升**（以更精炼的规则覆盖更广的变种） |
| **首跳确诊收敛时间 ($T_{\text{first\_hit}}$)** | 从输入 POI 到命中首个攻击入口的平均毫秒数 | **持续缩短**（快反射机制覆盖面增大） |
| **背景良性穿透率 ($FPR_{\text{benign}}$)** | 在 100 万条纯良性背景系统调用流上的误检率 | **严格保持 $\le 0.05\%$**（达尔文代谢保证不误杀） |

---

## 7. 结语

本设计彻底摆脱了“你攻击一次、我写一条正则”的低水平循环，将 TraceSage 构建为**集策略强化、拓扑抽象提升、反事实虚拟免疫与神经符号自适应晶体化于一体的活体防御智能体**。该机制与 PenAgent 形成真正的双智能体博弈进化对称闭环，在学术理论深度与工业系统实操性上均具备顶级竞争力。
