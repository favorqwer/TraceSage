# 论文与开题答辩核心材料交付物归档清单

> **目录说明**：本目录专门归档硕士学位论文（大论文核心章节）与高水平学术小论文撰写所需的核心学术成果、实测评测数据表以及案例拓扑矢量图。所有材料均严格遵循国际顶级系统安全会议（IEEE S&P, USENIX Security, ACM CCS, NDSS）的学术术语规范与论文实验设计标准。

---

## 目录文件清单

| 文件名 | 文件类型 | 用途与内容说明 |
| :--- | :--- | :--- |
| [`paper_core_contributions.md`](file:///E:/Work/TraceSage/docs/paper_materials/paper_core_contributions.md) | Markdown 文档 | **核心方法与创新点体系**：<br>1. 6 个顶会标准论文题目候选（机制陈述型与代号型）；<br>2. 顶会标准摘要范本（5 句式 Abstract Blueprint）；<br>3. 创新点一：受拓扑硬约束的神经-符号协同调查架构（分层行为抽象 + 确定性拓扑剪枝闸门 + 符号引用守卫）；<br>4. 创新点二：基于轻量状态重放的增量式因果基模同化机制（动态基模挖掘 + 零图重查增量同化 + 贪心准入）；<br>5. 创新点内在逻辑咬合架构；<br>6. 答辩与同行评审高频质询防御手册。 |
| [`paper_experimental_results.md`](file:///E:/Work/TraceSage/docs/paper_materials/paper_experimental_results.md) | Markdown 文档 | **核心实验评测数据与 LaTeX 源码**：<br>1. **实验一（Table 1）**：10 个 APT 场景端到端效果对比（对比 DEPIMPACT，召回率 77.81% vs 41.7%，查准率 59.11% vs 13.1%，Markdown 表格与 LaTeX 源码）；<br>2. **实验二（Table 2）**：系统运行耗时与大模型推理开销（中位数 57.2s，全流程总计 211 次大模型调用，Markdown 表格与 LaTeX 源码）；<br>3. **实验三**：典型案例因果图指标、同态聚合逻辑与去噪分析说明。 |
| [`case_study_scenario_8.svg`](file:///E:/Work/TraceSage/docs/paper_materials/case_study_scenario_8.svg) | 矢量图 (SVG) | **实验三案例高保真因果拓扑图**：<br>1. 采用场景 8（FTP 弱口令入侵与 WebShell 渗漏）；<br>2. 严格 100% 弱连通 DAG，长宽比 16:9；<br>3. 去除无意义标签，对高频扫描连接和同类数据文件执行同态折叠；<br>4. 高亮真实攻击主干（实线加粗），同时保留灰色虚线剪枝背景噪音，直观体现去噪能力。支持直接插入 LaTeX 论文或 PPT。 |
| [`case_study_scenario_8.dot`](file:///E:/Work/TraceSage/docs/paper_materials/case_study_scenario_8.dot) | Graphviz 源码 | **矢量图渲染源文件**：<br>可随时通过 `dot -Tsvg case_study_scenario_8.dot -o case_study_scenario_8.svg` 重新编译，或根据审稿人修改意见调整布局与节点样式。 |
| [`mechanism_supporting_metrics.md`](file:///E:/Work/TraceSage/docs/paper_materials/mechanism_supporting_metrics.md) | Markdown 文档 | **三大核心机制细粒度物理支撑数据测试报告**：<br>1. 机制 A：宏观去噪压缩率（91.21%）、前置闸门剪枝量（31,852 条事件）、弱连通主干集中度（90.2%）；<br>2. 机制 B：微观因果基模留一折覆盖率（100%）、宏观 MITRE ATT&CK 战术全阶段覆盖；<br>3. 机制 C：大模型四值判决分布（确认 35,876 / 排除 78,188）、安全降级兜底频次（129,307 次）、零虚假跳链物理验证（False Hops = 0）；<br>4. 包含完整 Table 3 LaTeX 排版代码与英文正文写作范式。 |

---

## 快速使用指引

1. **写小论文正文**：
   - 题目与摘要直接参考 [`paper_core_contributions.md`](file:///E:/Work/TraceSage/docs/paper_materials/paper_core_contributions.md) 的第一、二节；
   - 核心方法章节（Design/Methodology）直接对应第三、四、五、六节；
   - 实验章节（Evaluation）直接复制 [`paper_experimental_results.md`](file:///E:/Work/TraceSage/docs/paper_materials/paper_experimental_results.md) 中的 LaTeX 表格代码与分析；
   - 案例分析（Case Study）直接插入 [`case_study_scenario_8.svg`](file:///E:/Work/TraceSage/docs/paper_materials/case_study_scenario_8.svg)。
2. **准备开题答辩 PPT**：
   - PPT 结构建议：“研究背景与痛点” $\rightarrow$ “两个核心创新点（逻辑咬合架构）” $\rightarrow$ “三组核心实验验证（对比表 + 开销表 + 案例拓扑图）” $\rightarrow$ “原型系统展示”；
   - 答辩问答环节直接套用 [`paper_core_contributions.md`](file:///E:/Work/TraceSage/docs/paper_materials/paper_core_contributions.md) 第十节的《答辩与同行评审高频质询防御手册》。
