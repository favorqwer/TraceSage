"""provenance-navigator 的取数与判定底座。

这一层不是导航器自己的算法，而是导航器依赖的**确定性基础设施**：

- `core/`：只读图访问、顶点-时间索引、配置、场景、记录、模型接入等横切模块；
- `layers/l1_reach/`：反向因果闭包与折叠（navigator 的候选池来源）；
- `layers/l2_judge/`：束的五级划分、四道结构闸门、束级四值判定（navigator 的慢速通道内核）；
- `orchestration/`：起点定位、闭包编排、单轮判定推进；
- `deps.py`：一次调查的依赖容器。

导航器自己的算法（符号通道、基模蒸馏、报告装配）在上一级目录的
`closure/`、`rules/`、`orchestrator/`、`judge/` 里，两者边界不要混。
"""
