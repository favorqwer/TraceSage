"""五层各占一个包；只允许下游读上游，编排在 `pagent/orchestration/`，装配在 `pagent/app.py`。

- `l1_reach`：结构可达（决定上限）
- `l2_prepare`：压缩与准备（不许降低上限）
- `l3_semantic`：语义判别（第一轮，调模型）
- `l4_verify`：全局校验（复核与合并，调模型）
- `l5_express`：表达（报告装配）

包内文件按用途命名；下游层只 import 上游层的包入口（各包的 `__init__.py`）。
横切模块在 `pagent/core/`，任何一层都可以用。
"""
