"""横切基础设施：所有层都可以用、但不属于任何一层的模块。

- `settings`：配置与路径
- `scenarios`：场景与终点事件配置加载
- `db`：只读图访问（写守卫 + 审计）
- `llm`：模型工厂、JSON 调用自校正、记账、原始输出度量
- `record`：调查记录（实体/假设/缺口 + 四类边）
- `prompts`：提示词加载（读 `foundation/prompts/`）
- `rules`：规则表加载（读 `foundation/rules/`）
- `trace`：运行轨迹
"""
