# Hello-Agents 项目 Agent 架构与能力实现详解

## 一、先给结论：项目中的 Agent 是什么

在 Hello-Agents 中，Agent 不是一个简单的“调用大语言模型的函数”，而是一个围绕目标运行的闭环系统：

```text
用户任务/外部事件
        |
        v
输入感知与任务理解
        |
        v
上下文构建：历史 + 记忆 + 检索结果 + 工具状态 + 当前任务
        |
        v
LLM 推理/规划/决策
        |
        +-------> 直接生成答案
        |
        +-------> 选择工具/其他 Agent
                         |
                         v
                 工具执行或远程协作
                         |
                         v
                 Observation（执行结果）
                         |
                         +----> 更新历史、状态、记忆
                         |
                         +----> 继续推理循环
                                      |
                                      v
                           完成、失败、超时或人工接管
```

它的基本运行模型来自第 1 章描述的 **感知（Perception）-思考（Thought）-行动（Action）-观察（Observation）** 循环。LLM 提供语言理解和决策能力，但真正让系统成为 Agent 的，是以下组合：

1. 有明确的任务目标、角色和约束。
2. 能接收外部输入并感知环境变化。
3. 能维护短期状态、长期记忆和执行轨迹。
4. 能规划、分解、选择和执行行动。
5. 能调用工具、检索知识或委托给其他 Agent。
6. 能根据观察结果继续迭代，而不是只回答一次。
7. 有停止条件、最大步数、超时、错误处理和安全边界。
8. 能以稳定、可验证、可观测的方式输出结果。

因此，项目的核心思想可以概括为：

> **一个统一的 Agent 外壳，加上可替换的控制策略、工具、记忆、上下文和通信能力。**

---

## 二、项目整体架构

### 2.1 从环境交互角度理解架构

第 1 章先从传统智能体理论建立了统一抽象：

- **环境（Environment）**：用户、网页、文件系统、数据库、游戏世界、第三方 API 或其他 Agent。
- **观察（Observation）**：用户消息、工具返回值、搜索结果、文件内容、状态变化、错误信息。
- **内部状态（Internal State）**：当前任务、执行历史、对话历史、计划、记忆、笔记、工具状态。
- **目标（Goal）**：回答问题、完成订单、制定旅行计划、生成研究报告、维护代码库等。
- **策略（Policy）**：Simple、ReAct、Plan-and-Solve、Reflection、Function Calling 或状态图。
- **执行器（Actuator）**：工具函数、API 调用、代码执行器、文件系统、远程 Agent。
- **反馈（Feedback）**：行动结果被重新放入上下文，驱动下一轮决策。

从这个角度看，LLM 只相当于“策略和推理引擎”的一部分。没有环境接口、状态管理、执行器和反馈闭环，LLM 仍然只是一个文本生成器。

### 2.2 HelloAgents 的分层架构

第 7 章给出了基础目录和分层设计。结合后续章节，可以将项目完整架构整理为下图：

```text
┌──────────────────────────────────────────────────────────────┐
│  应用接入层                                                   │
│  CLI / Jupyter / FastAPI / Vue3 / Godot / SSE / HTTP          │
└──────────────────────────────┬───────────────────────────────┘
                               │ 用户请求、事件、流式状态
┌──────────────────────────────▼───────────────────────────────┐
│  Agent 编排层                                                 │
│  SimpleAgent / ReActAgent / ReflectionAgent                   │
│  PlanAndSolveAgent / FunctionCallAgent / 自定义业务 Agent      │
│  DeepResearchAgent / NPC Agent / TripPlannerAgent              │
└──────────────────────────────┬───────────────────────────────┘
                               │ 统一 run()、状态和生命周期
┌──────────────────────────────▼───────────────────────────────┐
│  Agent 核心运行时层                                            │
│  Agent 抽象基类 / Message / Config / 异常 / 日志 / 事件         │
└───────────────┬──────────────────────┬────────────────────────┘
                │                      │
                │                      │
┌───────────────▼──────────────┐ ┌─────▼────────────────────────┐
│ LLM 适配层                   │ │ 上下文与状态层                │
│ HelloAgentsLLM               │ │ 对话历史、ContextBuilder       │
│ OpenAI/ModelScope/智谱       │ │ NoteTool、任务状态、轨迹       │
│ vLLM/Ollama/本地模型          │ │ GSSC：Gather-Select-          │
│ 自动 provider 检测、流式调用  │ │ Structure-Compress            │
└───────────────┬──────────────┘ └──────────────┬─────────────────┘
                │                               │
┌───────────────▼───────────────────────────────▼────────────────┐
│ 工具与能力层                                                     │
│ Tool / ToolParameter / ToolRegistry / ToolChain / AsyncExecutor   │
│ 计算、搜索、文件、终端、代码执行、记忆、RAG、图片、业务 API       │
└──────────────────────────────┬──────────────────────────────────┘
                               │ 统一工具接口
┌──────────────────────────────▼──────────────────────────────────┐
│ 协议与多 Agent 网络层                                             │
│ MCP：Agent ↔ 工具/资源    A2A：Agent ↔ Agent                      │
│ ANP：服务发现、路由、负载均衡                                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│ 存储与基础设施层                                                  │
│ SQLite / Qdrant / Neo4j / 文件系统 / 缓存 / Embedding 服务         │
│ 云端 API、VLLM、Ollama、向量数据库、图数据库                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│ 训练、评估与观测层                                                │
│ SFT / LoRA / GRPO / 奖励函数 / BFCL / GAIA / LLM Judge / Win Rate   │
│ 日志、指标、错误样本、SSE 进度、TensorBoard、人工验证              │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 各层职责和边界

#### 2.3.1 应用接入层

这一层不负责“思考”，而负责把真实用户或外部系统接入 Agent：

- 命令行和 Notebook：适合教学、调试和实验。
- FastAPI：把 Agent 暴露成 Web API。
- Vue3 + TypeScript：旅行助手和深度研究项目中的前端交互。
- Godot：赛博小镇中的游戏画面、玩家移动和对话 UI。
- SSE：把深度研究的阶段、日志、进度和报告流式推送到浏览器。
- HTTP/JSON：在 Godot 与 FastAPI、前端与后端之间传递结构化数据。

应用层应该只依赖 Agent 的稳定接口，不应该把 Prompt、工具解析、记忆检索等逻辑散落在路由或 UI 代码中。

#### 2.3.2 Agent 编排层

这一层决定 Agent 如何思考和行动。项目通过多个范式展示了不同控制策略：

- `SimpleAgent`：单轮或多轮对话，可选工具调用。
- `ReActAgent`：显式执行 Thought -> Action -> Observation 循环。
- `PlanAndSolveAgent`：先生成计划，再逐步执行计划。
- `ReflectionAgent`：初稿 -> 反思 -> 改进的迭代循环。
- `FunctionCallAgent`：使用 OpenAI 原生函数调用协议，减少文本解析的不确定性。
- 自定义业务 Agent：把上面的能力组合到旅行、深度研究、NPC、代码维护等场景。

#### 2.3.3 核心运行时层

第 7 章将框架内核拆成三个基础文件：

1. `message.py`：统一消息结构。
2. `config.py`：集中配置和环境变量加载。
3. `agent.py`：所有 Agent 的抽象基类。

`Message` 至少包括 `role`、`content`、`timestamp`、`metadata`。角色被限制为 `user`、`assistant`、`system`、`tool`，并能转换为 OpenAI 兼容字典。

`Config` 统一管理模型、温度、最大 Token、调试开关、日志级别、最大历史长度等参数，支持默认值和环境变量覆盖。

`Agent` 抽象基类负责：

- 保存 `name`、`llm`、`system_prompt`、`config`。
- 提供统一的 `run(input_text, **kwargs)` 入口。
- 提供 `add_message`、`clear_history`、`get_history` 等历史管理方法。
- 强制具体 Agent 实现自己的控制策略。

#### 2.3.4 LLM 适配层

`HelloAgentsLLM` 的目标不是重新发明一套模型协议，而是在 OpenAI 兼容 API 之上提供统一入口：

- 支持 OpenAI、ModelScope、智谱 AI 等云端服务。
- 支持 VLLM、Ollama 等本地 OpenAI 兼容服务。
- 根据环境变量和 `base_url` 自动检测 provider。
- 允许手动指定 `provider`、`model`、`api_key`、`base_url`。
- 提供普通调用、思考调用和流式调用能力。
- 可通过继承 `HelloAgentsLLM` 扩展新服务商，而不修改框架源码。

这样，Agent 上层只依赖 `invoke`、`think`、`stream_invoke` 等统一方法，模型供应商可以独立替换。

#### 2.3.5 工具与能力层

HelloAgents 的关键简化是“万物皆为工具”：

- 记忆是工具。
- RAG 是工具。
- 终端访问是工具。
- MCP、A2A、ANP 也是工具。
- 业务 API、搜索引擎、代码分析器也都是工具。

工具统一由 `Tool`、`ToolParameter` 和 `ToolRegistry` 管理。复杂工具继承 `Tool`，简单函数可以直接注册；工具注册表负责注册、发现、描述、执行和生成 OpenAI schema。

#### 2.3.6 存储与基础设施层

项目文档给出了多种后端：

- SQLite：文档、会话或简单持久化。
- Qdrant：向量检索和语义记忆。
- Neo4j：语义记忆中的知识图谱关系。
- 文件系统：结构化笔记、报告、代码和原始资料。
- Embedding 服务：DashScope、`sentence-transformers`、TF-IDF 兜底。

这些后端不应直接暴露给 Agent。Agent 通过 MemoryTool、RAGTool、NoteTool 等工具访问它们。

#### 2.3.7 训练、评估与观测层

第 11、12 章说明 Agent 系统不是“写完 Prompt 就结束”：

- Agentic-RL 通过 SFT、LoRA、GRPO 和奖励函数优化模型行为。
- BFCL 评估工具调用和参数生成能力。
- GAIA 评估通用助手解决真实任务的能力。
- LLM Judge、Win Rate 和人工验证评估生成质量。
- 日志、错误样本、SSE 进度、TensorBoard 和对比报告支撑调试与迭代。

---

## 三、一次 Agent 任务的完整运行时流程

下面是把项目中多个章节合并后的标准运行流程。

### 步骤 1：接收并规范化请求

输入可能来自文本、JSON、文件、游戏事件或另一个 Agent。应用层先完成：

- 身份和会话识别。
- 参数校验和 Pydantic 模型转换。
- 任务 ID、用户 ID、请求时间和追踪 ID 注入。
- 对空输入、非法字段和超长输入进行处理。

旅行助手使用 `TripPlanRequest`，赛博小镇使用对话请求模型，深度研究使用研究主题和配置模型，这些都是“先结构化、后推理”的典型做法。

### 步骤 2：加载历史和内部状态

Agent 读取：

- 当前会话的短期对话历史。
- 当前计划、已完成步骤和工具执行轨迹。
- 相关 NoteTool 笔记。
- 用户偏好、NPC 好感度、业务状态等领域状态。

如果不做这一步，Agent 每轮都会退化为无状态问答。

### 步骤 3：构建上下文

第 9 章的 `ContextBuilder` 使用 GSSC 流水线：

1. **Gather**：汇集历史、记忆、RAG、笔记、工具结果和当前输入。
2. **Select**：按相关性、时间新鲜度、重要性、来源和 Token 预算筛选。
3. **Structure**：按系统指令、任务、背景、证据、历史和输出约束组织。
4. **Compress**：超过上下文窗口时进行压缩、截断或摘要。

这一步的目标不是把所有信息都塞进 Prompt，而是为当前决策选择最有用、最可信、最短的上下文。

### 步骤 4：选择控制策略

根据任务类型选择不同 Agent：

- 简单问答：`SimpleAgent`。
- 需要查资料和多步工具调用：`ReActAgent`。
- 子任务顺序清晰：`PlanAndSolveAgent`。
- 需要质量迭代：`ReflectionAgent`。
- 模型支持原生工具调用：`FunctionCallAgent`。
- 需要循环、分支、回溯或人工介入：LangGraph 风格状态图。
- 需要专家分工：多 Agent 编排或 A2A。

### 步骤 5：调用 LLM

LLM 输入通常包括：

- system prompt：角色、边界、工具说明和输出协议。
- 历史消息：用户、助手、工具消息。
- 当前任务和结构化上下文。
- Function Calling schema 或 ReAct 文本格式。

输出可能是：

- 最终自然语言答案。
- 工具调用文本标记，如 `[TOOL_CALL:name:parameters]`。
- ReAct 的 `Thought` 和 `Action`。
- 原生 `tool_calls`。
- 计划列表或 JSON 对象。

### 步骤 6：解析模型决策

项目中存在三种主要解析方法：

1. **文本协议解析**：使用正则表达式解析 `[TOOL_CALL:...]` 或 `Tool[input]`。
2. **结构化格式解析**：要求模型输出 Python 列表、JSON 或 Pydantic 对象，再校验和修复。
3. **原生函数调用解析**：直接读取 OpenAI 响应中的 `tool_calls` 和 JSON 参数。

原生函数调用通常比 Prompt 约束更稳健；但文本协议更容易教学、调试和兼容不支持原生工具调用的模型。

### 步骤 7：执行工具或委托任务

ToolRegistry 根据工具名找到实现，完成参数转换、调用、异常捕获和结果格式化。工具结果应当包含：

- 是否成功。
- 结构化数据或文本结果。
- 来源和时间。
- 错误类型、重试建议或降级信息。

对于 MCP 工具，注册表中的包装器会把本地调用转换为 MCP 的 `call_tool` 请求；对于 A2A 工具，则把调用转换为远程 Agent 请求。

### 步骤 8：将 Observation 写回上下文

工具结果不能只打印出来，而要进入下一轮决策：

- 追加 `tool` 消息。
- 追加 `Action` 和 `Observation` 执行轨迹。
- 更新任务状态和已完成步骤。
- 根据重要性写入短期或长期记忆。
- 必要时创建 NoteTool 笔记。

### 步骤 9：判断是否结束

结束条件至少包括：

- Agent 明确输出最终答案。
- ReAct 输出 `Finish[...]`。
- 所有计划步骤完成。
- 达到最大工具迭代次数或最大 ReAct 步数。
- 超时、预算耗尽、连续错误或需要人工批准。

没有停止条件的 Agent 可能陷入无限循环，项目在 ReAct 和 SimpleAgent 中都通过 `max_steps` 或 `max_tool_iterations` 作为安全阀。

### 步骤 10：输出、记录和评估

最终结果交给应用层，并同步：

- 记录输入、输出、工具调用和耗时。
- 保存错误样本和中间轨迹。
- 通过 SSE 或流式接口显示进度。
- 运行离线评估或人工复核。

---

## 四、项目实现的 Agent 范式

| 范式 | 核心机制 | 适用任务 | 主要优点 | 主要风险 |
|---|---|---|---|---|
| SimpleAgent | 直接把历史和当前输入交给 LLM | 问答、聊天、轻量助手 | 简单、延迟低、容易理解 | 复杂任务缺少显式控制 |
| Simple + Tools | 文本工具标记或多轮工具循环 | 计算、搜索、记忆、业务查询 | 扩展快，适合教学 | 文本解析和参数类型容易出错 |
| ReActAgent | Thought -> Action -> Observation | 需要探索环境的多步任务 | 推理和行动紧密结合，可解释 | 步数多、成本高，可能循环 |
| Plan-and-Solve | 先生成计划，再逐步执行 | 旅行、研究、数学题、项目任务 | 计划清晰，便于状态管理 | 初始计划错误会影响后续步骤 |
| ReflectionAgent | 初稿 -> 反思 -> 改进 | 写作、代码生成、质量提升 | 能主动发现问题 | 多轮调用，成本和延迟增加 |
| FunctionCallAgent | 原生函数调用和 JSON 参数 | 工具密集、生产系统 | 参数和协议更稳定 | 依赖模型能力和供应商接口 |
| 状态图 Agent | 节点、边、条件路由、循环 | 复杂业务流程、人工介入 | 控制流明确，可回溯和恢复 | 设计复杂，学习成本较高 |
| 多 Agent | 角色分工、委托、协商 | 研究、旅行、软件团队、NPC | 专业化和并行能力强 | 协作开销、状态同步和一致性问题 |

### 4.1 SimpleAgent

最小实现通常只有：

1. 组装 system prompt、历史和当前用户消息。
2. 调用 `llm.invoke`。
3. 把用户消息和助手回复写回历史。

加入工具后，项目的 `MySimpleAgent` 会循环：

```text
调用 LLM -> 解析 TOOL_CALL -> 执行工具 -> 将结果追加为新消息
       -> 再次调用 LLM -> 没有工具调用时返回最终答案
```

实现方法：

- 教学版：在系统提示词中写工具列表和文本调用格式。
- 稳定版：使用 `FunctionCallAgent` 和 OpenAI schema。
- 工作流版：把每个工具调用节点显式放进状态图。

### 4.2 ReActAgent

ReAct 要求模型每一轮输出一个 `Thought` 和一个 `Action`：

```text
Thought: 当前缺少实时天气，需要调用天气工具。
Action: weather[厦门]
Observation: 厦门今天有小雨，温度 24℃。
```

核心实现：

- 用 Prompt 固定输出格式。
- 每次只允许执行一个行动。
- 用正则或解析器拆出工具名和参数。
- 把 `Action`、`Observation` 放入 `current_history`。
- 达到 `max_steps` 时返回受控失败信息。

改进方法：

- 要求模型只调用一个工具，减少并行动作冲突。
- 给工具参数提供 schema 和示例。
- 为相同工具调用增加去重和缓存。
- 在连续失败时切换备用工具或请求人工确认。
- 对敏感 Action 设置审批节点。

### 4.3 Plan-and-Solve

规划器输出独立、可执行的 Python 列表：

```python
["确认出行日期和预算", "查询目的地天气", "检索景点", "生成逐日行程"]
```

执行器每次只处理当前步骤，并携带：

- 原始问题。
- 完整计划。
- 已完成步骤与结果。
- 当前步骤。

实现方法：

- 轻量版：规划器和执行器使用同一个 LLM 客户端。
- 强约束版：使用 JSON schema 或 Pydantic 校验计划。
- 可恢复版：把每个步骤持久化，失败后从最后一个未完成步骤继续。
- 图工作流版：将计划步骤展开成状态图节点。

### 4.4 ReflectionAgent

ReflectionAgent 至少需要三个 Prompt：

1. `initial`：生成第一版答案。
2. `reflect`：审查任务完成度、正确性、风格和风险。
3. `refine`：根据反馈重写答案。

实现方法：

- 文本反思：直接让同一个 LLM 充当生成器和评审器。
- 双模型反思：生成模型和评审模型分离。
- 规则反思：对代码运行测试、对 JSON 做 schema 校验、对事实做检索核对。
- 交叉反思：多个 Agent 分别审查，再由汇总 Agent 决策。

必须设置最大反思轮数和“无需改进”条件，否则会无限优化。

### 4.5 FunctionCallAgent

FunctionCallAgent 通过 `ToolRegistry.to_openai_schema()` 把工具转换为：

```json
{
  "type": "function",
  "function": {
    "name": "get_weather",
    "description": "查询天气",
    "parameters": {
      "type": "object",
      "properties": {"location": {"type": "string"}},
      "required": ["location"]
    }
  }
}
```

模型返回工具调用后，Agent 负责：

1. 提取函数名。
2. 解析 JSON 参数。
3. 按 `ToolParameter` 转换类型。
4. 执行工具。
5. 把工具结果作为 tool message 回传给模型。
6. 直到模型给出最终内容。

这是生产场景优先推荐的工具调用方式；文本协议可以作为不支持原生 function calling 的模型的兼容方案。

---

## 五、工具系统：Agent 的行动器

### 5.1 Tool 基类和 ToolRegistry

项目中的工具最小接口是：

```python
class Tool(ABC):
    name: str
    description: str

    @abstractmethod
    def run(self, parameters: dict) -> str:
        ...

    @abstractmethod
    def get_parameters(self) -> list[ToolParameter]:
        ...
```

`ToolParameter` 描述参数名、类型、说明、是否必填和默认值。`ToolRegistry` 提供：

- `register_tool(tool)`：注册复杂工具对象。
- `register_function(name, description, func)`：快速注册函数。
- `get_tools_description()`：生成给 LLM 阅读的工具说明。
- `get_tool(name)`：按名称发现工具。
- `execute_tool(name, input)`：执行工具。
- `to_openai_schema()`：生成原生函数调用 schema。

### 5.2 工具的实现方法

#### 方法 A：直接注册函数

适合无状态、参数简单的工具，例如：

- 基础计算。
- 字符串转换。
- 简单数据库查询。
- 已经存在的业务函数。

优点是代码最少；缺点是参数 schema、状态、资源管理和测试能力较弱。

#### 方法 B：继承 Tool

适合需要配置、客户端、缓存、降级和复杂参数的工具，例如多源搜索、记忆、RAG、文件系统。推荐将以下内容都封装在工具内部：

- 凭证读取。
- 外部客户端初始化。
- 参数验证。
- 错误转换。
- 结果标准化。
- 重试、缓存和降级。

#### 方法 C：工具链

`ToolChain` 通过模板变量把多个工具串联：

```text
搜索 -> 计算 -> 总结
```

适合固定顺序、可预测的流程。工具链比让 LLM 自由决定每一步更稳定，但灵活性较低。

#### 方法 D：异步和并行执行

`AsyncToolExecutor` 使用线程池和 `asyncio.gather` 并行执行多个独立工具任务，适合：

- 并行搜索多个主题。
- 同时查询多个服务。
- 批量生成 NPC 背景对话。
- 研究任务中的多来源采集。

并行执行必须考虑速率限制、结果顺序、超时和取消机制。

### 5.3 项目中的工具类型

| 工具类型 | 作用 | 典型实现 |
|---|---|---|
| 计算工具 | 数值和表达式计算 | 安全 AST 解析，不直接执行任意 `eval` |
| 搜索工具 | 获取实时网页信息 | Tavily、SerpApi、DuckDuckGo、Perplexity、SearXNG，支持混合降级 |
| 文件工具 | 读写文件或访问仓库 | 本地 Tool、MCP 文件系统服务器 |
| TerminalTool | 即时探索项目和日志 | 命令白名单、工作目录限制、超时、输出截断 |
| MemoryTool | 添加、检索、遗忘和整合记忆 | MemoryManager + 四种记忆后端 |
| RAGTool | 文档解析、切分、索引和问答 | Markdown 转换 + Embedding + Qdrant |
| NoteTool | 长任务结构化记录 | Markdown 笔记 + JSON 索引 |
| MCPTool | 发现和调用外部 MCP Server | Tool 包装器 + MCP Client |
| A2ATool | 调用远程 Agent | HTTP/P2P 任务、工件和流式响应 |
| ANPTool | 发现和选择服务 | 注册、查询、能力匹配和负载均衡 |
| 业务工具 | 旅行、图片、订单、NPC 状态等 | FastAPI 服务或第三方 API 封装 |

### 5.4 工具可靠性要求

一个可用于生产的工具应具备：

1. 明确的名称、描述和参数 schema。
2. 输入校验和类型转换。
3. 可读、可诊断的错误信息。
4. 超时、重试和最大输出限制。
5. 幂等性或重复调用保护。
6. 权限检查和审计日志。
7. 结构化结果，避免只返回无法解析的大段字符串。
8. 单元测试和离线模拟模式。

---

## 六、记忆、RAG 和上下文工程

### 6.1 记忆系统的四层结构

第 8 章将记忆划分为四种类型：

1. **工作记忆（Working Memory）**：当前会话的短期上下文，容量和生命周期有限。
2. **情景记忆（Episodic Memory）**：具体事件、对话和经历，支持按时间和主题回顾。
3. **语义记忆（Semantic Memory）**：用户偏好、概念、规则和抽象知识。
4. **感知记忆（Perceptual Memory）**：图像、音频等多模态信息及其元数据。

基础设施包括：

```text
MemoryManager
  ├── MemoryItem
  ├── MemoryConfig
  ├── BaseMemory
  ├── WorkingMemory
  ├── EpisodicMemory
  ├── SemanticMemory
  └── PerceptualMemory
```

### 6.2 MemoryTool 的操作

MemoryTool 提供统一入口：

- `add`：写入内容、类型、重要性、会话 ID、时间和元数据。
- `search`：按查询、记忆类型、重要性和数量检索。
- `summary`：生成记忆摘要。
- `stats`：查看数量、类型和容量统计。
- `update/remove`：修改或删除记忆。
- `forget`：按重要性、时间或容量执行遗忘。
- `consolidate`：把重要工作记忆提升为情景记忆，把情景记忆提炼为语义记忆。
- `clear_all`：清理用户或会话记忆。

### 6.3 记忆的实现方法

| 需求 | 简单实现 | 可扩展实现 |
|---|---|---|
| 当前会话 | Python 列表 | 带 TTL 和容量限制的 WorkingMemory |
| 持久化事件 | JSON/SQLite | EpisodicMemory + 时间和主题索引 |
| 语义召回 | 关键词匹配 | Qdrant 向量 + Neo4j 图谱混合检索 |
| 多模态 | 文件路径和元数据 | 图像/音频 Embedding + 跨模态检索 |
| 遗忘 | 按时间删除 | 重要性、时间衰减、容量联合评分 |
| 记忆固化 | 手动迁移 | 重要性阈值和后台任务自动 consolidate |

### 6.4 RAG 系统

项目中的 RAG 不只是“把文档切块后做向量搜索”，完整流程是：

```text
文档/网页/PDF
    -> 统一转换为 Markdown
    -> 识别标题层次和语义段落
    -> Token 大小分块 + overlap
    -> Embedding
    -> Qdrant 命名空间存储
    -> 查询扩展（可选 MQE / HyDE）
    -> 多路向量检索、去重、排序
    -> ContextBuilder 组织上下文
    -> LLM 基于证据回答
```

关键实现方法：

- **格式统一**：使用 MarkItDown 或兜底文本读取器把多种文档转换成 Markdown。
- **结构感知切分**：保留 `#`、`##`、`###` 标题路径，避免在语义中间粗暴切断。
- **Token 控制**：中文字符和英文空白词分别估算，使用 chunk size 和 overlap 控制上下文连续性。
- **向量存储**：用 Qdrant 保存向量和 `memory_id`、`rag_namespace`、`data_source` 等元数据。
- **MQE**：让 LLM 生成多个等价查询，提高召回率。
- **HyDE**：先生成假设答案段落，再用它检索真实文档，缩小问题和文档的语义差距。
- **混合检索**：向量相似度、关键词、时间、重要性和图谱关系联合排序。

RAG 的边界也很重要：它提供证据，不等于自动保证事实正确。最终回答仍应保留来源、时间和证据片段。

### 6.5 ContextBuilder 的 GSSC 流水线

ContextBuilder 解决的是“上下文太多、太旧、太杂”的问题：

- `ContextPacket`：候选信息包，携带内容、来源、相关性、时间、优先级和元数据。
- `ContextConfig`：控制最大 Token、每类信息上限、是否启用压缩和排序策略。
- `Gather`：从对话、记忆、RAG、笔记和工具结果收集候选信息。
- `Select`：综合查询相关性、时间新鲜度、重要性和预算排序。
- `Structure`：按固定区块输出，减少模型寻找关键信息的成本。
- `Compress`：超出预算时摘要、截断或保留关键片段。

### 6.6 NoteTool：长程任务的外部工作记忆

第 9 章用 Markdown 文件和 JSON 索引实现结构化笔记，支持：

- `create`、`read`、`update`、`search`、`list`、`summary`、`delete`。
- 记录任务状态、下一步计划、阻塞点、决策、风险和验证结果。
- 与 ContextBuilder 集成，把相关笔记转换为 `ContextPacket`。

NoteTool 和对话历史的区别是：历史记录“发生过什么”，笔记记录“未来需要记住什么”。这对跨天、跨会话和长时间维护任务非常关键。

### 6.7 TerminalTool：即时环境感知

TerminalTool 允许 Agent 在不预先索引全部文件的情况下探索项目：

- 查看目录、搜索代码、读取日志、统计 CSV、定位函数和 TODO。
- 只允许命令白名单。
- 固定工作目录，禁止访问目录外路径和 `..` 逃逸。
- 设置 30 秒执行超时。
- 输出超过 10 MB 时截断。
- 禁止危险命令，如 `rm`。

这说明“工具能力”必须和“安全边界”一起设计，不能把任意 shell 直接暴露给 LLM。

---

## 七、多智能体与通信协议架构

### 7.1 MCP：Agent 访问工具、资源和提示

MCP 采用 Host、Client、Server 三层结构：

- Host：承载 Agent 的应用。
- Client：在 Host 内连接 MCP Server。
- Server：发布工具、资源和 Prompt。

MCP 解决的是“每个 Agent 都要为每个外部服务编写适配器”的问题。HelloAgents 的 MCPTool 会：

1. 连接 Server。
2. 枚举工具、资源和提示模板。
3. 为远端工具生成本地包装器。
4. 注册到 Agent 的 ToolRegistry。
5. 将 Agent 的调用转换为 MCP `call_tool` 请求。
6. 把结果标准化后返回给 Agent。

文档覆盖的传输包括 Memory、Stdio、带参数的 Stdio、npx 社区服务器以及 HTTP/SSE/StreamableHTTP。教学场景可用 Memory，生产场景可用受控的 Stdio 或远程 HTTP。

### 7.2 A2A：Agent 之间的委托和协作

A2A 关注 Agent 与 Agent 的通信，不是 Agent 与工具的通信。其核心抽象包括：

- **Task**：需要完成的任务。
- **Artifact**：任务产物，如研究结果、文章草稿、代码或结构化数据。
- **Agent Card/技能**：描述远程 Agent 能做什么。
- **消息和流**：支持请求、响应、进度和结果。

项目示例包括：

- 研究员 Agent 收集资料。
- 撰写员 Agent 生成文章。
- 编辑 Agent 审查文章。
- 协调者 Agent 通过 A2A 工具调用这些专家。
- 技术专家和销售顾问分别处理客户咨询。
- 多个 Agent 通过提案和回应协商任务。

实现方式：

1. 小规模系统：中心协调 Agent + 若干远程 Agent Tool。
2. 中规模系统：多个服务通过 HTTP 暴露技能，协调器负责路由。
3. 大规模系统：结合 ANP 做发现，结合队列、身份认证、状态存储和流式事件。

### 7.3 ANP：服务发现和路由

ANP 解决的是“Agent 很多时，如何找到合适的服务”。核心能力包括：

- 注册 Agent 的名称、地址、类型、能力和负载。
- 按类型或能力查询。
- 根据能力匹配选择服务。
- 按当前负载选择实例。
- 建立 Agent 网络和连接关系。
- 在多个同类服务之间做负载均衡。

三种协议可以这样区分：

```text
MCP：我如何使用一个工具或资源？
A2A：我如何把任务交给另一个 Agent，并交换产物？
ANP：我如何发现网络中有哪些 Agent，以及应该连接哪一个？
```

---

## 八、项目案例如何验证这套架构

### 8.1 智能旅行助手

第 13 章把框架放入前后端分离 Web 应用：

```text
Vue3 表单
   -> FastAPI + Pydantic 请求模型
   -> TripPlannerAgent
       -> 天气、地图、景点、路线等 MCP 工具
       -> 多个专家角色协作
       -> 生成 TripPlan 结构化结果
   -> Unsplash 图片服务
   -> Vue3 Result 页面、预算、编辑和导出
```

这个案例体现：

- 用 Pydantic 保证输入和输出契约。
- 用多 Agent 或角色分工解决天气、景点、行程和预算等子任务。
- 用高德地图 MCP 自动获得多个地图能力。
- 用结构化 `TripPlan` 代替不稳定的纯文本答案。
- 用前后端分离和异步 API 承载真实产品体验。

### 8.2 自动化深度研究 Agent

第 14 章采用 TODO 驱动的研究流程：

```text
用户主题
  -> PlanningService 生成 TODO 列表
  -> SearchService 多轮搜索、去重、缓存、降级
  -> SummarizationService 逐任务总结并保存来源
  -> ReportingService 汇总为 Markdown 报告
  -> NoteTool 保存任务摘要和进度
  -> FastAPI SSE 推送实时状态
  -> Vue3 展示进度、日志和报告
```

它把“一个超长 Agent 循环”拆成多个服务和明确状态，优点是更容易恢复、调试、展示进度和限制成本。

### 8.3 赛博小镇 NPC Agent

第 15 章展示了长期运行和高并发场景：

```text
Godot 玩家输入
  -> FastAPI 对话接口
  -> NPC 专属 SimpleAgent
      -> WorkingMemory：最近对话
      -> EpisodicMemory：历史互动
      -> 好感度和角色 Prompt
      -> LLM 生成回复
  -> RelationshipManager 更新关系
  -> StateManager 更新忙碌、位置和状态
  -> DialogueLogger 记录日志
  -> Godot 更新对话 UI
```

为降低成本，系统同时采用：

- 即时模式：玩家发起对话时调用专属 Agent。
- 轻负载模式：后台批量生成多个 NPC 的背景对话。

这说明 Agent 架构还要考虑实时性、并发、缓存、批处理和角色状态一致性。

### 8.4 毕业设计和代码审查助手

第 16 章给出从需求、工具、Agent、演示、评估到 README 的完整项目闭环。代码审查助手的基本结构是：

1. 定义 `CodeAnalysisTool`、`StyleCheckTool` 等工具。
2. 创建 `ToolRegistry`。
3. 初始化 LLM 和系统提示词。
4. 创建 Agent 并注册工具。
5. 读取示例代码，执行审查，保存报告。
6. 补充性能评估和项目文档。

这也是一个可复用的 Agent 项目最小模板。

---

## 九、一个 Agent 应该具备哪些功能

下面区分“核心必备能力”“常用增强能力”和“生产级治理能力”。并不是每个 Agent 都必须一次性实现全部功能，但架构上应保留扩展位置。

### 9.1 核心必备能力

#### 能力 1：任务接收和目标理解

**作用**：把自然语言或事件转换为可执行目标、输入参数、约束和完成标准。

**实现方法**：

- 简单场景：直接把用户文本放入 Prompt。
- 稳定场景：定义 Pydantic `Request` 模型和字段校验。
- 复杂场景：先用意图识别 Agent 分流，再进入专用 Agent。
- 高风险场景：增加用户确认和权限校验。

#### 能力 2：角色、规则和系统提示词

**作用**：定义 Agent 的身份、专业范围、语气、工具使用规则、禁止事项和输出格式。

**实现方法**：

- 固定 system prompt。
- 模板化 prompt，把用户、日期、任务和工具说明作为变量。
- 按领域加载 Prompt 配置。
- 把角色规则、业务规则和安全规则分开管理，便于测试。

#### 能力 3：模型调用和供应商切换

**作用**：为 Agent 提供统一的大模型接口。

**实现方法**：

- 云端 OpenAI 兼容 API。
- ModelScope、智谱等 provider 适配。
- VLLM、Ollama 本地部署。
- 自动检测环境变量，手动指定 provider 作为覆盖。
- 普通调用、流式调用、重试和超时封装在 `HelloAgentsLLM` 内。

#### 能力 4：对话历史和执行状态

**作用**：让 Agent 知道已经说过什么、完成了哪些步骤、工具返回了什么。

**实现方法**：

- `Message` 列表保存短期历史。
- 用 `task_id`、`session_id` 和结构化状态对象保存任务状态。
- 长任务把状态写入 SQLite、JSON 或数据库。
- 对历史设置最大长度、摘要和裁剪策略。

#### 能力 5：行动循环和停止条件

**作用**：让 Agent 能够多轮决策，而不是一次性输出。

**实现方法**：

- Simple 多轮工具循环。
- ReAct Thought/Action/Observation。
- Plan-and-Solve 计划执行。
- LangGraph 状态图。
- 使用 `max_steps`、`max_tool_iterations`、超时、预算和人工审批作为终止条件。

#### 能力 6：工具调用

**作用**：访问实时信息、执行计算、修改环境和调用外部服务。

**实现方法**：

- 简单函数注册。
- `Tool` 子类和参数 schema。
- 原生 Function Calling。
- MCP 外部工具。
- A2A 远程 Agent。
- ToolChain 固定组合，AsyncExecutor 并行执行。

#### 能力 7：结果生成和输出契约

**作用**：给用户或下游系统返回可读、可解析、可验证的结果。

**实现方法**：

- 普通 Markdown 文本。
- JSON 输出并进行解析和修复。
- Pydantic 模型校验。
- Function Calling 返回结构化参数。
- 报告、表格、行程计划等专用数据模型。

### 9.2 常用增强能力

#### 能力 8：知识检索和 RAG

适用于领域知识、私有文档、实时资料和长文档问答。可选实现从简单关键词检索到 Qdrant 向量检索、MQE、HyDE 和混合排序。

#### 能力 9：长期记忆和个性化

适用于用户偏好、历史事件、NPC 关系和跨会话助手。可选实现从 SQLite/JSON 到四类记忆、向量检索、图谱和记忆固化。

#### 能力 10：上下文管理

适用于长对话、长研究和大规模工具结果。建议使用 ContextBuilder 的 GSSC 流水线，显式管理相关性、时效性、重要性和 Token 预算。

#### 能力 11：规划和任务分解

适用于旅行、研究、项目维护和复杂数学问题。可采用：

- LLM 生成列表计划。
- 规则化任务模板。
- 状态图节点。
- 计划评估器检查重复、缺失和不可执行步骤。

#### 能力 12：反思、校验和自我修正

适用于写作、代码、结构化数据和研究报告。可采用：

- 同模型反思。
- 独立评审模型。
- 工具型验证：运行测试、检查 schema、检索来源。
- 多评审结果投票或汇总。

#### 能力 13：多 Agent 协作

适用于专业分工、并行研究和复杂产品。可采用：

- 中心协调 Agent。
- A2A 点对点委托。
- ANP 动态服务发现。
- 角色扮演式协作，如作者、心理学家、研究员、编辑。
- 共享状态存储或事件总线。

#### 能力 14：流式输出和异步执行

适用于长任务和交互式应用。可采用：

- LLM token streaming。
- FastAPI SSE。
- WebSocket。
- AsyncToolExecutor 和并行搜索。
- 后台任务和批处理。

#### 能力 15：外部环境探索

适用于代码库维护、日志分析和数据处理。可采用 TerminalTool、文件系统 MCP 或专用 API，但必须有白名单、目录隔离、超时和输出上限。

### 9.3 生产级治理能力

#### 能力 16：安全和权限

至少包括：

- 工具白名单和用户权限。
- 文件系统沙箱。
- 命令白名单。
- 敏感操作二次确认。
- API Key 不进入 Prompt 和日志。
- 输出内容过滤和数据脱敏。
- MCP/A2A 身份认证、来源校验和网络访问控制。

#### 能力 17：可靠性和故障恢复

实现方法：

- LLM 和工具调用超时。
- 指数退避和有限重试。
- 搜索引擎、模型和存储后端降级。
- 任务状态持久化，支持从中断步骤恢复。
- 幂等操作和请求去重。
- 明确区分可重试错误、用户输入错误和系统错误。

#### 能力 18：可观测性

应记录：

- 请求和任务 ID。
- 每轮 Prompt/响应摘要。
- 工具名称、参数摘要、耗时和结果状态。
- Token、成本、重试和失败原因。
- 当前计划步骤和状态迁移。
- 用户反馈和人工接管。

实现方法可以从普通日志开始，逐步扩展到结构化日志、指标、Trace、SSE 进度和 TensorBoard。

#### 能力 19：评估和回归测试

不要只用“回答看起来不错”判断 Agent：

- BFCL：工具选择、函数名、参数和并行调用准确性。
- GAIA：通用助手真实任务完成率和难度分级。
- LLM Judge：正确性、相关性、完整性、风格等维度。
- Win Rate：两个版本答案的相对质量。
- 人工验证：处理自动指标无法覆盖的主观质量和安全问题。

#### 能力 20：训练和行为优化

当 Prompt、工具和上下文工程仍不足时，可以训练模型：

- SFT：学习任务格式和领域行为。
- LoRA：降低微调参数和资源成本。
- GRPO：根据准确率、长度、步骤质量等奖励优化推理行为。
- 自定义数据集和奖励函数：适配业务任务。
- 评估、错误分析和超参数调优：形成闭环。

---

## 十、不同功能的实现方式对比

### 10.1 “让 Agent 会用工具”有三种路线

| 路线 | 做法 | 适合场景 | 选择建议 |
|---|---|---|---|
| Prompt 文本协议 | 在 Prompt 中约定 `[TOOL_CALL:...]` | 教学、兼容弱模型 | 快速原型优先 |
| 框架 ToolRegistry | 统一注册、发现、执行 | HelloAgents 标准用法 | 大多数项目的默认选择 |
| 原生 Function Calling | 发送工具 schema，解析 tool_calls | 生产工具调用 | 对可靠性要求高时优先 |

### 10.2 “让 Agent 记住信息”有四种路线

1. 当前进程列表：最简单，但重启即丢失。
2. SQLite/JSON：适合小规模持久化和教学项目。
3. 向量数据库：适合语义召回和大量历史。
4. 向量 + 图数据库：同时支持相似度和关系推理。

实际系统通常混合使用：工作记忆在内存，情景记忆在 SQLite/Qdrant，语义记忆在 Qdrant/Neo4j，感知记忆存原文件和跨模态向量。

### 10.3 “让 Agent 处理复杂流程”有三种路线

1. ReAct：让模型动态决定下一步，灵活但不稳定。
2. Plan-and-Solve：先计划后执行，透明且容易恢复。
3. 状态图/工作流：节点和边由代码控制，最可靠但开发成本最高。

建议：开放探索用 ReAct，步骤可预见用 Plan-and-Solve，生产关键流程用状态图或固定工作流。

### 10.4 “让多个 Agent 协作”有三种路线

1. 单进程中心协调：实现简单，适合旅行和研究原型。
2. A2A 服务化：Agent 独立部署，适合跨团队和跨语言协作。
3. A2A + ANP：动态发现、路由和负载均衡，适合规模化网络。

### 10.5 “让 Agent 具备实时性”有四种路线

- LLM 流式 Token：改善用户等待体验。
- 工具并行：减少独立查询的总耗时。
- SSE/WebSocket：持续推送任务阶段和日志。
- 批量生成与缓存：减少高并发场景的模型调用次数。

---

## 十一、建议的 Agent 实现模板

### 11.1 最小可用版本（MVP）

```text
1. 定义输入和输出模型
2. 创建 HelloAgentsLLM
3. 创建一个明确的 system prompt
4. 继承 Agent 或使用 SimpleAgent
5. 保存 Message 历史
6. 注册一个最小 ToolRegistry
7. 设置超时、最大迭代次数和错误返回
8. 添加 5~20 个固定测试样例
```

### 11.2 可用版本

```text
1. 增加结构化输出校验
2. 增加工具 schema 和参数转换
3. 增加短期记忆和 RAG
4. 使用 ContextBuilder 控制上下文
5. 增加日志、工具耗时和失败统计
6. 对外提供 FastAPI 或流式接口
7. 增加重试、降级和任务状态持久化
```

### 11.3 生产版本

```text
1. 根据任务选择 ReAct、Plan-and-Solve、Function Calling 或状态图
2. 对敏感工具加入权限和人工确认
3. 用 MCP 接入标准化外部工具
4. 用 A2A/ANP 拆分和发现专业 Agent
5. 用 Qdrant/Neo4j 管理长期记忆和知识
6. 用 SSE/WebSocket 提供可观测进度
7. 建立 BFCL、GAIA、LLM Judge、人工验证回归集
8. 通过 SFT/GRPO 和错误分析优化行为
9. 做成本、延迟、吞吐和安全审计
```

### 11.4 一个推荐的代码边界

```text
app/
├── api/                 # FastAPI 路由，不放推理细节
├── agents/              # 业务 Agent 和控制策略
├── tools/               # Tool、注册表、MCP/A2A 包装器
├── context/             # ContextBuilder、压缩和排序
├── memory/              # MemoryTool、RAG、NoteTool
├── models/              # Pydantic 请求、响应和状态模型
├── services/            # 搜索、规划、总结、报告等业务服务
├── storage/             # SQLite、Qdrant、Neo4j 适配
├── evaluation/          # BFCL、GAIA、Judge 和回归测试
└── observability/       # 日志、指标、追踪和事件
```

这不是唯一目录结构，但应保持“路由、编排、工具、状态、存储、评估”之间的职责边界。

---

## 十二、设计时最容易犯的错误

### 12.1 把 LLM 当成完整 Agent

只调用一次模型并返回文本，不能解决状态、工具、失败恢复和外部环境交互问题。

### 12.2 把所有内容都塞进 Prompt

上下文越长不一定越好。应使用相关性、时间、重要性和 Token 预算进行选择和压缩。

### 12.3 没有严格的输出协议

让模型自由输出工具名、参数和 JSON，会造成解析失败。应使用 schema、示例、校验和重试。

### 12.4 没有最大步数和超时

ReAct、Reflection 和工具循环都可能无限执行，必须设置安全阀。

### 12.5 工具没有安全边界

尤其是 TerminalTool、文件写入、数据库和远程 API。必须限制命令、路径、权限、输出和网络范围。

### 12.6 把记忆、RAG、笔记混为一谈

- 对话历史：最近发生的消息。
- 记忆：需要跨会话保留的用户或事件信息。
- RAG：外部知识库中的证据。
- 笔记：长任务中明确记录的状态、决策和下一步。

### 12.7 只评估最终答案，不评估行动过程

Agent 可能碰巧给出正确答案，但工具选错、来源不可靠、成本过高或存在安全风险。应同时评估工具调用、过程轨迹、来源、延迟和成本。

### 12.8 多 Agent 过度拆分

不是 Agent 越多越好。只有当角色有清晰边界、可独立验证、需要并行或需要独立部署时，才值得拆分。

---

## 十三、最终归纳

### 13.1 此项目实现的 Agent 完整架构

Hello-Agents 的完整架构不是一个单一类，而是一套从模型到应用的分层系统：

1. **模型适配**：`HelloAgentsLLM` 统一云端和本地模型。
2. **消息与配置**：`Message`、`Config` 保证数据和行为一致。
3. **Agent 抽象**：`Agent` 提供统一生命周期和历史接口。
4. **控制策略**：Simple、ReAct、Plan-and-Solve、Reflection、Function Calling、状态图。
5. **工具系统**：`Tool`、`ToolParameter`、`ToolRegistry`、工具链和异步执行。
6. **知识与记忆**：MemoryTool、四类记忆、RAG、Qdrant、Neo4j、Embedding。
7. **上下文工程**：ContextBuilder 的 GSSC 流水线、NoteTool 和长程状态。
8. **环境访问**：搜索、终端、文件、代码分析和业务 API。
9. **通信协议**：MCP 访问工具，A2A 访问 Agent，ANP 做发现和路由。
10. **应用服务**：FastAPI、Vue3、Godot、SSE 和结构化数据模型。
11. **训练评估**：SFT、GRPO、奖励函数、BFCL、GAIA、Judge、Win Rate 和人工验证。
12. **工程治理**：安全、超时、重试、降级、日志、追踪、成本和恢复。

### 13.2 一个 Agent 最应该具备的能力

最低限度，一个实用 Agent 应具备：

```text
目标理解
  + LLM 推理
  + 消息和状态
  + 工具调用
  + 多轮循环
  + 明确停止条件
  + 结构化输出
  + 错误处理
```

当任务变长、知识变多、环境变复杂时，再逐步增加：

```text
长期记忆 + RAG + ContextBuilder
        + 计划执行 + 反思校验
        + MCP/A2A/ANP
        + 流式、异步和批处理
        + 安全、观测、评估和训练
```

项目文档最终传达的工程原则是：

> **先用统一接口把能力接起来，再用状态、上下文、协议、评估和安全把它做可靠。**

这也是从“能对话的模型”走向“能在真实环境中完成任务的 Agent 系统”的关键路径。

## 参考章节

- `docs/chapter1/第一章 初识智能体.md`
- `docs/chapter4/第四章 智能体经典范式构建.md`
- `docs/chapter6/第六章 框架开发实践.md`
- `docs/chapter7/第七章 构建你的Agent框架.md`
- `docs/chapter8/第八章 记忆与检索.md`
- `docs/chapter9/第九章 上下文工程.md`
- `docs/chapter10/第十章 智能体通信协议.md`
- `docs/chapter11/第十一章 Agentic-RL.md`
- `docs/chapter12/第十二章 智能体性能评估.md`
- `docs/chapter13/第十三章 智能旅行助手.md`
- `docs/chapter14/第十四章 自动化深度研究智能体.md`
- `docs/chapter15/第十五章 构建赛博小镇.md`
- `docs/chapter16/第十六章 毕业设计.md`
