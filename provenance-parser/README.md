# provenance-parser

`docs/LINUX_SYSDIG_LOG_PARSER_DESIGN_V2.md` 的实现：把 Sysdig `.scap` 直接流式解析成
Neo4j 溯源图（3 类顶点、5 类边），并把"每条日志行去了哪里"记成可对账的账本。

- 状态：可运行；123 个单测（含架构依赖方向测试）。默认 **2 趟**：容器元数据预扫 + 主趟。
- 主趟 15 列：`%proc.exepath` 取完整可执行路径，`%evt.rawres` 取统一结果，`%evt.buffer`
  配 `-b` 取 base64 载荷；所有条件字段配 `*`，缺失输出 `<NA>`，不再整行消失。
- 已补齐：`uid`（euid）、容器带序号挂载、`dirfd`、cwd/chroot 状态、
  路径 `?raw`、`File.kind` 枚举与回填、`head` base64。
- 已精简：Process 不再存 `born_src`；Edge 不再存 `flags`；`cmdline` 改名 `args`；
  `File.kind` 固定为 `file/directory/pipe/unix/netlink/special/unknown`。
- 场景 1 20k、场景 5 全量、场景 9 前 120 万事件已重跑：场景 1 保持 53/819；
  场景 5 由 12,249/129,771 变为 12,241/129,759（4 条失败 `create` 假边被 `rawres` 去掉，
  4 个 socket File 节点及其 8 条边不再落 File）；
  场景 9 由 3,859/97,334 变为 3,852/97,315（socket File 不再落 File），另有 4 个路径修正。
- 不依赖中间 JSONL；主趟一次配对、一次分类、一次结算；容器元数据是独立只读趟。
- 同一台机器、场景 5 全量、dry-run 连续对比：旧 4 趟约 39.7s，新 2 趟约 34.4s；
  其中 sysdig 读取部分约 14.4s -> 5.3s（WSL + sysdig 0.27.1）。
- 所有数字都能用 `report.json` 与四个 CSV 复盘；没有"凭印象"的边界。

## 快速开始

```bash
# 探测当前可用的读取后端
python provenance-parser/main.py --detect-backends

# 只解析、不写库（推荐先跑这个）
python provenance-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --dry-run

# 开发用小样本（容器/主趟都只读前 N 个事件）
python provenance-parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware \
  --dry-run --max-events 20000 --out-dir tmp/parser-v2/run1

# 写库（默认清掉该 host_id 的旧图；库名默认 attack-<scenario>）
python provenance-parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware
```

后端：`--backend auto|local|wsl|ssh|docker`。Windows 上默认走 WSL 里的 sysdig（实测可用）。
默认不跑审计；需要独立对账时加 `--audit`（额外两趟）。
`--detect-backends` 会实际探测四个后端（含 SSH 连通性与 Docker daemon），然后打印 `auto` 的选择结果。
SSH 后端在本地有 `.scap` 时会自动上传到远端缓存；`--no-ssh-sync` 可禁止上传。

## 结构

```
main.py                  CLI + 装配根（只在这里连具体实现）
data/verbs.toml          31 个动词（§4.2 的 30 个 + 新增 unmount；另有 4 个延后）
data/calls.toml          §4.3/§4.4 的调用 -> 账本桶 + 原因
provenance/
  settings.py            Settings + 各层配置切片
  core/                  纯逻辑，不碰 IO
    kinds.py             枚举、节点主键、label/key_tuple/key_cells
    events.py            EventRow / Call / BadRow
    graph.py             Node / Edge / Outcome
    classify.py          Tables + Decision（注入式，无全局缓存）
    args.py              evt.args 解码（纯函数）
    paths.py             路径规范化（纯函数）
    pair.py              进出配对、单向事件
    audit.py             Audit 值对象
    options.py           各层配置切片
    snapshots.py         收尾快照
    stats.py             统计聚合（不写文件）
    ports.py             Capture / GraphWriter / RunObserver
  graph/                 有状态的图构建
    state/               proc / fds / containers + State 快照
    objects.py           ResolvedObject + ObjectResolver + 统一流向
    emitter.py           只产 Node/Edge/seq
    policies.py          成功门、匿名 fd、/proc 派生边
    context.py           单次调用可用的协作对象
    store.py             节点登记 + 边缓冲 + 度统计（注入 GraphWriter）
    handlers/            dispatch / process / file / network / handles
  runtime/
    runner.py            读 -> 配对 -> 分类 -> 产出 -> 记账
    ledger.py            12 桶结算 + 对账等式 + 断号
  adapters/              外部世界
    scap/                backends/ + template.py + audit.py + capture.py
    neo4j.py             Neo4jWriter + Cypher
    report/              collector.py（统计 + edges.csv）+ report.py（其余输出）
tests/                   81 个标准库 unittest
```

依赖方向只有三条：

```
adapters  ->  core
runtime   ->  core + graph
graph     ->  core
```

`main.py` 是唯一装配根；`core/` 不 import 任何上层；`graph/` 不 import 配置、IO、runtime；
`runtime/` 不 import 具体适配器。新增 `tests/test_architecture.py` 用 AST 扫描 import，
防止这条规则回退。

### 读取层（`provenance/adapters/scap/`）

- `backends/`：`ScapSource` 抽象 + local/wsl/ssh/docker + 真实探测工厂。
- `template.py`：15 列主模板、容器带序号挂载模板、`*` 前缀、`<NA>` 解码、续行处理。
- `audit.py`：可选的审计 A/B。
- `capture.py`：`ScapCapture` 实现 `Capture` 端口；启动时探测 `*` 是否可用。

## 实测：为什么模板是这 12 个字段

设计文档 §1.3 要求"单趟取齐 + 禁止大而全模板"。下表是**不带 `*`** 时的逐字段实测
（sysdig 0.27.1 + 场景 1，20 万事件，`%evt.num` 为 100%）。带 `*` 后缺失字段会变成
`<NA>`，不会丢行。当前主模板实际 15 列：原 13 列中 `%proc.exe` 换成 `%proc.exepath`，
再加 `%evt.rawres`、`%evt.buffer`。

| 字段 | 可得率 | 结论 |
|---|---|---|
| `%evt.num` `%evt.rawtime` `%evt.dir` `%evt.type` `%thread.tid` `%evt.args` | 100% | 可用 |
| `%proc.pid` `%proc.exe` `%proc.cwd` `%proc.ppid` `%proc.args` `%user.uid` | 91.55% | **缺的行全是 `switch`**，可用 |
| `%fd.name` | 34.74% | 进模板会成行丢失 → 从 `evt.args` 解 |
| `%fd.type` | 34.65% | 同上 |
| `%evt.rawres` | 26.08% | 同上（`evt.args` 里有 `res=`） |
| `%evt.buffer` | 12.83% | 载荷在 `evt.args` 的 `data=` 里 |
| `%proc.duration` | 3.89%（且混入主模板时**整条流 0 行**） | 不放进主模板 |

所以主模板保留窄列，但补上了设计需要的完整路径、原始结果和 base64 载荷；其余仍从
`evt.args` 解。容器元数据单独用带序号挂载字段预扫。

主趟格式串以 `*` 开头：

```
*%evt.num	%evt.rawtime	...	%proc.args
```

这样条件字段缺失时 sysdig 输出 `<NA>` 占位，整行仍然保留；文本模式不是空字符串，
JSON 模式是 `null`。`<NA>` 在解码时还原成缺失语义。

审计是可选的（`--audit`）：

1. 审计 A：`%evt.num %evt.type` → 每个类型总行数。
2. 审计 B：`%evt.num %evt.type %proc.pid` → 每个类型"可归属进程"行数。

有审计时：`主趟接入行数 == 审计 A 总行数`，`主趟有 pid 的行数 == 审计 B 行数`。
没有审计时报告标记 `audit_skipped=true`，不声称独立校验。

## 与设计文档 V2 的差异（都有实测依据）

1. **`res` 优先 `%evt.rawres`**，缺失时回退 `evt.args` 的 `res=`；`openat`/`accept`
   成功时采集端不给 `res`，只给 `fd=`，这两种动词用 `fd` 判成功。
   **`res` 的语义由 `core/results.py` 统一规范**：`open` 家族与 `accept` 成功返回的是
   文件描述符、`mmap` 成功返回的是内存地址，这两类**都不落 `res`**（失败时仍写负错误码）；
   `exit` 永不写 `res`。这样 `res` 只有「字节数 / 负错误码 / 零」三种含义，
   查询里 `r.res > 0` 不会把 fd 号和地址算成字节数。
   场景 1 前 20k 事件实测：改前有 6 条 `create` 边的 `res` 是 fd 号、2 条 `mmap` 边的
   `res` 是内存地址，改后为「未观测」，其余 8 个 action 的四分类零变化。
2. **`head` 是 `%evt.buffer -b` 的前 80 字节 base64**，不再是可打印文本。
3. **`proc.duration` 暂不启用**：只在捕获内创建的进程上有值；本版不产出
   duration 推算，Process 节点不存 `born_src`，`born_ns` 来源只有 clone / exec / unknown / collision。
4. **`logical_calls`** = 退出行 + 单向事件行；报告里给出口径。
5. **`edges.csv` 按事件顺序写出**（确定性、可 diff），未做全局排序（外部排序代价高）。
6. **`umount` 建边**（新增）：文档 §4.4 只登记 `umount2` 并判为不建边，但 10 个场景
   1.02 亿行里 `umount2` 一次都没出现、`umount` 有 1,860 行且 49% 带 `name=` 挂载点。
   现在 `umount`/`umount2` 走 `unmount` 动词：成功建 p2f 边，失败进 attempts。
7. **`gaps` 口径**：主趟使用 `*`，`collector_unprintable` 固定为 0；
   `absent_from_file = missing_numbers`，字段缺失统计见 `placeholder_by_field`。

## 账本与报告

每个场景输出（默认 `output/parser-v2/<scenario>/`）：

- `report.json`：账本、缺号分解、参数可得性、未归类、容器、边分布、
  **`edges.res`（每个 action 的 res 语义 + null/负/零/正 四分类）**、born/fd 统计、边界清单。
  其中 `param_availability` 是调用级口径（`res_observed` / `res_from_rawres` /
  `res_from_args_fallback`），`edges.res` 是边级口径，两者**不能互推**。
- `report.md`：同一份内容的人读版。
- `nodes.csv` / `edges.csv`：逐字段可复现快照（同输入两次跑字节一致）。
- `ops.csv`：无客体动作与被合并参数（`signal:<n>`、`ioctl:<req>`、`mount:<fstype>` 等）。
- `attempts.csv`：§4.6 里"对象由本次调用产生但失败"的目标 + 错误码。
- `report.json` 另有三块校准/诚实披露：
  - `registered_without_edge`：动词表声明建边、本批零边的调用 + 零边主因
    （`no_object_arg`=数据源不给客体、`attempt:*`=本批全失败、`tuple_unusable`=元组不良构）；
  - `capability_gaps`：`calls.toml` 里 `value=L1/L2` 却因无客体归入记账/丢弃的调用；
  - `endpoint_visibility`：bind/listen 总数与真正产出监听端点边的次数（当前实测 0%）。
  **错误码只写真实负错误码**；结果未观测（退出行无 `%evt.rawres` 且参数无 `res=`）
  不写这一行——它落 `report.json` 账本的"其他"桶，reason 为 `result_unobserved:<动词>`，
  因为 `0` 在整套口径里是"成功/零字节"，不能拿来当"未知"。

12 个桶：边覆盖 / 属性更新 / 尝试未成立 / 未归类 / 仅句柄 / 未知句柄 / 无客体 /
显式丢弃 / 未配对 / 无进程归属 / 异常行 / 其他。等式不平时进程直接报错，不写"成功"。

## 已知边界（报告里逐条列出）

- PID 命名空间未翻译：容器内 `kill(局部pid)` 在普通 pidns 里解析不到；命中失败计
  `target_unresolved`，若该 pid 在别的容器存在另计 `target_pid_other_ns`。
- 未连接 UDP 的 `sendto` 目的地址不在参数里（`tuple=NULL`）→ 无客体。
- `bind` 到端口 0 的端点不可见（真实端口只出现在被丢弃的 `getsockname`）。
- unix 套接字只认带路径的（抽象命名空间不是身份）；无路径的计无客体。
- `rename`/`link` 不迁移历史（五边约束）；同路径删除后重建视为同一节点。
- 匿名 IPC（eventfd/signalfd/timerfd/inotify/netlink/无路径 unix）不建节点，计无客体。
- `bpf`/`module`/`io_uring`/`shm` 四个内核对象动词按约定延后（客体无稳定名字）。
- 节点登记表超过 `node_registry_max`（默认 300 万）立即阻断，不静默吞。
- 写库默认只删 `host_id` 相同的旧图；老解析器写入的节点没有这个属性，不会被清掉。
- SSH 远端缓存按文件大小判断是否复用（与 scap-parser 一致）；同尺寸替换不会触发重新上传。
- `proc.duration` 暂未启用；捕获内创建但 clone/exec 丢失的进程仍记 `unknown`。
- `uid`（euid）是稀疏属性，没有相关事件时留空，不能据此断言“无提权”。
- `head` 只有前 80 字节 base64，不是完整载荷；二进制内容需回原始 `.scap`。
- 容器带序号挂载最多解析 16 个，超过部分回退 `%container.mounts` 复合串。

## 测试

```bash
python -m unittest discover -s provenance-parser/tests -v
```

覆盖：动词表 35 个（31 生效 + 4 延后）、openat 分流、unix/网络改投、成功门与
attempts、自环、线程 clone、账本互斥穷尽、exec 分裂、pid 复用/撞键、fd 覆盖/CLOEXEC、
容器占位、写库 Cypher 参数名、每条边两端节点都已登记、后端命令构造与优先级、
批处理读取的 stderr/退出码；新增覆盖：15 列解码与 `<NA>`、`exepath`、`rawres`、
base64 `head`、`uid`、`dirfd`、cwd/fchdir/chroot、`?raw`、容器带序号挂载、
`File.kind` 枚举与 `unknown` 回填；**`res` 口径**：fd 号/地址不落图、失败写负错误码、
`exit` 无 res、结果只取退出行、缺失不伪造 `errno=0`、统计与图同源。
