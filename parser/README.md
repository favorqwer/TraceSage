# parser

`docs/LINUX_SYSDIG_LOG_PARSER_DESIGN_V2.md` 的实现：把 Sysdig `.scap` 直接流式解析成
Neo4j 溯源图（3 类顶点、5 类边），并把"每条日志行去了哪里"记成可对账的账本。

- 状态：可运行；172 个单测（含架构依赖方向测试）。默认 **2 趟**：容器元数据预扫 + 主趟。
- 主趟 16 列：`%proc.exepath` 取完整可执行路径，`%evt.rawres` 取统一结果，
  `%evt.latency` 供配对校验，`%evt.buffer` 配 `-b` 取 base64 载荷；所有条件字段配 `*`，缺失输出 `<NA>`，不再整行消失。
- 已补齐：`uid`（euid）、容器带序号挂载、`dirfd`、cwd/chroot 状态、
  路径 `?raw`、`File.file_type` 枚举与回填、`payload_b64` 载荷片段。
- fd 状态：只读/`O_PATH`/`O_TMPFILE` open 也登记 fd（不建边）；`dup/dup2/dup3`、
  `fcntl(F_DUPFD/F_SETFD)`、`close_range` 同步别名与 CLOEXEC；fd 表按 LRU 淘汰；
  进程退出销毁整张表。报告新增 `fd_table_hit/fd_from_token/dirfd_miss/dup_alias_*` 等计数。
- 已精简：Process 不再存 `born_src`；Edge 不再存 `flags`；
  `File.file_type` 固定为 `file/directory/pipe/unix/memfd/unknown`。
- 场景 1 20k、场景 5 全量、场景 9 前 120 万事件已重跑：场景 1 保持 53/819；
  场景 5 由 12,249/129,771 变为 12,241/129,759（4 条失败 `create` 假边被 `rawres` 去掉，
  4 个 socket File 节点及其 8 条边不再落 File）；
  场景 9 由 3,859/97,334 变为 3,852/97,315（socket File 不再落 File），另有 4 个路径修正。
- 不依赖中间 JSONL；主趟一次配对、一次分类、一次结算；容器元数据是独立只读趟。
- 配对：键 `(container,pid,tid,call)` + `%evt.latency` 时间校验；同键多个 pending 不做盲 FIFO，
  歧义/时间不符记未配对——宁可缺边，不配错边。
- 边带 `syscall`（家族名，如 `sendmsg -> sendto`、`mkdirat -> mkdir`）；原始 `evt.type` 用 `event_id` 回日志核对。
  `edges.csv` 与 Neo4j 都写，报告输出 `edges.by_syscall`。
- `mmap` 建边时读 `prot/flags`，不落 flags 属性，动作值三态对称：`FileToProcess mmap_read`；`MAP_SHARED|PROT_WRITE` 建 `ProcessToFile mmap_write`；`PROT_EXEC` 建 `FileToProcess mmap_exec`；私有写不建文件写边。
- `/proc/<pid>/mem` 才派生 `ProcessToProcess`：读 `mem_read` 目标→读取者，写 `mem_write` 写入者→目标；`maps/cmdline/environ` 等元数据不再标 `mem_read`。
- 方向修正：`mem_read/process_vm_readv/ptrace PEEK/pidfd_getfd/wait` 目标→当前；`mem_write/process_vm_writev/ptrace POKE` 当前→目标；`exit` 子→父。
- 同一台机器、场景 5 全量、dry-run 连续对比：旧 4 趟约 39.7s，新 2 趟约 34.4s；
  其中 sysdig 读取部分约 14.4s -> 5.3s（WSL + sysdig 0.27.1）。
- 所有数字都能用 `report.json` 与四个 CSV 复盘；没有"凭印象"的边界。

## 图上的名字（权威口径）

顶点标签：`Process`、`File`、`Network`。

| 关系类型 | 方向 | 说明 |
|---|---|---|
| `ProcessToProcess` | 进程 → 进程 | 派生/信号/调试/跨进程内存 |
| `ProcessToFile` | 进程 → 文件 | 把内容或操作施加到文件、挂载点、unix 套接字 |
| `FileToProcess` | 文件 → 进程 | 文件内容进入进程（读、映射、被执行映像） |
| `ProcessToNetwork` | 进程 → 连接 | 主动外联、绑定、发包 |
| `NetworkToProcess` | 连接 → 进程 | 收包、接受连接 |

关系类型只回答"两端是哪种顶点"，不表达数据流向：动作由边属性 `action` 给出
（普通 IP 的 `connect` 落 `ProcessToNetwork`，unix 域套接字的同名 `connect` 落 `ProcessToFile`）。

顶点属性（主键在前）：

- `Process {host_id, container_id, pid, start_ns, exe_path, cmdline, ppid, uid, euid,
  container_privileged, container_host_root_rw}`
  - `start_ns` 是进程实例出生时刻，同一 `pid` 不同 `start_ns` = exec 前后的两个进程；0 = 未知。
  - `uid` 是日志列 `%user.uid` 的观测值，`euid` 是 `geteuid`/`setuid` 跟踪出的有效用户 id。
  - `container_privileged` / `container_host_root_rw` 是所在容器的元数据结论，缺失 = 未知，不是 false。
- `File {host_id, container_id, path, file_type}`，`file_type ∈ {file, directory, pipe, unix, memfd, unknown}`
- `Network {host_id, endpoints, proto}`，`endpoints` 形如 `10.0.0.2:443->10.0.0.5:51834`

边属性：`event_id`、`action`、`start_ns`、`end_ns`、`syscall`、`result`、`payload_b64`、
`to_path`、`mode`。其中：

- `action` 用 Linux 术语，宾语由关系类型给出（`ProcessToFile {action:"write"}`）。
  取值：`clone`、`exec`、`exit`、`signal`、`ptrace`、`wait`、`mem_read`、`mem_write`、
  `pidfd_getfd`、`create`、`link`、`rename`、`unlink`、`truncate`、`write`、`chmod`、`mount`、
  `umount`、`chroot`、`setns`、`ioctl`、`mmap_read`、`mmap_write`、`mmap_exec`、`read`、
  `stat`、`connect`、`bind`、`listen`、`send`、`accept`、`recv`。
  `exec` 在同一次 `execve` 上出两条边：`ProcessToProcess`（旧身份 → 新身份）与
  `FileToProcess`（可执行映像 → 新进程）。
- `result` 单字段三种单位：数据类 = 字节数、失败 = 负错误码、零 = 实测零；未观测时不写属性。
  语义表见 `core/results.py`，报告里按 action 并列输出。
- `payload_b64` 是 `%evt.buffer -b` 的前 N 字节 base64，不是可打印文本。
- `rename` 在同一次调用上出两条边：`FileToProcess`（源路径 → 进程）与
  `ProcessToFile`（进程 → 新路径）；边属性里不再存源路径。`to_path` 只出现在 `link`（链接目标）。

## 快速开始

```bash
# 探测当前可用的读取后端
python parser/main.py --detect-backends

# 只解析、不写库（推荐先跑这个）
python parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --dry-run

# 开发用小样本（容器/主趟都只读前 N 个事件）
python parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware \
  --dry-run --max-events 20000 --out-dir tmp/parser-v2/run1

# 写库（默认清掉该 host_id 的旧图；库名默认 attack-<scenario>）
python parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware
```

后端：`--backend auto|local|wsl|ssh|docker`。Windows 上默认走 WSL 里的 sysdig（实测可用）。
`--detect-backends` 会实际探测四个后端（含 SSH 连通性与 Docker daemon），然后打印 `auto` 的选择结果。
SSH 后端在本地有 `.scap` 时会自动上传到远端缓存；`--no-ssh-sync` 可禁止上传。

## 结构

```
main.py                  CLI + 装配根（只在这里连具体实现）
data/verbs.toml          30 个动词（§4.2 的 30 个 + 新增 umount，load_image 已并入 exec；另有 4 个延后）
data/calls.toml          §4.3/§4.4 的调用 -> 账本桶 + 原因
provenance/
  settings.py            Settings + 各层配置切片
  core/                  纯逻辑，不碰 IO
    kinds.py             枚举、节点主键、label/key_tuple/key_cells
    events.py            EventRow / Call / BadRow
    graph.py             Node / Edge / Outcome
    classify.py          Classifier + Decision（纯逻辑，无 IO）
    syscalls.py          系统调用家族、OPEN_FAMILY、canonical_syscall
    args.py              evt.args 解码（纯函数）
    paths.py             路径规范化（纯函数）
    pair.py              进出配对、单向事件
    options.py           各层配置切片
    snapshots.py         收尾快照
    stats.py             统计聚合（不写文件）
    ports.py             Capture / GraphWriter / RunObserver
  graph/                 有状态的图构建
    state/               proc / fds / containers + State 快照
    objects.py           ResolvedObject + ObjectResolver（只做客体解析）
    flow.py              FlowRouter（客体 -> 边类/方向）
    emitter.py           只产 Node/Edge
    policies.py          成功门、匿名 fd、/proc 派生边
    context.py           单次调用可用的协作对象
    store.py             节点登记 + 边缓冲 + 度统计（注入 GraphWriter）
    handlers/            dispatch / process / file_lifecycle / file_io /
                         mmap / file_meta / namespace / network / handles
  runtime/
    runner.py            读 -> 配对 -> 分类 -> 产出 -> 记账
    ledger.py            13 桶结算 + 对账等式 + 断号
  adapters/              外部世界
    scap/                backends/ + template.py + capture.py
    config/tables.py     TOML 加载器（把 verbs/calls 转成 core 的内存表）
    neo4j.py             Neo4jWriter + Cypher
    report/              collector.py（统计 + edges.csv）
                         payload.py / tables.py / markdown.py / blocks.py / writer.py
tests/                   172 个标准库 unittest
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
- `template.py`：16 列主模板、容器带序号挂载模板、`*` 前缀、`<NA>` 解码、续行处理。
- `capture.py`：`ScapCapture` 实现 `Capture` 端口；启动时探测 `*` 是否可用。

## 实测：为什么模板是这 16 个字段

设计文档 §1.3 要求"单趟取齐 + 禁止大而全模板"。下表是**不带 `*`** 时的逐字段实测
（sysdig 0.27.1 + 场景 1，20 万事件，`%evt.num` 为 100%）。带 `*` 后缺失字段会变成
`<NA>`，不会丢行。当前主模板实际 16 列：原 13 列中 `%proc.exe` 换成 `%proc.exepath`，
再加 `%evt.rawres`、`%evt.latency`、`%evt.buffer`。

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

## 与设计文档 V2 的差异（都有实测依据）

1. **`result` 优先 `%evt.rawres`**，缺失时回退 `evt.args` 的 `res=`；`openat`/`accept`
   成功时采集端不给 `res`，只给 `fd=`，这两种动词用 `fd` 判成功。
   **`result` 的语义由 `core/results.py` 统一规范**：`open` 家族与 `accept` 成功返回的是
   文件描述符、`mmap` 成功返回的是内存地址，这两类**都不落 `result`**（失败时仍写负错误码）；
   `exit` 永不写 `result`。这样 `result` 只有「字节数 / 负错误码 / 零」三种含义，
   查询里 `r.result > 0` 不会把 fd 号和地址算成字节数。
   场景 1 前 20k 事件实测：改前有 6 条 `create` 边的 `result` 是 fd 号、2 条 `mmap` 边的
   `result` 是内存地址，改后为「未观测」，其余 8 个 action 的四分类零变化。
2. **`payload_b64` 是 `%evt.buffer -b` 的前 80 字节 base64**，不再是可打印文本。
3. **`proc.duration` 暂不启用**：只在捕获内创建的进程上有值；本版不产出
   duration 推算，Process 节点不存 `born_src`，`start_ns` 来源只有 clone / exec / unknown / collision。
4. **`logical_calls`** = 退出行 + 单向事件行；报告里给出口径。
5. **`edges.csv` 按事件顺序写出**（确定性、可 diff），未做全局排序（外部排序代价高）。
6. **`umount` 建边**（新增）：文档 §4.4 只登记 `umount2` 并判为不建边，但 10 个场景
   1.02 亿行里 `umount2` 一次都没出现、`umount` 有 1,860 行且 49% 带 `name=` 挂载点。
   现在 `umount`/`umount2` 走 `umount` 动词：成功建 `ProcessToFile` 边，失败进 attempts。
7. **`gaps` 口径**：主趟使用 `*`，`collector_unprintable` 固定为 0；
   `absent_from_file = missing_numbers`，字段缺失统计见 `placeholder_by_field`。

## 账本与报告

每个场景输出（默认 `output/parser-v2/<scenario>/`）：

- `report.json`：账本、缺号分解、参数可得性、未归类、容器、边分布、
  **`edges.result`（每个 action 的 result 语义 + null/负/零/正 四分类）**、身份/fd 统计、边界清单。
  其中 `param_availability` 是调用级口径（`result_observed` / `result_from_rawres` /
  `result_from_args_fallback`），`edges.result` 是边级口径，两者**不能互推**。
- `report.md`：同一份内容的人读版。
- `nodes.csv` / `edges.csv`：逐字段可复现快照（同输入两次跑字节一致）。
- `ops.csv`：无客体动作与被合并参数（`signal:<n>`、`ioctl:<req>`、`mount:<fstype>` 等）。
- `attempts.csv`：§4.6 里"对象由本次调用产生但失败"的目标 + 错误码。
- `report.json` 另有三块校准/诚实披露：
  - `registered_without_edge`：动词表声明建边、本批零边的调用 + 零边主因
    （`no_object_arg`=数据源不给客体、`attempt:*`=本批全失败、`tuple_unusable`=元组不良构）；
  - `capability_gaps`：`calls.toml` 里 `value=L1/L2` 却因无客体归入记账/丢弃的调用；
  - `endpoint_visibility`：bind/listen 总数与真正产出监听端点边的次数（当前实测 0%）；
  - `collector_blind`：采集端不认识的系统调用清单（读 `data/collector_blind.txt`），
    含关键盲区（`reboot`/`sync` 族/`settimeofday`/`swapon` 等 18 个）与本次盲区行数。
  **错误码只写真实负错误码**；结果未观测（退出行无 `%evt.rawres` 且参数无 `res=`）
  不写这一行——它落 `report.json` 账本的"其他"桶，reason 为 `result_unobserved:<动词>`，
  因为 `0` 在整套口径里是"成功/零字节"，不能拿来当"未知"。

13 个桶：边覆盖 / 属性更新 / 尝试未成立 / 未归类 / **采集端盲区** / 仅句柄 /
未知句柄 / 无客体 / 显式丢弃 / 未配对 / 无进程归属 / 异常行 / 其他。
「未归类」只剩「采集端报了名字但账本表没登记」；「采集端盲区」是「采集端连名字
都不报」——两者修复动作完全不同（改代码 vs 换采集端），必须分开。等式不平时进程直接报错，不写"成功"。

## 已知边界（报告里逐条列出）

- PID 命名空间未翻译：容器内 `kill(局部pid)` 在普通 pidns 里解析不到；命中失败计
  `target_unresolved`，若该 pid 在别的容器存在另计 `target_pid_other_ns`。
- 未连接 UDP 的 `sendto` 目的地址不在参数里（`tuple=NULL`）→ 无客体。
- `bind` 到端口 0 的端点不可见（真实端口只出现在被丢弃的 `getsockname`）。
- unix 套接字只认带路径的（抽象命名空间不是身份）；无路径的计无客体。
- `rename` 出两条边（旧路径 → 进程、进程 → 新路径），但旧路径的历史边不迁移到新路径；
  `link`/`symlink` 的 `to_path` 只是属性，不建边；同路径删除后重建视为同一节点。
- 匿名 IPC（eventfd/signalfd/timerfd/inotify/netlink/无路径 unix）不建节点，计无客体。
- `bpf`/`module`/`io_uring`/`shm` 四个内核对象动词按约定延后（客体无稳定名字）。
- 节点登记表超过 `node_registry_max`（默认 300 万）立即阻断，不静默吞。
- 写库默认只删 `host_id` 相同的旧图；老解析器写入的节点没有这个属性，不会被清掉。
- SSH 远端缓存按文件大小判断是否复用（与 scap-parser 一致）；同尺寸替换不会触发重新上传。
- `proc.duration` 暂未启用；捕获内创建但 clone/exec 丢失的进程仍记 `unknown`。
- `uid`（euid）是稀疏属性，没有相关事件时留空，不能据此断言“无提权”。
- `payload_b64` 只有前 80 字节 base64，不是完整载荷；二进制内容需回原始 `.scap`。
- 容器带序号挂载最多解析 16 个，超过部分回退 `%container.mounts` 复合串。
- 本版不做采集端独立审计：报告只保证内部账本自洽，不证明没有漏行；
  字段缺失统计见 `placeholder_by_field`。

## 测试

```bash
cd parser && python -m unittest discover -s tests -v
```

覆盖：动词表 35 个（31 生效 + 4 延后）、openat 分流、unix/网络改投、成功门与
attempts、自环、线程 clone、账本互斥穷尽、exec 分裂、pid 复用/撞键、fd 覆盖/CLOEXEC、
容器占位、写库 Cypher 参数名、每条边两端节点都已登记、后端命令构造与优先级、
批处理读取的 stderr/退出码；新增覆盖：16 列解码与 `<NA>`、`exepath`、`rawres`、`latency`、
配对（latency 精确/容差/歧义/单 pending/阻塞超时）、fd 状态机（只读 open/dup/fcntl/close_range/LRU/退出销毁）、
base64 `head`、`uid`、`dirfd`、cwd/fchdir/chroot、`?raw`、容器带序号挂载、
`File.kind` 枚举与 `unknown` 回填；**`res` 口径**：fd 号/地址不落图、失败写负错误码、
`exit` 无 res、结果只取退出行、缺失不伪造 `errno=0`、统计与图同源。
