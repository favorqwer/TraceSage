# TraceSage 溯源图设计

## 1. 日志采集与字段

### 1.1 采集命令

```bash
sudo sysdig -w capture.scap

sudo sysdig -r capture.scap -j -p '\*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' > attack.jsonl
```

### 1.2 溯源项目中所有可能使用的字段

| 属性 | 作用 | 是否一定存在 |
|---|---|---|
| `proc.pid` | 产生事件的进程 ID | 进程事件通常存在，其他事件可能为空 |
| `proc.name` | 可执行文件名称，不包含路径 | 进程事件通常存在 |
| `proc.exepath` | 可执行文件的完整路径 | 进程信息可解析时存在 |
| `proc.args` | 启动进程时传入的参数 | 进程信息可用时存在 |
| `proc.cwd` | 事件发生时进程的当前工作目录 | 进程状态和工作目录可解析时存在 |
| `proc.exeline` | 进程执行命令，可以由 proc.exepath + proc.args 合成，不作为独立字段采集或存储 | 进程信息可用时存在 |
| `fd.type` | 文件描述符类型，如 `file`、`directory`、`pipe`、`socket` 等 | 当前事件包含 FD 时存在 |
| `fd.name` | 文件描述符的完整名称；文件通常是路径，socket 通常是连接元组 | FD 名称解析成功时存在 |
| `evt.arg.filename` | 系统调用传入的文件名或路径参数 | 事件参数中包含 `filename=` 时存在 |
| `fd.l4proto` | 四层网络协议，如 TCP、UDP、ICMP、RAW | 网络 FD 事件中有意义 |
| `fd.lip` | socket 的本地 IP 地址 | 当前 FD 为 IP socket 时存在 |
| `fd.lport` | socket 的本地端口 | 协议包含端口信息时存在 |
| `fd.rip` | socket 的远程 IP 地址 | 已解析远端地址时存在 |
| `fd.rport` | socket 的远程端口 | 已解析远端端口时存在 |
| `evt.num` | 事件编号 | 正常捕获事件中一定存在 |
| `evt.rawtime` | Unix epoch 起始的绝对纳秒时间 | 正常捕获事件中一定存在 |
| `evt.dir` | 事件方向：`>` 表示进入，`<` 表示退出 | 系统调用事件通常存在 |
| `evt.type` | Sysdig 事件类型 | 正常捕获事件中一定存在 |
| `evt.args` | 事件所有参数拼接后的原始字符串 | 有事件参数时存在 |
| `evt.res` | 系统调用返回值或错误码 | 通常退出事件中存在 |
| `evt.latency` | 系统调用从进入到退出的耗时 | 通常退出事件中存在 |

### 1.3 字段恢复关系

```
proc.exeline       由 proc.exepath + proc.args 合成
fd.type            <- evt.args 中 FD 描述符类型，例如 <f>、<4t>
fd.name            <- evt.args 中 FD 的解析名称
fd.lip             <- fd.name 中 socket tuple 的本地地址
fd.lport           <- fd.name 中 socket tuple 的本地端口
fd.rip             <- fd.name 中 socket tuple 的远程地址
fd.rport           <- fd.name 中 socket tuple 的远程端口
evt.res            <- evt.args 中的 res=
evt.arg.filename   <- evt.args 中的 filename=
```

**不考虑多主机。**

---

## 3. 数据模型（Neo4j）

数据来源是把**新导出的单主机 JSONL 日志**直接导入 Neo4j，不是把 PostgreSQL 数据库迁移过来。

### 3.1 顶点（Node）

| Label | 去重键 / MERGE 键 | 属性（写入 Neo4j） |
|---|---|---|
| `Process` | `process_id`（= `pid + name` 拼接字符串） | `process_id`(str), `pid`(str), `name`(str), `exepath`(str, proc.exepath), `args`(str, proc.args), `cwd`(str, proc.cwd) |
| `File` | `file_id`（= path） | `file_id`(str), `path`(str), `type`(str, fd.type) |
| `Network` | `network_id`（= `lip:lport->rip:rport`） | `network_id`(str), `lip`(str), `lport`(str), `rip`(str), `rport`(str), `protocol`(str, fd.l4proto) |

- `process_id` / `file_id` / `network_id` 对应现有代码里 `Process` / `FileEntity` / `NetworkEntity` 的**去重字符串键**（pid+name / path / `src_ip:src_port->dst_ip:dst_port`），**不是**旧实现的 `Entity.uniq_id`（那是自增整数 ID，按 AGENTS.md §4 不迁移到 Neo4j）。
- `pipe`、`socket`、`anon_inode` 和 `tuple=NULL` **不构造 File 顶点**；无 File/Network 对象时只保留可识别的 Process 顶点，**不创建 Unknown 顶点**，不生成事件边，记录 `NO_OBJECT`。
- 连接型四元组不完整时不伪造字段，记录 `INCOMPLETE_NETWORK`，不建顶点、不建边（监听型不在本阶段范围，见 Network 提取）。
- `Network` 顶点只在四元组齐全时构造，所以已构造节点的 `lip`/`lport`/`rip`/`rport` 必有值；`protocol` 则在记录解析到四层协议（fd.l4proto）时写入。

### 3.2 关系（EventEdge）——五种事件边 = 五种关系名

| 关系名 | 方向（语义） | 系统调用（`evt.type`，现有代码注册） | 对应现有边队列 |
|---|---|---|---|
| `p2p` | Process → Process | `execve`（父进程 → 子进程） | `_process_process_lst` |
| `p2f` | Process → File | `write`、`writev`（FD 为 File 时）；`rename`（新路径侧） | `_process_file_lst` |
| `f2p` | File → Process | `read`、`readv`（FD 为 File 时）；`rename`（旧路径侧）；`execve`（可执行文件 → 子进程） | `_file_process_lst` |
| `p2n` | Process → Network | `sendto`、`sendmsg`、`write`、`writev`（FD 为 Network 时） | `_process_network_lst` |
| `n2p` | Network → Process | `read`、`readv`、`recvfrom`、`recvmsg`（FD 为 Network 时）；`accept`；`fcntl` | `_network_process_lst` |

- 表中系统调用即关系属性 `syscall`（原始 `evt.type`），边不再存规范化 action。所列即现有代码（`MetaConfig` 9 个 + 特殊 `execve`/`accept`/`fcntl`）实际建模的全部系统调用；`clone`/`fork`/`open`/`creat`/`bind`/`listen` 等不在范围内，不产生边（见 D6）。
- 同一系统调用按记录中 FD 的实体类型路由：`write`/`writev` 的 FD 为 File 时走 `p2f`、为 Network（socket）时走 `p2n`；`read`/`readv` 同理对应 `f2p` / `n2p`。
- 一个系统调用可产生多条边：`rename` → 旧路径 File→Process（`f2p`）+ 新路径 Process→File（`p2f`）；`execve` → 父进程→子进程（`p2p`）+ 可执行文件→子进程（`f2p`）。`accept`/`fcntl` 只产生单向 `n2p` 边。**不生成合成反向边**：`accept` 不再补 Process→Network 反向边，`execve` 不再补子→父反向边（边只表示实际发生的单向事件，避免假外发与重复计数）。

### 3.3 关系属性

| 属性 | 类型 | 说明 |
|---|---|---|
| `event_id` | int | 全局自增整数（每生成一条边递增 1）；同一条记录对生成的多条边拥有独立的 event_id |
| `starttime` | int(ns) | `>` 进入记录的时间 |
| `endtime` | int(ns) | `<` 退出记录的时间，也是事件真正完成的时间 |
| `syscall` | str | 原始 `evt.type`（如 `read`、`execve`），与 3.2 表中各边对应的系统调用一致 |
| `bytes` | int | 实际读写数据量，从退出记录 `res=` 解析（非负值），元数据类建边填 0 |

- **决策 D5：事件只保留 `bytes`，不保留 `res`。** `res` 仅用于成败判断：`res < 0`（失败）不建边；`res >= 0` 时取非负数值作为 `bytes`。与现有代码 `Utils.extract_size` + `size != -1` 的行为一致。
- 数据传输类调用（read/write/send/recv）正常填充 `bytes`；元数据类调用（open/stat/chmod）和特殊关联边（accept/fcntl/rename）填 `0`。
- 关系不存 `host`（单主机），不做多主机字段。

---

## 5. 已确认的关键决策

| # | 决策 | 说明 |
|---|---|---|
| D1 | 目标模型以本设计文档为准（命名面） | 旧 `.llm.query`（`optype`/`amount`/`srcip`…）是旧 PostgreSQL 列名映射的产物，**不兼容新模型**；按新模型属性（`syscall`/`bytes`/`lip`/`lport`/`rip`/`rport`/`path`）重写查询 |
| D2 | PID 复用的合并 | 不处理。`process_id=pid+name`，内核复用 PID 时不同进程的 (pid,name) 相同时会 MERGE 到同一节点，作为已知限制 |
| D3 | 五种事件边 = 五种关系名 | `p2p` / `p2f` / `f2p` / `p2n` / `n2p`。与现有代码五个边队列一一对应，方向语义自明 |
| D4 | 不补 `rel`、`eventno` | 下游 `.query` 里的 `rel` 与 `eventno` 不在本阶段建模（旧查询按新模型重写，不再依赖 `rel`） |
| D5 | 事件只保留 `bytes`，不保留 `res` | `res < 0`（失败）不建边；`res >= 0` 当作字节数。与现有代码 `Utils.extract_size` + `size != -1` 的行为一致 |
| D6 | 目前只用 9 个系统调用 + 3 个特殊 | 常规 `write writev rename read readv sendto sendmsg recvmsg recvfrom`（对应现有 `MetaConfig`，不再扩表）+ 特殊 `execve` `accept` `fcntl`（rename 亦按特殊规则建边，见 3.2） |
| D7 | 特殊边 `bytes=0` | 数据传输类（read/readv/write/writev/sendto/sendmsg/recvfrom/recvmsg 成功）填非负返回值；特殊关联边（execve/accept/fcntl/rename 边）显式填 0（元数据类 open/stat 等不在建模范围） |
| D8 | 不建 Unknown 顶点 | 无 File/Network 对象时只保留 Process 顶点，记录 `NO_OBJECT` |