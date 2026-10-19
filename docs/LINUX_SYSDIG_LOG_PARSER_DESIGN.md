# TraceSage Linux/Sysdig 单源日志解析与图建模设计规范

# 1 范围、不变量与攻击面对照

## 1.1 覆盖范围

- **覆盖**：一切会产生系统调用记录的攻击行为。
- **不覆盖**：`docs/多主机环境系统调用图物理级不可见与拓扑盲区攻击清单.md` 所列 **25 种单机物理绝缘攻击 + 7 种分布式拓扑盲区**（共 32 项），本模块不承诺任何覆盖能力，禁止在报告中宣称。

## 1.2 三条不变量

| # | 不变量 | 判定方式 |
|---|---|---|
| 1 | **事件不丢**：每条事件只有四个去处——进边、进节点属性、进显式记账丢弃桶、未归类桶 | §8 守恒等式差额为 0 |
| 2 | **语义不丢**：具备独立攻击含义的动作（读/写/改名/删除/权限/连接/监听/接收/身份/内核对象/命名空间/探测）均可单独查询 | §9.2 每个攻击族至少一条参考查询可跑通 |
| 3 | **证据不丢**：每条边自带时间戳、结果码、字节数与必要参数快照，回答"当时发生了什么"无需重读原始日志 | 随机抽 30 条边回原始日志核对 |

## 1.3 攻击面 → 图表达对照

| 攻击族 | 需要的溯源信息 | 图上的表达 |
|---|---|---|
| 初始访问 / 漏洞利用 | 入站连接、接收载荷、落地文件 | `n2p` + `f2p` / `p2f` |
| 执行 | 派生、镜像加载、命令行 | `p2p` + `f2p` + 节点属性 |
| 持久化 | 自启动文件、Cron/Systemd 单元、`authorized_keys`、内核模块 | `p2f`（含 `kernel_module` 客体） |
| 提权 | 身份变更、setuid 程序执行、权限/属主/能力变更 | 节点属性 + `p2f`（`chmod` 带 `mode`）；属主/能力变更只记无客体调用 |
| 防御规避（可见部分） | 日志截断/删除、时间戳篡改、扩展属性、`syslog`、`seccomp`/`personality` | `p2f` + 节点属性 + `p2p syslog`（自环）；时间戳篡改/扩展属性/`seccomp` 只记无客体调用 |
| 凭据访问（可见部分） | 敏感文件读取、密钥操作、`/proc/<pid>/mem` 读取 | `f2p` + 派生 `p2p` |
| 发现 | `stat`/`access`/`readlink`/`getdents64`、`uname`/`sysinfo` | `f2p`（探测）+ `p2p probe_system`（自环） |
| 横向移动 | SSH 会话与外联、`authorized_keys`、连接失败序列 | `p2n` / `n2p` + `p2f` |
| 收集与打包 | 敏感文件读取、零拷贝、管道、共享内存 | `f2p` + `p2f` |
| 命令与控制 | 外联、周期发送、文件描述符传递、半关闭 | `p2n` / `n2p` + 边属性 |
| 数据外泄 | 大流量发送、自定义协议出口 | `p2n` + `status`（字节数）+ 时间序 |
| 影响（勒索/擦除/挖矿） | 批量改名/覆盖/删除、资源占用 | `p2f` / `p2p` + 折叠次数（`covered_count`） |
| 容器逃逸 | 命名空间创建/加入、挂载、`chroot`/`pivot_root`、宿主路径访问 | `p2f`（`namespace` 客体）+ 节点属性 + `host_view_alias`（§3.5） |
| 内存注入 | `ptrace`、`process_vm_*`、`/proc/<pid>/mem`、可执行 `mmap`、`memfd`+`execveat` | `p2p` + `f2p` + 命名客体 + 内存边属性（§3.7） |

---

# 2 事件接入（直读 .scap）

## 2.1 硬要求：直读捕获，不落中间事件文件

**要求**：解析器必须直接读取 `.scap` 二进制捕获——由解析器启动一个 sysdig 进程读该文件，把它的输出当作**事件序列**逐条消费。**不得**先把捕获整体翻译成中间事件文件（JSONL/CSV 等）再解析。

理由（三条，均可独立成立）：

1. **事件身份唯一**：直读时“读到的第 N 条”就是捕获内的事件序号 N，天然可与原始捕获对账；一旦落盘式中转，“行号”与“事件序号”之间多一层依赖，不完整时无法区分“采集缺失”与“中转缺失”。
2. **规模**：最大场景 3,767 万条事件，落盘再读等于双倍 I/O 与双倍磁盘占用。
3. **诚实性**：禁止用历史中间文件替代直读（§2.5）。

代价：接入必须流式（有界内存），任何阶段不得整文件入内存（§7.5）；同时仍要产出 §8 的两层账本与 §11.7 的图快照。

## 2.2 硬要求：字段选择必须 null-safe

sysdig 的字段选择默认行为是：**任一点名字段在该事件上不存在，就丢弃整行**。因此：

**要求**：读取时必须采用“字段缺失也输出该行”的模式（缺失字段渲染为空值），**不得**让默认的整行丢弃行为生效。

实测证据（场景 5，全量 1,366,985 条事件；复现命令见附录 A）：

| 读取方式 | 输出行数 | 结论 |
|---|---|---|
| `%evt.type`（基线） | 1,366,985 | — |
| **裸 `-j`（不带模板）** | **1,366,985** | 一条不丢（默认 8 个键，含 `thread.tid`） |
| 默认文本输出（不带模板） | 1,366,985 | 一条不丢 |
| `%evt.type` + `%fd.num` | 693,437 | 丢 49% |
| `%evt.type` + `%evt.rawres` | 451,509 | 丢 67% |
| `switch` 类事件 + `%fd.name` | **0** | 该类事件整体消失 |

**机理**：字段的“上下文”整体不存在（例如事件没有描述符）时，默认行为会跳过整行；字段存在但无值时输出 `<NA>`。
**因此**：字段清单（§2.3）必须按“缺失也输出”的方式取。丢事件在这里是**按事件类型成批发生**且**不报错**的。

## 2.3 字段清单（单趟取齐）

| 分组 | 字段 |
|---|---|
| 基座 | `evt.num` `evt.rawtime` `evt.dir` `evt.type` `evt.category` `thread.tid` |
| 进程 | `proc.pid` `proc.vpid` `proc.ppid` `proc.exepath` `proc.args` `proc.cmdline` `proc.cwd` `proc.duration` `proc.env` |
| 容器与身份 | `container.id` `container.privileged` `container.mounts` `user.uid` |
| 描述符（条件字段） | `fd.num` `fd.name` `fd.type` `fd.l4proto` `fd.sockfamily` `fd.cip` `fd.cport` `fd.sip` `fd.sport` `fd.dev` |
| 返回值与载荷（条件字段） | `evt.rawres` `evt.failed` `evt.is_io` `evt.buflen` `evt.buffer`（base64） |
| 参数 | `evt.arg[0]` … `evt.arg[4]`；`evt.arg.<名字>` 仅在确认该事件类型支持时使用 |

**清单纪律**：只列有消费者的字段——每加一个字段必须同时指明它落到哪个节点/边属性、或参与哪条推导（§4）；否则不得入清单。

**单趟原则**：上表字段必须在**一次读取**内取齐。禁止把字段拆分到多趟读取再按事件序号合并——那会破坏事件的全序、让对账失去意义，并使“读了几趟”变成可被误用的自由度。唯一允许的例外是 §2.5 的**纯计数核对**（不取任何语义字段）。

## 2.4 执行通道（四选一，语义一致）

| 通道 | 前提 | 适用 |
|---|---|---|
| 本机 sysdig | 运行解析的机器装有 sysdig，且能读到该 `.scap` | Linux 分析机/采集机 |
| WSL2 | Windows 上通过 WSL 里的 sysdig 读取挂载路径 | 本地 Windows 开发 |
| SSH 远端 | 能免密登录一台装有 sysdig 的机器，且该机可读到 `.scap`（必要时先把文件送到该机临时目录） | 分析机与捕获文件不在同一台 |
| 容器 | 有可用容器运行时，能把捕获文件所在目录以只读方式挂进容器 | 不想在宿主机装 sysdig |

**设计约束**：

1. 通道选哪个只影响“在哪执行读取”，**不得影响事件语义**（同一字段清单、同一解析口径、同一对账判据）；
2. 通道不可用（无 sysdig / 连不上 / 无权限 / 读不到文件）→ **立即阻断**并说明缺哪一环，禁止静默降级；
3. **禁止**把“通道不可用”降级成“改读历史中间文件或历史导出产物”；
4. 自动探测顺序、是否允许人工指定通道属实现细节，但“选中的通道确实读到了该 `.scap`”是设计约束（由 §2.5 的计数对账证明）。

## 2.5 对账与禁止事项

**对账（必经）**：

```
独立计数  ==  接入累计事件数
```

- **独立计数**：分母必须来自解析器之外——同一捕获上只取事件序号的纯计数，或采集侧给出的总事件数；
- **接入累计事件数**：解析器实际消费到的行数；
- 差额非 0 → **阻断**，不得进入解析阶段。

**禁止**：

1. 分趟读取字段后合并（§2.3）；
2. 用历史中间文件 / 历史导出 / 上游阶段产物顶替直读；
3. 用“已读到的条数”倒推分母（分母必须独立取得）。

## 2.6 数据可得性

| 项 | 结论 |
|---|---|
| 载荷 | 通过 `evt.buffer` 取得（必须 base64 输出），真实长度看 `evt.buflen`；上限见 §10.2 |
| 容器归属 | `container.id` 可用（场景 9 实测 5 个容器 + 宿主）；`container.privileged`（特权标志）、`container.mounts`（挂载表，`host_view_alias` 的推导来源）按 §2.3 列入字段清单，**非空率待场景 9 验证趟实测确认**（复现命令见附录 A），确认前不得宣称可用 |
| 进程启动时间 | 由 `evt.rawtime − proc.duration` 反推 |
| 未覆盖的调用 | 清单与未验证标注见 §10.2 |

---

# 3 图模型

## 3.1 节点：3 类

设计原则：**节点标签只用于"必须靠遍历才能表达的共享客体"**；其余一律折叠为 `:File` 上的命名客体 + `object_class` 属性。

| # | 节点类 | 承载 | 主键（复合字段，不另存键串属性） | 创建时机 |
|---|---|---|---|---|
| 1 | `:Process` | 执行主体：身份、命令行、容器归属、身份变更史、资源画像 | (`host_id`, `container_id`, `pid`, `start_time_ns`) | 任一事件首次出现该进程时懒加载；`clone`/`execve` 时精确化 |
| 2 | `:File` | 全部客体（见 §3.2） | (`host_id`, `mount_view`, `path`) | 路径类或句柄类事件首次指向时 |
| 3 | `:Network` | 网络会话端点、监听端点与未建立四元组的网络客体 | 会话 (`host_id`, `proto`, `lower_ip`, `lower_port`, `upper_ip`, `upper_port`)；监听 (`host_id`, `proto`, `ip`, `port`) | `connect`/`accept`/`bind`/`listen`/收发报文首次出现时；裸 `socket()` 建 `:Network:PeerUnknown` |

`:Network` 节点按形态带第二标签：会话 `:Network:Session`、监听端点 `:Network:Listener`、未建立四元组的网络客体 `:Network:PeerUnknown`（键 `host_id` + `proto`，见 §4.3；三类主键字段不同，唯一约束各一条，见 §7.4）。

不建节点的东西：主机（`host_id` 属性）、线程（`thread.tid` 属性）、身份（进程属性）、单次调用参数与内存区间（边属性）。

## 3.2 非路径客体的命名与 `object_class`

| 客体 | `path` 命名 | `object_class` |
|---|---|---|
| 匿名/命名管道 | `pipe:[<ino>]` | `pipe` |
| UNIX 域套接字 | 有路径用路径；无路径 `unixsocket:[<地址对>]` | `socket_unix` |
| netlink 套接字 | `netlink:[<proto>]` | `socket_netlink` |
| packet 套接字 | `packet:[<ifindex>]` | `socket_packet` |
| eventfd / signalfd / timerfd / inotify / epoll | `eventfd:[<fd>]` 等 | `eventfd` / `signalfd` / `timerfd` / `inotify` / `epoll` |
| 内存文件 | `memfd:<name>` | `memfd` |
| 共享内存 | `shm:<shmid>` | `shm` |
| io_uring 环 | `ioring:<id>` | `io_uring` |
| 用户态缺页处理 fd | `userfaultfd:<fd>` | `userfaultfd` |
| 进程句柄 fd | `pidfd:<fd>` | `pidfd` |
| 匿名临时文件 | `tmpfile:<dev_major>:<dev_minor>:<inode>` | `regular`（靠 `path` 前缀 `tmpfile:` 区分） |
| 无路径句柄访问的客体 | `handle:<fsid>:<hex>` | `regular`（靠 `path` 前缀 `handle:` 区分） |
| 终端 | `tty:<dev>` | `tty` |
| `/proc` 虚拟文件 | 原路径 | `proc_virtual` |
| 内核模块 | `kernel:module:<name>` | `kernel_module` |
| eBPF 程序 / 映射 | `kernel:bpf:<prog\|map>:<id>` | `kernel_bpf` |
| 密钥 | `kernel:key:<serial>`（本数据源不可建） | `kernel_key` |
| 命名空间 | `ns:<type>:<id>` | `namespace` |
| 普通文件 / 目录 / 设备 | 原路径 | `regular` / `directory` / `device_char` / `device_block` |
| 未识别 | 原路径或占位 | `unknown` |

## 3.3 边：5 类语义边 + 1 类结构性关系

| # | 边类 | 方向 | 语义 | 覆盖动作族（§5.2） |
|---|---|---|---|---|
| 1 | `p2p` | 进程→进程 | 派生、线程创建、镜像替换、退出、等待、信号、内存读写/注入、保护属性变更（自环）、无客体元数据/密钥操作（自环）、pidfd 操作 | A、B、E、J |
| 2 | `p2f` | 进程→客体 | 写、创建、改名、截断、删除、链接、权限（`chmod`）、加锁、零拷贝出、IPC 写、内核对象操作、命名空间与挂载操作、io_uring 提交 | C 写向、D、E、I 写向、J、K |
| 3 | `f2p` | 客体→进程 | 读、映射、镜像加载、零拷贝入、IPC 读、探测、密钥读取、无路径句柄访问 | C 读向、I 读向、J 读向、F |
| 4 | `p2n` | 进程→网络 | 连接、绑定、监听、发送、半关闭、套接字选项、套接字创建 | H 主动向 |
| 5 | `n2p` | 网络→进程 | 接受入站、接收数据、地址查询 | H 被动向 |

补充约定：`accept` 生成的会话节点与监听端点之间建一条**结构性关系** `listen_ref`（不来自事件、不带 §4.4 属性）指回监听端点；`mprotect` 等进程内部动作用 `p2p` 自环。

## 3.4 升格规则（可逆机制）

仅当某客体同时满足以下三条，才允许从 `:File` 折叠态升格为独立节点标签（只改标签，不改主键与属性）：

1. 会被两个以上进程共享；
2. 该共享关系本身是必须遍历的因果链；
3. 没有可用的路径标识。

## 3.5 身份与视图规则

### 3.5.1 路径规范化

1. 以 `/` 开头视为绝对路径，直接使用；
2. 相对路径：优先用 `dirfd` 在句柄表中解析出的目录路径拼接 `arg.name`；`dirfd` 不可得时用进程当前 `cwd`；两者都不可得 → 计 `path_unresolved`，节点 `path` 写 `?<原始字符串>`；
3. 规范化：合并连续 `/`；解析 `.` 与 `..`（纯字符串处理，不访问文件系统）；去掉末尾 `/`（根除外）；**不做大小写折叠**（Linux 区分大小写）；
4. **不解析符号链接**：同一文件经不同软链接会得到多个节点（§10.2）；
5. `O_TMPFILE` 创建的匿名文件 → `tmpfile:<dev_major>:<dev_minor>:<inode>`；inode 不可得时用首次事件号。

### 3.5.2 `fd.name` 形态判定（按优先级）

1. 形如 `xxx:[数字]` → IPC 客体（`pipe:[n]` / `socket:[n]`）；
2. 含 `->` 且两侧形如 `地址:端口` → 网络四元组（配合 `fd.type` 判定地址族）；
3. 以 `/` 开头 → 路径；
4. 其余按 `fd.type` 判定；仍不可判 → `object_class=unknown` 并计数。

### 3.5.3 容器视图（`mount_view`）与宿主别名

1. `mount_view` = 进程的 `container_id`（无容器为 `host`）；
2. 同一字符串路径在不同视图**视为不同客体**（安全侧选择：宁可分裂，不可合并）；
3. 若容器事件给出挂载表（`Mounts` 的 `Source`/`Destination`），据此推导容器内路径对应的宿主路径，写入该 `:File` 的 `host_view_alias` 属性，并在报告中输出完整映射表（匹配算法见 §12 决策点 2）；
4. **不做节点合并**：两个视图各自保留节点，靠 `host_view_alias` 关联；无法推导时该属性留空。

### 3.5.4 网络归一化

1. 地址族不混比（`ipv4` 与 `ipv6`）；
2. IPv4 按四个八位组的数值比较；IPv6 先规范化为固定形式（去前导零、`::` 展开）再按数值比较；
3. 地址相同时比端口数值；
4. 通配地址（`0.0.0.0` / `::`）只用于监听端点，不参与会话归一化；
5. 结果写 `lower_*` / `upper_*`（身份与跨机缝合用），并写 `server_end`（由 `fd.sip`/`fd.sport` 与归一化结果比对得出，指出服务端端点落在归一化排序的哪一端）；两端归一化后相等或四元组缺失时不写 `server_end`；
6. 四元组缺失（`tuple=NULL` 且句柄表补不齐）→ 建"对端未知"节点（标签 `:Network:PeerUnknown`，`lower_*`/`upper_*` 留空）并计 `net_tuple_missing`。

## 3.6 缝合规则

| 场景 | 缝合方式 |
|---|---|
| 同主机 进程↔客体↔进程 | 天然两跳链（`p2f` 与 `f2p` 通过同一客体节点相连） |
| UNIX 域套接字 / 管道对端 | **不建额外边**，靠共享客体节点形成两跳 |
| 跨主机网络会话 | 两台主机的会话节点**不合并**（主键含 `host_id`）；跨机遍历用"`proto` + `lower_*` + `upper_*` 相同"做属性匹配，或与对端主机的 `bind`/`accept` 记录对齐 |
| 不可缝合 | NAT 重写、只采一侧、通配绑定、回环连接、容器 Overlay（§10.1） |

禁止把两台主机的会话节点强行合并为一个（回环与私网地址重叠会假缝合）。

## 3.7 内存区间的表达

内存映射区间**不作为节点**（不满足 §3.4 升格规则的第二条）：`mmap`/`mprotect` 只保留动作与 `flags`（保护位/标志）；`PROT_EXEC` 由 `flags` 表达，地址/长度不落图（§10.2 #15）。

## 3.8 图示意

```text
                        ┌──────────────────────────────┐
           p2p          │          :Process            │
   ┌───────────────────►│ host:container:pid:start     │
   │                    └──┬───────────────────────┬───┘
   │              p2f/f2p  │                       │  p2n / n2p
   │                       ▼                       ▼
   │              ┌──────────────────────┐   ┌──────────────┐
   │              │        :File         │   │  :Network    │
   │              │ 文件/目录/设备/管道/    │   │ 会话 / 监听   │
   │              │ 套接字/memfd/shm/tty/  │   └──────────────┘
   │              │ proc虚拟/内核对象/      │
   │              │ 命名空间(object_class)  │
   │              └──────────────────────┘
```

---

# 4 属性与折叠

**总则：节点只存身份与状态，细节在边上或由边推导。**

- **文件**：权限（`mode`）只在变更边上——节点快照只是“采集窗口内最后一次看到的值”，与 `chmod` 边重复；谁在何时改成什么由边记录。属主、时间戳、扩展属性在采集侧是泛型事件（无参数、无返回值），不落图（§10.2）。客体自身的编号已嵌在 `path` 里（`pipe:[<ino>]`、`tmpfile:<dev>:<dev>:<ino>`、`shm:<shmid>`），`handle:<fsid>:<hex>` 前缀本身就是“无路径句柄访问”的标记；命名空间的类型是节点身份的一部分（`ns:<type>:<id>`，§3.2）；内核对象的操作级参数（`kernel_cmd`）在边上，seccomp 的过滤器模式/内容不保留（§10.2）。
- **网络**：容器归属 = 接入边上进程节点的 `container_id`（一跳）；会话出现/结束时间 = 该节点所有边的 `min(start_time_ns)`/`max(end_time_ns)`；收发流量 = 数据类边的 `status`（成功时的字节数）× `covered_count`；地址族（IPv4/IPv6）由地址串形态判定；**服务端端点**（连接中哪一端是服务提供方）由 `server_end` 标注；**本机端是客户端还是服务端**由接入边动作决定（`connect` = 客户端，`accept` = 服务端）——两者是不同的事实，不可互相替代。

## 4.1 `:Process` 属性

| 属性 | 必/条 | 来源 |
|---|---|---|
| `host_id` / `container_id` | 必 | 配置注入 / `container.id`（无容器为 `host`）；与 `pid`、`start_time_ns` 共同构成复合主键 |
| `pid` | 必 | `proc.pid` |
| `exe_path` | 必 | `proc.exepath` |
| `cmdline` | 必 | `proc.cmdline`、`proc.args` |
| `start_time_ns` | 必 | `evt.rawtime − proc.duration`（首个观测事件处计算；缺失时按 §4.6 降级） |
| `container_privileged` | 条 | 容器事件字段 |
| `uid` / `ruid` | 条 | `user.uid`、`get*uid`、`set*uid` 事件 |
| `identity_history` | 条 | 身份与状态变更记录：时间、系统调用、字段、旧值、新值（`cwd`/限额等可取得值；`capset`/`prctl` 等泛型事件只记调用发生，见 §10.2） |
| `env` | 条 | `proc.env`（exec 时的环境变量块，采集侧上限 4096 字节） |

## 4.2 `:File` 属性

| 属性 | 必/条 | 来源 |
|---|---|---|
| `host_id` / `mount_view` / `path` | 必 | 复合主键与配置（§3.5.1、§3.5.3） |
| `object_class` | 必 | §3.2 映射 |
| `host_view_alias` | 条 | 由容器挂载表推导的宿主路径（§3.5.3） |

## 4.3 `:Network` 属性

**会话端点**（标签 `:Network:Session`，主键：`host_id` / `proto` / `lower_ip` / `lower_port` / `upper_ip` / `upper_port`）：`host_id`、`proto`（`fd.l4proto`）、`lower_*`/`upper_*`（§3.5.4 归一化结果）、`server_end`（取值 `lower` 或 `upper`，指出服务端端点落在归一化排序的哪一端；四元组缺失或两端归一化后相等时不写）。客户端端点即 `lower_*`/`upper_*` 中 `server_end` 所属端的另一端；本机角色（本机端是客户端还是服务端）由接入边动作推出（§4 前言），不另存属性；同一会话节点的 `server_end` 以首次观测为准，不回填覆盖（§11.3 契约纪律 3）。与监听端点的关联由结构性关系 `listen_ref` 承载（§3.3），不存键串属性。

**监听端点**（标签 `:Network:Listener`，主键：`host_id` / `proto` / `ip` / `port`）：`host_id`、`proto`、`ip`（含通配 `0.0.0.0`/`::`）、`port`。

**未建立四元组的网络客体**（标签 `:Network:PeerUnknown`，主键：`host_id` / `proto`）：裸 `socket()` 与四元组缺失时的落地节点；同一（`host_id`, `proto`）归一为一个节点，逐次调用的差异由边属性承载；`connect`/`accept` 得到四元组后，该 fd 的图客体切换为 `:Network:Session`，此前产生的边保留在本节点上。

## 4.4 边属性

**通用属性**（5 类语义边共有）

| 属性 | 必/条 | 来源 |
|---|---|---|
| `edge_id` | 必 | `evt.num`（折叠后为 `first:last`） |
| `action` | 必 | §5.3 动作词表 |
| `start_time_ns` / `end_time_ns` | 必 | 进入行/退出行 `evt.rawtime`（单点事件二者相等） |
| `status` | 条 | `evt.rawres` 的返回值本身（失败调用为负；数据类调用成功时即字节数；泛型退出行无值）。**只承载返回值语义（errno 值、字节数、零值），不承担“是否失败”的判定**；不得用 `evt.failed` 填充 |
| `failed` | 条 | `evt.failed`（独立布尔位：本次调用是否失败；**“是否失败”的判定一律看本属性**，不看 `status` 的正负；不得用 `evt.failed` 填充或代替 `status`） |
| `buffer_head_b64` | 条 | `evt.buffer`（base64；载荷保留可配置，见附录 C）；是否截断由 `status` 与快照解码长度比较现算 |
| `flags` | 条 | `arg.flags`（标志位与保护位的唯一落点，已解码 `O_*` / `PROT_*` / `MAP_*` / `MS_*` / `CLONE_*` / `AT_*`）；ioctl 请求码记 `request` |
| `missing_params` | 条 | 参数或客体取不到的标记，**仅限“本该有、本次取不到”**（规则 6、28）；“本数据源天然无客体/无参数”的动作由 §11.9 事件字典逐动作标注，不写本属性；不伪造取值 |
| `covered_count` | 条 | 折叠器 |

**三态语义**：有值 = 实测；无属性 = 未观测到；`0` = 实测零。特别注意：`mmap`/`brk` 的返回值是**地址**，禁止记入 `status`。

**专有属性**

| 边类 | 专有属性 |
|---|---|
| `p2p` | `signal` |
| `p2f` / `f2p` | `old_path`、`mode`、`kernel_cmd`、`request` |
| `p2n` / `n2p` | — |

结构性关系 `listen_ref`（§3.3）不承载 §4.4 任何属性。

## 4.5 折叠

**折叠**（同源、同宿、同 `action`、同 `status`）：

1. 判据：本条事件的结束时间与该槽位上一条事件的结束时间间隔 < `fold_window_ns`（默认 200 毫秒，附录 C）；每（主机, 容器, 进程, 源, 宿, 方向, 动作）一个槽位；
2. 合并为一条边，累加 `covered_count`（只有 `status` 相同才折叠；总字节 = `status` × `covered_count`），更新末时间戳，保留组内首个事件的载荷快照；
3. **禁止跨客体折叠**（客体切换即打断）、**禁止跨方向折叠**；
4. **禁止折叠**：`execve`、`rename`、`unlink`、`chmod`/`chown`、`mount`/`setns`、`bpf`/`keyctl`/模块加载、`connect`/`bind`/`listen`、以及任何失败调用（判据：`failed=true` **或** `status<0`；`status` 缺失的行靠 `failed` 判定）；
5. 窗口是**受控变量**：必须报告附录 C 的 `fold_window_sensitivity` 各档下的边数与关键指标变化。

## 4.6 缺失数据降级表

| 缺失项 | 降级动作 | 记账项 |
|---|---|---|
| `proc.duration` | `start_time_ns = 0`（启动时间未知，禁止当成 1970 年） | `start_time_unknown` |
| `evt.rawtime` | 阻断（不允许无时间的事件进入流水线） | `blocked_no_timestamp` |
| 事件语义需要客体但 `fd.num`/`fd.name` 缺失 | 不建数据流边（`openat` 类自带参数者除外） | `unknown_fd` |
| 句柄表未命中该 fd | 不建数据流边 | `unknown_fd` |
| `fd.type` 缺失 | `object_class = unknown` | `class_unknown` |
| `container.id` 缺失 | `container_id = host` | `container_attribution_missing` |
| `evt.rawres` 缺失 | 不写 `status`（`evt.failed` 可用时仍写 `failed`） | 计入对账表的对应分支 |
| 网络四元组缺失 | 建"对端未知"节点 `:Network:PeerUnknown`（`lower_*`/`upper_*` 留空） | `net_tuple_missing` |
| 相对路径无法解析 | `path = ?<原始字符串>` | `path_unresolved` |
| 孤儿退出行（无进入行） | 自带全部参数者独立建边；否则丢弃 | `unpaired_independent` / `unpaired` |
| `thread.tid` 缺失 | 用 `pid` 作线程标识 | `tid_missing` |

---

# 5 系统调用分类与动作词表

## 5.1 原则

1. 先判信息流（谁把数据给了谁）→ 再判状态变更（谁改了什么）→ 最后才判纯行为。
2. 每个系统调用恰好属于一个动作族；族决定落哪类边。映射不上的落 N 桶（未归类），不入族统计、不得静默丢弃。
3. 分类函数的输入是 **系统调用名 + 关键标志位 + 两端客体类型**（同名不同参数可落到不同动作）。

## 5.2 13 个动作族 + 未归类桶

| 族 | 含义 | 落哪类边 | 覆盖（代表性调用，全量名单见附录 B） |
|---|---|---|---|
| A 进程控制 | 主体的生灭与相互控制 | `p2p`（镜像加载 `f2p`）；`signaldeliver`/`wait*` 不建边 | `clone`/`execve`/`exit`/`wait*`/`kill`/`tgkill`/`signaldeliver`/`sigreturn`/`pidfd_*` |
| B 进程内存 | 进程内存读写/保护/映射 | `p2p`（文件后备时 `f2p`）；`munmap`/`mremap`/`madvise`/`brk`/`mincore` 不建边 | `mmap`/`munmap`/`mprotect`/`mremap`/`madvise`/`brk`/`mincore`/`userfaultfd` |
| C 文件数据流 | 进程与客体间数据搬运 | `p2f` / `f2p` | `read`/`write`/`readv`/`writev`/`pread`/`pwrite`/`splice`/`tee`/`sendfile`/`copy_file_range`/`io_uring_*` |
| D 文件生命周期 | 客体创建/删除/改名/链接 | `p2f` | `openat`(带 `O_CREAT`)/`mkdir`/`mknod`/`unlink`/`rmdir`/`rename`/`link`/`symlink`/`truncate`/`ftruncate`/`fallocate` |
| E 文件元数据 | 权限/属主/时间戳/扩展属性/刷新 | `p2f`（`chmod`、`fsync`）；`chown`/`utimes`/`setxattr` → 无客体 `p2p` 自环 | `chmod`/`chown`/`utimensat`/`*xattr`/`flock`/`fsync`/`fdatasync`/`msync`/`fadvise64` |
| F 探测（发现） | 只读询问，不搬运数据 | `f2p`（动作名 `probe`）；无客体者（`probe_system`）落 `p2p` 自环 | `stat`/`fstat`/`newfstatat`/`access`/`readlink`/`getdents64`/`statfs`/`getcwd`/`uname`/`sysinfo` |
| G 句柄管理 | 描述符复制/关闭/定位/控制 | 属性更新（必要时建边） | `close`/`dup`/`dup2`/`dup3`/`fcntl`/`lseek`/`ioctl`(可解码) |
| H 网络 | 连接、监听、收发 | `p2n` / `n2p`；`shutdown`/`setsockopt`/`getsockopt`/`getsockname`/`getpeername` 不建边 | `socket`/`connect`/`bind`/`listen`/`accept`/`send*`/`recv*`/`shutdown`/`setsockopt`/`getsockopt`/`getsockname`/`getpeername` |
| I 本地 IPC | 管道、UNIX 域套接字、事件/信号/定时/监听 fd、共享内存 | `p2f`（`object_create`）/ `f2p`（`mmap_file`，`shmat`） | `pipe`/`socketpair`/`eventfd`/`signalfd`/`timerfd_create`/`inotify_*`/`epoll_create*`/`epoll_ctl`/`shm*` |
| J 内核对象 | 模块、eBPF、密钥、过滤器、内核控制 | `p2f` / `f2p`（客体 `kernel:*`）；`keyctl`/`add_key`/`request_key`/`seccomp` 不建边 | `finit_module`/`init_module`/`delete_module`/`bpf`/`keyctl`/`add_key`/`request_key`/`seccomp`/`kexec_load` |
| K 命名空间与挂载 | 视图切换与挂载 | `p2f`（客体 `ns:*` / 挂载点 / 新根目录）；`umount*` 不建边 | `unshare`/`setns`/`chroot`/`pivot_root`/`mount`/`umount` |
| L 身份与状态 | 主体自身属性变更与身份观测 | 节点属性 | `set*uid`/`set*gid`/`setgroups`/`capset`/`prctl`/`personality`/`setrlimit`/`ioprio_set`/`sched_*set*`/`umask`/`chdir`/`get*uid` |
| M 时序与调度 | 不含信息流的等待/轮询/时钟/自省 | 只保留 `p2p`（自环）的 `syslog` 与 `timer_arm`；其余**显式记账丢弃**，不入图 | `syslog`/`setitimer`/`alarm`/`timerfd_settime`/`timer_settime`（建边）；`poll`/`select`/`futex`/`nanosleep`/`clock_*`/`switch`/`getpid` 等（丢弃，全量名单见附录 B） |
| N 未归类 | 映射表未覆盖 | 不入图，记账 + 告警 | — |

**权威声明**：本表“落哪类边”是族级汇总；动作级权威映射在 §5.3，边类定义在 §3.3、边属性在 §4.4。三者冲突时以 §5.3（动作级）为准。

> `openat` 按 `flags` 分流：带 `O_CREAT`/`O_TRUNC` → `create`（`p2f`）；其余打开不建边（后续读写由 `read`/`write` 边覆盖）。`ioctl` 一律归 G 族（`ioctl_op`）：请求码可解码时按方向落 `p2f`/`f2p`，解不出时落 `p2p` 自环并原样保留请求码。

## 5.3 动作词表（唯一枚举）

实现必须使用本表的动作名，不得自创同义词。

| 动作名 | 族 | 落边 | 适用调用（简写） |
|---|---|---|---|
| `spawn` | A | `p2p` | `clone`/`clone3`/`fork`/`vfork`（非线程；`CLONE_THREAD` 不建边） |
| `exec` | A | `p2p` | `execve`/`execveat`（失败同落 `exec`，由 `failed` 表达） |
| `load_image` | A | `f2p` | `execve`/`execveat`（与 `exec` 成对） |
| `exit` | A | `p2p` | `exit`/`exit_group`/`procexit`（`wait4`/`waitid` 不建边） |
| `signal` | A | `p2p` | `kill`/`tgkill`/`tkill`/`pidfd_send_signal`（`signaldeliver` 不建边） |
| `signal_return` | A | `p2p` | `sigreturn` |
| `pidfd_getfd` | A | `p2p` | `pidfd_getfd`（`pidfd_open` 只登记句柄、不建边） |
| `mmap_file` | B | `f2p` | `mmap`/`mmap2`（文件后备）、`shmat` |
| `mmap_anon` | B | `p2p`（自环） | `mmap`/`mmap2`（`MAP_ANONYMOUS`） |
| `mprotect` | B | `p2p`（自环） | `mprotect`（`munmap`/`mremap`/`madvise`/`brk`/`mincore` 不建边） |
| `mem_read` | B | `p2p` | `ptrace`/`process_vm_readv`/`/proc/<pid>/mem` 派生 |
| `mem_write` | B | `p2p` | `ptrace`/`process_vm_writev`/`/proc/<pid>/mem` 派生 |
| `ptrace_attach` | B | `p2p` | `ptrace`（`PTRACE_ATTACH`/`PTRACE_SEIZE`） |
| `ufd_register` | B | `p2f` | `userfaultfd`（客体 `:File`(`userfaultfd:<fd>`)） |
| `read` | C | `f2p` / `n2p`（套接字） | `read`/`readv`/`pread`/`preadv` + 零拷贝入向（`splice`/`tee`/`vmsplice`/`copy_file_range`） |
| `write` | C | `p2f` / `p2n`（套接字） | `write`/`writev`/`pwrite`/`pwritev` + 零拷贝出向（`splice`/`sendfile`/`copy_file_range`） |
| `io_uring_op` | C | `p2f` | `io_uring_setup`/`io_uring_enter`/`io_uring_register`（客体 `ioring:<id>`） |
| `create` | D | `p2f` | `openat`/`open`/`creat`（带 `O_CREAT`）、`mkdir`/`mkdirat`、`mknodat` |
| `unlink` | D | `p2f` | `unlink`/`unlinkat`、`rmdir` |
| `rename` | D | `p2f` | `rename`/`renameat`/`renameat2`（带 `old_path`） |
| `link` | D | `p2f` | `link`/`linkat` |
| `symlink` | D | `p2f` | `symlink`/`symlinkat` |
| `truncate` | D | `p2f` | `truncate`/`ftruncate`/`fallocate` |
| `chmod` | E | `p2f` | `chmod`/`fchmod`/`fchmodat`（带 `mode`） |
| `chown` | E | `p2p`（自环） | `chown`/`fchown`/`fchownat`/`lchown` |
| `utimes` | E | `p2p`（自环） | `utimensat` |
| `setxattr` | E | `p2p`（自环） | `setxattr`/`lsetxattr`/`fsetxattr`/`removexattr` |
| `fsync` | E | `p2f` | `fsync`/`fdatasync`/`msync`（`flock`/`fadvise64` 不建边） |
| `probe` | F | `f2p` | `stat`/`fstat`/`lstat`/`newfstatat`/`access`/`faccessat`/`readlink`/`readlinkat`/`getdents64`/`statfs`/`fstatfs` |
| `probe_system` | F | `p2p`（自环） | `uname`/`sysinfo`（`getcwd`/`getxattr` 不建边） |
| `ioctl_op` | G | `p2f` / `f2p`（视方向）；请求码解不出时 `p2p`（自环） | `ioctl`（`close`/`dup`/`fcntl`/`lseek` 只维护句柄表、不建边） |
| `socket_create` | H | `p2n`（`AF_INET`/`AF_INET6` → `:Network:PeerUnknown`；`AF_UNIX`/netlink/packet → `:File`） | `socket` |
| `connect` | H | `p2n`（unix 路径连接落 `p2f`） | `connect` |
| `bind` | H | `p2n` | `bind` |
| `listen` | H | `p2n` | `listen` |
| `accept` | H | `n2p` | `accept`/`accept4` |
| `send` | H | `p2n` | `sendto`/`sendmsg`/`sendmmsg` |
| `recv` | H | `n2p` | `recvfrom`/`recvmsg`/`recvmmsg`（`shutdown`/`setsockopt`/`getsockopt`/`getsockname`/`getpeername` 不建边） |
| `object_create` | I | `p2f` | `pipe`/`pipe2`/`socketpair`/`shmget`/`memfd_create`/`eventfd`/`signalfd`/`timerfd_create`/`inotify_init`/`epoll_create*`（对象种类由 `object_class` 区分；`inotify_add_watch`/`inotify_rm_watch`/`epoll_ctl`/`shmdt`/`shmctl` 不建边） |
| `module_load` | J | `p2f` | `finit_module`/`init_module`（客体 `kernel:module:<name>`） |
| `module_unload` | J | `p2f` | `delete_module` |
| `bpf_op` | J | `p2f` / `f2p` | `bpf`（客体 `kernel:bpf:<prog\|map>:<id>`） |
| `kexec_load` | J | `p2f` | `kexec_load`/`kexec_file_load`（`keyctl`/`add_key`/`request_key`/`seccomp` 不建边） |
| `ns_create` | K | `p2f` | `unshare`（客体 `:File`(`ns:<type>:<id>`)） |
| `ns_join` | K | `p2f` | `setns` |
| `mount` | K | `p2f` | `mount`（客体为挂载点；`umount*` 不建边） |
| `chroot` | K | `p2f` | `chroot`/`pivot_root` |
| `identity_change` | L | 节点属性 | `setuid`/`setresuid`/`setreuid`/`setfsuid`/`setgid`/`setresgid`/`setregid`/`setfsgid`/`setgroups` |
| `capability_change` | L | 节点属性 | `capset` |
| `identity_observe` | L | 节点属性（不建边） | `getuid`/`geteuid`/`getresuid` |
| `proc_attr_change` | L | 节点属性 | `setrlimit`/`prlimit`/`prctl`/`personality`/`umask`/`ioprio_set`/`arch_prctl`/`sched_*set*`/`setpriority`/`setsid`/`setpgid`/`chdir`/`fchdir`/`sethostname`/`quotactl`（具体调用名记在 `identity_history`） |
| `syslog` | M | `p2p`（自环） | `syslog`（防御规避：操作内核日志缓冲） |
| `timer_arm` | M | `p2p`（自环） | `setitimer`/`alarm`/`timerfd_settime`/`timer_settime`（C2 心跳） |

> M 族里除上表 `syslog`、`timer_arm` 之外的调用一律**不进图、显式记账丢弃**（全量名单见附录 B）；`ioctl` 无论请求码能否解码都归 G 族 `ioctl_op`；`object_create` 的对象种类一律由 §3.2 的 `object_class` 承载，动作名不重复表达。

动作名只描述动作语义，不承载状态：成功、失败、零字节、`EINPROGRESS` 一律由边属性 `failed` 与 `status` 表达（失败看 `failed`，取值看 `status`），同名动作在任何结果下都不改名。

## 5.4 未归类处理与映射表演进

- 每次运行输出未归类事件名与次数；非空即视为映射表不完整，必须在报告中披露，禁止宣称"映射表完整"；
- `<unknown>` 单独统计（它是采集侧未知事件，不是新系统调用）；
- 映射表以字典形式沉淀（系统调用名 + 条件 → 族/动作/边类），随解析器版本发布；新增系统调用先落入未归类桶，由人工评审归类，绝不静默丢弃。

---

# 6 特殊调用规则（34 条）

每条格式：**调用 → 判据 → 图上的表达 → 备注**

| # | 调用 | 判据 | 图上的表达 | 备注 |
|---|---|---|---|---|
| 1 | `clone`/`clone3`/`fork`/`vfork` | `arg.flags` 含 `CLONE_THREAD` | 线程：不建边（不新建进程节点，动作归所属进程）；进程：新建 `:Process` + `p2p spawn` + 复制句柄表与 cwd | 实测 `arg.flags` 可用 |
| 2 | `execve`/`execveat` | `status==0` | 旧节点的结束由 `p2p exec` 边时间给出；新建 `:Process`；`p2p exec` + `f2p load_image` | 失败同落 `p2p exec`，由 `failed=true` 表达（`status` 保留负返回值，不改动作名） |
| 3 | `openat`/`open`/`creat` | `flags` 含 `O_CREAT`/`O_TRUNC` | 建 `p2f create`；其余打开不建边（读写在后续 `read`/`write` 边体现） | 所有 fd 必须登记句柄表；`O_TMPFILE` → `tmpfile:*`；`O_CLOEXEC` 必须登记 |
| 4 | `read`/`write`/`readv`/`writev`/`pread`/`pwrite` | 客体由句柄表解析 | 文件 → `p2f`/`f2p`；套接字 → `p2n`/`n2p`；IPC → `p2f`/`f2p` | `status` 取 `evt.rawres`（失败为负、零字节为 0）、`failed` 取 `evt.failed`；动作名不变 |
| 5 | `mmap`/`mmap2` | `arg.flags` 含 `MAP_ANONYMOUS` | 匿名 → `p2p` 自环；文件 → `f2p` | 返回值是地址，禁止当 `status`；`PROT_EXEC` 记入 `flags` |
| 6 | `mprotect` | — | `p2p` 自环 + `flags`（保护位） | 地址/长度不落图；参数取不到时仍建边并置 `missing_params=true` |
| 7 | `splice`/`tee`/`sendfile`/`copy_file_range`/`vmsplice` | 方向由 `fd_in`/`fd_out` 决定 | 按方向落 `read`/`write`，输出 1～2 条边（管道两端为不同客体） | 禁止无条件双向建边；零拷贝与普通读写不再区分（§10.2 第 25 项） |
| 8 | `sendto`/`sendmsg`/`sendmmsg`/`recvfrom`/`recvmsg`/`recvmmsg` | 对端取自 `fd.name` 或 `arg.tuple` | `p2n` / `n2p` | `SCM_RIGHTS` 的 fd 列表不在采集数据中 → **不建任何“fd 传递”边**，只保留收发事实（§10.2） |
| 9 | `connect`/`accept`/`bind`/`listen` | — | `connect` → `p2n`；`accept` → `n2p` + 会话指向监听端点的 `listen_ref` 结构性关系；`bind`/`listen` → 监听端点 | `EINPROGRESS` 仍落 `connect`，由 `status` 保留负返回值（不丢）；`shutdown` 不建边 |
| 10 | `socket`/`socketpair` | `domain`/`type` | `AF_INET`/`AF_INET6` → `:Network:PeerUnknown`（待四元组）；`AF_UNIX` → `:File`(`socket_unix`)；netlink/packet → `:File`；`socketpair` 按 I 族 `object_create` 建 `:File`（`object_class='socket_unix'`） | — |
| 11 | `memfd_create` | — | `p2f object_create`（客体 `:File`(`memfd:<name>`)，`object_class='memfd'`）；后续 `write` → `p2f`；`execveat` → `f2p load_image` | **本数据 0 次，未验证** |
| 12 | `ptrace`/`process_vm_readv`/`process_vm_writev` | `arg.request`/地址长度 | `p2p ptrace_attach` / `mem_read` / `mem_write` | **本数据 0 次，未验证** |
| 13 | `/proc/<pid>/(mem\|maps\|environ\|cmdline\|fd/<n>)` | 路径匹配 | 保留原文件边 + **派生 `p2p`** 指向该 pid 的进程（`mem_read`/`mem_write`）；容器内进程用 `vpid` 匹配 | 覆盖不依赖 `ptrace` 的注入与凭据窃取通道 |
| 14 | `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD*)` | — | 只更新句柄表 | 别名不继承 `CLOEXEC`；`fcntl(F_SETFD)` 更新标志；不建边 |
| 15 | `close`/`lseek` | — | `close` 注销句柄；`lseek` 更新偏移并**打断折叠序列** | 不建边 |
| 16 | `pipe`/`pipe2` | 退出行 `fd1`/`fd2`/`ino` | `p2f object_create` 建 `:File pipe:[<ino>]`（`object_class='pipe'`），两端 fd 指向同一客体 | 无 inode → `pipe:[unknown-<事件号>]` + 计数 |
| 17 | `eventfd`/`signalfd`/`timerfd_create`/`inotify_init`/`epoll_create*` | — | `p2f object_create` + `:File`（`object_class` 区分种类） | 本进程内读写按 IPC 处理；`epoll_ctl`/`inotify_add_watch`/`inotify_rm_watch` 不建边 |
| 18 | `setitimer`/`alarm`/`timerfd_settime`/`timer_settime` | — | `p2p timer_arm`（自环） | C2 心跳节奏的直接证据；定时器对象本身由 `timerfd_create` 登记；`nanosleep`/`clock_nanosleep`/`timer_create`/`timer_delete` 等不进图（显式记账丢弃） |
| 19 | `poll`/`select`/`pselect6`/`ppoll`/`epoll_wait`/`epoll_pwait`/`futex`/`switch`/`sched_yield` | — | 不入图，显式记账丢弃 | 纯等待/轮询类噪声；`switch` 可能无 `proc.pid` → 计入“无进程归属数”；`brk` 与 `madvise` 按 §5.3 落 B 族 `p2p` 自环，不再有第二种归属 |
| 20 | `exit_group`/`procexit`/`exit`/`wait4`/`waitid` | — | 退出 → 建 `p2p exit` 指向父进程（父进程取自进程表里 `clone` 建立的父子关系，或该退出事件的 `proc.ppid`）；等待 → `p2p wait` | `procexit` 的 `status` 是进程退出码，**不是**系统调用返回值；采集起点前已在跑、且无父记录的进程**不建 exit 边**，结束时间未知 |
| 21 | `kill`/`tgkill`/`tkill`/`sigreturn` | — | `kill` 族 → `p2p signal`（带 `signal`）；`sigreturn` → `p2p signal_return` | `sigreturn` 高频是 SROP 攻击特征；`signaldeliver` 不建边 |
| 22 | `ioctl` | `arg.request` 码 | 客体由句柄表；`p2f`/`f2p` 视方向；属性记 `request` | 解不出请求码时仍落 `p2p ioctl_op`（自环）并原样保留请求码，不得丢弃；常用码（`TIOCSTI`/`SIOCGIF*`/`FIONREAD`/`BLKDISCARD`）解码 |
| 23 | `chmod`/`chown`/`utimensat`/`*xattr`/`fsync`/`fdatasync`/`msync` | — | `chmod` → `p2f`（带 `mode`）；`fsync`/`fdatasync`/`msync` → `p2f`；`chown`/`utimensat`/`*xattr` 为泛型事件（无参数/无返回值）→ **无客体 `p2p` 自环**（`chown`/`utimes`/`setxattr`，属静态无客体，由字典标注，不写 `missing_params`） | 属主/时间戳/扩展属性只记“调用发生过”，**不能按文件查**；`chmod` 的 `mode` 可查；`flock`/`fadvise64`/`getxattr` 不建边 |
| 24 | `newfstatat`/`fstat`/`stat`/`lstat`/`access`/`readlink*`/`getdents64`/`statfs`/`uname`/`sysinfo` | — | `f2p`（动作名 `probe`）；`uname`/`sysinfo` 无客体 → `p2p`（自环，`probe_system`） | 不得丢弃；同进程同路径连续探测折叠；`stat` 族在本数据无路径参数，只能记"无客体探测"；`getcwd`/`getxattr` 不建边 |
| 25 | `set*uid`/`set*gid`/`setgroups`/`capset`/`prctl`/`personality`/`setrlimit`/`prlimit`/`ioprio_set`/`sched_*`/`umask`/`arch_prctl` | — | 更新 `uid`/`ruid` + `identity_history`（`set*gid` 的变更只写历史，不落当前 `gid`）；`proc_attr_change` 只更新解析器的 `cwd` 状态（不落节点属性）；`get*uid` 作为观测来源更新 `uid`/`ruid`（取值在退出行 `evt.args`，不写 `identity_history`、不建边） | `capset`/`prctl`/`setgroups`/`umask`/`setreuid`/`setregid` 为泛型事件，只记调用发生、无值可写（§10.2）；`PR_SET_NAME` 不解码 |
| 26 | `rt_sigaction`/`rt_sigprocmask`/`sigaltstack`/`rt_sigtimedwait`/`rt_sigpending` | — | 不入图，显式记账丢弃 | 配置类噪声，无溯源信息（M 族） |
| 27 | `finit_module`/`init_module`/`delete_module`/`bpf`/`kexec_load`/`keyctl`/`add_key`/`request_key`/`seccomp` | — | `module_load`/`module_unload`/`bpf_op`/`kexec_load` → `:File`(`kernel:*`) + `p2f`/`f2p`；`seccomp`/`keyctl`/`add_key`/`request_key` 属静态无客体且无攻击链独占信息 → **不建边、显式记账丢弃**（**不建 `kernel:key:*` 节点**） | 边界见 §10.1（C5 类不承诺）与 §10.2（密钥不可建、seccomp 不可见） |
| 28 | `unshare`/`setns`/`chroot`/`pivot_root`/`mount` | 标志位与路径 | `setns`/`unshare` → `:File`(`ns:*`)；`mount` → 挂载点 `:File`；`chroot`/`pivot_root` → 新根目录 `:File`；均建 `p2f`，挂载点用于推导 `host_view_alias`（§3.5.3、§12 决策点 2） | 实测 `dev=`/`type=` 常为空 → 置 `missing_params=true`，不得伪造；`umount*` 不建边 |
| 29 | 失败 / 零字节 | `evt.failed` / `status==0` | 动作名不变：边上落 `failed=true`、`status` 为负（零字节则 `status=0`）；失败不传播数据流 | 全部保留，计入对应记账项；长阻塞由 `end_time_ns − start_time_ns` 查询时判断（孤儿退出行无法判断） |
| 30 | `io_uring_setup`/`io_uring_enter`/`io_uring_register` | — | `:File`(`ioring:<id>`) + `p2f io_uring_op`；提交次数由 `covered_count` 记 | **本数据 0 次，未验证**；环内实际 I/O 内容不可见（§10.2） |
| 31 | `userfaultfd` | — | `:File`(`userfaultfd:<fd>`) + `p2f ufd_register` | **本数据 0 次，未验证** |
| 32 | `pidfd_open`/`pidfd_send_signal`/`pidfd_getfd` | — | `pidfd_open` 只登记 `:File`(`pidfd:<fd>`) 句柄、不建边；`pidfd_send_signal` → `p2p signal`；`pidfd_getfd` → `p2p pidfd_getfd` | **本数据 0 次，未验证** |
| 33 | `open_by_handle_at` | handle 参数 | 打开动作本身不建边；后续 `read`/`write` 落到 `handle:<fsid>:<hex>` 客体上（`object_class` 同普通文件） | **本数据 0 次，未验证**；无路径访问仍经数据流边可见 |
| 34 | `kexec_load`/`kexec_file_load` | — | `p2f kexec_load`（内核镜像文件）+ 进程标记 | **本数据 0 次，未验证**；属内核级（§10.1 C5 精神范围） |

---

# 7 解析流水线

## 7.1 配对规格

### 7.1.1 配对键与顺序

- 键：`(host_id, container_id, pid, thread_id, evt.type)`；
- 同键内 **FIFO**：先出现的未闭合进入行先配；
- 快路径：若某进入行与下一行的 `evt.num` 相邻且同键，直接配对，跳过池查询。

### 7.1.2 需要配对的事件（进入行给参数、退出行给结果）

`read` `write` `pread` `pwrite` `readv` `writev` `preadv` `pwritev`；`sendto` `sendmsg` `sendmmsg` `recvfrom` `recvmsg` `recvmmsg`；`connect`；`socket` `socketpair`；`close` `dup` `dup2` `dup3` `fcntl` `lseek`；`mmap` `mprotect` `munmap` `mremap`；`splice` `sendfile` `tee` `vmsplice` `copy_file_range`；`shmget` `shmat` `shmdt` `shmctl`；`mount` `umount*` `setns` `unshare` `chroot` `pivot_root`；`bpf` `keyctl` `add_key` `request_key` `seccomp` `finit_module` `init_module` `delete_module` `kexec_load`；`ptrace` `process_vm_readv` `process_vm_writev` `userfaultfd` `io_uring_*` `pidfd_*`；`ioctl` `kill` `tgkill` `tkill`；`openat` `open` `creat`（**可省**：退出行自带全部参数）；`getuid` `geteuid` `getresuid`（进入行无参数、退出行给身份值，实测成对出现）。

### 7.1.3 不需要配对的事件

路径类（`unlink`/`rename`/`symlink`/`mkdir`/`rmdir`/`chmod`/`chown`/`utimensat`/`stat`/`access`/`readlink`/`getdents64`：退出行自带路径与结果）、进程类（`clone`/`execve`/`procexit`）、纯结果类（`futex`/`poll`/`clock_*` 等 M 族）、对象创建类（`pipe`/`eventfd`/`signalfd`/`timerfd_create`/`epoll_create*`）。

### 7.1.4 边界情形

| 情形 | 处理 |
|---|---|
| 孤儿退出行（捕获开始处） | 自带全部参数者（`openat` 类）独立建边计 `unpaired_independent`；否则计 `unpaired` |
| 进入行超时未闭合 | 超过 `pair_timeout_ns`（默认 5 秒）淘汰并计 `evicted_unpaired`；阻塞类调用（`accept`/`read`/`wait`）超时不淘汰，只保留进入行等待配对 |
| 配对池容量 | 上限 `pair_pool_max`（默认 10 万条），超限按最老未闭合淘汰并计 `evicted_unpaired` |

## 7.2 九阶段流水线

| 阶段 | 输入 | 动作 | 输出 | 记账 |
|---|---|---|---|---|
| 1 接入 | `.scap` | 按 §2 直读捕获、流式产出事件，并与独立计数对账 | 事件流（逐条，不落盘） | `N_total`、实际行数、差额 |
| 2 行解析 | 事件流每一行 | 解析、补 `host_id`、时间戳归一、校验事件序号单调 | 规范化事件 | `parse_errors` |
| 3 分类与配对 | 规范化事件 | 查 §5 字典定族与动作；按 §6 取参数；按 §7.1 配对 | 逻辑调用 | `unclassified`、`unpaired`、`missing_params` |
| 4 实体注册 | 逻辑调用 | 进程表（含启动时间）、句柄表、cwd 状态、容器与命名空间视图、路径规范化（§3.5） | 实体引用 | `unknown_fd`、`lazy_created`、`pid_reuse_anomaly`、`path_unresolved` |
| 5 动作分发 | 逻辑调用 + 实体 | 生成边 / 属性更新 / 记账丢弃 / 未归类 | 待写边与属性 | `N_edges_pending`、`N_attr`、`N_discarded` |
| 6 状态机 | 逻辑调用 | 镜像分裂、句柄生命周期（`CLOEXEC` 裁剪）、身份变更史、命名空间切换 | 状态更新 | `execve_splits`、`ns_switches`、`identity_changes` |
| 7 折叠 | 待写边 | §4.5 规则 | 压缩后的边 | `folded_groups`、`covered_count` 总和 |
| 8 图写入 | 压缩后的边 | 按 §7.4 写库 | Neo4j 图 | `pruned_vertices`、`write_retries`、`write_failures` |
| 9 审计报告 | 全部计数 | §8 | 可复算凭证 | `N_diff` |

## 7.3 状态与容量

| 结构 | 键 | 容量上限（默认） | 淘汰策略与记账 |
|---|---|---|---|
| 配对池 | `(host, container, pid, tid, 事件名)` | `pair_pool_max` = 10 万条 | 最老未闭合；计 `evicted_unpaired` |
| 句柄表 | `(host, container, pid, fd_num)` | 单进程 `fd_table_max` = 4096 | 最早登记；计 `handle_evicted` |
| 折叠槽位 | `(host, container, pid, 源, 宿, 方向, action)` | `fold_slot_max` = 10 万 | 最早未结算；计 `slot_evicted` |
| 进程表 | `(host, container, pid)` | 无硬上限（受进程数限制） | 进程退出后保留至运行结束 |
| 待写边缓冲 | — | `write_buffer_max` = 5 万条 | 触发背压（不淘汰） |

**内存预算**：各结构上限的规模之和必须 ≤ 峰值内存目标（默认 6 GB，附录 C）。若超限，优先下调 `pair_pool_max` 与 `fold_slot_max`，不得下调记账粒度。

## 7.4 写库规格

1. **唯一约束**（多属性复合唯一约束，Neo4j node key）：`:Process(host_id, container_id, pid, start_time_ns)`、`:File(host_id, mount_view, path)`、`:Network:Session(host_id, proto, lower_ip, lower_port, upper_ip, upper_port)`、`:Network:Listener(host_id, proto, ip, port)`、`:Network:PeerUnknown(host_id, proto)`；
2. **索引**：`File.object_class`、`Process.container_id`、`Network.proto`、`Network.lower_ip`、边属性 `action`、边属性 `start_time_ns`；
3. **批量**：顶点 `MERGE` 每批 `vertex_batch`（默认 5,000）；边 `MATCH`+`CREATE` 每批 `edge_batch`（默认 10,000）或 `flush_interval_ms`（默认 500 毫秒）触发；
4. **背压**：待写批次数超过 `backpressure_batches`（默认 5）时暂停读取，降至 2 批以下恢复；
5. **重试**：锁冲突按 100→200→400→800→1600 毫秒（±20% 抖动）重试 `retry_max`（默认 5）次；仍失败则阻断并输出冲突主键；
6. **幂等**：默认"按场景清库后整批导入"；需要增量时用 `evt.num` 水位续跑（水位存于运行元数据），重复导入的边按 `edge_id` 去重。
7. **一致性断言**：写库前校验每条待写边满足 `status < 0` ⇒ `failed = true`；不成立即阻断并输出该边的 `edge_id` 与两端主键，禁止静默跳过（判定失败一律看 `failed`，见 §4.4）。

## 7.5 工程约束

1. **流式**：任何阶段不得整文件入内存（最大场景 3,767 万事件）；峰值内存目标 ≤ 6 GB；
2. **可重放**：同输入 + 同版本 + 同参数 + 同附录 C 参数 → 主键集合、边集合与丢弃记账逐一致；
3. **断点可续**：写库按 `evt.num` 水位续跑，不重复计数；接入不设断点——每次从头直读，避免“从中间开始读”造成静默缺段。

---

# 8 审计与报告

## 8.1 两层账本

**第一层（接入）**：见 §2.5。

**第二层（解析）**：

```
逻辑调用数 == 边覆盖数 + 属性更新数 + 显式丢弃数 + 仅句柄数 + 失败数 + 空操作数
            + 未知句柄数 + 未配对数 + 未归类数 + 无进程归属数 + 其他
```

| 记账项 | 含义 |
|---|---|
| 边覆盖数 | 被边覆盖的逻辑调用数（折叠边按其 `covered_count` 计数） |
| 属性更新数 | 仅更新节点属性的调用 |
| 显式丢弃数 | 按白名单丢弃、不入图的调用；**按系统调用名逐名计数**（含 M 族噪声与 §5.3 声明的无信息调用），不按动作名聚合 |
| 仅句柄数 | 只维护句柄表且未产生语义边的调用 |
| 失败数 / 空操作数 | 失败调用 / 零字节读写（失败按 `failed` 判定；零字节按 `status=0`；均不依赖动作名） |
| 未知句柄数 / 未配对数 / 未归类数 / 无进程归属数 | 各自的丢弃原因 |
| 其他 | 必须逐类列出并说明 |

**判据**：差额 ≠ 0（含负数）即判定解析失败，禁止输出"解析成功"。

## 8.2 必须打印的报告项

1. 两层账本全部分项与差额；
2. 未归类事件名与次数；`<unknown>` 次数与占比；
3. 配对成功率（按事件类型分组）与未配对明细；
4. 未知句柄次数、缺失参数明细（仅“本该有而缺失”，静态无客体动作不计入）、路径未解析明细、降级表（§4.6）各项计数；
5. 折叠统计（组数、覆盖次数总和、最大组）；
6. 显式丢弃统计（按系统调用名逐名列出次数，不按动作名聚合）；
7. 容器与命名空间清单（含是否特权，并披露 `container.privileged`/`container.mounts` 的空值率）与**容器视图→宿主路径映射表**（§3.5.3）；
8. **未验证规则清单**（本数据未覆盖的调用）；
9. §10 边界声明逐条勾选结果；
10. 本次运行的附录 C 参数快照。

---

# 9 验收标准

## 9.1 九条硬验收

| # | 验收项 | 判据 |
|---|---|---|
| 1 | 接入无损 | 直读层的独立计数与接入累计数差额为 0（§2.5） |
| 2 | 可复现 | 同输入同参数 → 主键集合、边集合、丢弃记账逐一致（以 §11.7 图快照逐字段比对） |
| 3 | 归类完备 | 未归类为空；非空必须逐名披露 |
| 4 | 攻击面覆盖 | §9.2 的 14 条参考查询全部可跑通 |
| 5 | 特殊规则落地 | §6 的 34 条逐条有实现与测试（样例出处见 §9.3）；未验证项已标注 |
| 6 | 规模达标 | 9 个场景（8,945 万事件）全部跑通；峰值内存 ≤ 6 GB；耗时与吞吐有记录 |
| 7 | 端到端评测 | 5 个有标准答案的场景输出召回率、查准率、耗时、模型调用次数 |
| 8 | 边界对齐 | 报告逐条勾选 §10 的适用边界 |
| 9 | 接口契约一致 | 各模块间传递的数据与 §11.3 的四个对象字段完全一致；模块不得直接读原始 `.scap` 或数据库 |

## 9.2 每族参考查询（跑通即证明该族表达可用）

族名与各族的溯源信息需求见 §1.3；本节只给参考查询，不重复定义。

| 族 | 参考查询（示意，变量为时间窗与容器） |
|---|---|
| 初始访问 | `MATCH (n:Network)-[r:n2p]->(p:Process)-[w:p2f]->(f:File) WHERE r.start_time_ns>=$t0 RETURN n,p,f,w LIMIT 50` |
| 执行 | `MATCH (p:Process)-[r:p2p {action:'spawn'}]->(c:Process) WHERE r.start_time_ns>=$t0 RETURN p.cmdline,c.cmdline,r` |
| 持久化 | `MATCH (p:Process)-[r:p2f]->(f:File) WHERE f.path CONTAINS 'authorized_keys' OR f.path CONTAINS 'cron' OR f.path CONTAINS 'systemd/system' RETURN p,f,r` |
| 提权 | `MATCH (p:Process) WHERE p.uid<>p.ruid OR p.identity_history IS NOT NULL RETURN p.exe_path,p.uid,p.identity_history` |
| 防御规避 | `MATCH (p:Process)-[r:p2p {action:'utimes'}]->(p) RETURN p,r` 与 `MATCH (p:Process)-[r:p2f]->(f:File) WHERE f.path STARTS WITH '/var/log' RETURN p,f,r` |
| 凭据访问 | `MATCH (f:File)-[r:f2p]->(p:Process) WHERE f.path IN ['/etc/shadow','/etc/passwd'] OR f.object_class='proc_virtual' RETURN f,p,r` |
| 发现 | `MATCH (f:File)-[r:f2p]->(p:Process) WHERE r.action STARTS WITH 'probe' AND r.start_time_ns BETWEEN $t0 AND $t1 RETURN p.exe_path,count(r) ORDER BY count(r) DESC LIMIT 20` |
| 横向移动 | `MATCH (p:Process)-[r:p2n {action:'connect'}]->(n:Network) WHERE (n.server_end='upper' AND n.upper_port=22) OR (n.server_end='lower' AND n.lower_port=22) RETURN p,n,r` |
| 收集与打包 | `MATCH (f:File)-[:f2p]->(p:Process)-[:p2f]->(ipc:File {object_class:'pipe'}) RETURN f.path,ipc.path LIMIT 50` |
| 命令与控制 | `MATCH (p:Process)-[r:p2n]->(n:Network) WITH p,n,count(r) AS c, min(r.start_time_ns) AS t0 ORDER BY c DESC RETURN p.exe_path, CASE WHEN n.server_end='upper' THEN n.upper_ip ELSE n.lower_ip END AS peer_ip, c, t0` |
| 数据外泄 | `MATCH (p:Process)-[r:p2n]->(n:Network) WHERE r.status > 0 RETURN p.exe_path, CASE WHEN n.server_end='upper' THEN n.upper_ip ELSE n.lower_ip END AS peer_ip, sum(r.status * r.covered_count) AS sent ORDER BY sent DESC LIMIT 20` |
| 影响（勒索/擦除/挖矿） | `MATCH (p:Process)-[r:p2f]->(f:File) WHERE r.action IN ['write','rename','unlink'] AND r.covered_count>10 RETURN p.exe_path,count(DISTINCT f) AS files ORDER BY files DESC` |
| 容器逃逸 | `MATCH (p:Process)-[r:p2f]->(ns:File {object_class:'namespace'}) WHERE ns.path STARTS WITH 'ns:mnt:' RETURN p,p.container_id,r,ns` 与 `MATCH (f:File) WHERE f.host_view_alias IS NOT NULL RETURN f.path,f.host_view_alias LIMIT 20` |
| 内存注入 | `MATCH (a:Process)-[r:p2p]->(b:Process) WHERE r.action IN ['ptrace_attach','mem_write'] RETURN a.exe_path,b.exe_path,r` 与 `MATCH (p:Process)-[r:f2p]->(f:File) WHERE r.action='mmap_file' AND 'PROT_EXEC' IN r.flags RETURN p,f,r` |

## 9.3 规则测试样例出处

**观测型样例**（9 个场景的实测数据中已存在，可直接回放验证）

| 规则 | 样例来源 | 期望结果 |
|---|---|---|
| 1 `clone` 线程/进程分流 | 任一场景的 `clone` 事件（`arg.flags` 可见） | 含 `CLONE_THREAD` 者不新建进程节点、不建边 |
| 2 `execve` 分裂 | 场景 1「`execve` 后进程 `exe_path` 变化」 | 旧节点的结束由 `p2p exec` 边时间给出；新节点有 `p2p exec` + `f2p load_image` |
| 3 `openat` 分派 | 场景 1 的 `openat`（`flags=4097(O_RDONLY\|O_CLOEXEC)`） | 只读打开不建边（读写在后续 `read` 边体现） |
| 4 数据流分客体 | 场景 2「sshd 在套接字上 read/write」 | 边指向 `:Network` 而非 `:File` |
| 7 零拷贝方向 | 场景 5 的 `splice`（2 次） | 按方向落 `read`/`write`，不双向 |
| 8 `sendmsg` 载荷 | 场景 1 的 `sendmsg`（`res=184`） | `status=184` + 载荷快照 |
| 9 连接生命周期 | 场景 5 的 `connect`/`accept`（`res=0`） | 会话节点 + `listen_ref` 结构性关系存在 |
| 10 `socket` 分流 | 场景 5 的 `socket`（`domain=1(AF_LOCAL)`） | 建 `:File socket_unix` |
| 13 `/proc/<pid>/mem` 派生 | 任一场景的 `/proc/*/mem` 读写 | 同时出现文件边与 `p2p` 派生边 |
| 14 `dup` 别名 | 场景 1 的 `dup`（`res=2(<f>/dev/null)`） | 句柄表出现两个 fd 指向同一客体 |
| 16 管道 inode | 场景 5 的 `pipe`（`fd1/fd2/ino=43797`） | `p2f object_create` 建 `:File pipe:[43797]` |
| 19 时序噪声丢弃 | 场景 5 的 `switch`/`poll`/`futex` | 不建边，且这些调用全部计入“显式丢弃数” |
| 20 退出与父进程 | 场景 5 的 `procexit`（`status=0`） | 建 `p2p exit`（父进程有记录时；无记录则不建边） |
| 21 信号投递 | 场景 1 的 `kill`（`sig=10(SIGUSR1)`） | `p2p signal` + `signal=10` |
| 22 `ioctl` 解码 | 场景 5 的 `ioctl` | 可解码者带 `request` 落 `p2f`/`f2p`；解不出者落 `p2p` 自环并原样带 `request` |
| 23 元数据变更 | 场景 5 的 `fchmod`（`mode=0644`） | `p2f chmod` + `mode` |
| 24 探测 | 场景 1 的 `access`（`res=-13(EACCES) name=/home`） | `f2p probe` + `failed=true`（`status<0`） |
| 25 身份变更 | 场景 1 的 `geteuid`（`euid=0(root)`） | 进程属性 `uid` 更新 |
| 27 内核对象 | 场景 9 的 `bpf`（`arg.cmd` 可见） | `:File kernel:bpf:*` + `p2f bpf_op` |
| 28 命名空间与挂载 | 场景 9 的 `mount` + 容器事件挂载表 | `p2f mount` + `host_view_alias` 有值 |
| 29 失败调用保留 | 场景 1 的 `access res=-13`、场景 5 的端口扫描失败 | 失败边存在（`failed=true`）且不传播数据流 |
| 30–34 未验证规则 | — | 需合成数据（见下） |

**合成型样例**（本数据未覆盖，须自建触发场景后才能宣称验证）

| 规则 | 合成方式 |
|---|---|
| 11 `memfd_create` + `execveat` | 在测试机执行"内存文件 + 执行"的最小程序 |
| 12 `ptrace`/`process_vm_*` | 测试机执行一次进程注入（gdb attach 或自写小程序） |
| 30 `io_uring_*` | 用 `io_uring` 做一次文件读写 |
| 31 `userfaultfd` | 注册一次用户态缺页处理 |
| 32 `pidfd_*` | 用 `pidfd_open` + `pidfd_send_signal` |
| 33 `open_by_handle_at` | 需 `CAP_DAC_READ_SEARCH`，用 `name_to_handle_at` + `open_by_handle_at` 组合 |
| 34 `kexec_load` | 需特权，建议仅在隔离测试机验证 |

---

# 10 边界声明

## 10.1 继承的恒定盲区（不承诺）

《不可见清单》的 25 种单机物理绝缘攻击（C1-01…C5-02）与 7 种分布式拓扑盲区（M-01…M-07）。凡涉及 NAT 重写、未纳管跳板、公网匿名多跳、Overlay 隧道、共享存储解耦的链路，只能声明拓扑断裂，**禁止人工补边**。

## 10.2 本模块的实测边界

| # | 边界 | 依据 |
|---|---|---|
| 1 | 载荷仅前 80 字节 | 采集快照长度上限 80 字节 |
| 2 | `mount`/`umount` 的源与文件系统类型常缺失（仅 `flags` 可用） | 实测 `evt.args` 中 `dev=`/`type=` 为空 |
| 3 | 存在 `<unknown>` 事件（场景 5 占 0.4%） | 采集侧与读取侧 sysdig 版本不一致 |
| 4 | 9 个调用在本数据中 0 次出现，规则未验证：`ptrace`、`process_vm_readv`、`process_vm_writev`、`memfd_create`、`io_uring_setup`、`userfaultfd`、`pidfd_open`、`open_by_handle_at`、`kexec_load` | 3,767 万事件实测 |
| 5 | 文件身份无版本号与 inode：同路径"删除后重建"视为同一文件；**符号链接不解析**，同一文件经不同软链接会成为多个节点 | 数据源限制与 §3.5.1 规则 |
| 6 | 容器归属依赖采集侧容器元数据；缺失时退化为宿主归属 | `container.id` 可用性 |
| 7 | 时间戳来自被测主机时钟（实测样例约对应 2026 年），跨主机比较前必须核对时钟一致性 | 实测 |
| 8 | `stat`/`fstat` 族无路径参数，无法归因到具体文件 | 实测两行参数均为空 |
| 9 | `ioctl` 仅常用请求码可解码 | 数据源限制 |
| 10 | 折叠窗口内的逐次参数序列不可恢复（仅能还原次数） | 压缩规则 |
| 11 | **`io_uring` 环内实际 I/O 内容不可见**（只可见 ring 的创建、提交次数与注册动作） | 环内存共享机制绕过 read/write 系统调用 |
| 12 | **`mmap`/共享内存建立后的内存内容流不可见**（含 `MAP_SHARED` 脏页回写由内核完成） | 建立映射后的 memcpy 不产生系统调用 |
| 13 | **`AF_PACKET`（`PACKET_MMAP`）环收发的逐包数据流不可见**（套接字创建与 mmap 可见） | 报文经共享环收发，无逐包系统调用 |
| 14 | **`AF_XDP`/XDP 卸载路径的报文数据流不可见** | 报文在驱动层被处理，不进套接字层 |
| 15 | **内存区间无节点**：地址/长度不落图，只有 `flags` 的保护位，无法回答"哪个内存区间后来被执行" | §3.7 设计选择 |
| 16 | **容器视图与宿主视图不做同一性合并**：同名路径在不同视图是两个节点，靠 `host_view_alias` 属性关联 | §3.5.3 安全侧选择；跨视图同一性需要可靠挂载映射 |
| 17 | **身份字段取值有前提**：`ruid` 仅在进程出现过 `get*uid` 或 `set*uid` 事件时才有值，其余为空；**禁止用空值判“无提权”** | §5.2 L 族、§6 规则 25 |
| 18 | **属主变更不可归属**：`chown`/`fchown`/`lchown`/`fchownat` 为泛型事件（只有调用名/调用号），无路径、uid/gid、返回值；图上的属主字段一律不存在 | 5 场景实测 |
| 19 | **扩展属性不可归属**：`setxattr`/`getxattr`/`removexattr` 为泛型事件，无路径、名称、值、返回值；扩展属性字段不落图 | 5 场景实测 |
| 20 | **内核密钥不可建**：`keyctl`/`add_key` 为泛型事件，无 serial/type/desc、返回值；`kernel:key:*` 节点不可建 | 5 场景实测 |
| 21 | **时间戳篡改不可归属**：`utimensat` 为泛型事件，无路径、新时间、返回值；只能按进程/时间查，不能按文件查 | 5 场景实测 |
| 22 | **fd 传递不可见**：`SCM_RIGHTS` 的 fd 列表不在采集数据中（`sendmsg`/`recvmsg` 只有返回值与载荷），不建 fd 传递边 | 5 场景实测 |
| 23 | **泛型事件无参数/无返回值**：约 24% 的事件只含调用名/调用号（如 `newfstatat`/`readlink`/`mprotect`/`epoll_ctl`/`prctl`/`capset`/`setreuid`），这些调用没有路径/地址/结果；约 26% 的退出行没有 `status` | 5 场景实测 |
| 24 | **seccomp 过滤器不可见**：只能看到 `seccomp` 调用发生；过滤器内容与模式不落图 | 5 场景实测（场景 5 共 40 条事件） |
| 25 | **零拷贝与普通读写不再区分**：`splice`/`tee`/`vmsplice`/`sendfile`/`copy_file_range` 统一落 `read`/`write`，“未落盘直接转发”这一特征不可见 | §5.3 精简 |
| 26 | **打开意图不落图**：`openat`/`open`/`creat` 仅在带 `O_CREAT`/`O_TRUNC` 时落 `create`，只读打开、写打开、只读但从不读均不建边（读写在后续数据流边上体现） | §5.3 精简 |
| 27 | **线程创建不落图**：`clone(CLONE_THREAD)` 不建边（无线程节点、无 tid 属性），线程内动作归所属进程 | §5.3 精简 |
| 28 | **内存映射只保留可执行相关**：仅 `mmap`（匿名/文件，含 `shmat`）与 `mprotect` 落图；`munmap`/`mremap`/`madvise`/`brk`/`mincore`、`shmdt`/`shmctl` 不建边 | §5.3 精简 |
| 29 | **无对象元数据操作只保留三个动词**：`chown`/`utimes`/`setxattr` 落进程自环；属主/时间戳/扩展属性仍不能按文件查 | §5.3 精简 |
| 30 | **`seccomp`/`keyring`/`socket 选项`/`shutdown`/`flock`/`fadvise` 不落图**：只有“调用发生过”、没有对象或值，统一显式丢弃 | §5.3 精简 |
| 31 | **`open_by_handle_at` 的“无路径打开”不单独建边**：打开动作不建边，但后续 `read`/`write` 会落到 `handle:<fsid>:<hex>` 客体上，无路径访问仍可见 | §5.3 精简 |

---

# 11 实现规格（工程约定与接口契约）

本章是施工约定，不包含语义判定（语义全部在 §1–§10）。

## 11.1 运行环境与依赖

| 项 | 约定 |
|---|---|
| 读取侧 | 需要一个装 sysdig 的执行环境（本机 / WSL2 / SSH 远端 / 容器四选一，§2.4）；本项目当前可用：WSL Ubuntu 22.04 + sysdig 0.27.1 |
| 解析侧 | Python 3.11；仅依赖标准库 + Neo4j 官方驱动；**不引入 pandas 等重型库**（内存纪律） |
| 图库 | Neo4j 5.x，每场景一库（§11.8） |
| 运行位置 | 解析与写库可在任一侧运行，只要求所选执行通道能读到该 `.scap`；同一场景只允许一处运行 |
| 并行度 | 单场景内串行（单进程流式）；场景间可串行批跑；禁止并行跑多个吃内存的任务 |
| 内存目标 | 单场景峰值 ≤ `memory_target_gb`（附录 C） |

## 11.2 模块划分与数据流

| # | 模块 | 输入 | 输出 | 职责 |
|---|---|---|---|---|
| 1 | 接入器（执行通道） | `.scap` | 事件流（逐条，不落盘） | 按 §2 直读；null-safe 取字段；通道不可用即阻断 |
| 2 | 对账器 | 接入累计计数 + 独立计数 | 对账报告 | §2.5 的判据；差额非 0 则阻断 |
| 3 | 行解析器 | 事件流每一行 | 规范化事件 | 补 `host_id`、时间戳归一、校验事件序号单调 |
| 4 | 字典与规则 | 规范化事件 | 族/动作/边类/参数 | 读 §11.9 的两份字典；未命中进未归类 |
| 5 | 状态机 | 逻辑调用 + 实体 | 实体引用 + 待写边 | 配对（§7.1）、句柄表、路径与视图（§3.5）、容器与命名空间 |
| 6 | 折叠器 | 待写边 | 压缩边 | §4.5 折叠 |
| 7 | 写库器 | 压缩边 | Neo4j 图 | §7.4 两阶段写入、背压、重试、幂等 |
| 8 | 审计报告器 | 全部计数 | 报告与台账 | §8 两层账本与报告项 |
| 9 | 参数验证趟 | `.scap` | 两份字典 | 一次性工具，生成 §11.9 的字典 |

数据流：`.scap` →(1)→ 事件流（内存，不落盘）→(3)→ 规范化事件 →(4)(5)→ 实体引用与待写边 →(6)→ 压缩边 →(7)→ 图；(2)(8) 为旁路，只产出报告。

## 11.3 内部数据契约（四个对象）

模块之间**只**传递这四个对象。

### 对象 1：规范化事件

**本表是 §2.3 清单的 1:1 映射**（原料字段 → 内部字段名）：字段口径与增删一律以 §2.3 为准，本表只规定内部命名与类型。

| 字段组 | 字段 | 类型 | 来源 |
|---|---|---|---|
| 事件标识 | `event_num` `ts_ns` `dir` `event_type` `category` | int / int / str / str / str | `evt.num` `evt.rawtime` `evt.dir` `evt.type` `evt.category` |
| 归属 | `host_id` `container_id` | str | 配置 / `container.id`（缺省 `host`） |
| 容器元数据 | `container_privileged` `container_mounts` | bool/str/null | `container.privileged` `container.mounts` |
| 进程 | `pid` `vpid` `ppid` `tid` `exe_path` `cmdline` `cwd` `proc_duration_ns` `uid` `ruid` `env` | int/str/null | `proc.*` `thread.tid`（缺省用 `pid`）`user.*` |
| 描述符 | `fd_num` `fd_name` `fd_type` `fd_dev` | int/str/null | `fd.*` |
| 网络 | `fd_l4proto` `fd_family` `net`（子字段 `client_ip`/`client_port`/`server_ip`/`server_port`，为原始读取值，仅用于推导图属性 `server_end`） | str/int/null | `fd.l4proto` `fd.sockfamily` `fd.cip`/`fd.cport`/`fd.sip`/`fd.sport` |
| 返回值与 I/O | `rawres` `failed` `is_io` `buflen` `buffer_b64` | int/str/bool/null | `evt.*` |
| 参数 | `args`（长度 5 的数组，元素可空） | list | `evt.arg[0..4]` |

### 对象 2：逻辑调用

| 字段 | 类型 | 说明 |
|---|---|---|
| `call_id` | str | `{host}:{container}:{pid}:{tid}:{事件名}:{进入行事件号}`，全局唯一 |
| `event_type` `family` `action` `edge_class` | str | 由 §11.9 字典填充；未命中则 `family=N` |
| `enter` / `exit` | 规范化事件 / null | 配对的进入行与退出行 |
| `ts_start_ns` `ts_end_ns` | int/null | 由两行时间戳得出（时长 = 两者相减） |
| `status` | int/null | `evt.rawres`（失败为负；数据类调用成功时即字节数） |
| `pairing` | str | `adjacent` / `pooled` / `independent` / `unpaired` |
| `params` | dict | 按 §6 规则提取的语义参数（`old_path`/`mode`/`signal`/`ns_type`/`prot`/`addr`/`len`/`flags`…） |
| `missing_params` `degraded` | list | 缺失参数清单 / 触发的 §4.6 降级项 |
| `subject` | 实体引用/null | 发起进程 |
| `objects` | 实体引用列表 | 涉及的客体（主客体与目标客体） |

### 对象 3：实体引用

| 字段 | 类型 | 说明 |
|---|---|---|
| `kind` | str | `process` / `file` / `network` |
| `key` | str | 由 §3.1 的主键字段生成的内存句柄（不落库），仅用于模块间引用与快照导出 |
| `label` | str | 节点标签（`:Network` 节点写 `Network:Session` / `Network:Listener` / `Network:PeerUnknown` 双标签） |
| `props` | dict | 本次新观测到的属性（增量，不覆盖已有值；仅缺失字段可回填） |
| `created` | bool | 本次是否为首次创建 |
| `view` | str/null | `:File` 的 `mount_view` |

### 对象 4：待写边

| 字段 | 类型 | 说明 |
|---|---|---|
| `edge_class` | str | `p2p` / `p2f` / `f2p` / `p2n` / `n2p`；结构性关系 `listen_ref`（会话→监听端点，`attrs` 为空） |
| `src` / `dst` | 实体引用 | 两端 |
| `attrs` | dict | §4.4 的通用与专有属性 |
| `fold_key` | str/null | 折叠槽键（§4.5） |
| `covered_count` | int | 默认 1；折叠后累加 |

### 契约纪律

1. 模块间不得直接读原始 `.scap` 或数据库（只传这四个对象）；
2. 字段增删必须提升文档版本号并同步更新 §11.3；
3. `props` 只做“缺失回填”，不覆盖已写入的非空值（保证可重放）。

## 11.4 命令行接口

| 步骤 | 参数 | 默认 |
|---|---|---|
| 一次运行（接入+解析+写库） | `--scap <路径>` `--channel local\|wsl\|ssh\|container` `--host-id <sN>` `--dict <字典目录>` `--out <快照目录>` `--no-db` | 通道自动探测（§2.4） |
| 对账 | `--expected <全量事件数>`（或由独立计数趟取得） | 必填 |
| 写库 | `--uri` `--user` `--password` `--database <trace-sN>` | **`--database` 必填**（禁止默认库，防误写入） |
| 覆盖参数 | `--set k=v`（可重复，键见附录 C） | 附录 C 默认值 |
| 验证趟 | `--scap <路径>` `--emit-dict <目录>` | 必填 |

每次运行报告必须包含：生效参数快照、字典版本号、代码版本号。

## 11.5 目录布局

| 路径 | 内容 | 是否保留 |
|---|---|---|
| `tools/ingest/` | 接入通道与对账器 | 入库 |
| `tools/parse/` | 模块 3–6（行解析、字典规则、状态机、折叠） | 入库 |
| `tools/write/` | 模块 7–8（写库、审计报告）与模块 9（验证趟） | 入库 |
| `tools/dict/` | §11.9 的两份字典（版本化） | 入库 |
| `tests/` | 单元测试、固定样本 | 入库 |
| `tmp/reports/<场景>/` | 对账与审计报告（可复算凭证） | 保留 |
| `output/<场景>/` | 图快照（节点表/边表）+ 评测结果 | 保留 |

## 11.6 测试与固定样本

| 项 | 约定 |
|---|---|
| 固定样本 | 场景 5 前 50,000 条事件的捕获片段（极小 `.scap`），纳入 `tests/`，用同一执行通道直读，作为回归基线 |
| 单元测试覆盖 | 字典命中（每族至少 1 条）、配对四个分支、路径规范化（绝对/相对/dirfd/`..`/`O_TMPFILE`）、`fd.name` 四类形态、网络归一化（IPv4/IPv6/通配）、折叠（合并与四条禁止）、§4.6 降级逐项、账本平账 |
| 快照测试 | 同固定样本运行两次 → 图快照逐字段一致 |
| 未验证规则 | 按 §9.3 合成型样例在隔离测试机采集后补入 `tests/`，补完前不得宣称已验证 |

## 11.7 图快照格式

| 文件 | 列 | 排序 |
|---|---|---|
| `nodes.csv` | `label` `key`（导出时由 §3.1 主键字段生成）+ §4.1–4.3 属性的并集（空值留空） | `(label, key)` |
| `edges.csv` | `edge_class` `src_key` `dst_key`（同上生成）+ §4.4 属性的并集（空值留空） | `(src_key, edge_class, dst_key, edge_id)` |

用途：验收第 2 条（可复现）的比对基准；与数据库内容做双向一致性校验。

## 11.8 场景与库名映射

| 场景目录 | `host_id` | Neo4j 库 |
|---|---|---|
| `1_Web_Exploit_Ransomware` | `s1` | `trace-s1` |
| `2_SSH_Spray_Lateral_Exfiltration` | `s2` | `trace-s2` |
| `3_Phishing_Beacon_Cryptomining` | `s3` | `trace-s3` |
| `4_Repo_Poisoning_Backdoor` | `s4` | `trace-s4` |
| `5_Exposed_Service_Pivot` | `s5` | `trace-s5` |
| `6_Web_SQLi_Data_Exfiltration` | `s6` | `trace-s6` |
| `7_DB_BruteForce_DataWipe` | `s7` | `trace-s7` |
| `9_Exposed_Container_Escape` | `s9` | `trace-s9` |
| `10_Tomcat_WeakCreds_DNS_Exfiltration` | `s10` | `trace-s10` |

## 11.9 实现前置：两份字典（尚未生成）

| 字典 | 内容 | 生成方式 | 完成判据 |
|---|---|---|---|
| 事件字典 | 事件名 → 族 → 动作 → 边类（含 §6 的判据条件）；并逐动作标注是否“本数据源天然无客体/无参数”（决定是否写 `missing_params`，见 §4.4） | 验证趟扫全量 9 场景收集事件名后逐条映射 | 211 个实测事件名 + 9 个未出现调用全部有映射；天然无客体清单已逐动作标注；未归类为 0 |
| 参数字典 | 需要配对的事件类型 → 进入行/退出行的参数序号 → 语义；含身份观测类 `get*uid`（取值在退出行 `evt.args`，如 `euid=0(root)`） | 验证趟对每个需配对事件抽取并人工核对 | §7.1.2 列出的全部事件类型均有对照；`get*uid` 的取值位置均已核对 |

两份字典生成前，参数解析部分无法开工；生成后固化并打版本号，运行报告必须携带该版本号。

---

# 12 实现决策点（8 条）

以下为文档未规定到算法级、但实现必须钉死的细节。实现必须采用本表的默认做法，偏离需在报告中声明。

| # | 决策点 | 默认做法 | 可配置 | 影响面 |
|---|---|---|---|---|
| 1 | 折叠槽结算时机 | 客体切换 / `lseek` / 超 `fold_window_ns` / 进程退出 / 场景结束 五点结算 | `fold_window_ns` | §4.5 |
| 2 | `host_view_alias` 推导 | 挂载表按挂载点路径长度降序做最长前缀匹配；嵌套挂载取最长者 | — | §3.5.3、§6 规则 28 |
| 3 | IPv6 归一化 | 自写：去前导零 → `::` 展开为定长 → 按 16 字节数值比较 | — | §3.5.4 |
| 4 | 配对池淘汰例外 | 阻塞类调用（`accept`/`read`/`recv*`/`wait*`）超时不淘汰，只保留进入行等待配对 | `pair_timeout_ns` | §7.1.4 |
| 5 | 异常行处理 | JSON 损坏/字段类型异常 → 记账后跳过（不参与对账；但计数必须出现在报告里）；连续异常超阈值则阻断 | 异常阈值 | §7.2 阶段 2、§8 |
| 6 | 写库失败阀值 | 重试 `retry_max` 次仍失败 → 阻断并输出冲突主键（不静默跳过） | `retry_max` | §7.4 |
| 7 | 图快照 | 节点表/边表 CSV，按 §11.7 排序，用于逐字段比对 | — | §9.1 第 2 条 |
| 8 | 场景→库名映射 | 按 §11.8 表；写库必须显式指定 `--database` | — | §11.4、§11.8 |

---

# 附录 A 复现命令

```bash
S=/path/to/capture.scap

# 全量事件数（对账分母）
sysdig -r $S -p "%evt.num" | wc -l

# 事件类型分布与并集
sysdig -r $S -p "%evt.type" | sort | uniq -c | sort -rn

# 接入无损性验证（三条对照）
sysdig -r $S -p "%evt.type" | wc -l
sysdig -r $S -j | wc -l
sysdig -r $S -p "%evt.type|%fd.name" | wc -l

# 分类计数（过滤器为位置参数）
sysdig -r $S -p "%evt.num" "evt.is_io=true" | wc -l
sysdig -r $S -p "%evt.num" "evt.failed=true" | wc -l
sysdig -r $S -p "%evt.num" "evt.dir=<" | wc -l
sysdig -r $S -p "%evt.num" "evt.category=unknown" | wc -l

# 结构化参数
sysdig -r $S "evt.type=openat" -p "%evt.type|%evt.arg[2]|%evt.arg[3]|%evt.rawres" -n 3
sysdig -r $S "evt.type=rename" -p "%evt.arg.oldpath|%evt.arg.newpath" -n 3

# 载荷（必须 base64）
sysdig -r $S "evt.type=read" -p "%evt.buflen|%evt.buffer" -b -n 3

# 网络四元组
sysdig -r $S "evt.type=accept and evt.dir=<" -p "%fd.name|%fd.l4proto|%evt.rawres" -n 3

# 容器元数据可得性（验证 §4.1 的 container_privileged 与 §3.5.3 挂载表是否有值）
sysdig -r $S -p "%container.id|%container.privileged|%container.mounts" -n 5
for f in container.id container.privileged container.mounts; do
  printf "%s 非空条数: " "$f"; sysdig -r $S -p "%$f" | grep -vc '^<NA>$'
done

# 进程启动时间反推
sysdig -r $S "evt.type=execve" -p "%evt.rawtime|%proc.duration|%thread.tid|%proc.pid|%proc.vpid|%proc.ppid" -n 3

# 事件规模（9 场景合计 89,448,266 条）
for d in 5 7 4 6 9 2 3 1 10; do echo -n "$d "; sysdig -r <dir>/$d/capture.scap -p "%evt.num" | wc -l; done
```

---

# 附录 B 实测事件名的族归属

按 §5.2 的族归类；括号内为出现在多少个场景中（9 = 全部场景）。本附录是"事件名 → 族"的权威映射，由 §5.3 的动作词表驱动。

**A 进程控制**：`clone(9) clone3 fork(2) vfork(9) execve(9) execveat exit(9) exit_group(9) procexit(9) wait4(9) waitid(9) kill(9) tgkill(9) tkill signaldeliver(9) sigreturn(9)`

**B 进程内存**：`mmap(9) munmap(9) mprotect(9) mremap(5) madvise(9) brk(9) mincore(1) userfaultfd`

**C 文件数据流**：`read(9) write(9) readv(2) writev(9) pread(9) pwrite(9) splice(2) sendfile(2) copy_file_range tee vmsplice io_uring_setup io_uring_enter io_uring_register`

**D 文件生命周期**：`openat(9) open(2) creat(2) mkdir(9) mkdirat(7) rmdir(9) mknodat(6) unlink(9) unlinkat(9) rename(9) renameat(7) renameat2(4) link(3) linkat(1) symlink(9) symlinkat(7) truncate(1) ftruncate(9) fallocate(9)`

**E 文件元数据**：`chmod(7) fchmod(7) fchmodat(7) chown(5) fchown(7) fchownat(5) lchown(4) utimensat(9) setxattr(9) lsetxattr(4) fsetxattr(3) getxattr(9) lgetxattr(4) fgetxattr(3) removexattr(9) flock(9) fsync(9) fdatasync(8) msync(5) fadvise64(9)`

**F 探测**：`newfstatat(9) fstat(9) stat(2) lstat(1) access(9) faccessat(3) readlink(9) readlinkat(9) getdents64(9) statfs(9) fstatfs(9) getcwd(9) uname(9) sysinfo(9)`

**G 句柄管理**：`close(9) dup(9) fcntl(9) lseek(9) ioctl(9)`

**H 网络**：`socket(9) socketpair(9) connect(9) bind(9) listen(8) accept(9) sendto(9) sendmsg(9) sendmmsg(9) recvfrom(9) recvmsg(9) recvmmsg(9) shutdown(9) setsockopt(9) getsockopt(9) getsockname(9) getpeername(9)`

**I 本地 IPC**：`pipe(9) eventfd(9) signalfd(8) timerfd_create(9) inotify_init(8) inotify_add_watch(9) inotify_rm_watch(9) epoll_create(5) epoll_create1(8) epoll_ctl(9) shmget(4) shmat(4) shmdt(4) shmctl(4)`

**J 内核对象**：`finit_module(1) bpf(7) keyctl(9) add_key(9) seccomp(7) kexec_load`

**K 命名空间与挂载**：`mount(8) umount(8) chroot(8) pivot_root(1) setns(7) unshare(7)`

**L 身份与状态**：`setuid(9) setgid(9) setresuid(9) setresgid(9) setreuid(7) setregid(7) setfsuid(3) setfsgid(3) setgroups(9) capset(9) prctl(9) personality(4) setrlimit(5) prlimit(9) ioprio_set(4) sched_setscheduler(5) sched_setaffinity(2) setsid(9) setpgid(3) setpriority(9) umask(9) arch_prctl(9) quotactl(1) sethostname(1) chdir(9) fchdir(9) getuid(9) geteuid(9) getresuid(8)`

**M 时序与调度**：`switch(9) futex(9) nanosleep(9) clock_nanosleep(9) setitimer(9) alarm(9) timerfd_settime(9) timer_settime(3) timer_create(2) timer_delete(2) times(9) getpid(9) getppid(9) gettid(9) getgid(9) getegid(9) getresgid(8) getgroups(7) getrusage(9) getrandom(9) clock_gettime(1) clock_getres(2) clock_adjtime(6) gettimeofday(1) set_tid_address(9) set_robust_list(9) restart_syscall(3) syslog(9) poll(9) ppoll(9) select(6) pselect6(9) epoll_wait(9) epoll_pwait(9) sched_yield(9) sched_getaffinity(9) sched_getparam(5) sched_getscheduler(5) sched_get_priority_min(4) sched_get_priority_max(4) getrlimit(5) getpriority(9) ioprio_get(1) capget(9) rt_sigaction(9) rt_sigprocmask(9) rt_sigpending(3) rt_sigtimedwait(5) sigaltstack(7)`

**本族处理**：除 `syslog(9)`、`setitimer(9)`、`alarm(9)`、`timerfd_settime(9)`、`timer_settime(3)` 建 `p2p` 自环（动作名 `syslog` / `timer_arm`）外，本族调用一律不进图、显式记账丢弃；`uname`/`sysinfo` 归 F 族、`ioctl` 归 G 族（均见上）。

**未归类风险项**：`<unknown>(9)`

---

# 附录 C 配置参数表

| 参数 | 默认值 | 说明 |
|---|---|---|
| `host_id` | 必填 | 每个场景一个（如 `s1`…`s10`） |
| `fold_window_ns` | 200 毫秒 | 折叠判据的时间间隔（§4.5） |
| `pair_timeout_ns` | 5 秒 | 进入行超时淘汰阈值（§7.1.4） |
| `pair_pool_max` | 100,000 | 配对池容量上限（§7.3） |
| `fd_table_max` | 4,096 | 单进程句柄表容量上限（§7.3） |
| `fold_slot_max` | 100,000 | 折叠槽位上限（§7.3） |
| `keep_payload` | 开启 | 是否保留载荷快照（§4.4） |
| `payload_max_bytes` | 80 | 载荷上限（受采集快照长度限制） |
| `vertex_batch` | 5,000 | 顶点批量写入条数（§7.4） |
| `edge_batch` | 10,000 | 边批量写入条数（§7.4） |
| `flush_interval_ms` | 500 | 边写入的时间触发阈值（§7.4） |
| `write_buffer_max` | 50,000 | 待写边缓冲上限（§7.3） |
| `backpressure_batches` | 5 | 背压触发批次数（§7.4） |
| `retry_max` | 5 | 写冲突重试次数（§7.4） |
| `memory_target_gb` | 6 | 峰值内存目标（§7.3、§7.5） |
| `fold_window_sensitivity` | 200ms/1s/5s | 折叠敏感性实验的三档取值（§4.5） |
