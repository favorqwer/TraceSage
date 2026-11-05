# 溯源图模型契约

**适用范围**：需要写 Cypher、修改建图逻辑、判定某条系统调用落到哪条边，或阅读 groundtruth 标注时读本文件。日常汇报、规划与文档整理不必读。

图模型以 `parser` 代码为准，完整字段口径见 `parser/README.md`，建模公理见 `docs/PROVENANCE_GRAPH_MODELING_AXIOMS.md`。本文件是 agent 判定用的契约口径；实现细节（读取后端、模板字段、已知边界）以 `parser/README.md` 为准。

## 核心边界

- 系统默认面向企业级多主机环境建模；节点以 `host_id` 作为命名空间属性与复合主键最高前缀，支持单机独立溯源。跨主机场景下 Network 顶点同样按 `host_id` 隔离，两端因果连接需要网络端点（IP、端口、时间）对齐；当前解析器只负责单次 capture 的图，不做跨主机对端自动合并。
- 跨主机关联不属于 `parser` 的职责；当前仓库没有对端流量对齐模块，跨主机关联只能作为外部前置步骤，不得在能力汇报中算作系统自主能力。

## 顶点

顶点 3 类，主键均以 `host_id` 开头：

| 顶点 | 主键（Neo4j MERGE 键） | 主要属性 | 说明 |
|---|---|---|---|
| `Process` | `host_id, container_id, pid, start_ns` | `exe_path`、`cmdline`、`ppid`、`uid`、`euid`、`container_privileged`、`container_host_root_rw` | `start_ns` 是进程实例的出生时刻；同一 `pid` 不同 `start_ns` 代表 exec 前后的两个进程，`0` 表示出生时刻未知。`ppid` 是父进程的 pid 数字，不是父节点键。 |
| `File` | `host_id, container_id, path` | `file_type` | `path` 是规范化后的路径；`file_type ∈ {file, directory, pipe, unix, memfd, unknown}`。unix 套接字与 memfd 也建 `File` 节点，网络套接字不建。 |
| `Network` | `host_id, endpoints` | `proto` | `endpoints` 是 Sysdig 的连接元组字符串（形如 `lip:lport->rip:rport`）；`proto` 可能是 tcp/udp 等，也可能缺失；主键不含 `container_id`。 |

匿名 IPC（`event`、`timerfd`、`signalfd`、`inotify`、`eventpoll`、`netlink`、`bpf`、`other`）没有可区分名字，不建节点。容器属性 `container_privileged` / `container_host_root_rw` 缺失表示未知，不是 false。

## 关系边

关系边 5 类。关系类型只表示两端是哪种顶点，不表示数据流向；具体动作由边属性 `action` 给出。

| 关系类型 | 方向 | 典型 `action` |
|---|---|---|
| `ProcessToProcess` | 进程 → 进程 | `clone`、`exec`、`exit`、`signal`、`ptrace`、`wait`、`mem_read`、`mem_write`、`pidfd_getfd` |
| `ProcessToFile` | 进程 → 文件 | `create`、`write`、`mmap_write`、`rename`、`link`、`unlink`、`truncate`、`chmod`、`mount`、`umount`、`chroot`、`setns`、`ioctl`、`connect`（unix）、`send`（unix） |
| `FileToProcess` | 文件 → 进程 | `read`、`stat`、`mmap_read`、`mmap_exec`、`exec`、`rename`（源端）、`recv`（unix） |
| `ProcessToNetwork` | 进程 → 连接 | `connect`、`bind`、`listen`、`send` |
| `NetworkToProcess` | 连接 → 进程 | `accept`、`recv` |

## 边属性与写库约束

边属性：`event_id`、`action`、`start_ns`、`end_ns`、`syscall`、`result`、`payload_b64`、`to_path`、`mode`。

- 写库以 `(event_id, action)` 作为关系唯一约束；同一事件可以产生多条边（如 `exec` 出 `ProcessToProcess` + `FileToProcess`，`rename` 出 `FileToProcess` + `ProcessToFile`）；自环不落图。
- `result` 是单字段三语义：数据类为字节数、失败为负错误码、`0` 为实测零；未观测时不写该属性。`fd` 号与 `mmap` 成功返回的地址不写入 `result`。
- `syscall` 是系统调用家族名（如 `sendmsg -> sendto`），原始 `evt.type` 用 `event_id` 回原始捕获核对。
- `payload_b64` 是载荷前 N 字节的 base64，不是可打印文本；`to_path` 只用于 `link` 的目标路径；`mode` 只用于 `chmod` 的权限模式。
- 方向约定：`read`/`recv`/`stat`/`mmap_read`/`mmap_exec`/`exec` 是「文件或连接 → 进程」；`write`/`send`/`create` 等是「进程 → 文件或连接」。unix 域套接字的 `connect`/`send`/`recv` 走 `ProcessToFile`/`FileToProcess`，不建 `Network` 节点；unix `accept` 只登记 fd，不建边。
