# TraceSage 多系统通用日志解析器与全平台图建模工程设计规范

> **文档状态**：正式发布 / 架构基线  
> **制定依据**：基于 DARPA Transparent Computing CDM 20 规范、Linux 内核系统调用接口、Windows ETW / Sysmon 审计规范与分布式因果溯源图理论。  
> **工程法则**：严格遵守《AGENTS.md》四大通用工程法则（声明边界法则、阻断诚实法则、独立可验证法则、真实绝对压倒形式法则）。

---

## 目录
1. [系统定位与四大正交支柱设计哲学](#一-系统定位与四大正交支柱设计哲学)
2. [支柱一：图数据模式与静态约束规范 (Graph Schema Specification)](#二-支柱一图数据模式与静态约束规范)
3. [支柱二：多源接入与事件全景分发矩阵 (Ingestion & Dispatch Matrix)](#三-支柱二多源接入与事件全景分发矩阵)
4. [支柱三：内存因果状态机与防 OOM 机制 (Context & State Machine)](#四-支柱三内存因果状态机与防-oom-机制)
5. [支柱四：持久化图管道与守恒审计体系 (Storage Pipeline & Audit)](#五-支柱四持久化图管道与守恒审计体系)
6. [项目工程模块实现与落地结构清单](#六-项目工程模块实现与落地结构清单)

---

## 一、 系统定位与四大正交支柱设计哲学

### 1.1 系统定位与核心使命
本系统是 TraceSage 威胁溯源体系的**数据接入与图构建核心引擎**。其核心使命是：接收来自 DARPA TC CDM 官方规范定义的全部 4 大操作系统家族（Linux、FreeBSD、Windows、Android）及各探针系统（Sysdig SCAP、Linux Auditd/BEEP/THEIA、FreeBSD OpenBSM/CADETS、Windows Sysmon/ETW/Faros、Android ClearScope 等）的底层审计日志，通过流式事件驱动与内存状态追踪，无损构建出统一的因果溯源属性图并存入 Neo4j 图数据库。

系统严格贯彻以下核心哲学：
1. **4 类物理顶点 + 7 类因果边**：从 DARPA TC CDM 规范的 9 类实体中消除超级节点，将模型高度收敛为 4 类物理顶点（`:Process`, `:File`, `:Network`, `:Registry`）与 7 类有向因果边（`p2p`, `p2f`, `f2p`, `p2n`, `n2p`, `p2r`, `r2p`）。
2. **主机命名空间属性化**：主机（`Host`）不作为图顶点，而是作为全图所有实体的主键前缀与分区属性（`host_id`），彻底绝杀因主机顶点出入度破百万而导致的图遍历崩溃。
3. **全平台客体无损收敛**：对异构系统的专有客体（如 Windows 注册表、Android 传感器与 Binder 通信、Linux/BSD 管道）建立严格的无损映射，统一归纳于 4 类顶点中。
4. **四大正交支柱架构**：将解析器内部严格划分为四个单一职责、彼此正交的工程支柱，杜绝逻辑耦合与状态碎片化。

### 1.2 四大正交支柱全景数据流
```text
 原始审计日志流 (Linux SCAP / Auditd / Windows Sysmon EVTX / JSONL)
                               │
                               ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 【支柱二：多源接入与事件全景分发矩阵】                                 │
 │  1. 抽象接入适配器 (LogStreamSource) 统一转换为 RawLogRecord           │
 │  2. 56 类事件一站式判定：28 类因果边 / 7 类句柄 / 7 类属性 / 14 类剪枝 │
 └─────────────────────────┬──────────────────────────────────────────────┘
                           │ 提取待还原局部事件
                           ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 【支柱三：内存因果状态机与防 OOM 机制】                                │
 │  1. TID 独立系统调用配对池 (PairingBuffer，5 秒窗口，防内存泄漏)       │
 │  2. PID 共享文件描述符表 (ProcessFdTable) 与注册表表 (RegistryTable)  │
 │  3. 在途未知进程懒加载 (Lazy Instantiation, start_time_ns=0)          │
 └─────────────────────────┬──────────────────────────────────────────────┘
                           │ 产出具备全局唯一键的完整实体与边
                           ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 【支柱四：持久化图管道与守恒审计体系】                                 │
 │  1. 严格滑动保序因果边微观折叠 (连续同源同宿同操作，打断时推入队列)   │
 │  2. Neo4j 双阶段批量事务写入 (先提交存活顶点，再提交因果边，防孤儿边) │
 │  3. 共享节点锁冲突 5 次指数退避重试 (Exponential Backoff with Jitter) │
 │  4. 输入输出守恒平衡审计自检天平 (N_total ≡ ∑ N_parts)                 │
 └─────────────────────────┬──────────────────────────────────────────────┘
                           │ 物理写入
                           ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 【支柱一：图数据模式与静态约束规范】                                   │
 │  持久化落盘至 Neo4j 数据库：                                           │
 │  - 4 类顶点 (:Process, :File, :Network, :Registry)                     │
 │  - 7 类因果边 (p2p, p2f, f2p, p2n, n2p, p2r, r2p)                     │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 二、 支柱一：图数据模式与静态约束规范

> **职责边界**：静态定义图数据库的物理结构、复合主键算法、属性类型字典及空值（Null-safe）规范。

### 2.1 四类物理顶点的复合主键与完整属性字典

```text
┌───────────────┬────────────────┬─────────────────┬─────────────────────┐
│  1. :Process  │    2. :File    │   3. :Network   │    4. :Registry     │
│  (执行主体)   │ (存储/IPC载体) │  (网络通信流)   │ (Windows配置数据库) │
└───────────────┴────────────────┴─────────────────┴─────────────────────┘
```

#### (1) `:Process` 顶点（活动计算主体）
*   **概念定义**：操作系统中执行代码与系统调用的唯一动态活动主体（包含普通用户进程与内核守护线程）。
*   **复合主键（唯一标识）**：`{host_id}:{pid}:{start_time_ns}`。
    *   *未捕获启动时间口径*：若进程在日志捕获前已在系统常驻运行（中途接入），`start_time_ns` 严格固定为 `0`，禁止填充随机数。
*   **属性字典与约束**：
    *   `host_id` (string, 必须): 所在物理机/虚拟机唯一标识。
    *   `pid` (int/long, 必须): 操作系统分配的进程 ID。
    *   `name` (string, 必须): 进程可执行文件短名称（例如 `bash`, `cmd.exe`）。
    *   `exe_path` (string, 必须): 二进制映像文件的规范化绝对路径。
    *   `cmdline` (string, 必须): 启动命令行完整参数；若无参数则存为空字符串 `""`。
    *   `start_time_ns` (long, 必须): 进程启动的 Unix 纳秒时间戳（未捕获填 `0`）。
    *   `ppid` (int, 可选): 父进程 ID。
    *   `end_time_ns` (long, 可选): 进程退出时的纳秒时间戳。
    *   `principal_id` (string, 可选): 规范化用户身份凭据标识。Linux 格式为 `uid:<id>`（如 `uid:0`）；Windows 格式为 `SID:<sid>`（如 `SID:S-1-5-18`）。
    *   `euid` (int, 可选): Linux 特有有效用户 ID（用于监控 `setuid` 提权）。
    *   `integrity_level` (string, 可选): Windows 特有完整性级别（`Low`, `Medium`, `High`, `System`）。
    *   `cwd` (string, 可选): 进程当前工作目录路径。
    *   `is_in_flight` (boolean, 可选): 标记该进程是否为日志中途接入的在途存量进程。
    *   `failed_probes` (list of string, 可选): 该进程执行失败的敏感操作清单。

#### (2) `:File` 顶点（持久化客体与 IPC 通道）
*   **概念定义**：持久化文件、目录、特殊字符/块设备、管道以及遵循 VFS（虚拟文件系统）抽象的一切数据存储/流转客体。
*   **复合主键（唯一标识）**：`{host_id}:{path}`。
*   **属性字典与约束**：
    *   `host_id` (string, 必须): 所在主机唯一标识。
    *   `path` (string, 必须): 规范化绝对路径。路径分隔符统一强制使用正斜杠 `/`；Windows 盘符必须小写化（例如 `c:/windows/system32/kernel32.dll`），杜绝大小写分裂。
    *   `file_type` (string, 必须): 实体子类型枚举，取值范围：`regular`（普通文件）、`directory`（目录）、`pipe`（匿名/命名管道）、`socket`（UNIX 域套接字文件）、`char`（字符设备）、`block`（块设备）、`android_resource`（Android 专有资源）。
        *   *IPC 管道命名收敛规约*：Linux/BSD 匿名管道统一命名为 `pipe:[<inode>]`；Windows 命名管道统一命名为 `//./pipe/<name>`。
        *   *Android 专有客体 (`SrcSinkObject`) 收敛规约*：Android 平台特有的硬件传感器（GPS、陀螺仪、摄像头、麦克风等）与系统组件资源（Binder 进程间通信、剪贴板、SMS 短信），在 Linux 内核层本质上全是以字符设备（`cdev`）或 VFS 抽象呈现。系统将其统一无损收敛为 `:File` 顶点：
            - 底层设备节点统一命名为 `/dev/binder`, `/dev/sensors/<type>`, `/dev/video*`；
            - 框架层服务汇统一命名为 `android://service/<name>`（如 `android://service/clipboard`, `android://sensor/gps`）；
            - 读写传感器或发起 Binder 调用，天然对应 `p2f` 与 `f2p` 边，无需为了 Android 移动端膨胀出第 5 类顶点。
    *   `epoch` (int, 可选): 文件生命周期代数。初次创建为 0，当文件被截断清空（`O_TRUNC`）时递增，防止因果时光倒流。
    *   `permissions` (string, 可选): POSIX 权限八进制文本（如 `0755`）。

#### (3) `:Network` 顶点（网络通信会话）
*   **概念定义**：跨网络的数据传输端点与通信流实体。
*   **复合主键（唯一标识）**：`{protocol}:{lower_ip}:{lower_port}<->{upper_ip}:{upper_port}`。
    *   *升序自然序对齐算法*：将通信两端的 `IP:Port` 字符串按字典序比对，较小的一端置于左侧（lower），较大的一端置于右侧（upper）。例如无论是 `10.0.0.1:5000` 连接 `10.0.0.2:80` 还是反向连接，主键均收敛为 `tcp:10.0.0.1:5000<->10.0.0.2:80`。
*   **属性字典与约束**：
    *   `protocol` (string, 必须): 传输层协议，取值：`tcp`, `udp`。
    *   `src_ip` (string, 必须): 升序对齐较小端 IP 地址。
    *   `src_port` (int, 必须): 升序对齐较小端端口号。
    *   `dst_ip` (string, 必须): 升序对齐较大端 IP 地址。
    *   `dst_port` (int, 必须): 升序对齐较大端端口号。
    *   `is_loopback` (boolean, 必须): 是否为本机 127.0.0.1 环回通信。
    *   `ip_family` (string, 可选): `ipv4` 或 `ipv6`。

#### (4) `:Registry` 顶点（Windows 专有配置项）
*   **概念定义**：Windows 操作系统专有的分层配置数据库项与值客体（Linux/BSD/Android 系统中此实体实例数量自然为 0）。
*   **复合主键（唯一标识）**：`{host_id}:{hive}\{normalized_key_path}`。
*   **属性字典与约束**：
    *   `host_id` (string, 必须): 所在主机唯一标识。
    *   `hive` (string, 必须): 注册表配置单元根，强制统一大写缩写：`HKLM` (HKEY_LOCAL_MACHINE), `HKCU` (HKEY_CURRENT_USER), `HKCR` (HKEY_CLASSES_ROOT), `HKU` (HKEY_USERS)。
    *   `key_path` (string, 必须): 注册表子键路径，层级使用反斜杠 `\` 分隔（例如 `Software\Microsoft\Windows\CurrentVersion\Run`）。
    *   `value_name` (string, 可选): 具体操作的键项名称。
    *   `data_type` (string, 可选): 键值数据类型（如 `REG_SZ`, `REG_DWORD`, `REG_BINARY`）。

---

### 2.1.1 CDM 官方全量实体与跨操作系统收敛映射总表

本设计对 DARPA TC CDM 20 规范中定义的全部 9 类实体对象（涵盖 Linux、FreeBSD、Windows、Android 4 大平台），建立了严格、无损的收敛映射闭环：

| CDM 官方实体类型 (Record) | 归属操作系统平台 | 在属性图中的最终落地形态 | 物理复合主键 / 归属属性 |
|---|---|---|---|
| **`Subject`** (活动执行主体) | Linux, FreeBSD, Windows, Android | **`:Process` 物理顶点** | `{host_id}:{pid}:{start_time_ns}` |
| **`FileObject`** (文件与目录) | Linux, FreeBSD, Windows, Android | **`:File` 物理顶点** | `{host_id}:{canonical_path}` |
| **`NetFlowObject`** (网络会话) | Linux, FreeBSD, Windows, Android | **`:Network` 物理顶点** | `{proto}:{lower_ip:port}<->{upper_ip:port}` |
| **`RegistryKeyObject`** (注册表) | Windows 平台独有 | **`:Registry` 物理顶点** | `{host_id}:{hive}\{key_path}` (非 Windows 系统数量为 0) |
| **`SrcSinkObject`** (外设/传感器/Binder) | Android 移动端独有 | **`:File` 物理顶点** (字符设备/服务汇) | `{host_id}:android://sensor/<type>` 或 `/dev/<device>` |
| **`IpcObject`** (管道/套接字) | Linux, FreeBSD, Windows, Android | **`:File` 物理顶点** (统一收敛) | Linux: `pipe:[inode]`; Windows: `//./pipe/<name>` |
| **`Host`** (主机节点) | 全平台通用 | **所有实体的主键前缀与属性** | `node.host_id` (绝不建独立超级节点) |
| **`Principal`** (身份凭据) | 全平台通用 | **内嵌为 Process 的身份属性** | `p.principal_id` (Linux/BSD 为 UID，Win 为 SID) |
| **`MemoryObject`** (虚拟内存) | 全平台通用 | **转化为 `p2p` 内存注入边与状态** | `p2p {action: 'mprotect' / 'remote_thread'}` |
| **`Packet`** (网络报文) | 全平台通用 | **内嵌为 Network 节点与边属性** | `edge.bytes`, `edge.flags` (不建独立报文节点) |

---

### 2.2 七类因果边的拓扑连接与通用属性字典

图数据库中物理持久化的边严格限定为以下 7 种类型，其端点连接类型固定不变：

| 边类型 | 起点实体 (Source Node) | 终点实体 (Sink Node) | 物理因果语义 |
|---|---|---|---|
| `p2p` | `:Process` | `:Process` | 进程间控制流转移、派生、注入 |
| `p2f` | `:Process` | `:File` | 进程向文件/管道写入、修改 |
| `f2p` | `:File` | `:Process` | 进程从文件/管道读取、加载映像 |
| `p2n` | `:Process` | `:Network` | 进程发起网络外联、绑定监听 |
| `n2p` | `:Network` | `:Process` | 服务端接受连接、网络接收报文 |
| `p2r` | `:Process` | `:Registry` | Windows 进程写入注册表配置项 |
| `r2p` | `:Registry` | `:Process` | Windows 进程读取注册表配置项 |

#### 通用强约束边属性字典（7 类边通用）
*   `event_id` (long, 必须): 图内全局递增的唯一事件流水号，用于幂等写入与边更新。
*   `action` (string, 必须): 规范化因果动作枚举名（对齐 CDM 28 类因果动作，例如 `EVENT_WRITE`, `EVENT_CLONE`）。
*   `syscall` (string, 必须): 操作系统原生系统调用或审计事件名（例如 `write`, `execve`, `RegSetValueEx`）。
*   `start_time_ns` (long, 必须): 系统调用进入或事件发生的 Unix 纳秒时间戳。
*   `end_time_ns` (long, 必须): 系统调用退出或连接终止的 Unix 纳秒时间戳（瞬时单点事件时等于 `start_time_ns`）。
*   `bytes` (long, 必须): 传输数据载荷字节数。非数据传输类控制边（如 `fork`, `signal`）严格记为 `0`。
*   `op_count` (int, 必须): 微观流式折叠的操作次数（未折叠前初始为 1）。

#### 空值处理规范（Null-safe Protocol）
*   若原始日志未采集到某可选字段，向 Neo4j 传 `None`。Neo4j 底层直接不写入该属性键，不占用物理磁盘与内存空间。
*   **严禁在属性中写入 `"-1"`、`"UNKNOWN"`、`"N/A"` 或空字符串 `""` 伪装数据**。

---

### 2.3 边端点存活过滤公理（Orphan Pruning Protocol）

在解析过程中，实体（进程、文件）会在最外层被初始化，但大量实体可能仅执行了无因果的只读探测（如 `stat`）后便退出，**从未参与过任何一条物理因果边的构建**。
*   **公理规约**：
    1. 解析器在内存中维护 `IncidentVertexKeys`（边端点存活集合）；
    2. 只有当某条因果边被正式生成并进入待写入队列时，才将其源节点与宿节点的主键加入该集合；
    3. 批量向 Neo4j 写入顶点时，**严格只提交存在于 `IncidentVertexKeys` 中的顶点**；
    4. 从未挂载任何边的孤立节点直接在内存中丢弃，**绝对禁止向数据库写入孤立节点**，保证整图的紧凑性与连通性。

---

## 三、 支柱二：多源接入与事件全景分发矩阵

> **职责边界**：抹平多系统原始日志输入格式差异，将操作系统的每一条原生事件，通过单一分发路由矩阵一站式判定其物理去向。

### 3.1 多源探针接入抽象层（`LogStreamSource`）

定义统一的抽象接口，将不同操作系统的输入源统一解耦为标准化事件流：
1. **Linux Sysdig 适配器 (`sysdig_scap.py`)**：对接本地/远程子进程管道，读取 Sysdig 对二进制 `.scap` 文件流式解析吐出的 JSONL 文本行。
2. **Linux Auditd 适配器 (`linux_auditd.py`)**：流式读取 `/var/log/audit/audit.log` 文本行，按 `msg=audit(time.seq)` 合并多行记录。
3. **Windows Sysmon 适配器 (`windows_sysmon.py`)**：解析 Windows 事件日志导出流（XML 或 JSONL 格式），抽取 Event ID 与参数字段。
4. **DARPA TC CDM 官方适配器 (`cdm_avro.py`)**：直接反序列化符合 `TCCDMDatum.avsc` 规范的官方 Avro 二进制或 JSON 流，将 `Host`, `Subject`, `Event` 记录解包并对接 Linux (THEIA/BEEP)、FreeBSD (CADETS)、Windows (Faros/FiveDirections)、Android (ClearScope) 全量探针数据。
5. **输出契约（`RawLogRecord`）**：所有适配器必须输出包含以下核心字段的统一内存结构：
   `RawLogRecord(host_id, timestamp_ns, event_name, pid, tid, raw_params, return_code)`。

---

### 3.2 56 类全量事件一站式权威分发矩阵

每个操作系统事件输入分发引擎后，通过**全景分发矩阵**严格归入以下 4 个处理分支之一，杜绝任何代码死角：

```text
┌────────────────────────────────────────────────────────────────────────┐
│              56 类事件全景一站式分发矩阵 (Dispatcher)                  │
├───────────────────┬───────────────────┬───────────────────┬────────────┤
│ 1. 因果建边流     │ 2. 句柄状态追踪   │ 3. 节点属性更新   │ 4. 显式剪枝│
│    (28 类事件)    │    (6 类事件)     │    (6 类事件)     │ (16类管理与│
│    生成待入库边   │   更新内存句柄表  │  直接更新节点属性 │  框架丢弃) │
└───────────────────┴───────────────────┴───────────────────┴────────────┘
```

#### (1) 因果建边流（28 类：在 Neo4j 中建立物理边）
1. `EVENT_FORK`: 映射为 `p2p`（父 $\to$ 子进程派生控制流，`action: 'spawn'`）。
2. `EVENT_CLONE`: 映射为 `p2p`（创建轻量级线程/进程控制流，`action: 'clone'`）。
3. `EVENT_EXECUTE`: 映射为 `f2p`（镜像加载）与 `p2p`（进程状态突变）复合边。
4. `EVENT_EXIT`: 映射为 `p2p`（进程终止通知父进程，`action: 'exit'`）。
5. `EVENT_CREATE_THREAD`: 映射为 `p2p`（跨进程注入控制流，`action: 'remote_thread'`）。
6. `EVENT_SIGNAL`: 映射为 `p2p`（异步信号控制，`action: 'signal', sig: N`）。
7. `EVENT_MPROTECT`: 映射为 `p2p` 自环边（自身内存保护属性修改，`action: 'mprotect'`）。
8. `EVENT_WRITE`: 映射为 `p2f` 或 `p2r`（数据写文件、管道或写注册表，`action: 'write'`）。
9. `EVENT_READ`: 映射为 `f2p` 或 `r2p`（从文件、管道或注册表读载荷，`action: 'read'`）。
10. `EVENT_CREATE_OBJECT`: 映射为 `p2f` 或 `p2r`（创建文件客体或注册表项，`action: 'create'`）。
11. `EVENT_UNLINK`: 映射为 `p2f`（文件删除，`action: 'unlink'`）。
12. `EVENT_RENAME`: 映射为 `p2f`（路径变更，`action: 'rename', old_path: ...`）。
13. `EVENT_LINK`: 映射为 `p2f`（建立硬/软链接，`action: 'link'`）。
14. `EVENT_TRUNCATE`: 映射为 `p2f`（文件截断清空破坏流，`action: 'truncate'`）。
15. `EVENT_MODIFY_FILE_ATTRIBUTES`: 映射为 `p2f`（`chmod/chown` 权限属主变更，赋执行权核心步骤）。
16. `EVENT_LOADLIBRARY`: 映射为 `f2p`（动态加载 DLL 或 .so 共享库，`action: 'load_library'`）。
17. `EVENT_MMAP`: 映射为 `f2p`（文件内容映射到虚拟内存空间，`action: 'mmap'`）。
18. `EVENT_CONNECT`: 映射为 `p2n`（主动外联会话，`action: 'connect'`）。
19. `EVENT_ACCEPT`: 映射为 `n2p`（接受入站网络连接，`action: 'accept'`）。
20. `EVENT_BIND`: 映射为 `p2n`（绑定本地服务端点/后门监听端口，`action: 'bind'`）。
21. `EVENT_SENDTO`: 映射为 `p2n`（UDP 无连接外发数据报文，`action: 'sendto'`）。
22. `EVENT_RECVFROM`: 映射为 `n2p`（UDP 无连接接收数据报文，`action: 'recvfrom'`）。
23. `EVENT_SENDMSG`: 映射为 `p2n`（结构化多通道网络发送，`action: 'sendmsg'`）。
24. `EVENT_RECVMSG`: 映射为 `n2p`（结构化多通道网络接收，`action: 'recvmsg'`）。
25. `EVENT_SPLICE`: 映射为 `f2p` + `p2f`（管道与文件间零拷贝移动，`action: 'splice'`）。
26. `EVENT_TEE`: 映射为 `f2p` + `p2f`（管道间零拷贝数据旁路复制，`action: 'tee'`）。
27. `EVENT_VMSPLICE`: 映射为 `p2f`（用户内存向管道零拷贝注入，`action: 'vmsplice'`）。
28. `EVENT_SHM`: 映射为 `f2p` / `p2f`（共享内存附着与因果数据交换，`action: 'shm'`）。

---

#### (2) 28 类非边事件四大精密工程处理方案（绝对不上图建边）

根据三大因果判决公理与操作系统内核机制，28 类非边事件严格划分为 4 大确定性处理方案（$6 + 6 + 4 + 12 = 28$ 类）：

##### 方案一：内存句柄与虚拟状态追踪方案（6 类，纯内存消化，0 字节上图）
*   **目标与机理**：操作的是操作系统为进程分配的虚拟描述符表（`files_struct`），物理传输数据量严格为 0。它们不上图建边，全部在解析器内存中作为“状态机燃料”就地消耗，为后续建边事件提供精准的客体坐标。
*   **包含事件与处理规约**：
    1. `EVENT_OPEN`: **纯句柄绑定**。在 `ProcessFdTable` 记录 `(host_id, pid, fd) -> path` 映射。因果流严格递延至后续真实读写。*(注：带有创建意图的 `open(O_CREAT)` 早已在输入适配层归一化为建边事件 `EVENT_CREATE_OBJECT`，带有截断意图的 `open(O_TRUNC)` 归一化为 `EVENT_TRUNCATE`，此处进入的严格是纯句柄打开)*。
    2. `EVENT_CLOSE`: **句柄注销**。从内存句柄表中物理删除该映射，防止后续 PID 循环复用句柄造成因果污染。
    3. `EVENT_DUP`: **描述符别名复制**。在内存表中复制句柄映射：`fd_table[new_fd] = fd_table[old_fd]`（反弹 Shell 管道重定向关键）。
    4. `EVENT_FCNTL`: **选择性别名复制**。检查其命令参数 `cmd`：若为 `F_DUPFD` 或 `F_DUPFD_CLOEXEC`，在内存中复制别名；其余参数（如非阻塞 `F_SETFL`、文件锁 `F_SETLK`）直接丢弃。
    5. `EVENT_READ_SOCKET_PARAMS`: `getsockopt` 状态查询，内存更新 Socket 选项，处理完立即 `return`。
    6. `EVENT_WRITE_SOCKET_PARAMS`: `setsockopt` 选项配置，内存更新 Socket 选项，处理完立即 `return`。

##### 方案二：实体内部状态单向突变方案（6 类，转为 Cypher SET 属性，不建边）
*   **目标与机理**：它们不是两个实体间的数据流动，而是实体自身元数据的单向改变。强行建自环边会引发图模式严重膨胀，因此全部收敛为对应图节点的属性（Attribute）增量更新，完整榨取 APT 核心攻击战术特征。
*   **包含事件与处理规约**：
    1. `EVENT_CHANGE_PRINCIPAL`（身份提权）：更新当前进程有效权限：`SET p.euid = event.uid, p.is_elevated = true`。
    2. `EVENT_LOGCLEAR`（抹除痕迹）：追加高危标签：`SET p.suspicious_tags = coalesce(p.suspicious_tags, []) + 'log_clear'`。
    3. `EVENT_INIT_MODULE`（从内存加载驱动）：记录内核驱动模块：`SET p.loaded_modules = coalesce(p.loaded_modules, []) + module_name`。
    4. `EVENT_FINIT_MODULE`（从描述符加载驱动）：现代 Linux 加载 Rootkit 主力，记录驱动：`SET p.loaded_modules = coalesce(p.loaded_modules, []) + module_name`。
    5. `EVENT_MODIFY_PROCESS`（进程伪装）：捕获 `prctl(PR_SET_NAME)` 伪装内核线程，更新别名：`SET p.comm_alias = new_name, p.is_masqueraded = true`。
    6. `EVENT_ADD_OBJECT_ATTRIBUTE`（扩展属性隐匿）：捕获 Windows ADS 备用数据流隐匿木马，更新目标文件：`SET f.has_ads = true`。

##### 方案三：全局命名空间与服务管理方案（4 类，底层已有覆盖，不建独立边）
*   **目标与机理**：操作的是操作系统全局文件树（VFS）或外层服务管理框架（SCM/systemd）。在底层物理级，真实的攻击因果早已被读写边或进程派生边所完整覆盖，无需建立多余的虚假宏观边。
*   **包含事件与处理规约**：
    1. `EVENT_MOUNT`: 挂载文件系统。路径已由内核展开为绝对路径，仅在内存更新挂载点重定向表，不在图中建边。
    2. `EVENT_UMOUNT`: 卸载文件系统。更新内存挂载映射，不在图中建边。
    3. `EVENT_SERVICEINSTALL`: 注册 Windows 持久化服务。底层已被注册表写入边（`p2r`）或服务配置文件写入边（`p2f`）覆盖，目标客体打持久化标记，不建独立边。
    4. `EVENT_STARTSERVICE`: 启动服务管理器任务。底层已被服务控制管理器（`services.exe` / `systemd`）派生服务进程的控制流（`p2p`）覆盖，不建重复宏观边。

##### 方案四：纯框架插桩与显式记账剪枝方案（12 类，严格显式记账后丢弃）
*   **目标与机理**：包含极高频的无害只读元数据探测（`stat`，超级节点爆炸罪魁祸首）、指针相对偏移寻道、进程退出等待以及 DARPA TC 评估框架插桩标记，与单机攻防因果图无物理关联。
*   **包含事件与处理规约**：
    1. `EVENT_CHECK_FILE_ATTRIBUTES`: `stat/fstat/access` 高频探测，直接丢弃，彻底消除超级节点。
    2. `EVENT_LSEEK`: 文件读写指针相对偏移寻道，传输 0 字节，直接丢弃。
    3. `EVENT_WAIT`: 父进程等待子进程退出状态。丢弃前顺手刷新父进程活跃窗口：`state_machine.refresh_process_active_time(pid, ts)`，保持生命周期精度。
    4. `EVENT_BOOT`: 系统开机基线时间戳审计标记，直接丢弃。
    5. `EVENT_LOGIN`: 用户登录认证审计标记，直接丢弃。
    6. `EVENT_LOGOUT`: 用户登出审计标记，直接丢弃。
    7. `EVENT_UNIT`: DARPA BEEP 程序循环单元迭代分割标记，直接丢弃。
    8. `EVENT_CORRELATION`: 评估框架跨源关联打标，直接丢弃。
    9. `EVENT_BLIND`: 沙箱隔离盲区提示标记，直接丢弃。
    10. `EVENT_UPDATE`: 实体字段增量刷新通知，直接丢弃。
    11. `EVENT_OTHER`: 未枚举原生系统调用兜底，直接丢弃。
    12. `EVENT_FLOWS_TO`: 分析框架宏观流标记，直接丢弃。
    *   **零静默丢弃纪律（No Silent Drop）**：
        所有方案四事件在丢弃时，**必须显式调用 `reporter.inc_pruned(event_name)` 累加计数**，严禁使用裸 `continue` 静默吞噬，保证守恒审计天平 100% 平账。

---

### 3.3 失败系统调用（`retval < 0`）与数据流未遂判定口径

在操作系统底层，大量黑客攻击伴随着由于权限不足或参数错误而导致的失败系统调用：
- **数据传输类调用（`read`, `write`, `recv`, `mmap`）**：
  若返回码 `retval < 0`（发生错误，如 `-EACCES`, `-ENOENT`）或实际传输载荷 `bytes == 0`：
  - **绝对禁止建立物理数据流边**（因为物理世界中没有发生任何字节搬运，建边会导致污点分析发生严重误报）；
  - **记录失败事实**：将未遂行为转化为源进程节点的属性记录：`SET p.failed_probes = coalesce(p.failed_probes, []) + '{action}:{target_path}'`。
- **网络连接调用（`connect`）**：
  若返回码 `< 0` 且不为 `EINPROGRESS`，说明三次握手未完成，**不建立 `p2n` 边**，记入 `failed_network_attempts`。

---

### 3.4 Windows `ProcessCreate`（Event ID 1）的“一步双边”复合裂变

- **跨系统差异**：Linux 进程创建由 `fork` 与 `execve` 两步完成；Windows `CreateProcess` 由单条日志（Sysmon Event ID 1）一次性完成。
- **代码级裂变规约**：
  当分发器接收到 Windows Event ID 1 时，必须在同一事务中**裂变为两条原子图边**：
  1. **控制流边 (`p2p`)**：
     `ParentProcess` $\xrightarrow{\text{EVENT\_FORK / action:'spawn'}}$ `CurrentProcess`；
  2. **镜像加载边 (`f2p`)**：
     `ImageFile` $\xrightarrow{\text{EVENT\_EXECUTE / action:'load_image'}}$ `CurrentProcess`。
  - 两条边继承相同的纳秒时间戳，确保 Windows 恶意二进制文件落地执行时，因果链路与 Linux 完全等价、不发生截断。

---

## 四、 支柱三：内存因果状态机与防 OOM 机制

> **职责边界**：在内存中追踪动态上下文，把局部整数句柄还原为全局实体路径，统筹内存生命周期与防爆上限。

### 4.1 线程（TID）配对池与进程（PID）句柄表的内核级分离准则

这是确保多线程高并发程序因果不丢失的**最关键内部机制**：

```text
 线程 1 (TID: 101) ──sys_enter_open──> [配对池: key=(host_id, 101)]
                                                │
                                       sys_exit 返回 fd=3
                                                ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 进程句柄表 (ProcessFdTable): key=(host_id, PID: 100)                   │
 │ 登记: fd=3 -> "/etc/data.txt" (同一进程内所有线程完全共享!)           │
 └──────────────────────────────────────────────┬─────────────────────────┘
                                                ▲
 线程 2 (TID: 102) ──sys_enter_write(fd=3)──────┘ (立即成功命中客体路径!)
```

1. **配对缓冲池（`PairingBuffer`）**：
   - 必须以 **`(host_id, tid)`** 为键！不同线程的系统调用在内核态交替执行，必须按具体线程隔离配对。
   - **时间容忍窗口**：设定为 **5 秒（$5 \times 10^9$ 纳秒）**。若超过 5 秒未收到对应的退出事件，判定为调用挂起或日志丢失，触发超时淘汰。
2. **句柄状态表（`ProcessFdTable`）**：
   - 必须以 **`(host_id, pid)`** 为键！同一进程内的所有线程完全共享同一份句柄表。线程 1 打开的文件，线程 2 写入时能够瞬间通过 PID 查找到目标客体。

---

### 4.2 句柄状态表生命周期全生命周期追踪

1. **Linux 描述符表（`ProcessFdTable`）**：
   - 结构：`(host_id, pid, fd) -> {path: str, type: str, flags: int}`。
   - `open`/`socket`/`pipe` 成功：登记句柄；
   - `dup`/`dup2`/`fcntl`：建立别名映射；
   - `fork`/`clone`：子进程完整深拷贝克隆父进程整张句柄表；
   - `close`：安全从表中移除该 fd。
2. **Windows 注册表句柄表（`RegistryHandleTable`）**：
   - 结构：`(host_id, pid, hKey) -> {hive: str, full_key_path: str}`。
   - `RegOpenKeyEx` / `RegCreateKey` 成功：登记句柄；
   - `RegCloseKey`：安全注销并移除该句柄。

---

### 4.3 在途未知实体的懒加载机制（On-the-fly Lazy Instantiation）

- **背景**：日志采集中途启动时，系统中早已存在存量进程（如常驻守护进程），日志中绝无它们的 `fork` 或创建时间戳。
- **规约**：
  - 当事件中的 `(host_id, pid)` 在内存表中不存在时，解析器立即以当前日志行所附带的进程元数据（进程名、`proc.exepath`、`proc.cmdline`）就地构造 `:Process` 实体。
  - 其启动时间戳统一赋默认值 `start_time_ns = 0`，并赋予布尔属性 `is_in_flight = true`。既确保因果链不断裂，又如实声明了该进程是在途存量进程。

---

### 4.4 内存硬上限与 LRU 逃生机制（防 OOM 规范）

为防止长周期解析进程内存无限膨胀，状态机设定严格的物理容量上限：
1. **全局配对池上限**：最大保留未决事件数固定为 **100,000 条**。
2. **单进程持有句柄上限**：单个进程最大允许持有句柄数固定为 **4,096 个**。
3. **强制逃生与淘汰策略**：
   - 配对池超限时，自动触发 LRU（最近最少使用）淘汰机制，丢弃最老的未闭合记录，并在报表中累加 `evicted_unpaired_events`；
   - 收到 `EVENT_EXIT`（进程退出）事件时，**立即物理销毁该进程名下的整张句柄表**；
   - 遇到在句柄表中查找不到客体的野指针 fd，记录为 `unknown_fd_count`，放弃建边，坚决杜绝向数据库写入包含空路径的脏节点。

---

## 五、 支柱四：持久化图管道与守恒审计体系

> **职责边界**：控制数据向 Neo4j 数据库的高性能、防死锁写入，并提供贯穿全流程的数学守恒审计验证。

### 5.1 严格滑动保序因果边微观折叠公理

大文件读写或网络传输会产生数十万次重复调用，必须在写入数据库前做流式折叠：

```text
 时间轴: ───[write(A)]───[write(A)]───[write(B)]───[write(A)]───>
              │              │            │            │
 状态机: └───折叠累加 bytes───┘            │            │
         (edge.bytes += b, op_count=2)    │            │
                                          │            │
                     遇到客体 B 立即打断! ┘            │
                     (强制发射 A 并推入写入队列)       │
                                                       │
                                  新槽位开启: 写入客体 A ┘
```

1. **折叠判据（必须 4 项全同）**：
   - 起始节点、终点节点、因果动作（`action`）、底层调用（`syscall`）完全相同；
   - 两次调用的时间间隔 $\Delta t < 1 \text{ 秒}$。
2. **严格滑动保序公理（防止因果时序错乱）**：
   - 每个进程在内存中**仅保留唯一一个活动的待折叠边槽位（`ActiveEdgeSlot`）**；
   - 进程一旦发起了对不同客体的操作（例如从写 File A 切换为写 File B），或者执行了 `lseek` 指针寻道，**必须立即打断当前槽位，将当前边推入写入队列**，并开启新槽位；
   - **绝对禁止跨越其他客体的操作进行跳跃式合并**，严格捍卫因果拓扑的偏序一致性。

---

### 5.2 Neo4j 双阶段批量写入管线（防死锁与外键孤儿边）

1. **两阶段提交管线（Two-Phase Flush Pipeline）**：
   - **阶段一（提交存活顶点）**：
     提取经过存活过滤的顶点集合（`Process`, `File`, `Network`, `Registry`），执行基于复合主键的 `MERGE` 语句批量写入，等待事务提交确认。
   - **阶段二（提交因果边）**：
     顶点确认落盘后，再执行边的批量写入（`MATCH` 两端顶点主键，执行 `CREATE` 或 `MERGE` 关系边）。
   - **保证**：从拓扑底层确保边两端的顶点 100% 存在，彻底消灭外键引用失败与孤儿边。
2. **批量阈值与背压流控**：
   - 默认缓冲区满 **10,000 条边** 或解析等待满 **500 毫秒** 触发一次提交；
   - 采用多线程异步写入队列，若写入队列积压超过 **5 个批次**，主解析线程触发背压等待，暂停读取日志，防止内存撑爆。

---

### 5.3 共享节点并发锁冲突与指数退避重试算法

- **冲突机理**：多台主机或并发工作流向 Neo4j 写入横向移动流量时，会同时尝试 `MERGE` 相同的升序 `:Network` 节点，导致 Neo4j 事务引擎抛出独占写锁竞争异常：`TransientTransactionFailureException: LockAcquisitionTimeout`。
- **指数退避重试标准算法**：
  1. 遇到锁竞争异常时，严禁立即崩溃，捕获异常并启动自旋重试；
  2. **最大重试次数**：固定为 **5 次**；
  3. **退避间隔（带随机扰动 Jitter）**：
     - 第 1 次：$100\text{ms} \pm 20\text{ms}$
     - 第 2 次：$200\text{ms} \pm 40\text{ms}$
     - 第 3 次：$400\text{ms} \pm 80\text{ms}$
     - 第 4 次：$800\text{ms} \pm 160\text{ms}$
     - 第 5 次：$1600\text{ms} \pm 320\text{ms}$
  4. 若 5 次重试均失败，触发阻断机制，输出详细冲突节点主键并安全停止解析。

---

### 5.4 输入输出守恒平衡审计表（独立可验证法定律）

遵循《通用工程四法则》第三条“独立可验证法则”，解析器退出时**必须打印并验证平衡审计自检天平**：

$$\mathbf{N_{\text{total}}} \equiv \mathbf{N_{\text{edges}}} + \mathbf{N_{\text{handle}}} + \mathbf{N_{\text{attr\_update}}} + \mathbf{N_{\text{namespace}}} + \mathbf{N_{\text{pruned}}} + \mathbf{N_{\text{evicted}}}$$

| 审计记账分类变量 | 物理含义与统计范围 |
|---|---|
| **$N_{\text{total}}$** | 输入原始日志总行数（由适配器严格累计）。 |
| **$N_{\text{edges}}$** | 成功生成并写入 Neo4j 物理图边的事件总数（涵盖 28 类因果建边事件，含流式折叠内的微观累加操作数）。 |
| **$N_{\text{handle}}$** | 在内存中消化用于维护 FD / Handle 表的非边事件数（方案一严格 6 类：`OPEN`, `CLOSE`, `DUP`, `FCNTL`, `READ_SOCKET_PARAMS`, `WRITE_SOCKET_PARAMS`）。 |
| **$N_{\text{attr\_update}}$** | 转换为节点内部属性增量更新的非边事件数（方案二严格 6 类：`CHANGE_PRINCIPAL`, `LOGCLEAR`, `INIT_MODULE`, `FINIT_MODULE`, `MODIFY_PROCESS`, `ADD_OBJECT_ATTRIBUTE`）。 |
| **$N_{\text{namespace}}$** | 全局命名空间与服务管理事件数（方案三严格 4 类：`MOUNT`, `UMOUNT`, `SERVICEINSTALL`, `STARTSERVICE`）。 |
| **$N_{\text{pruned}}$** | 按规则显式记账丢弃的高频元数据与框架标记事件数（方案四严格 12 类：`CHECK_FILE_ATTRIBUTES`, `LSEEK`, `WAIT`, `BOOT`, `LOGIN`, `LOGOUT`, `UNIT`, `CORRELATION`, `BLIND`, `UPDATE`, `OTHER`, `FLOWS_TO`）。 |
| **$N_{\text{evicted}}$** | 因配对超时、句柄超限或野指针逃生丢弃的异常事件数。 |

- **差额为零准则**：
  若等式两端存在任何不平衡（$N_{\text{diff}} = |N_{\text{total}} - \sum N_{\text{parts}}| > 0$），解析器直接在控制台输出红色错误警报，**禁止宣称解析成功**，必须提供每项分类的具体行号区间以供溯源。

---

## 六、 项目工程模块实现与落地结构清单

根据四大正交支柱设计，TraceSage 项目主干代码（位于 [`scap-parser/parsers/`](file:///E:/Work/TraceSage/scap-parser/parsers/)）在实现时形成以下清晰的模块结构：

```text
scap-parser/parsers/
├── config.py                 # 全局配置（连接串、批量大小、容忍超时等）
├── reporting.py              # [支柱四] 平衡审计表与进度打印器
├── model/                    # [支柱一] 图模式实体与边对象
│   ├── entities.py           # Process, FileEntity, NetworkEntity, RegistryEntity
│   └── event_edge.py         # EventEdge（含 7 类关系类型与通用属性）
├── adapters/                 # [支柱二] 多源输入接入抽象层
│   ├── base.py               # LogStreamSource 接口契约
│   ├── sysdig_scap.py        # Linux Sysdig SCAP 适配器
│   ├── linux_auditd.py       # Linux Auditd 文本流适配器
│   ├── windows_sysmon.py     # Windows Sysmon XML/JSON 适配器
│   └── cdm_avro.py           # DARPA TC CDM 官方 Avro/JSON 流适配器
├── dispatch/                 # [支柱二] 56 类事件一站式分发矩阵
│   ├── dispatcher.py         # EventDispatcher 核心路由分发器
│   └── syscall_matrix.py     # 28 建边 / 7 句柄 / 7 属性 / 14 剪枝权威字典
├── state/                    # [支柱三] 内存因果状态机与防 OOM 控制
│   ├── context_machine.py    # 状态机门面（统管配对与句柄）
│   ├── pairing_buffer.py     # TID 独立系统调用配对池（含 10 万条容量硬上限）
│   ├── fd_table.py           # PID 共享文件描述符表（含 4096 容量硬上限）
│   └── registry_table.py     # Windows 注册表句柄表
└── storage/                  # [支柱四] 持久化图管道与 Neo4j 驱动
    ├── aggregator.py         # 滑动保序因果边微观流式折叠器
    ├── incident_filter.py    # 边端点存活过滤器（防孤立节点写入）
    └── neo4j_writer.py       # 双阶段事务写入驱动与指数退避重试引擎
```

---

### 规范结语与实施准则

本规范将多系统通用日志解析器的**静态数据模型、多源事件分发矩阵、内存因果状态机以及图存储写入管道**严格解耦为四大正交支柱，并在代码微观层面彻底解决了孤立节点截断、失败调用处理、Windows 双边裂变、多线程 FD 共享、在途实体懒加载与滑动聚合保序这 6 大关键难题。

编写代码时，开发人员必须严格遵循本规范中的判定口径与常量约束，严禁随意发明未定义的边类型或属性，确保解析器一次性高质量闭环交付！
