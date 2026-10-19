# TraceSage 全平台图建模与多系统通用日志解析器架构设计总规范 (Unified Master Specification)

> **文档状态**：正式发布 / 架构基线（全系统单一权威真源 Single Source of Truth）  
> **制定依据**：基于 DARPA Transparent Computing CDM 20 规范、Linux 内核系统调用接口、Windows ETW / Sysmon 审计规范与分布式因果溯源图理论。  
> **工程法则**：严格遵守《AGENTS.md》四大通用工程法则（声明边界法则、阻断诚实法则、独立可验证法则、真实绝对压倒形式法则）。  
> **公理理论依据**：因果建模底层元公理与十六项物理工程规矩，严格遵循 👉 [`docs/PROVENANCE_GRAPH_MODELING_AXIOMS.md`](file:///E:/Work/TraceSage/docs/PROVENANCE_GRAPH_MODELING_AXIOMS.md)。

---

## 目录
1. [第一章：系统定位与四大正交支柱设计哲学](#第一章系统定位与四大正交支柱设计哲学)
   - 1.1 系统定位与核心使命
   - 1.2 四大正交支柱全景数据流
   - 1.3 双平面架构：多主机环境物理隔离与横向移动自然缝合
2. [第二章：支柱一：图数据模式与静态约束规范](#第二章支柱一图数据模式与静态约束规范)
   - 2.1 实体无损压缩：4 类物理顶点表示 CDM 9 类实体
   - 2.2 四类物理顶点的复合主键与完整强约束属性字典
   - 2.3 四类操作系统日志源保真度与推导核对矩阵 (Fidelity Matrix)
   - 2.4 七类因果边的拓扑连接与强约束属性字典
   - 2.5 边端点存活过滤公理 (Orphan Pruning Protocol)
3. [第三章：支柱二：多源接入与事件全景分发矩阵](#第三章支柱二多源接入与事件全景分发矩阵)
   - 3.1 多源探针接入抽象层 (`LogStreamSource` 与 `RawLogRecord`)
   - 3.2 56 类全量事件一站式权威分发矩阵
   - 3.3 失败系统调用（`retval < 0`）与数据流未遂判定口径
   - 3.4 Windows `ProcessCreate`（Event ID 1）的“一步双边”复合裂变规约
4. [第四章：支柱三：内存因果状态机与防 OOM 机制](#第四章支柱三内存因果状态机与防-oom-机制)
   - 4.1 线程（TID）配对池与进程（PID）句柄表的内核级分离准则
   - 4.2 句柄状态表全生命周期追踪与 `CLOEXEC` 自动注销
   - 4.3 在途未知实体的懒加载机制
   - 4.4 内存硬上限与 LRU 逃生机制 (防 OOM 规范)
5. [第五章：支柱四：持久化图管道与守恒审计体系](#第五章支柱四持久化图管道与守恒审计体系)
   - 5.1 严格滑动保序因果边微观流式折叠公理
   - 5.2 Neo4j 双阶段批量写入管线与背压流控
   - 5.3 共享节点并发锁冲突与 5 次指数退避重试算法
   - 5.4 输入输出守恒平衡审计表（物理守恒数学天平）
6. [第六章：内容三元组硬件抽象层（HAL）与上层算法零破坏兼容](#第六章内容三元组硬件抽象层hal与上层算法零破坏兼容)
   - 6.1 三元组统一规范与典型攻防场景对照表
   - 6.2 既有代码适配改动清单
7. [第七章：系统方案深度客观评价与三大物理边界声明](#第七章系统方案深度客观评价与三大物理边界声明)
   - 7.1 核心架构优势
   - 7.2 技术局限性与物理边界声明（诚实报告）
8. [第八章：项目工程模块实现与落地结构清单](#第八章项目工程模块实现与落地结构清单)

---

# 第一章：系统定位与四大正交支柱设计哲学

## 1.1 系统定位与核心使命
在现代主机与网络攻击溯源（Attack Provenance）系统中，图数据库是承载操作系统系统调用事件流（Sysdig SCAP、Linux Auditd、Windows ETW/Sysmon、FreeBSD OpenBSM、Android ClearScope）的核心载体。美国国防高级研究计划局（DARPA）透明计算项目（Transparent Computing, TC）提出的通用数据模型（Common Data Model, 简称 CDM）是目前学术界与工业界最公认的溯源因果标准。

然而，**CDM 原始设计是面向流式传输的平面对象规范（Avro Record），不能未经改造直接作为属性图（Property Graph）节点入库**。机械地将 CDM 的 9 类实体建为顶点，不仅会导致模式膨胀，更会引发致命的**「超节点爆炸（Supernode Explosion）」**与**「无意义图遍历坍缩」**。

本系统是 TraceSage 威胁溯源体系的**数据接入与图构建核心引擎**。其核心使命是：接收来自底层探针的事件流，通过流式事件驱动与内存状态追踪，无损构建出紧凑、统一的因果溯源属性图并存入 Neo4j 图数据库。

系统严格贯彻以下核心哲学：
1. **4 类物理顶点 + 7 类因果边**：从 DARPA TC CDM 规范的 9 类实体中消除超级节点，将模型高度收敛为 4 类物理顶点（`:Process`, `:File`, `:Network`, `:Registry`）与 7 类有向因果边（`p2p`, `p2f`, `f2p`, `p2n`, `n2p`, `p2r`, `r2p`）。
2. **主机命名空间属性化**：主机（`Host`）不作为图顶点，而是作为全图所有实体的主键前缀与分区属性（`host_id`），彻底绝杀因主机顶点出入度破百万而导致的图遍历崩溃。
3. **全平台客体无损收敛**：对异构系统的专有客体（如 Windows 注册表、Android 传感器与 Binder 通信、Linux/BSD 管道）建立严格的无损映射，统一归纳于 4 类顶点中。
4. **四大正交支柱架构**：将解析器内部严格划分为四个单一职责、彼此正交的工程支柱，杜绝逻辑耦合与状态碎片化。

---

## 1.2 四大正交支柱全景数据流

```text
 原始审计日志流 (Linux SCAP / Auditd / Windows Sysmon EVTX / JSONL)
                               │
                               ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 【支柱二：多源接入与事件全景分发矩阵】                                 │
 │  1. 抽象接入适配器 (LogStreamSource) 统一转换为 RawLogRecord           │
 │  2. 56 类事件一站式判定：28 类因果边 / 6 类句柄 / 6 类属性 / 16 类剪枝 │
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

## 1.3 双平面架构：多主机环境物理隔离与横向移动自然缝合

### 1. 为什么 `Host` 绝不能在图中作为独立顶点？
在图论和图数据库工程中，**超级节点（Supernode）是深度图遍历（DFS、BFS、最短路径、随机游走）的头号杀手**。
- 如果将每台物理机/虚拟机建一个 `(:Host)` 顶点，单台主机在 1 小时内产生数万个进程、数万个文件；
- 所有这些进程和文件如果通过边（如 `[:RUNS_ON]`）连到该 `Host` 节点，这个节点的入度将迅速达到 **$10^5 \sim 10^7$**；
- 当 `provenance-navigator` 或 `provenance-agent` 从某个受感染的文件或进程进行反向因果追溯时，一旦搜索逻辑扫到该 `Host` 节点，Neo4j 会瞬间展开上百万个邻居，导致**内存耗尽（OOM）或查询超时（Query Timeout）**。

### 2. 双平面架构机制
我们采用**逻辑管理平面**与**因果数据流平面**分离的设计：
- **管理平面**：通过属性检索 `WHERE node.host_id = "host-01"` 快速做数据分片、主机级威胁评分汇总或租户隔离；
- **因果平面**：所有图遍历算法严格只在因果数据流平面运行。两台主机之间的跨主机横向移动（Lateral Movement），天然通过共享的 `:Network` 节点形成因果闭环。

```text
【主机 A: host-192-168-1-10】                        【主机 B: host-192-168-1-20】
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│         :Process 节点           │                 │         :Process 节点           │
│ host_id: "host-192-168-1-10"    │                 │ host_id: "host-192-168-1-20"    │
│ name: "ssh"                     │                 │ name: "sshd"                    │
│ pid: 4512                       │                 │ pid: 9102                       │
└────────────────┬────────────────┘                 └────────────────▲────────────────┘
                 │                                                   │
                 │ [:p2n]                                            │ [:n2p]
                 │ action: "EVENT_CONNECT"                           │ action: "EVENT_ACCEPT"
                 │ syscall: "connect"                                │ syscall: "accept"
                 ▼                                                   │
         ┌───────────────────────────────────────────────────────────────┐
         │                         :Network 节点                         │
         │          192.168.1.10:45210 <───> 192.168.1.20:22             │
         │          protocol: "tcp"                                      │
         └───────────────────────────────────────────────────────────────┘
```

#### 跨主机攻击路径回溯推演验证：
1. 分析员在主机 B 上发现异常子进程 `bash (pid 9150)`；
2. 反向追溯 `[:p2p]` 找到父进程 `sshd (pid 9102)`；
3. 反向追溯 `[:n2p]` 找到入站网络流 `192.168.1.10:45210 <-> 192.168.1.20:22`；
4. 继续反向追溯 `[:p2n]`，直接跳入主机 A 的客户端进程 `ssh (pid 4512)`；
5. 继续追溯主机 A 上谁执行了 `ssh` 密码喷洒脚本。
- **整个横向移动回溯全流程顺畅无阻，节点数严格保持在 4 类，查询不经过任何超级节点**。

---

# 第二章：支柱一：图数据模式与静态约束规范

## 2.1 实体无损压缩：4 类物理顶点表示 CDM 9 类实体

CDM 20 规范中定义了 9 类核心实体对象（Subject, FileObject, NetFlowObject, RegistryKeyObject, Host, Principal, MemoryObject, IpcObject, Packet）。本设计通过**实体映射**、**属性内嵌**与**边语义化**将其完整、无损地投影到 4 类物理图节点上：

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        4 类物理图节点 (Vertex)                         │
├───────────────┬────────────────┬─────────────────┬─────────────────────┤
│  1. :Process  │    2. :File    │   3. :Network   │    4. :Registry     │
│  (执行主体)   │ (存储/IPC载体) │  (网络端点/流)  │ (Windows配置单元)   │
└───────┬───────┴────────┬───────┴────────┬────────┴──────────┬──────────┘
        │                │                │                   │
  [吸收 Principal]  [吸收 IpcObject]  [吸收 Packet]           │
  (内嵌为属性)      (统一为文件路径)  (内嵌为流属性)          │
        │                │                │                   │
        └────────────────┼────────────────┼───────────────────┘
                         ▼
        ┌─────────────────────────────────────────────────────────┐
        │ [吸收 Host]：作为所有节点的主键前缀与分区属性 (node.host_id)│
        │ [吸收 MemoryObject]：转化为 :Process 间的 p2p 内存注入边│
        └─────────────────────────────────────────────────────────┘
```

### 5 类 CDM 实体的无损吸收与证明表

| 被吸收的 CDM 实体 | 图工程落地形态 | 无损证明与技术机理 |
|---|---|---|
| **`Host` (主机)** | **所有节点的前缀主键与 `node.host_id` 属性** | **避免百万度超级节点崩溃**。主机本身不主动产生系统调用，它是一个物理边界。将 `host_id` 注入每个节点，既保留了全图的主机切片能力（`WHERE node.host_id = ...`），又杜绝了遍历算法陷入 Host 超节点的灾难。 |
| **`Principal` (凭证)** | **内嵌为 `:Process` 与 `:File` 的身份属性** | 用户的权限（UID, GID, euid, SID, integrity_level）必须依附于运行态进程或静态文件才能发挥作用。分析提权攻击只需检查 `p.euid != p.ruid` 或 Windows Token 变化，信息完全保全，省去无谓的跨节点跳转。 |
| **`IpcObject` (管道)** | **统一收敛为 `:File` 节点** | Linux 的匿名管道（`pipe:[inode]`）、命名管道（FIFO）与 UNIX Domain Socket，在操作系统内核 VFS 中全都是以文件描述符（FD）和 Inode 呈现。采用统一的文件读写边（`p2f` / `f2p`）表达 IPC 因果，完全符合信息流动模型。 |
| **`MemoryObject` (内存)** | **转化为 `:Process` 间的 `p2p` 内存注入边与状态** | 虚拟内存段是进程内部易失空间。威胁建模真正关心的不是内存块本身，而是「攻击者进程通过何种系统调用污染了受害者进程的内存」。直接投影为 `p2p {action: 'EVENT_WRITE_PROCESS_MEMORY'}` 或自身的 `p2p {action: 'EVENT_MPROTECT'}`，语义更直接精准。 |
| **`Packet` (网络报文)** | **内嵌为 `:Network` 节点与连接边的流量属性** | 系统调用审计的职责是因果可达性而非全流量抓包重组。报文大小、传输字节数、关键 TCP 标志位直接写在 `p2n` / `n2p` 边的 `bytes` 与 `flags` 属性中，完全满足通信特征分析。 |

---

## 2.2 四类物理顶点的复合主键与完整强约束属性字典

#### (1) `:Process` 顶点（承载 CDM `Subject`，活动计算主体）
*   **概念定义**：操作系统中执行代码与系统调用的唯一动态活动主体（包含普通用户进程与内核守护线程）。
*   **复合主键（唯一标识）**：`{host_id}:{pid}:{start_time_ns}`。
    *   *未捕获启动时间口径*：若进程在日志捕获前已在系统常驻运行（中途接入），`start_time_ns` 严格固定为 `0`，禁止填充随机数。
    *   *Execve 镜像突变分裂原则*：以 `fork` 或 `execve` 发生的时刻作为阶段起点。当进程调用 `execve` 载入全新二进制镜像时，物理上封闭旧阶段节点，分裂出全新的进程节点，并建立 `[:p2p {syscall: "execve"}]` 因果边相连，彻底杜绝主体人格重塑造成的因果混淆。
*   **通用强约束属性字典**：
    *   `process_id` (string, 必须): 节点唯一主键属性，值为 `{host_id}:{pid}:{start_time_ns}`。
    *   `host_id` (string, 必须): 所在物理机/虚拟机唯一标识。
    *   `pid` (int/long, 必须): 操作系统分配的进程 ID。
    *   `name` (string, 必须): 进程可执行文件短名称（例如 `bash`, `cmd.exe`）。
    *   `exe_path` (string, 必须): 二进制映像文件的绝对规范路径（L2 束聚合第一主键）。
    *   `cmdline` (string, 必须): 进程启动时的完整命令行参数（大模型战术载荷分析核心）；若无参数则存为空字符串 `""`。
    *   `cwd` (string, 必须): 进程当前工作目录路径（相对路径转绝对路径前置必要参数）。
    *   `start_time_ns` (long, 必须): 进程本阶段启动的 Unix 纳秒时间戳（未捕获填 `0`）。
    *   `end_time_ns` (long, 可选): 进程退出时的纳秒时间戳（划定生命周期窗口，未退出则为 null）。


#### (2) `:File` 顶点（承载 CDM `FileObject`，持久化客体与 IPC 通道）
*   **概念定义**：持久化文件、目录、特殊设备节点、管道以及遵循 VFS（虚拟文件系统）抽象的一切数据存储/流转客体。
*   **复合主键（唯一标识）**：`{host_id}:{path}`（规范化绝对路径，跨平台 100% 具备）。
*   **通用强约束属性字典**：
    *   `file_id` (string, 必须): 节点唯一主键属性，值为 `{host_id}:{path}`。
    *   `host_id` (string, 必须): 所在主机唯一标识。
    *   `path` (string, 必须): 规范化绝对路径。路径分隔符统一强制使用正斜杠 `/`；Windows 盘符必须小写化（例如 `c:/windows/system32/kernel32.dll`），杜绝大小写分裂。
    *   `file_type` (string, 必须): ★ **唯一新增文件通用实体子类型**，取值范围：`regular`（普通文件）、`directory`（目录）、`pipe`（匿名/命名管道）、`socket`（UNIX 域套接字文件）、`char`（字符设备）、`block`（块设备）、`android_resource`（Android 专有资源）。
        *   *IPC 管道命名收敛规约*：Linux/BSD 匿名管道统一命名为 `pipe:[<inode>]`；Windows 命名管道统一命名为 `//./pipe/<name>`。
        *   *Android 专有客体 (`SrcSinkObject`) 收敛规约*：Android 平台特有的硬件传感器（GPS、陀螺仪、摄像头、麦克风等）与系统组件资源（Binder 进程间通信、剪贴板、SMS 短信），统一无损收敛为 `:File` 顶点：
            - 底层设备节点统一命名为 `/dev/binder`, `/dev/sensors/<type>`, `/dev/video*`；
            - 框架层服务汇统一命名为 `android://service/<name>`（如 `android://service/clipboard`, `android://sensor/gps`）；
            - 读写传感器或发起 Binder 调用，天然对应 `p2f` 与 `f2p` 边，无需膨胀出额外实体。

#### (3) `:Network` 顶点（承载 CDM `NetFlowObject`，网络通信会话）
*   **概念定义**：网络通信端点与会话流对象。
*   **复合主键（唯一标识）**：`{protocol}:{lower_ip}:{lower_port}<->{upper_ip}:{upper_port}`。
    *   *升序自然序对齐算法*：为保证通信双方（无论客户端还是服务端先发起）都能唯一收敛至同一节点，IP 与端口按自然字典序升序排列（`lower <= upper`），端点采用对称中立命名，真实的发起方向与数据流向完全由边方向与系统调用（`connect` vs `accept`）表达。
*   **通用强约束属性字典**：
    *   `network_id` (string, 必须): 节点唯一主键属性，值为 `{protocol}:{lower_ip}:{lower_port}<->{upper_ip}:{upper_port}`。
    *   `protocol` (string, 必须): 传输层协议，取值：`tcp`, `udp`。
    *   `src_address` (string, 必须): 升序对齐较小端 IP 地址。
    *   `src_port` (int, 必须): 升序对齐较小端端口号。
    *   `dst_address` (string, 必须): 升序对齐较大端 IP 地址。
    *   `dst_port` (int, 必须): 升序对齐较大端端口号。

#### (4) `:Registry` 顶点（承载 CDM `RegistryKeyObject`，Windows 专有配置项）
*   **概念定义**：Windows 操作系统专有的配置项，颗粒度精确下沉至 Key-Value 原子项（非 Windows 系统数量自然为 0）。
*   **复合主键（唯一标识）**：`{host_id}:{key_path}\{value_name}`。
    *   *原子化键值规约*：每个具体的值项独立建模为顶点（若操作键本身则 `value_name` 填 `(Default)`），彻底杜绝合法程序与后门写入同一注册表键（如 `Run`）引发的配置读写交叉污染与超节点。
*   **属性字典与约束（Windows 专属节点）**：
    *   `reg_id` (string, 必须): 节点唯一主键属性，值为 `{host_id}:{key_path}\{value_name}`。
    *   `host_id` (string, 必须): 所在主机唯一标识。
    *   `key_path` (string, 必须): 注册表子键路径，层级使用反斜杠 `\` 分隔（如 `Software\Microsoft\Windows\CurrentVersion\Run`）。
    *   `value_name` (string, 必须): 具体注册表项名称（如 `Backdoor`）。
    *   `data` (string, 可选): 写入或读取的具体配置内容/载荷数据（大模型判定持久化武器的核心依据）。

---

## 2.3 四类操作系统日志源保真度与推导核对矩阵 (Fidelity Matrix)

为保证全平台图数据模型在工程落地时严格遵循《声明边界法则》与《阻断诚实法则》，杜绝任何不可落地的私有假设，下表对 **Linux (Sysdig/Auditd)、FreeBSD (OpenBSM)、Windows (Sysmon/ETW)、Android (ClearScope)** 四大类日志源的全部属性存在性与推导规约进行穷举核定：

| 实体分类 | 属性名称 | Linux (Sysdig/Auditd) | FreeBSD (OpenBSM) | Windows (Sysmon/ETW) | Android (ClearScope) | 跨平台推导与保真度规约 |
|---|---|---|---|---|---|---|
| **:Process** | `process_id` | 原生具备 (`host:pid:start`) | 原生具备 (`host:pid:start`) | 原生具备 (`ProcessGuid`) | 原生具备 (`host:pid:start`) | 复合键全局唯一，execve 发生时执行分裂 |
| | `host_id` | 解析层注入 | 解析层注入 | 解析层注入 | 解析层注入 | 全局命名空间属性，界定多主机边界 |
| | `pid` | 原生具备 | 原生具备 | 原生具备 | 原生具备 | 操作系统原生数字进程号 |
| | `name` | 原生具备 (`comm`) | 原生具备 | 原生具备 (`Image` 文件名) | 原生具备 | 快速程序短名索引 |
| | `exe_path` | 原生具备 (绝对规范路径) | 原生具备 | 原生具备 (`Image` 全路径) | 原生具备 | L2 束聚类第一主键 |
| | `cmdline` | 原生具备 (`args`) | 原生具备 (`exec_args`) | 原生具备 (`CommandLine`) | 原生具备 | 大模型战术意图与载荷分析核心线索 |
| | `cwd` | 原生具备 (`proc.cwd`) | 原生具备 (Audit Context) | 原生具备 (`CurrentDirectory`) | 原生具备 | 相对路径转绝对路径前置参数，识别暂存落地点 |
| | `start_time_ns` | 原生纳秒级时间戳 | 原生纳秒级时间戳 | 原生 UTC 时间戳 (100ns) | 原生时间戳 | 统一转换为 Unix Epoch 纳秒时间戳 |
| | `end_time_ns` | 原生退出时间戳 | 原生退出时间戳 | 原生 Event 5 退出时间戳 | 原生退出时间戳 | 划定生命周期窗口，未退出填 null |
| **:File** | `file_id` / `path` | 原生规范绝对路径 | 原生规范绝对路径 | 原生规范绝对路径 | 原生规范绝对路径 | 统一格式化为绝对路径，保持路径主键 |
| | `file_type` | 原生具备 (`file/pipe/sock`) | 原生具备 (Vnode Type) | 推导 (普通文件/`\pipe\`) | 原生具备 | 区分存储文件与本地 IPC 管道 |
| **:Network** | `network_id` | 原生五元组 | 原生 Socket Token | 原生 Event 3 四元组 | 原生网络四元组 | 升序算法归一化：`proto:lower<->upper` |
| | `protocol` | 原生具备 (`tcp/udp`) | 原生具备 | 原生具备 | 原生具备 | 传输层协议 |
| | `src_address`, `src_port` | 原生具备 | 原生具备 | 原生具备 | 原生具备 | 自然升序对齐较小端点，对称中立命名 |
| | `dst_address`, `dst_port` | 原生具备 | 原生具备 | 原生具备 | 原生具备 | 自然升序对齐较大端点，对称中立命名 |
| **:Registry** | `reg_id` / `key_path` / `value_name` / `data` | 不适用 (NULL) | 不适用 (NULL) | 原生 Event 12/13/14 | 不适用 (NULL) | Windows 专属原子项，直接搭载载荷数据 |
| **因果边** | `event_id` | 原生全局事件序号 | 原生 Audit 序列号 | 原生 Record ID / 哈希 | 原生事件序号 | Neo4j 唯一约束去重与幂等导入 |
| | `action` | 映射标准枚举名 | 映射标准枚举名 | 映射标准枚举名 | 映射标准枚举名 | 对齐 CDM 28 类因果动作标准大写枚举 |
| | `syscall` | 原生系统调用名 | 原生 BSM 操作名 | 原生 Sysmon 动作名 | 原生操作名 | 字典映射为统一小写标准动作名 |
| | `start_time_ns` | 原生纳秒时间戳 | 原生纳秒时间戳 | 原生 UTC 时间戳 (100ns) | 原生时间戳 | 因果偏序单调性检查硬判据 ($T_1 \le T_2$) |
| | `end_time_ns` | 原生退出时间戳 | 原生退出时间戳 | **推导: 赋值等于 start_time_ns** | 原生退出时间戳 | Sysmon 等单点事件安全折叠为点事件 |
| | `bytes` | 原生 I/O 字节数 | 原生 Return Token 字节 | **推导: 赋值 -1 (未知)** | 原生 I/O 字节数 | 三态吞吐：>0 实测，==0 空读剪枝，-1 跳过剪枝 |
| | `status` | 原生返回值 (0/>0) | 原生错误码 (0/>0) | **推导: 默认赋值 0 (成功)** | 原生返回值 (0/>0) | 只有成功边传递数据流污点，失败边阻断扩散 |
| *(调用可选)* | `old_path` | 原生具备 (rename 事件) | 原生具备 | 原生具备 (Event 2 目标名) | 原生具备 | 仅 rename 文件重命名边具备 |
| *(调用可选)* | `sig` | 原生具备 (kill 信号) | 原生具备 | 原生具备 | 原生具备 | 仅 kill 异步信号边具备 |


---

## 2.4 七类因果边的拓扑连接与强约束属性字典

图数据库中物理持久化的边严格限定为以下 7 种类型，其端点连接类型固定不变：

| 边类型标识 | 起点实体 (Source Node) | 终点实体 (Sink Node) | 物理因果语义 | 典型覆盖事件与系统调用 |
|:---:|:---:|:---:|---|---|
| **`p2p`** | `:Process` | `:Process` | 进程间控制流转移、派生、信号、内存注入与保护变更 | `FORK`, `CLONE`, `EXECUTE`, `EXIT`, `CREATE_THREAD`, `SIGNAL`, `MPROTECT` |
| **`p2f`** | `:Process` | `:File` | 进程对文件的写入、创建、重命名、截断、删除、权限变更及管道零拷贝 | `WRITE`, `CREATE_OBJECT`, `RENAME`, `TRUNCATE`, `UNLINK`, `LINK`, `MODIFY_FILE_ATTRIBUTES`, `SPLICE`, `TEE`, `VMSPLICE`, `SHM` |
| **`f2p`** | `:File` | `:Process` | 进程从文件读取载荷、映射虚存、载入共享库及管道零拷贝流动 | `READ`, `MMAP`, `LOADLIBRARY`, `EXECUTE`, `SPLICE`, `TEE`, `SHM` |
| **`p2n`** | `:Process` | `:Network` | 进程向网络端点发起主动连接、发送报文或绑定本地监听端点 | `CONNECT`, `BIND`, `SENDTO`, `SENDMSG` |
| **`n2p`** | `:Network` | `:Process` | 本地进程接受入站连接或从网络端点接收外部数据报文 | `ACCEPT`, `RECVFROM`, `RECVMSG` |
| **`p2r`** | `:Process` | `:Registry` | Windows 进程创建注册表键项或写入注册表键值配置 | `CREATE_OBJECT`, `WRITE` (`RegCreateKey`, `RegSetValue`) |
| **`r2p`** | `:Registry` | `:Process` | Windows 进程读取注册表键项值或系统配置数据 | `READ` (`RegQueryValue`) |

#### 通用强约束边属性字典（7 类边通用，共 7 项）
*   `event_id` (long/string, 必须): 图内全局递增的唯一事件流水号，用于幂等写入与边更新。
*   `action` (string, 必须): 规范化因果动作枚举名（对齐 CDM 28 类因果动作，例如 `EVENT_WRITE`, `EVENT_CLONE`）。
*   `syscall` (string, 必须): 操作系统原生系统调用或审计事件名（例如 `write`, `execve`, `RegSetValueEx`）。
*   `start_time_ns` (long, 必须): 系统调用进入或事件发生的 Unix 纳秒时间戳。
*   `end_time_ns` (long, 必须): 系统调用退出或连接终止的 Unix 纳秒时间戳（瞬时单点事件时等于 `start_time_ns`）。
*   `bytes` (long, 必须): 传输数据载荷字节数。非数据传输类控制边（如 `fork`, `signal`）严格记为 `0`。**未知载荷存储为 `-1`**。
*   `status` (int, 必须): 系统调用执行结果码。0 为成功，正数为 errno。只有成功边传递污点，失败边阻断扩散。
*   *特定调用的可选字段（仅随特定系统调用入参产生，不设专用概念）*：
    *   `old_path` (string, 可选): 仅在 `rename` 文件重命名边上记录被改名的原绝对规范路径。
    *   `sig` (int, 可选): 仅在 `kill`/`signal` 异步信号边上记录信号编号（如 9 为 SIGKILL）。

#### 空值处理规范（Null-safe Protocol）
*   若原始日志未采集到某可选字段，向 Neo4j 传 `None`。Neo4j 底层直接不写入该属性键，不占用物理磁盘与内存空间。
*   **严禁在属性中写入 `"-1"`、`"UNKNOWN"`、`"N/A"` 或空字符串 `""` 伪装数据**。

---

## 2.5 边端点存活过滤公理 (Orphan Pruning Protocol)

在解析过程中，实体（进程、文件）会在最外层被初始化，但大量实体可能仅执行了无因果的只读探测（如 `stat`）后便退出，**从未参与过任何一条物理因果边的构建**。
*   **公理规约**：
    1. 解析器在内存中维护 `IncidentVertexKeys`（边端点存活集合）；
    2. 只有当某条因果边被正式生成并进入待写入队列时，才将其源节点与宿节点的主键加入该集合；
    3. 批量向 Neo4j 写入顶点时，**严格只提交存在于 `IncidentVertexKeys` 中的顶点**；
    4. 从未挂载任何边的孤立节点直接在内存中丢弃，**绝对禁止向数据库写入孤立节点**，保证整图的紧凑性与连通性。

---

# 第三章：支柱二：多源接入与事件全景分发矩阵

## 3.1 多源探针接入抽象层 (`LogStreamSource` 与 `RawLogRecord`)

定义统一的抽象接口，将不同操作系统的输入源统一解耦为标准化事件流：
1. **Linux Sysdig 适配器 (`sysdig_scap.py`)**：对接本地/远程子进程管道，读取 Sysdig 对二进制 `.scap` 文件流式解析吐出的 JSONL 文本行。
2. **Linux Auditd 适配器 (`linux_auditd.py`)**：流式读取 `/var/log/audit/audit.log` 文本行，按 `msg=audit(time.seq)` 合并多行记录。
3. **Windows Sysmon 适配器 (`windows_sysmon.py`)**：解析 Windows 事件日志导出流（XML 或 JSONL 格式），抽取 Event ID 与参数字段。
4. **DARPA TC CDM 官方适配器 (`cdm_avro.py`)**：直接反序列化符合 `TCCDMDatum.avsc` 规范的官方 Avro 二进制或 JSON 流。
5. **输出契约（`RawLogRecord`）**：所有适配器必须输出包含以下核心字段的统一内存结构：
   `RawLogRecord(host_id, timestamp_ns, event_name, pid, tid, raw_params, return_code, is_point_event=False)`。

---

## 3.2 56 类全量事件一站式权威分发矩阵

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

#### (2) 28 类非边事件四大精密工程处理方案（绝对不上图建边）
1. **方案一：内存句柄与虚拟状态追踪方案（6 类，纯内存消化）**：
   `EVENT_OPEN`（纯句柄绑定，因果严格递延）、`EVENT_CLOSE`（句柄注销）、`EVENT_DUP`（别名复制）、`EVENT_FCNTL`（提取 `F_DUPFD` 别名）、`EVENT_READ_SOCKET_PARAMS`（Socket 状态查询）、`EVENT_WRITE_SOCKET_PARAMS`（Socket 选项配置）。
2. **方案二：实体内部状态单向突变方案（6 类，转为 Cypher SET 属性，不建边）**：
   `EVENT_CHANGE_PRINCIPAL`（`SET p.euid = event.uid, p.is_elevated = true`）、`EVENT_LOGCLEAR`（`SET p.suspicious_tags = coalesce(p.suspicious_tags, []) + 'log_clear'`）、`EVENT_INIT_MODULE`（`SET p.loaded_modules = coalesce(p.loaded_modules, []) + module_name`）、`EVENT_FINIT_MODULE`（记录驱动加载）、`EVENT_MODIFY_PROCESS`（`SET p.comm_alias = new_name`）、`EVENT_ADD_OBJECT_ATTRIBUTE`（`SET f.has_ads = true`）。
3. **方案三：全局命名空间与服务管理方案（4 类，底层已有覆盖，不建独立边）**：
   `EVENT_MOUNT`、`EVENT_UMOUNT`、`EVENT_SERVICEINSTALL`（底层已被文件/注册表写边覆盖）、`EVENT_STARTSERVICE`（底层已被进程派生边覆盖）。
4. **方案四：纯框架插桩与显式记账剪枝方案（12 类，严格显式记账后丢弃）**：
   `EVENT_CHECK_FILE_ATTRIBUTES`（`stat` 高频探测，彻底消除超级节点）、`EVENT_LSEEK`（0 字节寻道）、`EVENT_WAIT`（刷新父进程活跃窗口后丢弃）、`EVENT_BOOT`、`EVENT_LOGIN`、`EVENT_LOGOUT`、`EVENT_UNIT`、`EVENT_CORRELATION`、`EVENT_BLIND`、`EVENT_UPDATE`、`EVENT_OTHER`、`EVENT_FLOWS_TO`。
   *   **零静默丢弃纪律（No Silent Drop）**：必须显式调用 `reporter.inc_pruned(event_name)` 累加计数，保证守恒审计天平 100% 平账。

---

## 3.3 失败系统调用（`retval < 0`）与数据流未遂判定口径
- **数据传输类调用（`read`, `write`, `recv`, `mmap`）**：
  若返回码 `retval < 0` 或实际传输载荷 `bytes == 0`，**绝对禁止建立物理数据流边**（防止污点分析严重误报）；记录为源进程节点的未遂属性：`SET p.failed_probes = coalesce(p.failed_probes, []) + '{action}:{target_path}'`。
- **网络连接调用（`connect`）**：
  若返回码 `< 0` 且不为 `EINPROGRESS`，**不建立 `p2n` 边**，记入 `failed_network_attempts`。

---

## 3.4 Windows `ProcessCreate`（Event ID 1）的“一步双边”复合裂变规约
当分发器接收到 Windows Sysmon Event ID 1 时，必须在同一事务中**裂变为两条原子图边**：
1. **控制流边 (`p2p`)**：`ParentProcess` $\xrightarrow{\text{EVENT\_FORK / action:'spawn'}}$ `CurrentProcess`；
2. **镜像加载边 (`f2p`)**：`ImageFile` $\xrightarrow{\text{EVENT\_EXECUTE / action:'load_image'}}$ `CurrentProcess`。
- 两条边继承相同的纳秒时间戳，确保 Windows 恶意二进制文件落地执行时，因果链路与 Linux 完全等价。

---

# 第四章：支柱三：内存因果状态机与防 OOM 机制

## 4.1 线程（TID）配对池与进程（PID）句柄表的内核级分离准则

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
   - 必须以 **`(host_id, tid)`** 为键，按具体线程隔离配对；
   - **时间容忍窗口**：设定为 **5 秒**。超过 5 秒未收到退出事件触发超时淘汰；
   - **单点事件直通**：若 `record.is_point_event == True`，直接跳过配对池直通分发器。
2. **句柄状态表（`ProcessFdTable`）**：
   - 必须以 **`(host_id, pid)`** 为键，同一进程内的所有线程完全共享同一份句柄表。

---

## 4.2 句柄状态表全生命周期追踪与 `CLOEXEC` 自动注销
1. **登记与继承**：`open` 成功登记句柄；`dup/fcntl` 建立别名；`fork/clone` 子进程深拷贝父进程句柄表；
2. **`execve` 裂变 `FD_CLOEXEC` 自动注销机制**：
   - 当收到 `execve` 成功事件时，状态机裂变出新进程节点；
   - **遍历旧进程句柄表，物理剔除所有打上 `O_CLOEXEC` 标记的句柄**，仅将未设置标记的继承句柄交接至新节点；
3. **注销与销毁**：`close` 安全移除该 fd；收到 `EVENT_EXIT` 时，**立即物理销毁该进程名下的整张句柄表**。

---

## 4.3 在途未知实体的懒加载机制
- 当事件中的 `(host_id, pid)` 在内存表中不存在时，解析器立即以当前日志行携带的进程元数据就地构造 `:Process` 实体；
- 启动时间戳统一赋默认值 `start_time_ns = 0`，并赋予布尔属性 `is_in_flight = true`，确保因果链不断裂。

---

## 4.4 内存硬上限与 LRU 逃生机制 (防 OOM 规范)
1. **全局配对池上限**：固定为 **100,000 条**。超限自动触发 LRU 淘汰最老未闭合记录，累加 `evicted_unpaired_events`；
2. **单进程持有句柄上限**：固定为 **4,096 个**；
3. **野指针保护**：遇到句柄表中不存在的未知 fd，累加 `unknown_fd_count`，放弃建边，杜绝脏节点写入。

---

# 第五章：持久化图管道与守恒审计体系

## 5.1 严格滑动保序因果边微观流式折叠公理
1. **折叠判据（必须 4 项全同）**：
   - 起始节点、终点节点、因果动作（`action`）、底层调用（`syscall`）完全相同；
   - `status` 执行结果状态码必须相同；
   - 两次调用的时间间隔 $\Delta t < 1 \text{ 秒}$。
2. **未知字节保护规约**：若待折叠边的 `bytes == -1`（未知），折叠后维持 `bytes = -1`，严禁代数累加产生负数脏值；
3. **严格滑动保序公理**：每个进程在内存中仅保留唯一活动的待折叠边槽位（`ActiveEdgeSlot`）；一旦切换操作客体或发生寻道，立即打断当前槽位推入队列，**严禁跨越其他客体的跳跃式合并**。

---

## 5.2 Neo4j 双阶段批量写入管线与背压流控
1. **两阶段提交管线（Two-Phase Flush Pipeline）**：
   - **阶段一（提交存活顶点）**：提取经过存活过滤的顶点集合，执行基于复合主键的 `MERGE` 批量写入，等待事务确认；
   - **阶段二（提交因果边）**：顶点确认落盘后，再执行边的批量写入（`MATCH` 两端主键，执行 `CREATE` 或 `MERGE` 边）。从拓扑底层确保边端点 100% 存在，彻底消灭外键孤儿边。
2. **批量阈值与背压流控**：
   - 默认缓冲区满 **10,000 条边** 或等待满 **500 毫秒** 触发一次提交；
   - 若异步写入队列积压超过 **5 个批次**，主解析线程触发背压等待，暂停读取日志。

---

## 5.3 共享节点并发锁冲突与 5 次指数退避重试算法
多主机并发写入 `:Network` 节点触发 `TransientTransactionFailureException: LockAcquisitionTimeout` 时，执行最多 **5 次带随机扰动（Jitter）的指数退避重试**：
$$100\text{ms} \pm 20\text{ms} \to 200\text{ms} \pm 40\text{ms} \to 400\text{ms} \pm 80\text{ms} \to 800\text{ms} \pm 160\text{ms} \to 1600\text{ms} \pm 320\text{ms}$$
若 5 次重试均失败，触发阻断机制并输出详细冲突节点主键。

---

## 5.4 输入输出守恒平衡审计表（物理守恒数学天平）
遵循《通用工程四法则》第三条“独立可验证法则”，解析器退出时**必须打印并验证平衡审计自检天平**：

$$\mathbf{N_{\text{total}}} + \mathbf{N_{\text{split\_bonus}}} \equiv \mathbf{N_{\text{edges}}} + \mathbf{N_{\text{handle}}} + \mathbf{N_{\text{attr\_update}}} + \mathbf{N_{\text{namespace}}} + \mathbf{N_{\text{pruned}}} + \mathbf{N_{\text{evicted}}}$$

| 审计记账分类变量 | 物理含义与统计范围 | Linux 实测口径 |
|---|---|---|
| **$N_{\text{total}}$** | 输入原始日志总行数（由适配器严格累计）。 | 原生日志行数 |
| **$N_{\text{split\_bonus}}$** | 复合事件双边裂变补偿项（Windows Event 1 启用）。 | Linux 恒为 0 |
| **$N_{\text{edges}}$** | 成功写入 Neo4j 图边的总事件数。 | 物理图边涵盖的原始调用数 |
| **$N_{\text{handle}}$** | 在内存中消化用于维护 FD / Handle 表的非边事件数（方案一严格 6 类）。 | `open`, `close`, `dup`, `fcntl` 等 |
| **$N_{\text{attr\_update}}$** | 转换为节点内部属性增量更新的非边事件数（方案二严格 6 类）。 | 提权、模块加载、进程重命名等 |
| **$N_{\text{namespace}}$** | 全局命名空间与服务管理事件数（方案三严格 4 类）。 | 挂载、卸载等 |
| **$N_{\text{pruned}}$** | 按规则显式记账丢弃的高频元数据与框架标记事件数（方案四严格 12 类）。 | `stat`, `lseek`, `wait` 等 |
| **$N_{\text{evicted}}$** | 因配对超时、句柄超限或野指针逃生丢弃的异常事件数。 | LRU 淘汰与野指针计数 |

- **差额为零准则**：若存在任何不平衡（$N_{\text{diff}} > 0$），解析器直接在控制台输出红色错误警报，**禁止宣称解析成功**。

---

# 第六章：内容三元组硬件抽象层（HAL）与上层算法零破坏兼容

TraceSage 上层组件（智能体、因果导航器、评测工具）均高度依赖 **内容三元组（Content Triple）** 作为抽象硬件接口：
$$\text{Content Triple} = \langle \text{Source Entity String}, \text{Normalized Action}, \text{Destination Entity String} \rangle$$

## 6.1 三元组在各场景下的统一生成规范

| 操作系统与攻击场景 | 物理图中的节点与边 | 投影输出的标准三元组 (Upper Layer Triple) |
|---|---|---|
| **Linux 勒索文件加密** | `(p:ransomware)-[:p2f {syscall: 'write'}]->(f:/data.enc)` | `(p:ransomware, write, f:/data.enc)` |
| **Linux 命名管道通信** | `(p:cat)-[:p2f {syscall: 'write'}]->(f:pipe:[1234])`, `(f:pipe:[1234])-[:f2p {syscall: 'read'}]->(p:grep)` | `(p:cat, write, f:pipe:[1234])`<br>`(f:pipe:[1234], read, p:grep)` |
| **Windows 注册表自启动**| `(p:cmd.exe)-[:p2r {syscall: 'reg_set_value'}]->(r:HKLM\...\Run\Backdoor)` | `(p:cmd.exe, reg_set_value, r:HKLM\...\Run\Backdoor)` |
| **Windows 跨进程内存注入**| `(p:mimikatz)-[:p2p {syscall: 'create_thread'}]->(p:lsass)` | `(p:mimikatz, create_thread, p:lsass)` |
| **跨主机横向移动 (A $\to$ B)** | **主机 A 端**：`(p:ssh)-[:p2n {syscall: 'connect'}]->(n:10.0.0.2:22)`<br>**主机 B 端**：`(n:10.0.0.2:22)-[:n2p {syscall: 'accept'}]->(p:sshd)` | `(p:ssh, connect, n:10.0.0.2:22)`<br>`(n:10.0.0.2:22, accept, p:sshd)` |

---

## 6.2 既有代码适配改动清单（改动行数 $\le 5$ 行）

由于边语义与实体类型被严格控制，已有代码只需要增加对 Windows 注册表边类型的枚举：
*   **[`provenance-agent/pagent/core/graph_facts.py`](file:///E:/Work/TraceSage/provenance-agent/pagent/core/graph_facts.py)**：
    ```python
    # 原查询：
    # MATCH (s)-[r:p2p|p2f|f2p|p2n|n2p]->(d)
    # 扩展支持 Windows 后的查询：
    # MATCH (s)-[r:p2p|p2f|f2p|p2n|n2p|p2r|r2p]->(d)
    ```
*   **[`provenance-navigator/rules/motifs.py`](file:///E:/Work/TraceSage/provenance-navigator/rules/motifs.py)**：子图模式挖掘逻辑完全无感知，由于注册表在拓扑上也是有向二部交互（Process $\leftrightarrow$ Registry），现有的 Motif 抽取器可直接复用。
*   **[`tools/eval_agent_attack_path.py`](file:///E:/Work/TraceSage/tools/eval_agent_attack_path.py)**：由于 groundtruth 评测脚本严格按照 `(src, syscall, dst)` 比对，只要解析器输出对齐的三元组，评测脚本无需任何修改。

---

# 第七章：系统方案深度客观评价与三大物理边界声明

## 7.1 核心架构优势
1.  **彻底绝杀了百万度超级节点（Supernode-Free）**：将 `Host` 与 `Principal` 属性化，使图数据库的平均节点出入度维持在 $3 \sim 8$ 的健康稀疏水平，保证了百万级事件规模下的毫秒级路径遍历性能；
2.  **全量覆盖 CDM 语义，无信息截断，根治依赖爆炸**：严格对照 CDM 20 规范建立了 28 类骨干因果建边 + 28 类轻量吸收的完整处理闭环。既无任何因果信息截断，又将无信息流的微调与伪事件拦截在内存层，切断图数据库的依赖爆炸；
3.  **异构混合系统的单库统一表达**：无论 Linux 主机还是 Windows 主机，日志均收敛到同一套数据模型中，复杂纵深攻击能够在同一图实例中实现无缝横向追溯。

---

## 7.2 技术局限性与物理边界声明（诚实报告）
依据项目最高准则《通用工程四法则》第一条“声明边界法则”，系统如实声明以下 3 项物理级不可见边界：
1.  **细粒度操作依赖边属性二次过滤**：由于 56 类细粒度事件被收敛到 7 类边类型上，边标签（Edge Label）粒度变粗（如 `p2f` 同时包含了写入、删除和权限修改）。针对特定动作的高频查询必须在 Neo4j 中为 `r.action` 建立属性索引；
2.  **物理级不可见无文件内存漏洞利用细节**：将 `MemoryObject` 扁平化意味着系统只能观察到跨进程系统调用（如 `process_vm_writev`）或权限修改（`mprotect`）。对于单个进程内部的 ROP 链拼接、堆喷射布局等纯用户态内存行为，主机内核系统调用审计图在物理上依然不可见；
3.  **孤立文件系统离线篡改因果断裂**：所有因果边均依附于运行态进程的主动行为。如果攻击者通过物理拔盘或关机状态下修改磁盘文件，由于缺少内核系统调用事件，因果链路必然发生物理阻断，系统只能如实报告无法回溯。

---

# 第八章：项目工程模块实现与落地结构清单

根据四大正交支柱设计，TraceSage 项目主干代码（位于 [`scap-parser/parsers/`](file:///E:/Work/TraceSage/scap-parser/parsers/)）在实现时形成以下清晰的模块结构：

```text
scap-parser/parsers/
├── config.py                 # 全局配置（连接串、批量大小、容忍超时等）
├── reporting.py              # [支柱四] 平衡审计表与进度打印器
├── model/                    # [支柱一] 图模式实体与边对象
│   ├── entities.py           # Process, FileEntity, NetworkEntity, RegistryEntity
│   └── event_edge.py         # EventEdge（含 7 类关系类型与通用属性）
├── adapters/                 # [支柱二] 多源输入接入抽象层
│   ├── base.py               # LogStreamSource 接口契约与 RawLogRecord
│   ├── sysdig_scap.py        # Linux Sysdig SCAP 适配器
│   ├── linux_auditd.py       # Linux Auditd 文本流适配器
│   ├── windows_sysmon.py     # Windows Sysmon XML/JSON 适配器
│   └── cdm_avro.py           # DARPA TC CDM 官方 Avro/JSON 流适配器
├── dispatch/                 # [支柱二] 56 类事件一站式分发矩阵
│   ├── dispatcher.py         # EventDispatcher 核心路由分发器
│   └── syscall_matrix.py     # 28 建边 / 6 句柄 / 6 属性 / 16 剪枝权威字典
├── state/                    # [支柱三] 内存因果状态机与防 OOM 控制
│   ├── context_machine.py    # 状态机门面（统管配对与句柄）
│   ├── pairing_buffer.py     # TID 独立系统调用配对池（含 10 万条容量硬上限）
│   ├── fd_table.py           # PID 共享文件描述符表（含 4096 容量硬上限与 CLOEXEC 注销）
│   └── registry_table.py     # Windows 注册表句柄表
└── storage/                  # [支柱四] 持久化图管道与 Neo4j 驱动
    ├── aggregator.py         # 滑动保序因果边微观流式折叠器
    ├── incident_filter.py    # 边端点存活过滤器（防孤立节点写入）
    └── neo4j_writer.py       # 双阶段事务写入驱动与指数退避重试引擎
```

---

### 规范结语与实施准则
本规范将多系统通用日志解析器的**静态数据模型、多源事件分发矩阵、内存因果状态机以及图存储写入管道**严格解耦为四大正交支柱，并完整收敛了 CDM 实体证明、双平面跨机回溯、HAL 三元组接口及四大操作系统保真度矩阵。开发人员编写代码时必须严格遵循本规范中的判定口径与常量约束，确保系统一次性高质量闭环交付！
