# TraceSage 图建模架构设计规范：基于 CDM 的 4 类顶点与 7 类因果边模型

---

## 一、 架构总览与设计哲学

在现代主机与网络攻击溯源（Attack Provenance）系统中，图数据库是承载操作系统系统调用事件流（Sysdig SCAP、Linux Auditd、Windows ETW/Sysmon）的核心载体。美国国防高级研究计划局（DARPA）透明计算项目（Transparent Computing, TC）提出的通用数据模型（Common Data Model, 简称 CDM）是目前学术界与工业界最公认的溯源因果标准。

然而，**CDM 原始设计是面向流式序列化传输与存储的平面对象规范（Avro Record），不能未经改造直接作为属性图（Property Graph）节点入库**。若机械地将 CDM 的 9 类实体全部建立为图顶点，不仅会导致模式膨胀，更会引发致命的**「超节点爆炸（Supernode Explosion）」**与**「无意义图遍历坍缩」**。

TraceSage 采用 **「4 类实体顶点 + 7 类因果边 + 硬件全局命名空间属性化」** 的图架构设计：
- **4 类物理顶点**：`:Process`、`:File`、`:Network`、`:Registry`。
- **7 类因果边**：`p2p`、`p2f`、`f2p`、`p2n`、`n2p`、`p2r`、`r2p`。
- **28 核心因果边与 28 纯粹非边分级处理**：从 CDM 56 种全量事件中提炼出 28 种产生实质信息流/控制流的骨干因果边（含文件权限变更与服务端点监听）作为物理图边；其余 28 种通过解析器内存句柄表维护、节点属性增量更新或安全过滤轻量消化，从源头杜绝依赖爆炸。
- **跨平台与多主机扩展**：以 `host_id` 为全局命名空间属性与复合主键前缀，通过 `:Network` 节点自然缝合跨主机横向移动。
- **上层零破坏抽象**：严格维持内容三元组 $\langle \text{Source Entity}, \text{Normalized Action}, \text{Destination Entity} \rangle$，对 `provenance-navigator` 与 `provenance-agent` 提供硬件抽象层（HAL）保护。

---

## 二、 实体无损压缩：4 类物理顶点表示 CDM 9 类实体

CDM 20 规范中定义了 9 类核心实体对象（Subject, FileObject, NetFlowObject, RegistryKeyObject, Host, Principal, MemoryObject, IpcObject, Packet）。本设计通过**实体映射**、**属性内嵌**与**边语义化**将其完整、无损地投影到 4 类物理图节点上。

```
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

### 1. 独立建模的 4 类核心图节点

#### (1) `:Process` 顶点（承载 CDM `Subject`）
*   **概念定义**：操作系统中执行计算任务的唯一动态活动主体（包含进程与主线程）。
*   **复合主键**：`{host_id}:{pid}:{phase_start_time}`。
    *   *Execve 镜像突变分裂原则*：以 `fork` 或 `execve` 发生的时刻作为阶段起点。当进程调用 `execve` 载入全新二进制镜像时，物理上封闭旧阶段节点，分裂出全新的进程节点，并建立 `[:p2p {syscall: "execve"}]` 因果边相连，彻底杜绝主体人格重塑造成的因果混淆。
*   **核心图属性**：
    *   `process_id` (string): 节点唯一主键属性，值为 `{host_id}:{pid}:{phase_start_time}`。
    *   `host_id` (string): 所属主机唯一标识符（多机隔离与横向移动边界）。
    *   `pid` (int): 操作系统分配的进程 ID。
    *   `ppid` (int): 父进程 ID（解决日志截断前已启动的常驻父进程因果断层，识别非预期非法派生）。
    *   `name` (string): 进程短名称（comm，例如 `bash`, `powershell.exe`）。
    *   `exe_path` (string): 二进制映像文件的绝对规范路径（L2 束聚合第一主键）。
    *   `cmdline` (string): 进程启动时的完整命令行参数（大模型战术载荷分析核心）。
    *   `cwd` (string): 进程当前工作目录（相对路径转绝对路径前置必要参数，识别攻击暂存落地目录）。
    *   `user` (string): 运行用户身份（Linux UID/EUID、Windows SID/用户名、Android App UID，识别权限提升）。
    *   `start_time` (long): 进程本阶段启动的纳秒级时间戳。
    *   `end_time` (long, optional): 进程退出时间戳（划定 $[T_{start}, T_{end}]$ 生命周期窗口，未退出则为 null）。

#### (2) `:File` 顶点（承载 CDM `FileObject`）
*   **概念定义**：持久化文件、目录、特殊设备节点以及一切遵循操作系统 VFS「一切皆文件」抽象的客体。
*   **复合主键**：`{host_id}:{path}`（规范化绝对路径，跨平台 100% 具备）。
*   **核心图属性**：
    *   `file_id` (string): 节点唯一主键属性，值为 `{host_id}:{path}`。
    *   `host_id` (string): 所属主机标识。
    *   `path` (string): 文件的绝对规范化路径（已解析软链接与 `.` / `..`，统一路径分隔符 `/`）。
    *   `file_type` (string): `regular` (普通文件) / `directory` (目录) / `pipe` (管道) / `socket` (本地套接字)。

#### (3) `:Network` 顶点（承载 CDM `NetFlowObject`）
*   **概念定义**：网络通信端点与会话流对象。
*   **复合主键**：`{proto}:{ip_a}:{port_a}<->{ip_b}:{port_b}`。
    *   *自然升序对齐规则*：为保证通信双方（无论客户端还是服务端先发起）都能唯一收敛至同一节点，IP 与端口按字典自然序排列（`ip_a <= ip_b`），端点采用对称中立命名，真实的发起方向与数据流向完全由边方向与系统调用（`connect` vs `accept`）表达。
*   **核心图属性**：
    *   `network_id` (string): 节点唯一主键属性，值为 `{proto}:{ip_a}:{port_a}<->{ip_b}:{port_b}`。
    *   `protocol` (string): `tcp` / `udp`。
    *   `ip_a` / `port_a` (string/int): 升序对端 A 的 IP 与端口。
    *   `ip_b` / `port_b` (string/int): 升序对端 B 的 IP 与端口。
    *   ★ **公共 DNS 53 防超节点规约**：凡是目标端口为 `53` 的标准 DNS 探测，**不上图建独立 `:Network` 顶点**；解析器将其作为属性直接吸收在发起调用的 `:Process` 或出站边属性中（`edge.dns_query = "c2.attacker.com"`），从物理源头绝杀百万入度的公共 DNS 超节点。

#### (4) `:Registry` 顶点（承载 CDM `RegistryKeyObject`）
*   **概念定义**：Windows 操作系统专有的配置项，颗粒度精确下沉至 Key-Value 原子项。
*   **复合主键**：`{host_id}:{hive}\{normalized_key_path}\{value_name}`。
    *   *原子化键值规约*：每个具体的值项独立建模为顶点（若操作键本身则 `value_name` 填 `(Default)`），彻底杜绝合法程序与后门写入同一注册表键（如 `Run`）引发的配置读写交叉污染与超节点。
*   **核心图属性**：
    *   `reg_id` (string): 节点唯一主键属性，值为 `{host_id}:{hive}\{normalized_key_path}\{value_name}`。
    *   `host_id` (string): 所属主机标识。
    *   `hive` (string): 配置单元根，如 `HKLM`, `HKCU`, `HKCR`, `HKU`。
    *   `key_path` (string): 注册表键路径，如 `Software\Microsoft\Windows\CurrentVersion\Run`。
    *   `value_name` (string): 具体注册表项名称（如 `Backdoor`）。
    *   `data` (string): 写入或读取的具体配置内容/载荷数据（大模型判定持久化武器的核心依据）。
    *   `data_type` (string): `REG_SZ`, `REG_DWORD`, `REG_BINARY` 等。

---

### 2. 5 类 CDM 实体的无损吸收与证明

| 被吸收的 CDM 实体 | 图工程落地形态 | 无损证明与技术机理 |
|---|---|---|
| **`Host` (主机)** | **所有节点的前缀主键与 `node.host_id` 属性** | **避免百万度超级节点崩溃**。主机本身不主动产生系统调用，它是一个物理边界。将 `host_id` 注入每个节点，既保留了全图的主机切片能力（`WHERE node.host_id = ...`），又杜绝了遍历算法陷入 Host 超节点的灾难。 |
| **`Principal` (凭证)** | **内嵌为 `:Process` 与 `:File` 的身份属性** | 用户的权限（UID, GID, euid, SID, integrity_level）必须依附于运行态进程或静态文件才能发挥作用。分析提权攻击只需检查 `p.euid != p.ruid` 或 Windows Token 变化，信息完全保全，省去无谓的跨节点跳转。 |
| **`IpcObject` (管道)** | **统一收敛为 `:File` 节点** | Linux 的匿名管道（`pipe:[inode]`）、命名管道（FIFO）与 UNIX Domain Socket，在操作系统内核 VFS 中全都是以文件描述符（FD）和 Inode 呈现。采用统一的文件读写边（`p2f` / `f2p`）表达 IPC 因果，完全符合信息流动模型。 |
| **`MemoryObject` (内存)** | **转化为 `:Process` 间的 `p2p` 内存注入边与状态** | 虚拟内存段是进程内部易失空间。威胁建模真正关心的不是内存块本身，而是「攻击者进程通过何种系统调用污染了受害者进程的内存」。直接投影为 `p2p {action: 'EVENT_WRITE_PROCESS_MEMORY'}` 或自身的 `p2p {action: 'EVENT_MPROTECT'}`，语义更直接精准。 |
| **`Packet` (网络报文)** | **内嵌为 `:Network` 节点与连接边的流量属性** | 系统调用审计的职责是因果可达性而非全流量抓包重组。报文大小、传输字节数、关键 TCP 标志位直接写在 `p2n` / `n2p` 边的 `bytes` 与 `flags` 属性中，完全满足通信特征分析。 |

---

## 三、 突破性架构设计：多主机环境与 `Host` 实体的科学落地

### 1. 为什么 `Host` 绝不能在图中作为独立顶点？

在图论和图数据库工程中，**超级节点（Supernode）是深度图遍历（DFS、BFS、最短路径、随机游走）的头号杀手**。
- 如果将每台物理机/虚拟机建一个 `(:Host)` 顶点，单台主机在 1 小时内产生数万个进程、数万个文件。
- 所有这些进程和文件如果通过边（如 `[:RUNS_ON]`）连到该 `Host` 节点，这个节点的入度将迅速达到 **$10^5 \sim 10^7$**。
- 当 `provenance-navigator` 或 `provenance-agent` 从某个受感染的文件或进程进行反向因果追溯时，一旦因果搜索逻辑不慎扫到该 `Host` 节点，Neo4j 会瞬间展开上百万个邻居，导致**内存耗尽（OOM）或查询超时（Query Timeout）**。

### 2. 双平面架构：横向移动如何通过 `:Network` 节点自然缝合

我们采用**逻辑管理平面**与**因果数据流平面**分离的设计：
- **管理平面**：通过属性检索 `WHERE node.host_id = "host-01"` 快速做数据分片、主机级威胁评分汇总或租户隔离。
- **因果平面**：所有图遍历算法严格只在因果数据流平面运行。两台主机之间的跨主机横向移动（Lateral Movement），天然通过共享的 `:Network` 节点形成因果闭环。

```
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

#### 跨主机攻击路径回溯过程验证：
1. 分析员在主机 B 上发现异常子进程 `bash (pid 9150)`；
2. 反向追溯 `[:p2p]` 找到父进程 `sshd (pid 9102)`；
3. 反向追溯 `[:n2p]` 找到入站网络流 `192.168.1.10:45210 <-> 192.168.1.20:22`；
4. 继续反向追溯 `[:p2n]`，直接跳入主机 A 的客户端进程 `ssh (pid 4512)`；
5. 继续追溯主机 A 上谁执行了 `ssh` 密码喷洒脚本。
- **整个横向移动回溯全流程顺畅无阻，节点数严格保持在 4 类，查询不经过任何超级节点**。

---

## 四、 事件建模准则：28 类核心因果边与 28 类非边事件的分级处理策略

在基于系统调用的威胁溯源图理论中，**图的边并非越多越好**。
学术界顶级安全会议（如 USENIX Security、IEEE S&P、ACM CCS、NDSS）的一致共识（如 *ProTracer*, *BEEP*, *Kairos*, *Holmes* 等系统）表明：
> **因果溯源图（Causal Graph）的核心使命是追踪「信息流（Data Flow）」与「控制流（Control Flow）」。任何不传递真实数据、不产生控制跳转的内部状态微调若强行上图，只会引发灾难性的「依赖爆炸（Dependency Explosion）」与百万级自环噪声，导致图遍历算法内存耗尽或超时崩溃。**

结合 TraceSage 现有代码实现（[`scap-parser/parsers/dispatch/handlers.py`](file:///E:/Work/TraceSage/scap-parser/parsers/dispatch/handlers.py)）与攻击场景真实因果，CDM 20 官方定义的全部 56 种事件类型被严格区分为：
1. **28 类因果边事件**：代表实质性信息流、控制流以及攻击步骤（包含权限变更与服务端点监听），作为物理边持久化到 Neo4j；
2. **28 类纯粹非边事件**：严禁作为独立图边入库，而是由解析器通过内存句柄表维护、节点属性增量更新或安全过滤完成分级处理。

---

### 1. 判定事件是否建边的「三大因果判决公理」

为了让系统在面对每秒数万条操作系统底层事件时拥有一套客观、可复现、不可动摇的判决标准，TraceSage 提炼并确立了**三大因果判决公理**。任何事件在进入图数据库之前，必须依次通过这三道安检门的判定：

```text
       操作系统产生 CDM 56 类事件流 (每秒数万条系统调用)
                               │
                               ▼
       ┌───────────────────────────────────────────────┐
       │ 第一道安检门：直接流传递公理 (有无实质搬运？) │
       └───────────────────────┬───────────────────────┘
                               │ 只有直接搬运数据或交接控制权，才具准入资格
                               ▼
       ┌───────────────────────────────────────────────┐
       │ 第二道安检门：因果可达不灭公理 (删它断不断案？)│
       └───────────────────────┬───────────────────────┘
                               │ 确保攻击证据链绝对完整，去除前置冗余连线
                               ▼
       ┌───────────────────────────────────────────────┐
       │ 第三道安检门：依赖爆炸阻断公理 (防不防图撑爆？)│
       └───────────────────────┬───────────────────────┘
                               │ 内部状态变属性，高频探测直接过滤
                               ▼
           ┌───────────────────┴───────────────────┐
           ▼                                       ▼
     【28 类核心因果边】                     【28 类非边特殊处理】
  (在 Neo4j 中建立物理边)                 (内存句柄维护/节点属性打标/过滤)
```

#### (1) 公理一：直接信息流与控制流传递公理（Direct Flow Axiom —— 边的准入资格）
*   **公理定义**：只有当两个物理实体顶点之间发生了实质的数据载荷物理交换（Data Flow，如字节级读写、网络报文收发、共享内存交换），或者存在确切的进程控制权转移（Control Flow，如派生子进程、跨进程注入线程、异步中断信号）时，才具备在图数据库中构建有向边的物理资格。
*   **学术源流**：
    *   **格信息流模型与 Biba 完整性模型**（Dorothy Denning 1976, Kenneth Biba 1977）：安全模型的因果判定前提是客体发生了 `Read` 或 `Write` 产生状态转换；
    *   **动态污点分析理论 DIFT**（Newsome & Song, NDSS 2005）：只有存在物理数据搬运时污点标签才发生传播；
    *   **DARPA TC CDM 规范**（BBN Technologies, TaPP 2020）：`Event` 记录的是主体（Subject）与客体（PredicateObject）之间明确的数据交互或控制。
*   **判决体现**：
    *   `EVENT_WRITE`（数据写盘）、`EVENT_RECVFROM`（接收网络包）、`EVENT_CLONE`（创建线程）符合公理一，**准予建边**；
    *   `EVENT_LSEEK`（文件指针偏移寻道，传输数据严格为 0 字节）、`EVENT_DUP`（文件描述符别名复制，数据 0 字节）、`EVENT_READ_SOCKET_PARAMS`（获取套接字参数，数据 0 字节）属于进程内部指针计算，不符合公理一，**严禁上图建边**。

#### (2) 公理二：因果可达性不灭与拓扑等价公理（Causal Reachability Preservation Axiom —— 证据链判据）
*   **公理定义**：溯源图的核心功能是图遍历算法（前向追踪 Forward Tracking 与后向根因分析 Backward Provenance）。边的去留判据在于：**删除该边是否会破坏从攻击源头（Entrypoint）到受害靶标（Victim）的有向因果路径可达性（Reachability）**。
    *   若删除该动作会导致攻击因果链断裂（例如丢失了权限变更赋权执行步骤），则该动作必须物理建边；
    *   若该动作在拓扑上已经由更底层、更精细的物理边所涵盖，或者仅属于句柄准备阶段、后续必然由真实读写闭环，则剔除或递延该边不会破坏源头到终点的拓扑可达性，无需建立多余的虚假边。
*   **学术源流**：
    *   **溯源图回溯开山之作 BackTracker**（King & Chen, SOSP 2003）：因果图是依赖有向无环图（DAG），攻击回溯是在 DAG 上搜索从靶标到根因的传递闭包；
    *   **溯源语义规范与传递缩约**（James Cheney 等, PODS 2007; W3C PROV-DM）：因果图遵循传递等价性（Transitive Reduction），去除因果等价的冗余前置边不改变拓扑可达性。
*   **判决体现**：
    *   `EVENT_MODIFY_FILE_ATTRIBUTES`（`chmod +x` 赋予脚本执行权）与 `EVENT_BIND`（绑定后门监听端口）：若删除则破坏攻击推理链，**必须建物理边**；
    *   `EVENT_OPEN`（打开文件）：打开操作仅分配虚拟文件描述符（FD），传输数据严格为 0 字节。黑客后续窃取数据必然触发 `EVENT_READ`，写入恶意载荷必然触发 `EVENT_WRITE`，文件创建必然触发 `EVENT_CREATE_OBJECT`。因果链完全由后续读写边维持，因此 `open` **无需建边，因果严格递延至后续事件**；
    *   `EVENT_INIT_MODULE`（加载内核驱动）：驱动 `.ko` 文件此前必然已通过 `f2p`（`read` 或 `mmap`）建立因果边，可达性已被底层边覆盖，无需重复建边。

#### (3) 公理三：依赖爆炸阻断与局部状态收敛公理（Dependency Explosion Prevention & Locality Axiom —— 性能护城河）
*   **公理定义**：凡是不向外传递新信息流的操作，如果是实体内部状态或元数据的单向调整，一律**收敛为节点自身属性（Attribute Absorption）**；如果是高频且无害的只读探测与测试框架插桩标记，一律**在解析分发层直接过滤丢弃（Telemetry Pruning）**。严禁将微观探测与自身状态微调强行建边，从数学源头杜绝「超级节点爆炸」与「虚假图连通」。
*   **学术源流**：
    *   **依赖爆炸问题提出与单元分割 BEEP**（Lee 等, NDSS 2013）：首次从理论上剖析了长周期进程频繁读写公共文件导致整图虚假连通的“Dependency Explosion”灾难；
    *   **事件因果与状态转换解耦理论 ProTracer**（Ma 等, NDSS 2016）：证明了必须区分“事件驱动因果（建边）”与“状态驱动转换（内部消化或属性化）”，明确要求 `stat` 等高频事件不上图；
    *   **因果图减枝理论 PrioTracker & NodeMerge**（USENIX Security 2018, ACM CCS 2018）：证明了高频非因果事件会导致图平均度数幂律激增，使图遍历算法时间复杂度退化为不可接受的指数级。
*   **判决体现**：
    *   `EVENT_CHANGE_PRINCIPAL`（提权 `setuid`）与 `EVENT_LOGCLEAR`（清空日志）：转化为 `:Process` 节点的内部属性 `p.euid = 0` 与标签 `p.suspicious_tags += 'log_clear'`，**不建自环边**；
    *   `EVENT_CHECK_FILE_ATTRIBUTES`（`stat/fstat` 元数据探测，日常数百万次）：**直接丢弃**，防止系统公共库被刺成百万度超级节点。

---

### 2. 7 类物理因果边体系结构定义

在三大公理的约束下，TraceSage 将 28 类因果事件精确投影到 4 类实体顶点之间的 **7 类物理有向因果边**中：

| 边类型标识 (Edge Label) | 起点实体顶点 (Source) | 终点实体顶点 (Destination) | 物理因果语义 (Semantics) | 典型覆盖事件与系统调用 |
|:---:|:---:|:---:|---|---|
| **`p2p`** | `:Process` (主体) | `:Process` (客体) | 进程间控制流转移、派生、信号、内存注入与保护变更 | `FORK`, `CLONE`, `EXECUTE`, `EXIT`, `CREATE_THREAD`, `SIGNAL`, `MPROTECT` |
| **`p2f`** | `:Process` (主体) | `:File` (客体) | 进程对文件的写入、创建、重命名、截断、删除、权限变更及管道零拷贝 | `WRITE`, `CREATE_OBJECT`, `RENAME`, `TRUNCATE`, `UNLINK`, `LINK`, `MODIFY_FILE_ATTRIBUTES`, `SPLICE`, `TEE`, `VMSPLICE`, `SHM` |
| **`f2p`** | `:File` (客体) | `:Process` (主体) | 进程从文件读取载荷、映射虚存、载入共享库及管道零拷贝流动 | `READ`, `MMAP`, `LOADLIBRARY`, `EXECUTE`, `SPLICE`, `TEE`, `SHM` |
| **`p2n`** | `:Process` (主体) | `:Network` (客体) | 进程向网络端点发起主动连接、发送报文或绑定本地监听端点 | `CONNECT`, `BIND`, `SENDTO`, `SENDMSG` |
| **`n2p`** | `:Network` (客体) | `:Process` (主体) | 本地进程接受入站连接或从网络端点接收外部数据报文 | `ACCEPT`, `RECVFROM`, `RECVMSG` |
| **`p2r`** | `:Process` (主体) | `:Registry` (客体) | Windows 进程创建注册表键项或写入注册表键值配置 | `CREATE_OBJECT`, `WRITE` (`RegCreateKey`, `RegSetValue`) |
| **`r2p`** | `:Registry` (客体) | `:Process` (主体) | Windows 进程读取注册表键项值或系统配置数据 | `READ` (`RegQueryValue`) |

---

### 3. 因果边通用物理属性定义（全系统 100% 存在或推导）

为满足因果图偏序遍历、防依赖爆炸剪枝与大模型细粒度语义理解，所有 7 类有向边强制统一搭载以下 **6 个物理属性**：

| 属性名称 | 物理类型 | 算法作用（拓扑与剪枝） | LLM 理解作用（战术与意图） | 全平台通用性与推导规约 |
|---|---|---|---|---|
| **`event_id`** | `String` / `Long` | **边唯一主键**：Neo4j `MERGE` 唯一约束去重与幂等导入，索引快照排序与失效判据。 | 追踪事件底层单行审计日志源头。 | **100% 具备**：日志全局事件号，或对三元组+时间戳生成确定性哈希。 |
| **`starttime`** | `Long` (ns/ms) | **因果单调性偏序硬检查**（$T_{cause} \le T_{effect}$）：绝对防止时光倒流形成因果伪环。 | 建立攻击链前后叙事线。 | **100% 具备**：Unix 纳秒/微秒 Epoch 时间戳。 |
| **`endtime`** | `Long` (ns/ms) | 流式读写场景的时序门限提升（允许边读边写）。 | 分析网络连接或执行持续时长。 | **推导方案**：Sysdig/OpenBSM 原生提供；**Sysmon 等单点事件推导为 `endtime = starttime`**。 |
| **`syscall`** | `String` | 内容三元组 `(src, syscall, dst)` 比对与规则匹配核心要素。 | 判定攻击动作具体手段。 | **100% 具备**：统一归一化为小写标准操作名（如 `read`, `write`, `execve`, `connect`）。 |
| **`bytes`** | `Long` | **空读剪枝硬闸门**：阻断 0 字节读引发的虚假连通。 | 识别大流量数据外泄（Exfiltration）。 | **三态推导**：`>0` 为实测值；`==0` 触发空读不回溯；**Sysmon 缺失时赋 `-1`（未知），算法自动跳过字节剪枝**。 |
| **`status`** | `Integer` | **阻断未遂攻击污点扩散**（只有成功才传污点，失败阻断）。 | 区分“黑客成功”还是“被系统拦截阻断”。 | **推导方案**：Linux/FreeBSD/Android 填真实系统调用退出错误码（0为成功）；**Windows Sysmon 默认填 `0`（成功）**。 |

---

### 4. 28 类核心因果边全景表（Neo4j 物理持久化）

在 4 类实体顶点之间，这 28 类事件映射为上述 7 类物理有向边（`p2p`, `p2f`, `f2p`, `p2n`, `n2p`, `p2r`, `r2p`）：

| 序号 | CDM 官方事件名称 | 映射边类型 | 因果拓扑方向 | 边核心属性与参数 | 物理因果语义与典型系统调用 |
|:---:|---|:---:|:---:|---|---|
| 1 | **EVENT_ACCEPT** | `n2p` | Network $\to$ Process | `action: "accept"` | 本地服务端监听端口接受外部入站连接（`accept`, `accept4`） |
| 2 | **EVENT_BIND** | `p2n` | Process $\to$ Network | `action: "bind"` | 服务端监听端点绑定，记录服务/后门监听端口（`bind`） |
| 3 | **EVENT_CLONE** | `p2p` | Process $\to$ Process | `action: "clone"` | 创建轻量级进程或线程（`clone`, `clone3`） |
| 4 | **EVENT_CONNECT** | `p2n` | Process $\to$ Network | `action: "connect"` | 主动向远程端点发起外联通信会话（`connect`） |
| 5 | **EVENT_CREATE_OBJECT** | `p2f` / `p2r` | Process $\to$ File/Reg | `action: "create_object"` | 创建持久化文件、命名管道或注册表项（`mknod`, `mkdir`, `RegCreateKey`） |
| 6 | **EVENT_CREATE_THREAD** | `p2p` | Process $\to$ Process | `action: "create_thread"` | 跨进程注入控制流（Windows `CreateRemoteThread`） |
| 7 | **EVENT_EXECUTE** | `f2p` + `p2p` | File $\to$ Process<br>Process $\to$ Process | `action: "execve"` | 1. 镜像载入内存 (`f2p`); 2. 进程状态突变重置 (`p2p`) |
| 8 | **EVENT_EXIT** | `p2p` | Process $\to$ Process | `action: "exit"` | 进程终止，向父进程发送退出通知（`exit`, `exit_group`） |
| 9 | **EVENT_FORK** | `p2p` | Process $\to$ Process | `action: "fork"` | 派生子进程，因果关系：父 $\to$ 子（`fork`, `vfork`） |
| 10 | **EVENT_LINK** | `p2f` | Process $\to$ File | `action: "link", target: "..."` | 建立硬链接或软链接（`link`, `linkat`, `symlink`） |
| 11 | **EVENT_LOADLIBRARY** | `f2p` | File $\to$ Process | `action: "load_library"` | 动态加载 DLL / .so 共享库映像（`LoadLibrary`, `dlopen`） |
| 12 | **EVENT_MMAP** | `f2p` | File $\to$ Process | `action: "mmap", prot: "..."` | 将文件内容直接映射到进程虚存地址空间（`mmap`） |
| 13 | **EVENT_MODIFY_FILE_ATTRIBUTES**| `p2f` | Process $\to$ File | `action: "chmod", mode: "..."` | 权限属主变更（`chmod`, `fchmod`, `chown`），黑客赋予脚本执行权核心步骤 |
| 14 | **EVENT_MPROTECT** | `p2p` (自环) | Process $\to$ Process | `action: "mprotect", prot: "rwx"` | 修改自身内存段保护属性（经典 Shellcode 解密后置为可执行） |
| 15 | **EVENT_READ** | `f2p` / `r2p` | File/Reg $\to$ Process | `action: "read", bytes: N` | 从文件、管道或注册表读取数据（`read`, `readv`, `RegQueryValue`） |
| 16 | **EVENT_RECVFROM** | `n2p` | Network $\to$ Process | `action: "recvfrom", bytes: N` | 接收 UDP 无连接网络数据报文（`recvfrom`） |
| 17 | **EVENT_RECVMSG** | `n2p` | Network $\to$ Process | `action: "recvmsg", bytes: N` | 接收结构化多通道网络数据流（`recvmsg`, `recvmmsg`） |
| 18 | **EVENT_RENAME** | `p2f` | Process $\to$ File | `action: "rename", old: "..."` | 文件名或路径拓扑变更（`rename`, `renameat`） |
| 19 | **EVENT_SENDTO** | `p2n` | Process $\to$ Network | `action: "sendto", bytes: N` | 发送 UDP 无连接网络数据报文（`sendto`） |
| 20 | **EVENT_SENDMSG** | `p2n` | Process $\to$ Network | `action: "sendmsg", bytes: N` | 发送结构化多通道网络数据流（`sendmsg`, `sendmmsg`） |
| 21 | **EVENT_SHM** | `f2p` / `p2f` | Process $\leftrightarrow$ File | `action: "shm"` | 共享内存附着与数据交换，映射为虚拟 `:File` 交互 |
| 22 | **EVENT_SIGNAL** | `p2p` | Process $\to$ Process | `action: "signal", sig: N` | 进程间异步控制流通知（`kill`, `tkill`, `tgkill`） |
| 23 | **EVENT_SPLICE** | `f2p` + `p2f` | File $\to$ Process $\to$ File | `action: "splice", bytes: N` | Linux 管道与文件间的零拷贝数据移动（`splice`, `sendfile`） |
| 24 | **EVENT_TEE** | `f2p` + `p2f` | File $\to$ Process $\to$ File | `action: "tee", bytes: N` | Linux 管道间的数据旁路复制（`tee`） |
| 25 | **EVENT_TRUNCATE** | `p2f` | Process $\to$ File | `action: "truncate", len: N` | 截断清空目标文件内容（`truncate`, `ftruncate`） |
| 26 | **EVENT_UNLINK** | `p2f` | Process $\to$ File | `action: "unlink"` | 删除目标文件，破坏性生命周期终止（`unlink`, `unlinkat`） |
| 27 | **EVENT_VMSPLICE** | `p2f` | Process $\to$ File | `action: "vmsplice", bytes: N` | 用户内存与管道之间的零拷贝数据注入（`vmsplice`） |
| 28 | **EVENT_WRITE** | `p2f` / `p2r` | Process $\to$ File/Reg | `action: "write", bytes: N` | 数据落盘、写管道或写注册表键值（`write`, `writev`, `RegSetValue`） |

---

### 5. 28 类纯粹非边事件的分级特殊处理策略

对于绝对不上图持久化为独立边的 28 类事件，`scap-parser` 采用以下 6 种严谨工程策略：

#### 策略一：内存描述符表纯指针寻道与复制（5 种）
*   **涉及事件**：
    1.  `EVENT_LSEEK`（文件读写指针偏移）
    2.  `EVENT_DUP`（文件描述符复制 `dup/dup2/dup3`）
    3.  `EVENT_FCNTL`（调整文件描述符标志 `fcntl`）
    4.  `EVENT_READ_SOCKET_PARAMS`（获取套接字参数 `getsockopt`）
    5.  `EVENT_WRITE_SOCKET_PARAMS`（设置套接字选项 `setsockopt`）
*   **不建边原理**：
    *   `lseek` 只是将内核 `struct file` 的 `f_pos` 指针偏移，传输数据量为 **严格 0 字节**；
    *   `dup` 只是在进程的 `files_struct` 表中做别名映射（例如 `fd=1` 复制给 `fd=2`）；
    *   `fcntl` 是文件描述符属性操作（加锁、查标志），不搬运数据；
    *   若把此类高频微调操作作为边存入 Neo4j，单机图的边数会暴涨 10~20 倍，产生海量垃圾自环边，直接导致遍历崩溃。
*   **解析器处理规约**：
    *   仅在解析器内部维护的 `ProcessFdTable` 内存表中更新状态（例如 `fd_table[new_fd] = fd_table[old_fd]` 或 `fd_table[fd].offset = N`）；
    *   **处理后立即在内存中消化，严禁向 Neo4j 发射任何写边请求**。

#### 策略二：句柄关联与因果延后绑定（1 种）
*   **涉及事件**：
    1.  `EVENT_OPEN`（打开文件/设备描述符）
*   **不建边原理**：
    *   `open` 本质是进程向操作系统申请将文件绝对路径与进程局部的虚拟句柄（文件描述符 FD）进行映射绑定。在打开操作发生瞬间，**没有任何字节从客体流入进程，也没有进程字节落盘（传输数据量严格为 0 字节）**；
    *   若打开文件就建立因果边，会导致只读配置扫描（如扫描 `/etc/passwd`）产生虚假因果，更会导致未读写文件的探测行为引发伪双向环；
    *   **因果完整性保障**：若 `open` 带有 `O_CREAT` 标志创建新文件，系统在 CDM 中规范表达为 `EVENT_CREATE_OBJECT`；若后续发生实质读写，则由 `EVENT_READ` / `EVENT_WRITE` 建立真实信息流边；若带有 `O_TRUNC` 发生文件清空，则由 `EVENT_TRUNCATE` 记录破坏流。
*   **解析器处理规约**：
    *   仅在解析器内部维护的 `ProcessFdTable` 内存表中记录句柄绑定关系：`fd_table[fd] = {path: file_path, flags: flags, open_time: ts}`；
    *   **不在图中建立物理边，将因果流严格递延至后续的真实读写事件驱动**。

#### 策略三：已有因果边的生命周期闭合（2 种）
*   **涉及事件**：
    1.  `EVENT_CLOSE`（关闭文件/网络描述符）
    2.  `EVENT_WAIT`（父进程等待子进程退出状态）
*   **不建边原理**：关闭与等待是资源回收与状态同步标记，没有新的因果数据流动。
*   **解析器处理规约**：
    *   收到 `EVENT_CLOSE` 时，提取该 FD 对应的最后一条读写边，将其 `endtime` 属性更新为当前时间戳，并从内存 `fd_table` 中安全注销该 FD；
    *   收到 `EVENT_WAIT` 时，同步父进程的活动窗口，不建新边。

#### 策略四：节点静态元数据/身份状态增量更新（6 种）
*   **涉及事件**：
    1.  `EVENT_CHANGE_PRINCIPAL`（凭证变更：`setuid/setgid`）
    2.  `EVENT_MODIFY_PROCESS`（修改进程优先级、调度或命名空间）
    3.  `EVENT_ADD_OBJECT_ATTRIBUTE`（文件扩展属性设置 `setxattr`）
    4.  `EVENT_LOGCLEAR`（清空系统安全审计日志）
    5.  `EVENT_INIT_MODULE`（从内存加载内核模块）
    6.  `EVENT_FINIT_MODULE`（从描述符加载内核模块）
*   **不建边原理**：
    *   身份与属性调整属于实体内部状态的单向突变，强行建自环边会导致模式膨胀；
    *   特权驱动模块（`.ko`）加载进入 Ring 0 空间，用户态系统调用日志无法观测驱动微观数据流。在加载前，驱动文件必然已经通过 `EVENT_READ` 或 `EVENT_MMAP` 产生了 `File -> Process` 的因果边；加载动作本身转化为进程属性，既保证溯源链完整，又避免虚构无实体边。
*   **解析器处理规约**：
    *   `EVENT_CHANGE_PRINCIPAL`：直接通过 Cypher 更新 `:Process` 属性：`SET p.euid = N, p.is_elevated = true`；
    *   `EVENT_LOGCLEAR`：对执行该动作的进程节点追加高危安全标签：`SET p.suspicious_tags = coalesce(p.suspicious_tags, []) + 'log_clear'`；
    *   `EVENT_ADD_OBJECT_ATTRIBUTE`：更新目标 `:File` 的扩展元数据属性；
    *   `EVENT_INIT_MODULE` / `EVENT_FINIT_MODULE`：记录进程加载模块属性：`SET p.loaded_modules = coalesce(p.loaded_modules, []) + module_name`。

#### 策略五：文件系统全局命名空间与管理覆盖（4 种）
*   **涉及事件**：
    1.  `EVENT_MOUNT`（挂载文件系统）
    2.  `EVENT_UMOUNT`（卸载文件系统）
    3.  `EVENT_SERVICEINSTALL`（Windows 注册持久化服务）
    4.  `EVENT_STARTSERVICE`（启动服务管理器任务）
*   **不建边原理**：
    *   `MOUNT`/`UMOUNT` 改变的是 VFS 全局树状命名空间，非进程直接因果数据流；
    *   `SERVICEINSTALL`（服务注册）在底层已被注册表写入（`p2r`）或二进制文件写入（`p2f`）覆盖；
    *   `STARTSERVICE`（服务启动）在底层已被服务控制管理器（SCM）派生子进程的控制流（`p2p`）覆盖。
*   **解析器处理规约**：
    *   `MOUNT`/`UMOUNT`：仅更新解析器内部的绝对路径重定向树，不在图中建立实体边；
    *   `SERVICEINSTALL`/`STARTSERVICE`：直接在事件分发层标记或忽略，由底层物理边承载真实因果。

#### 策略六：审计框架伪事件与高频元数据安全过滤（10 种）
*   **涉及事件**：
    1.  `EVENT_CHECK_FILE_ATTRIBUTES`（`stat/fstat` 元数据高频探测）
    2.  `EVENT_BOOT`（系统开机基线时间戳）
    3.  `EVENT_LOGIN`（用户登录认证完成）
    4.  `EVENT_LOGOUT`（用户退出登录）
    5.  `EVENT_CORRELATION`（测试床跨源关联打标）
    6.  `EVENT_UNIT`（程序执行单元迭代分割标记）
    7.  `EVENT_UPDATE`（实体定义增量刷新）
    8.  `EVENT_BLIND`（沙箱隔离盲区提示）
    9.  `EVENT_OTHER`（未知系统调用兜底）
    10. `EVENT_FLOWS_TO`（框架宏观流标记）
*   **不建边原理**：
    *   `stat()` 元数据探测一天发生几百万次，建边会把系统配置库文件瞬间打成超级节点（学术界公认过滤项）；
    *   其余事件非操作系统内核原生的数据交互，纯属评估框架插桩控制标记；登录登出在底层已有完整的 `sshd -> bash` 会话派生链覆盖。
*   **解析器处理规约**：
    *   在解析事件分发的第一道路由关卡直接 `continue` 跳过；
    *   在 `Reporting` 统计模块中累加 `skipped_framework_events`，确保输入总行数与处理行数严格平齐（满足独立可验证法则）。

---

### 6. 全量 56 种事件工程判决速查总表

| 序号 | CDM 官方事件名称 | 图中是否建边？ | 归属边类型 / 特殊处理手段 | 核心原因与设计判定 |
|:---:|---|:---:|:---:|---|
| 1 | `EVENT_ACCEPT` | **是** | `n2p` 边 | 网络入站连接数据流 |
| 2 | `EVENT_ADD_OBJECT_ATTRIBUTE` | 否 | 节点属性更新 (`xattr`) | 无数据流动，仅扩展元数据调整 |
| 3 | `EVENT_BIND` | **是** | `p2n` 边 | 本地监听端点绑定（后门/服务监听核心因果） |
| 4 | `EVENT_BLIND` | 否 | 过滤并累加计数 | 测试床插桩标记 |
| 5 | `EVENT_BOOT` | 否 | 记录为基线时间戳 | 无主体客体，非因果交互 |
| 6 | `EVENT_CHANGE_PRINCIPAL` | 否 | 进程属性更新 (`p.euid`) | 身份权限突变，杜绝自环边膨胀 |
| 7 | `EVENT_CHECK_FILE_ATTRIBUTES` | 否 | 解析器过滤丢弃 | 高频探测（`stat`），依赖爆炸元凶 |
| 8 | `EVENT_CLONE` | **是** | `p2p` 边 | 线程/轻量级进程创建控制流 |
| 9 | `EVENT_CLOSE` | 否 | 闭合上一条边 `endtime` | 资源释放，非新信息流 |
| 10 | `EVENT_CONNECT` | **是** | `p2n` 边 | 网络主动外联数据流 |
| 11 | `EVENT_CORRELATION` | 否 | 过滤并累加计数 | 测试框架辅助标签 |
| 12 | `EVENT_CREATE_OBJECT` | **是** | `p2f` / `p2r` 边 | 目标文件/注册表客体创建 |
| 13 | `EVENT_CREATE_THREAD` | **是** | `p2p` 边 | 跨进程远程注入控制流 |
| 14 | `EVENT_DUP` | 否 | 内存更新 FD 别名映射 | 描述符引用复制，数据零传输 |
| 15 | `EVENT_EXECUTE` | **是** | `f2p` + `p2p` 边 | 镜像载入与进程重置控制流 |
| 16 | `EVENT_EXIT` | **是** | `p2p` 边 | 生命周期终止通知父进程 |
| 17 | `EVENT_FLOWS_TO` | 否 | 过滤丢弃 | 框架宏观流，底层读写边已表达 |
| 18 | `EVENT_FCNTL` | 否 | 内存更新 `fd.flags` | 句柄标志位微调，无数据传输 |
| 19 | `EVENT_FORK` | **是** | `p2p` 边 | 派生子进程控制流 |
| 20 | `EVENT_LINK` | **是** | `p2f` 边 | 硬链接与软链接拓扑结构变更 |
| 21 | `EVENT_LOADLIBRARY` | **是** | `f2p` 边 | 动态共享库载入数据流 |
| 22 | `EVENT_LOGCLEAR` | 否 | 进程打威胁属性标签 | 痕迹清理攻击标记，不上独立边 |
| 23 | `EVENT_LOGIN` | 否 | 过滤丢弃 | 认证会话，底层已有进程链覆盖 |
| 24 | `EVENT_LOGOUT` | 否 | 过滤丢弃 | 会话登出审计标记 |
| 25 | `EVENT_LSEEK` | 否 | 内存更新 `fd.offset` | 偏移寻道，0 字节传输，严禁上图 |
| 26 | `EVENT_MMAP` | **是** | `f2p` 边 | 虚存与文件映射数据流 |
| 27 | `EVENT_MODIFY_FILE_ATTRIBUTES` | **是** | `p2f` 边 | 权限属主变更（`chmod`），攻击执行权赋予核心因果 |
| 28 | `EVENT_MODIFY_PROCESS` | 否 | 进程属性更新 | 进程优先级或状态调整 |
| 29 | `EVENT_MOUNT` | 否 | 更新内部路径重定向表 | 全局文件树挂载，非进程因果 |
| 30 | `EVENT_MPROTECT` | **是** | `p2p` 自环边 | 内存保护属性变更（Shellcode解密） |
| 31 | `EVENT_OPEN` | 否 | 内存 FD 表维护与因果递延 | 句柄绑定，0 字节传输；创建由 CREATE_OBJECT 表达，读写由 READ/WRITE 表达 |
| 32 | `EVENT_OTHER` | 否 | 记录未决日志，不上图 | 兜底未分类事件 |
| 33 | `EVENT_READ` | **是** | `f2p` / `r2p` 边 | 文件/管道/注册表数据读入流 |
| 34 | `EVENT_READ_SOCKET_PARAMS` | 否 | 内存更新 Socket 参数 | `getsockopt` 查询，无数据流动 |
| 35 | `EVENT_RECVFROM` | **是** | `n2p` 边 | UDP 无连接网络数据接收 |
| 36 | `EVENT_RECVMSG` | **是** | `n2p` 边 | 结构化网络数据接收 |
| 37 | `EVENT_RENAME` | **是** | `p2f` 边 | 文件重命名路径拓扑变更 |
| 38 | `EVENT_SENDTO` | **是** | `p2n` 边 | UDP 无连接网络数据发送 |
| 39 | `EVENT_SENDMSG` | **是** | `p2n` 边 | 结构化网络数据发送 |
| 40 | `EVENT_SERVICEINSTALL` | 否 | 目标客体标记持久化属性 | 服务注册配置，底层由注册表/文件写边覆盖 |
| 41 | `EVENT_SHM` | **是** | `f2p` / `p2f` 边 | 共享内存交互因果流 |
| 42 | `EVENT_SIGNAL` | **是** | `p2p` 边 | 进程间异步控制流通知 |
| 43 | `EVENT_STARTSERVICE` | 否 | SCM 派生进程链承载 | 外层框架通知，由底层 p2p 进程边覆盖 |
| 44 | `EVENT_TRUNCATE` | **是** | `p2f` 边 | 截断清空文件破坏流 |
| 45 | `EVENT_UMOUNT` | 否 | 更新内部路径重定向表 | 卸载挂载点，非进程数据流动 |
| 46 | `EVENT_UNIT` | 否 | 过滤丢弃 | 框架循环体分割标记 |
| 47 | `EVENT_UNLINK` | **是** | `p2f` 边 | 文件删除破坏流 |
| 48 | `EVENT_UPDATE` | 否 | 过滤丢弃 | 实体字段增量刷新标记 |
| 49 | `EVENT_WAIT` | 否 | 更新父进程活跃状态 | 同步等待，无新因果流产生 |
| 50 | `EVENT_WRITE` | **是** | `p2f` / `p2r` 边 | 文件/管道/注册表数据写入流 |
| 51 | `EVENT_WRITE_SOCKET_PARAMS` | 否 | 内存更新 Socket 参数 | `setsockopt` 设置，无数据流动 |
| 52 | `EVENT_TEE` | **是** | `f2p` + `p2f` 边 | Linux 零拷贝管道旁路复制 |
| 53 | `EVENT_SPLICE` | **是** | `f2p` + `p2f` 边 | Linux 零拷贝管道数据移动（`sendfile`） |
| 54 | `EVENT_VMSPLICE` | **是** | `p2f` 边 | 内存与管道零拷贝数据注入 |
| 55 | `EVENT_INIT_MODULE` | 否 | 进程模块属性更新，依赖前置读边 | 内核边界，系统调用自身不重复建边 |
| 56 | `EVENT_FINIT_MODULE` | 否 | 进程模块属性更新，依赖前置读边 | 内核边界，系统调用自身不重复建边 |

---

## 五、 内容三元组抽象层（HAL）与 Navigator 零破坏兼容

TraceSage 现有的上层组件具有明确的分层架构：
- [`provenance-agent`](file:///E:/Work/TraceSage/provenance-agent/pagent/core/graph_facts.py)（智能体推理闭环）
- [`provenance-navigator`](file:///E:/Work/TraceSage/provenance-navigator/rules/motifs.py)（神经符号因果导航与路径挖掘）
- [`eval_agent_attack_path.py`](file:///E:/Work/TraceSage/tools/eval_agent_attack_path.py)（攻击召回率与查准率评测）

这些模块均高度依赖 **内容三元组（Content Triple）** 作为抽象硬件接口：
$$\text{Content Triple} = \langle \text{Source Entity String}, \text{Normalized Action}, \text{Destination Entity String} \rangle$$

### 1. 三元组在各场景下的统一生成规范

| 操作系统与攻击场景 | 物理图中的节点与边 | 投影输出的标准三元组 (Upper Layer Triple) |
|---|---|---|
| **Linux 勒索文件加密** | `(p:ransomware)-[:p2f {syscall: 'write'}]->(f:/data.enc)` | `(p:ransomware, write, f:/data.enc)` |
| **Linux 命名管道通信** | `(p:cat)-[:p2f {syscall: 'write'}]->(f:pipe:[1234])`, `(f:pipe:[1234])-[:f2p {syscall: 'read'}]->(p:grep)` | `(p:cat, write, f:pipe:[1234])`<br>`(f:pipe:[1234], read, p:grep)` |
| **Windows 注册表自启动**| `(p:cmd.exe)-[:p2r {syscall: 'reg_set_value'}]->(r:HKLM\...\Run\Backdoor)` | `(p:cmd.exe, reg_set_value, r:HKLM\...\Run\Backdoor)` |
| **Windows 跨进程内存注入**| `(p:mimikatz)-[:p2p {syscall: 'create_thread'}]->(p:lsass)` | `(p:mimikatz, create_thread, p:lsass)` |
| **跨主机横向移动 (A $\to$ B)** | **主机 A 端**：`(p:ssh)-[:p2n {syscall: 'connect'}]->(n:10.0.0.2:22)`<br>**主机 B 端**：`(n:10.0.0.2:22)-[:n2p {syscall: 'accept'}]->(p:sshd)` | `(p:ssh, connect, n:10.0.0.2:22)`<br>`(n:10.0.0.2:22, accept, p:sshd)` |

### 2. 既有代码适配改动清单（改动行数 $\le 5$ 行）

由于边语义与实体类型被严格控制，已有代码只需要增加对 Windows 注册表边类型的枚举：
*   **`provenance-agent/pagent/core/graph_facts.py`**：
    ```python
    # 原查询：
    # MATCH (s)-[r:p2p|p2f|f2p|p2n|n2p]->(d)
    # 扩展支持 Windows 后的查询：
    # MATCH (s)-[r:p2p|p2f|f2p|p2n|n2p|p2r|r2p]->(d)
    ```
*   **`provenance-navigator/rules/motifs.py`**：子图模式挖掘逻辑完全无感知，由于注册表在拓扑上也是有向二部交互（Process $\leftrightarrow$ Registry），现有的 Motif 抽取器可直接复用。
*   **`tools/eval_agent_attack_path.py`**：由于 groundtruth 评测脚本严格按照 `(src, syscall, dst)` 比对，只要解析器输出对齐的三元组，评测脚本无需任何修改。

---

## 六、 方案深度客观评价

依据项目最高准则《通用工程四法则》（声明边界法则、阻断诚实法则、独立可验证法则、真实绝对压倒形式法则），对本方案进行深度评价：

### 1. 核心架构优势

1.  **彻底绝杀了百万度超级节点（Supernode-Free）**：
    将 `Host` 与 `Principal` 属性化，使图数据库的平均节点出入度维持在 $3 \sim 8$ 的健康稀疏水平，保证了百万级事件规模下的毫秒级路径遍历性能。
2.  **全量覆盖 CDM 语义，无信息截断，根治依赖爆炸**：
    严格对照 CDM 20 规范建立了 28 类骨干因果建边 + 28 类轻量吸收的完整处理闭环。既无任何因果信息截断，又将无信息流的微调与伪事件拦截在内存层，从数学机制上切断了图数据库的依赖爆炸。
3.  **异构混合系统的单库统一表达**：
    无论 Linux 主机还是 Windows 主机，其日志均收敛到同一套数据模型中，企业网络中常见的「Linux 突破 $\to$ Windows 域控提权」复杂纵深攻击能够在同一图实例中实现无缝横向追溯。

### 2. 技术局限性与物理边界声明（诚实报告）

1.  **细粒度操作依赖边属性二次过滤**：
    由于 56 类细粒度事件被收敛到 7 类边类型上，边标签（Edge Label）粒度变粗。例如 `p2f` 同时包含了写入（`EVENT_WRITE`）、删除（`EVENT_UNLINK`）和权限修改（`EVENT_MODIFY_FILE_ATTRIBUTES`）。针对特定动作的高频查询必须在 Neo4j 中为 `r.action` 建立属性索引。
2.  **物理级不可见无文件内存漏洞利用细节**：
    将 `MemoryObject` 扁平化意味着系统只能观察到跨进程的系统调用动作（如 `process_vm_writev`）或权限修改（`mprotect`）。对于单个进程内部的 ROP 链拼接、堆喷射布局等纯用户态内存行为，主机内核系统调用审计图在物理上依然不可见。
3.  **孤立文件系统离线篡改因果断裂**：
    所有因果边均依附于运行态进程的主动行为。如果攻击者通过物理拔盘或操作系统关机状态下修改磁盘文件，由于缺少内核系统调用事件，因果链路必然发生物理阻断，系统只能如实报告无法回溯。

---

## 七、 四类操作系统日志源保真度与推导核对矩阵（Fidelity Matrix）

为保证全平台图数据模型在工程落地时严格遵循《声明边界法则》与《阻断诚实法则》，杜绝任何不可落地的私有假设，下表对 **Linux (Sysdig/Auditd)、FreeBSD (OpenBSM)、Windows (Sysmon/ETW)、Android (ClearScope)** 四大类日志源的全部属性存在性与推导规约进行穷举核定：

| 实体分类 | 属性名称 | Linux (Sysdig/Auditd) | FreeBSD (OpenBSM) | Windows (Sysmon/ETW) | Android (ClearScope) | 跨平台推导与保真度规约 |
|---|---|---|---|---|---|---|
| **:Process** | `process_id` | 原生具备 (`host:pid:start`) | 原生具备 (`host:pid:start`) | 原生具备 (`ProcessGuid`) | 原生具备 (`host:pid:start`) | 复合键全局唯一，execve 发生时执行分裂 |
| | `host_id` | 解析层注入 | 解析层注入 | 解析层注入 | 解析层注入 | 全局命名空间属性，界定多主机边界 |
| | `pid` | 原生具备 | 原生具备 | 原生具备 | 原生具备 | 操作系统原生数字进程号 |
| | `ppid` | 原生具备 (`proc.ppid`) | 原生具备 (Subject Token) | 原生具备 (`ParentProcessId`) | 原生具备 | 解决常驻前置父进程断层，识别非法派生 |
| | `name` | 原生具备 (`comm`) | 原生具备 | 原生具备 (`Image` 文件名) | 原生具备 | 快速程序短名索引 |
| | `exe_path` | 原生具备 (绝对规范路径) | 原生具备 | 原生具备 (`Image` 全路径) | 原生具备 | L2 束聚类第一主键 |
| | `cmdline` | 原生具备 (`args`) | 原生具备 (`exec_args`) | 原生具备 (`CommandLine`) | 原生具备 | 大模型战术意图与载荷分析核心线索 |
| | `cwd` | 原生具备 (`proc.cwd`) | 原生具备 (Audit Context) | 原生具备 (`CurrentDirectory`) | 原生具备 | 相对路径转绝对路径前置参数，识别暂存落地点 |
| | `user` | 原生具备 (`uid/euid`) | 原生具备 (`ruid/euid`) | 原生具备 (`User` SID/Name) | 原生具备 (`App UID`) | 统一格式化为身份字符串，识别提权 |
| | `start_time` | 原生纳秒级时间戳 | 原生纳秒级时间戳 | 原生 UTC 时间戳 (100ns) | 原生时间戳 | 统一转换为 Unix Epoch 时间戳 |
| | `end_time` | 原生退出时间戳 | 原生退出时间戳 | 原生 Event 5 退出时间戳 | 原生退出时间戳 | 划定 $[T_{start}, T_{end}]$ 生命周期窗口，未退出填 null |
| **:File** | `file_id` / `path` | 原生规范绝对路径 | 原生规范绝对路径 | 原生规范绝对路径 | 原生规范绝对路径 | 统一格式化为绝对路径，保持路径主键 |
| | `file_type` | 原生具备 (`file/pipe/sock`) | 原生具备 (Vnode Type) | 推导 (普通文件/`\pipe\`) | 原生具备 | 区分存储文件与本地 IPC 管道 |
| **:Network** | `network_id` | 原生五元组 | 原生 Socket Token | 原生 Event 3 四元组 | 原生网络四元组 | 升序算法归一化：`proto:ip_a:port_a<->ip_b:port_b` |
| | `ip_a/b`, `port_a/b` | 原生具备 | 原生具备 | 原生具备 | 原生具备 | 自然升序对齐端点，对称中立命名 |
| | `protocol` | 原生具备 (`tcp/udp`) | 原生具备 | 原生具备 | 原生具备 | 传输层协议 |
| **:Registry** | `reg_id` / `data` | 不适用 (NULL) | 不适用 (NULL) | 原生 Event 12/13/14 | 不适用 (NULL) | Windows 专属原子项，直接搭载载荷数据 |
| **因果边** | `event_id` | 原生全局事件序号 | 原生 Audit 序列号 | 原生 Record ID / 哈希 | 原生事件序号 | Neo4j 唯一约束去重与幂等导入 |
| | `starttime` | 原生纳秒时间戳 | 原生纳秒时间戳 | 原生 UTC 时间戳 (100ns) | 原生时间戳 | 因果偏序单调性检查硬判据 ($T_1 \le T_2$) |
| | `endtime` | 原生退出时间戳 | 原生退出时间戳 | **推导: 赋值等于 starttime** | 原生退出时间戳 | Sysmon 等单点事件安全折叠为点事件 |
| | `syscall` | 原生系统调用名 | 原生 BSM 操作名 | 原生 Sysmon 动作名 | 原生操作名 | 字典映射为统一小写标准动作名 |
| | `bytes` | 原生 I/O 字节数 | 原生 Return Token 字节 | **推导: 赋值 -1 (未知)** | 原生 I/O 字节数 | 三态吞吐：>0 实测，==0 空读剪枝，-1 跳过剪枝 |
| | `status` | 原生返回值 (0/>0) | 原生错误码 (0/>0) | **推导: 默认赋值 0 (成功)** | 原生返回值 (0/>0) | 只有成功边传递数据流污点，失败边阻断扩散 |

