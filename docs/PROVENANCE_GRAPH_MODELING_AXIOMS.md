# 溯源图建模物理公理与工程规矩手册 (Provenance Graph Modeling Axioms & Principles)

> **文档定位**：本手册系统化梳理了系统级因果溯源图（System-level Provenance Graph）在跨平台日志解析、图建模、内核状态机维护与图数据库工程落地中的 **三大因果判决元公理与十六项物理工程规矩**。本手册是 TraceSage 全系统（解析器、图模型设计、智能体调查引擎与因果溯源）的最高因果与物理正确性约束准则。

---

## 目录

- [总纲：三大因果判决元公理 (Three Meta-Axioms for Causal Decision)](#总纲三大因果判决元公理-three-meta-axioms-for-causal-decision)
  - [元公理一：直接信息流与控制流传递公理 (Direct Flow Axiom)](#元公理一直接信息流与控制流传递公理-direct-flow-axiom)
  - [元公理二：因果可达性不灭与拓扑等价公理 (Causal Reachability Preservation Axiom)](#元公理二因果可达性不灭与拓扑等价公理-causal-reachability-preservation-axiom)
  - [元公理三：依赖爆炸阻断与局部状态收敛公理 (Dependency Explosion Prevention & Locality Axiom)](#元公理三依赖爆炸阻断与局部状态收敛公理-dependency-explosion-prevention--locality-axiom)
- [第一部分：实体与标识公理 (Entity & Identity)](#第一部分实体与标识公理-entity--identity)
  - [公理一：进程生命周期复合唯一性公理 (Lifecycle Uniqueness & PID Wraparound)](#公理一进程生命周期复合唯一性公理-lifecycle-uniqueness--pid-wraparound)
  - [公理二：映像重载裂变原则 (Process Versioning & Split on Execve)](#公理二映像重载裂变原则-process-versioning--split-on-execve)
  - [公理三：客体文件路径规范化与 Inode 冲突准则 (Canonicalization & Inode Recycling)](#公理三客体文件路径规范化与-inode-冲突准则-canonicalization--inode-recycling)
  - [公理四：网络连接时空四元组与临时端口准则 (Ephemeral Port Recycling)](#公理四网络连接时空四元组与临时端口准则-ephemeral-port-recycling)
  - [公理五：多主机环境物理级命名空间隔离公理 (Host Boundary Isolation)](#公理五多主机环境物理级命名空间隔离公理-host-boundary-isolation)
- [第二部分：因果与关系流动公理 (Causality & Direction)](#第二部分因果与关系流动公理-causality--direction)
  - [公理六：物理数据与控制载荷流向准则 (Physical Information Flow Direction)](#公理六物理数据与控制载荷流向准则-physical-information-flow-direction)
  - [公理七：时间偏序单调性公理 (Temporal Monotonicity & Clock Skew)](#公理七时间偏序单调性公理-temporal-monotonicity--clock-skew)
  - [公理八：系统调用生命周期二阶段与成败准则 (Syscall Enter/Exit Pairing & Return Code)](#公理八系统调用生命周期二阶段与成败准则-syscall-enterexit-pairing--return-code)
- [第三部分：状态机与句柄生命周期公理 (State Tracking & Handles)](#第三部分状态机与句柄生命周期公理-state-tracking--handles)
  - [公理九：文件描述符继承与 CLOEXEC 状态准则 (FD Table Inheritance & Cloexec)](#公理九文件描述符继承与-cloexec-状态准则-fd-table-inheritance--cloexec)
  - [公理十：句柄重定向与别名机制 (Handle Aliasing & dup/dup2/fcntl)](#公理十句柄重定向与别名机制-handle-aliasing--dupdup2fcntl)
  - [公理十一：隐式因果映射准则 (Implicit Flows: mmap & Shared Memory)](#公理十一隐式因果映射准则-implicit-flows-mmap--shared-memory)
- [第四部分：规模治理与依赖爆炸减灾公理 (Scale & Dependency Explosion)](#第四部分规模治理与依赖爆炸减灾公理-scale--dependency-explosion)
  - [公理十二：依赖爆炸扇出抑制公理 (Fan-out Explosion & Execution Partitioning)](#公理十二依赖爆炸扇出抑制公理-fan-out-explosion--execution-partitioning)
  - [公理十三：边折叠与滑窗聚合准则 (Edge Folding & Consolidation)](#公理十三边折叠与滑窗聚合准则-edge-folding--consolidation)
  - [公理十四：系统噪音分级降噪与剪枝边界公理 (Noise Reduction & Trade-off)](#公理十四系统噪音分级降噪与剪枝边界公理-noise-reduction--trade-off)
- [第五部分：图数据库物理工程落地死线 (Graph DB Implementation)](#第五部分图数据库物理工程落地死线-graph-db-implementation)
  - [公理十五：超级节点严禁公理 (No Attribute-as-Node Anti-pattern)](#公理十五超级节点严禁公理-no-attribute-as-node-anti-pattern)
  - [公理十六：索引先行与参数化微批提交公理 (Unique Index & UNWIND Batching)](#公理十六索引先行与参数化微批提交公理-unique-index--unwind-batching)
- [第六部分：全维度设计检查表 (Checklist)](#第六部分全维度设计检查表-checklist)
- [第七部分：权威参考学术文献 (References)](#第七部分权威参考学术文献-references)

---

# 总纲：三大因果判决元公理 (Three Meta-Axioms for Causal Decision)

在面对每秒数万条操作系统底层系统调用事件流时，为了让系统拥有一套客观、可复现、不可动摇的建边判决标准，TraceSage 确立了**三大因果判决元公理**。任何事件在进入图数据库之前，必须依次通过这三道安检门的判定：

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

### 元公理一：直接信息流与控制流传递公理 (Direct Flow Axiom —— 边的准入资格)
*   **公理定义**：只有当两个物理实体顶点之间发生了实质的数据载荷物理交换（Data Flow，如字节级读写、网络报文收发、共享内存交换），或者存在确切的进程控制权转移（Control Flow，如派生子进程、跨进程注入线程、异步中断信号）时，才具备在图数据库中构建有向边的物理资格。
*   **学术源流**：
    *   **格信息流模型与 Biba 完整性模型**（Dorothy Denning 1976 [16], Kenneth Biba 1977 [17]）：安全模型的因果判定前提是客体发生了 `Read` 或 `Write` 产生状态转换；
    *   **动态污点分析理论 DIFT**（Newsome & Song, NDSS 2005 [18]）：只有存在物理数据搬运时污点标签才发生传播；
    *   **DARPA TC CDM 规范**（BBN Technologies, TaPP 2020 [3]）：`Event` 记录的是主体（Subject）与客体（PredicateObject）之间明确的数据交互或控制。
*   **判决体现**：
    *   `EVENT_WRITE`（数据写盘）、`EVENT_RECVFROM`（接收网络包）、`EVENT_CLONE`（创建线程）符合元公理一，**准予建边**；
    *   `EVENT_LSEEK`（文件指针偏移寻道，传输数据严格为 0 字节）、`EVENT_DUP`（文件描述符别名复制，数据 0 字节）、`EVENT_READ_SOCKET_PARAMS`（获取套接字参数，数据 0 字节）属于进程内部指针计算，不符合元公理一，**严禁上图建边**。

### 元公理二：因果可达性不灭与拓扑等价公理 (Causal Reachability Preservation Axiom —— 证据链判据)
*   **公理定义**：溯源图的核心功能是图遍历算法（前向追踪 Forward Tracking 与后向根因分析 Backward Provenance）。边的去留判据在于：**删除该边是否会破坏从攻击源头（Entrypoint）到受害靶标（Victim）的有向因果路径可达性（Reachability）**。
    *   若删除该动作会导致攻击因果链断裂（例如丢失了权限变更赋权执行步骤），则该动作必须物理建边；
    *   若该动作在拓扑上已经由更底层、更精细的物理边所涵盖，或者仅属于句柄准备阶段、后续必然由真实读写闭环，则剔除或递延该边不会破坏源头到终点的拓扑可达性，无需建立多余的虚假边。
*   **学术源流**：
    *   **溯源图回溯开山之作 BackTracker**（King & Chen, SOSP 2003 [14]）：因果图是依赖有向无环图（DAG），攻击回溯是在 DAG 上搜索从靶标到根因的传递闭包；
    *   **溯源语义规范与传递缩约**（James Cheney 等, PODS 2007, TODS 2009 [19]; W3C PROV-DM）：因果图遵循传递等价性（Transitive Reduction），去除因果等价的冗余前置边不改变拓扑可达性。
*   **判决体现**：
    *   `EVENT_MODIFY_FILE_ATTRIBUTES`（`chmod +x` 赋予脚本执行权）与 `EVENT_BIND`（绑定后门监听端口）：若删除则破坏攻击推理链，**必须建物理边**；
    *   `EVENT_OPEN`（打开文件）：打开操作仅分配虚拟文件描述符（FD），传输数据严格为 0 字节。黑客后续窃取数据必然触发 `EVENT_READ`，写入恶意载荷必然触发 `EVENT_WRITE`，文件创建必然触发 `EVENT_CREATE_OBJECT`。因果链完全由后续读写边维持，因此 `open` **无需建边，因果严格递延至后续事件**；
    *   `EVENT_INIT_MODULE`（加载内核驱动）：驱动 `.ko` 文件此前必然已通过 `f2p`（`read` 或 `mmap`）建立因果边，可达性已被底层边覆盖，无需重复建边。

### 元公理三：依赖爆炸阻断与局部状态收敛公理 (Dependency Explosion Prevention & Locality Axiom —— 性能护城河)
*   **公理定义**：凡是不向外传递新信息流的操作，如果是实体内部状态或元数据的单向调整，一律**收敛为节点自身属性（Attribute Absorption）**；如果是高频且无害的只读探测与测试框架插桩标记，一律**在解析分发层直接过滤丢弃（Telemetry Pruning）**。严禁将微观探测与自身状态微调强行建边，从数学源头杜绝「超级节点爆炸」与「虚假图连通」。
*   **学术源流**：
    *   **依赖爆炸问题提出与单元分割 BEEP**（Lee 等, NDSS 2013 [20]）：首次从理论上剖析了长周期进程频繁读写公共文件导致整图虚假连通的“Dependency Explosion”灾难；
    *   **事件因果与状态转换解耦理论 ProTracer**（Ma 等, NDSS 2016 [4]）：证明了必须区分“事件驱动因果（建边）”与“状态驱动转换（内部消化或属性化）”，明确要求 `stat` 等高频事件不上图；
    *   **因果图减枝理论 PrioTracker & NodeMerge**（USENIX Security 2018 [7], ACM CCS 2018 [8]）：证明了高频非因果事件会导致图平均度数幂律激增，使图遍历算法时间复杂度退化为不可接受的指数级。
*   **判决体现**：
    *   `EVENT_CHANGE_PRINCIPAL`（提权 `setuid`）与 `EVENT_LOGCLEAR`（清空日志）：转化为 `:Process` 节点的内部属性 `p.euid = 0` 与标签 `p.suspicious_tags += 'log_clear'`，**不建自环边**；
    *   `EVENT_CHECK_FILE_ATTRIBUTES`（`stat/fstat` 元数据探测，日常数百万次）：**直接丢弃**，防止系统公共库被刺成百万度超级节点。

---


# 第一部分：实体与标识公理 (Entity & Identity)

图数据库中的顶点代表操作系统里的客观资源。如果标识符设计失误，后续所有的因果分析都会建立在“张冠李戴”的虚假图谱之上。

---

### 公理一：进程生命周期复合唯一性公理 (Lifecycle Uniqueness & PID Wraparound)

#### 1. 现象与底层原理
*   **PID 回绕（PID Wraparound）**：操作系统的进程号（PID）是一个有限的整型变量。在 Linux 默认配置下，`/proc/sys/kernel/pid_max` 仅为 32768。当高并发服务（如短生命周期的 CGI 脚本、Shell 编译构建任务、Cron 定时任务）快速启动和退出时，内核会在几分钟到几小时内**循环重用同一个 PID 数字**。
*   **Windows 下的 PID 极度复用**：Windows 内核中进程 ID 和线程 ID 统一由内核全局句柄表分配，且通常以 4 的倍数递增（如 1024, 1028）。一个进程刚调用 `ExitProcess` 退出，内核几毫秒后就会把这个 PID 分配给完全不相干的新进程。

#### 2. 违背公理的致命危害（幽灵进程重叠 Ghost Process Overlap）
若直接把 `PID: 1024` 作为图中的节点唯一标识（UID），图数据库中将会发生**时空坍塌**：
*   上午 09:00，一个恶意的黑客脚本以 PID 1024 运行，读取了敏感文件 `/etc/shadow` 后退出；
*   下午 15:00，正常的 Web 服务以 PID 1024 启动，向外部客户端返回正常的网页内容。
*   **后果**：图数据库会将这两个相差 6 小时的进程**强行合并为同一个图顶点**。当安全分析引擎进行后向追溯时，系统会得出荒谬的结论：“Web 服务把敏感密码发送给了外部客户端”，造成灾难性的误报与威胁归因错误。

#### 3. 严格工程规矩与判定维度
*   **主键合成公式**：
    $$\text{Process\_UID} = \text{Hash}(host\_id \parallel pid \parallel start\_time\_nanos)$$
*   **各判定维度标准**：
    *   **时间单位**：**必须精确至纳秒（nanoseconds）**。毫秒级时间戳在高并发脚本（如 `xargs -P`、并发构建）快速派生子进程时会出现毫秒内重名碰撞。
    *   **粒度**：进程级单实例。
    *   **边界**：进程从被 `fork/clone` 成功创建的瞬间开始，到被 `exit/kill` 彻底回收终止为止。
    *   **多实例处理**：只要进程启动时间戳不同，即便 PID、可执行文件路径、命令行参数完全一样，在图数据库中也**绝对必须是两个独立的顶点**。

---

### 公理二：映像重载裂变原则 (Process Versioning & Split on Execve)

#### 1. 现象与底层原理
在 Unix/Linux 进程派生模型中，创建并运行一个新程序分为两步：
1.  **`fork()` / `clone()`**：父进程复制一份自身的内存镜像，生成子进程。此时子进程与父进程运行相同的代码（如父进程是 Bash，子进程也是 Bash）。
2.  **`execve()`**：子进程调用 `execve(path, argv, envp)`。此时内核会**彻底销毁并释放该进程先前的所有代码段、数据段、堆和栈**，重新加载磁盘上的目标二进制文件（如 `/usr/bin/whoami`），但**操作系统的 PID 保持不变**。

#### 2. 违背公理的致命危害（黑盒进程状态污染 BBI）
如果在 `execve()` 发生后，依然让该进程沿用 `fork()` 时分配的同一个图节点，会导致**因果倒流与上下文污染**：
*   用户在 Bash 中输入了敏感环境变量；
*   Bash 通过 `fork()` 产生子进程，随后子进程调用 `execve("/bin/ls")` 列出目录；
*   若不裂变节点，图数据库会将 `ls` 发出的读目录边，与之前父级 Bash 加载配置文件 `.bashrc` 的边混在同一个实体上。在因果推断中，`ls` 会被错误判定为“读取并泄露了 Bash 的环境变量”。

#### 3. 严格工程规矩与拓扑构建
*   **裂变规矩**：**任何成功的 `execve()` 调用，必须强制终结前序进程状态，裂变为一个新的“进程版本节点”**。
*   **拓扑结构规范**：
```
┌─────────────────────────────────┐
│ Parent Process (e.g. sshd)      │
└────────────────┬────────────────┘
                 │ clone (p2p)
                 ▼
┌─────────────────────────────────┐
│ Child Process V1 (e.g. bash)    │
└────────────────┬────────────────┘
                 │ execve (p2p / version split)
                 ▼
┌─────────────────────────────────┐
│ Child Process V2 (e.g. whoami)  │
└─────────────────────────────────┘
```
*   **主键递增机制**：裂变出的新节点，其 UID 采用 `Hash(host_id || pid || exec_time_nanos)`，或在原主键后追加版本序号 `_v2`。

---

### 公理三：客体文件路径规范化与 Inode 冲突准则 (Canonicalization & Inode Recycling)

#### 1. 现象与底层原理
*   **路径多义性**：同一个文件在系统调用中可能以千奇百怪的形式出现：
    *   相对路径：`./config.yaml`、`../../etc/config.yaml`；
    *   符号链接（Symlink）：`/bin/sh -> /bin/dash`；
    *   硬链接（Hardlink）：多个目录项（dentry）指向磁盘上的同一个数据索引节点（Inode）。
*   **Inode 快速复用**：操作系统中，文件被 `unlink()`（删除）后，其 Inode 编号会被文件系统立即释放。几毫秒后新建一个完全不相干的文件，极大概率会分配到刚才释放的同一个 Inode 编号。

#### 2. 违背公理的致命危害
*   如果仅以**原始路径字符串**建节点：会导致同一文件的读写在图数据库中分散成数十个互不相连的孤立节点（`./a.txt` 和 `/home/user/a.txt` 断绝关联）。
*   如果仅以 **Inode** 建节点：黑客上传了恶意文件 `/tmp/malware`，执行后立刻删除；随后系统创建了正常的日志文件 `/var/log/daily.log`，刚好分配了同一 Inode。图数据库会把这两个文件算作同一个，导致后向追溯把正常日志文件误判为恶意木马。

#### 3. 严格工程规矩
*   **绝对路径规范化（Canonicalization）**：在系统调用入图前，解析器必须维护当前进程的工作目录（CWD, Current Working Directory）。遇到任何相对路径，必须结合 CWD 计算出**全局唯一的绝对真实路径**，并消除所有的 `.` 和 `..`。
*   **主键规范**：
    $$\text{File\_UID} = \text{Hash}(host\_id \parallel canonical\_path)$$
*   **版本控制（退化规矩）**：当文件被删除并重新创建时，如果需要精细化区分其内容快照，必须记录其 `version`（如 Linux 内核 `i_version` 或时间戳）。在标准溯源图中，以物理规范路径为核心实体标识。

---

### 公理四：网络连接时空四元组与临时端口准则 (Ephemeral Port Recycling)

#### 1. 现象与底层原理
*   **临时端口（Ephemeral Port）**：当系统作为客户端发起对外连接时，操作系统会从内核端口池（通常为 49152~65535）中临时借用一个端口。该连接一旦断开（进入 TIME_WAIT 状态并超时清除后），该端口会被内核迅速分配给另一个完全不同的程序。
*   **NAT 穿透与外网感知盲区**：在内网多主机环境中，多台机器通过同一个 NAT 网关访问外网时，从外部看源 IP 完全一致。

#### 2. 违背公理的致命危害
如果简单地以“本地 IP:本地端口”或永久性的“四元组”作为长期节点：
*   进程 A 在 10:00 借用 50001 端口连接了 GitHub；
*   进程 B 在 10:05 借用 50001 端口连接了黑客的恶意 C2 服务器；
*   图数据库会将这两个网络事件连接到同一个网络节点上，导致 GitHub 与黑客 C2 在拓扑上通过 50001 端口产生虚假的连通性。

#### 3. 严格工程规矩与判定维度
*   **实体划分标准**：将网络客体抽象为**通信端点（Endpoint）**与**会话流（Flow）**：
    *   **端点节点（Network Node）**：严格以通信的目的地为核心，即 `Remote_IP:Remote_Port:Protocol`。
    *   **主键公式**：
        $$\text{Network\_UID} = \text{Hash}(host\_id \parallel remote\_ip \parallel remote\_port \parallel protocol)$$
    *   **连接边载荷**：本地占用的临时端口（`local_port`）**绝对不能作为网络节点的主键**，它只能作为边（`p2n` 或 `n2p`）上的瞬时属性记录在具体通信发生的时间段内。

---

### 公理五：多主机环境物理级命名空间隔离公理 (Host Boundary Isolation)

#### 1. 现象与底层原理
企业真实网络环境必定包含数十到数千台主机。在分布式场景下，所有单机操作系统的命名空间完全平行独立：
*   主机 A 上有一个 `root` 用户运行的 PID 1000（`sshd`）；
*   主机 B 上也有一个 `root` 用户运行的 PID 1000（`dockerd`）；
*   两台主机都有 `/etc/passwd`、`/tmp/run.sh`。

#### 2. 违背公理的致命危害
如果数据库没有强制加上物理主机标识：
*   主机 A 上的攻击操作会和主机 B 上的日常运维在图谱中强行粘连在一起；
*   溯源引擎在查询主机 A 的失陷路径时，会顺着没有 `host_id` 隔离的文件路径跨越物理空间，“跳”到主机 B 上继续追踪，得出完全虚假的横向移动结论。

#### 3. 严格工程规矩
*   **最高优先级前缀**：所有图节点（进程、文件、注册表、网络套接字句柄）在生成任何主键前，**必须把 `host_id` 作为不可剥离的复合主键最高前缀**。
*   **跨机物理连通的唯一桥梁**：
    *   两台主机在图上的实体**绝对不能直接共享节点**；
    *   多主机之间唯一的合法因果连接路径，只能是：
        $$\text{Host\_A: Process} \xrightarrow{p2n} \text{Host\_A: Outbound\_Net} \Longrightarrow \text{Host\_B: Inbound\_Net} \xrightarrow{n2p} \text{Host\_B: Process}$$
    *   必须通过网络流量数据对齐（对端 IP、端口与传输时间匹配）来实现主机间的因果跳跃。

---

# 第二部分：因果与关系流动公理 (Causality & Direction)

图中的有向边决定了因果追溯（后向找根因、前向找受害范围）的方向。边方向错一步，图搜索算法全盘皆废。

---

### 公理六：物理数据与控制载荷流向准则 (Physical Information Flow Direction)

#### 1. 现象与底层原理
计算机底层本质是图灵机。一切因果关系，归根结底是**比特（Bits）在寄存器、内存与外部存储介质之间的物理转移**。
*   人类自然语言习惯用“主谓宾”语序描述行为：“进程 A 读取了密码文件 B”；
*   如果按照人类语序建图，容易直觉画出 `进程 A ──> 密码文件 B`。

#### 2. 违背公理的致命危害
溯源分析的核心算子是**后向追溯（Backward Trace / Root-Cause Analysis）**：即顺着入边（In-edges）去反查“谁的数据影响了我”。
*   如果读取操作画成 `Process ──> File`：
    *   当进程 A 被黑客控制，我们要追查它从哪里读了恶意脚本时，顺着入边去搜，**根本找不到文件 B**，反而会错漏关键的攻击载荷源头；
    *   搜索算法会误以为是文件 B 受到了进程 A 的写入污染，导致因果颠倒。

#### 3. 严格工程规矩（七大物理流动全貌对照表）

| 系统动作类型 | 物理底层流动本质 | 边类型 | 规范图边连接定义 | 语义解释 |
|---|---|---|---|---|
| **`read` / `pread` / `mmap(R)`** | 磁盘扇区数据读入进程内存页 | `f2p` | `(File) ──[read]──> (Process)` | 客体数据流入主体 |
| **`write` / `pwrite` / `truncate`** | 进程内存数据刷入磁盘扇区 | `p2f` | `(Process) ──[write]──> (File)` | 主体数据流向客体 |
| **`recv` / `read(socket)`** | 网卡接收缓冲区拷入进程堆栈 | `n2p` | `(Network) ──[recv]──> (Process)` | 外部数据流入主体 |
| **`send` / `write(socket)`** | 进程内存数据发往网卡驱动 | `p2n` | `(Process) ──[send]──> (Network)` | 主体数据泄露至外网 |
| **`fork` / `clone` / `inject`** | 操作系统控制权与执行上下文分裂 | `p2p` | `(Parent) ──[clone]──> (Child)` | 控制流从父传给子 |
| **`RegQueryValue`** (Windows) | 注册表配置字节读入内存 | `r2p` | `(Registry) ──[reg_query]──> (Process)` | 配置客体流入主体 |
| **`RegSetValue`** (Windows) | 进程将持久化配置写入注册表 | `p2r` | `(Process) ──[reg_set]──> (Registry)` | 主体数据修改客体 |

---

### 公理七：时间偏序单调性公理 (Temporal Monotonicity & Clock Skew)

#### 1. 现象与底层原理
物理世界中，因果律的前提是“原因必然发生在结果之前”。
在溯源图上，一条因果路径 $e_1 \to e_2 \to e_3$，其对应的时间戳序列必须严格满足非递减：
$$t(e_1) \le t(e_2) \le t(e_3)$$
但在操作系统多核并发环境下，不同 CPU 核心各自向内核环形缓冲区（Ring Buffer）提交日志，由于上下文切换和无锁队列并发，**事件刷盘顺序与物理发生顺序可能存在几十微秒的颠倒**。跨主机时钟（NTP）更有可能存在数十毫秒的漂移。

#### 2. 违背公理的致命危害（时间倒流回路 Time-Inversion Cycles）
如果图分析引擎允许“未来发生的事情作为过去的原因”：
*   时间戳颠倒会导致图中出现闭环：`进程 A ──> 进程 B ──> 进程 A`；
*   这会导致图遍历算法陷入死循环，或者在执行动态污点传播时产生“先花钱、后提款”的逻辑崩溃。

#### 3. 严格工程规矩与判定维度
*   **逻辑序列号（Lamport Sequence）保序**：
    *   在单机解析层，**绝对不能完全依赖单调时钟浮点数排序**；
    *   必须在系统调用事件流中引入**内核全局自增序列号（Event Sequence Number）**。同一主机上的因果边，优先根据内核事件序列号判定先后。
*   **跨主机偏斜容差（Clock Skew Tolerance）**：
    *   对于跨主机的网络边对齐，设定明确的时钟容差窗口 $\Delta t$（通常设定为 $50\text{ms} \sim 200\text{ms}$）。
    *   若对端接收时间在 $[t_{\text{send}} - \Delta t, t_{\text{send}} + T_{\text{RTT}}]$ 内，允许校正时钟建立有效边，并在边属性中明确标记 `clock_skew_corrected: true`。

---

### 公理八：系统调用生命周期二阶段与成败准则 (Syscall Enter/Exit Pairing & Return Code)

#### 1. 现象与底层原理
*   任何系统调用都是一个执行跨度（Span）。
*   在 `sys_enter` 时：内核刚收到请求，参数包含请求路径，但此时操作还未发生，FD 还不存在，也完全不知道磁盘是否满、权限是否够。
*   在 `sys_exit` 时：操作执行完毕，内核返回状态码（成功为 $\ge 0$ 的非负数，失败为负的错误码如 `-ENOENT`, `-EPERM`, `-EACCES`）。

#### 2. 违背公理的致命危害
*   如果解析器在 `sys_enter` 阶段就急于建边：一旦该系统调用随后被内核抛出错误崩溃（例如 `openat("/root/secret", O_RDONLY) = -EACCES` 被拒绝），此时数据根本没有读到进程内存中。如果提前建了读边，就会无中生有地制造出一条“凭空读取成功”的虚假证据链。

#### 3. 严格工程规矩
*   **状态暂存与延迟确认**：
    *   解析器内部按 `TID`（线程 ID）设立短期内存暂存区。在 `sys_enter` 收到事件时只存上下文参数；
    *   直到收到对应的 `sys_exit` 且确认返回值 $\ge 0$ 时，才提取实际客体、正式提交生成图边；
    *   配对超时或发生段错误退出时，清空暂存区，不建边。
*   **否定事实（Negative Facts / 失败调用）处理标准**：
    *   **通用常识**：对 `-ENOENT`（文件不存在）等日常失败，**直接丢弃，不建任何边**。
    *   **安全敏感降级**：对敏感操作失败（如暴力破解触发的密集 `-EACCES`、提权触发的 `-EPERM`），**严禁建普通因果边**，只将其转化为目标实体的统计属性（如 `failed_login_count: 50`），避免虚假数据流污染图谱。

---

# 第三部分：状态机与句柄生命周期公理 (State Tracking & Handles)

日志本身是离散、扁平的文本，真正的图因果完全依赖解析器内部的“内核级状态机”。

---

### 公理九：文件描述符继承与 CLOEXEC 状态准则 (FD Table Inheritance & Cloexec)

#### 1. 现象与底层原理
操作系统中，进程并不直接与文件、套接字交互，而是通过一个整数索引——**文件描述符（FD / HANDLE）**。
*   **继承性**：进程 A 打开了 `/etc/passwd`（分配了 FD 3）。当进程 A 调用 `fork()` 产生进程 B 时，进程 B 的内核句柄表被完整复制，进程 B 里的 FD 3 同样指向 `/etc/passwd`。
*   **`O_CLOEXEC`（Close-on-Exec）标志位**：如果打开文件时带了 `O_CLOEXEC` 标志，当进程随后调用 `execve()` 启动新二进制程序时，内核会自动关闭该 FD；如果没有设置该标志，新程序将继续持有该 FD 并能够读写。

#### 2. 违背公理的致命危害
如果在解析器中把 FD 当作全局静态变量或不考虑继承：
*   **ShadeWatcher 的严重缺陷复现**：ShadeWatcher 在其代码中处理不了 `close` 与内存映射的冲突，直接注销了 `SyscallClose()`。导致子进程长期运行中，所有的 FD 只增不减，旧的 FD 映射覆盖新的客体，使得后续成千上万个无关事件全都连到了最初打开的文件上，发生毁灭性的状态串线。

#### 3. 严格工程规矩（状态机三层表设计）
解析器内部必须实现与操作系统内核一致的句柄生命周期状态机：
```
┌─────────────────────────────────────────────────────────────────┐
│                    解析器进程-句柄核心状态表                    │
├─────────────────┬────────┬──────────────────────────────────────┤
│ 进程标识 (PID)  │ 句柄号 │ 映射指向的真实客体及属性             │
├─────────────────┼────────┼──────────────────────────────────────┤
│ PID: 1001       │ FD: 0  │ /dev/pts/1 (标准输入)                │
│ PID: 1001       │ FD: 1  │ /var/log/app.log (标准输出)          │
│ PID: 1001       │ FD: 3  │ /etc/shadow (Flags: O_RDONLY|CLOEXEC)│
│ PID: 1001       │ FD: 4  │ Socket(192.168.1.5:80 -> 1.1.1.1:443)│
└─────────────────┴────────┴──────────────────────────────────────┘
```
*   **生命周期规矩**：
    1.  `open/accept/socket` 成功返回 $\implies$ 在对应 PID 的句柄表中登记 `FD -> Object`；
    2.  `fork/clone` 成功 $\implies$ 将父进程整张句柄表深拷贝至子进程；
    3.  `execve` 成功 $\implies$ 遍历当前进程句柄表，**强制删除所有带有 `CLOEXEC` 标志的项**，仅保留未设置标志的项；
    4.  `close` 成功 $\implies$ 从当前进程句柄表中彻底移除该 FD；
    5.  `exit/kill` 进程退出 $\implies$ 销毁该进程的整张句柄表，防止内存泄漏。

---

### 公理十：句柄重定向与别名机制 (Handle Aliasing & dup/dup2/fcntl)

#### 1. 现象与底层原理
在命令行与后台守护进程中，重定向是极度常见的操作：
*   例如执行脚本：`app > output.log 2>&1`。
*   底层调用：程序打开了 `output.log` 得到 FD 3，然后通过 `dup2(3, 1)` 把标准输出（FD 1）重定向到该文件，再调用 `dup2(1, 2)` 把标准错误（FD 2）也重定向过去。
*   此时，FD 1、FD 2、FD 3 在内核中形成了**别名（Aliasing）**，全部指向同一个文件 `output.log`。

#### 2. 违背公理的致命危害
如果状态机只处理 `open`，遇到 `dup/dup2/fcntl(F_DUPFD)` 时不跟踪：
*   后续程序所有的 `printf` 或标准写操作（`write(fd:1, ...)`）在状态机中根本找不到客体；
*   导致解析器误以为程序只向屏幕输出了数据，漏掉了关键的攻击落盘日志（日志外溢丢失）。

#### 3. 严格工程规矩
*   状态机必须显式拦截并处理 `dup`, `dup2`, `dup3`, `fcntl`：
    *   当遇到 `dup2(old_fd, new_fd)` 时，如果 `new_fd` 已经打开了某个文件，先将其**隐式关闭并清理原映射**；
    *   然后将 `old_fd` 所指向的客体指针，完整同步拷贝至 `new_fd`，确立同等映射。

---

### 公理十一：隐式因果映射准则 (Implicit Flows: mmap & Shared Memory)

#### 1. 现象与底层原理
*   **内存映射（`mmap`）**：高效的数据处理程序或恶意载荷通常通过 `mmap()` 把磁盘上的可执行文件或大文件直接映射入进程的虚拟内存空间。
*   **内核盲区**：一旦映射建立，程序后续读取代码、修改文件内容全部通过**内存指针（Pointers）与 CPU 内存管理单元（MMU）直接完成**。**整个过程中操作系统内核绝不会拦截到任何一条 `read()` 或 `write()` 系统调用！**

#### 2. 违背公理的致命危害（失明漏洞 Blind Spot）
*   黑客通过 `mmap()` 加载并写入了一段无文件木马（Fileless Payload），随后立刻调用 `close(fd)` 关闭了句柄，之后在内存中肆意运行；
*   如果你依赖常规的 `read/write` 判定因果，你的溯源图在这里会出现**断层**，完全看不出进程到底从哪个文件吸取了恶意指令。

#### 3. 严格工程规矩
*   **原子化捕获**：解析器在捕获到 `mmap` 系统调用时，必须立即检查其内存保护标志（`prot`）：
    *   若包含 `PROT_READ`：立即视为一次完整的读取，**强制建立 `File ──[load/read]──> Process` 边**；
    *   若包含 `PROT_WRITE` 且映射标志包含 `MAP_SHARED`：立即视为一次完整的写入，**强制建立 `Process ──[write]──> File` 边**；
    *   绝不等待后续永远不会到来的读写调用。

---

# 第四部分：规模治理与依赖爆炸减灾公理 (Scale & Dependency Explosion)

如果一个图模型不能防止无节制的指数级扩散，它在工程上就毫无可用性。

---

### 公理十二：依赖爆炸扇出抑制公理 (Fan-out Explosion & Execution Partitioning)

#### 1. 现象与底层原理
*   **传递闭包与全图污染**：
    假设一个长期运行的后台系统守护进程（如 `systemd`、`sshd`、`dockerd`、`nginx`）。在过去的 72 小时里，它因维护自身运行，读取了 200 个系统配置文件；随后，攻击者通过某次 SSH 连接成功执行了一条恶意命令。
*   **数学崩溃**：
    由于该守护进程在图上是一个汇聚点，它拥有 $M$ 个入度边（先前的配置读取）和 $N$ 个出度边（后续的所有派生任务）。在图遍历算法计算传递闭包时，所有后续任务都会被追溯关联到前序的 200 个无辜配置文件上。**路径数量呈 $M \times N$ 发生扇出爆炸**。

#### 2. 违背公理的致命危害
*   当你请求“调查该次攻击的根因”时，溯源引擎返回的子图包含数万个节点，涵盖了操作系统的每一个角角落落，安全分析师根本无法人工甄别（“大海捞针”问题）。

#### 3. 严格工程规矩（`ProTracer` 与 `MPI` 的落地经验）
*   **逻辑分代（Epoch / Task Splitting）**：
    *   对于长周期进程，严禁使用单一大节点贯穿始终。
    *   **触发点切片**：每当长驻进程完成一次阻塞等待（如 `epoll_wait`、`accept` 收到新的网络连接）、或者在派生出不同任务时，在状态机中将其划分为新的**任务代数（Epoch）**，在图上虚拟裂变出 `sshd_session_1`、`sshd_session_2`；
    *   只将当前会话读入的输入传递给子进程，从源头上切断历史无关依赖的传播通道。

---

### 公理十三：边折叠与滑窗聚合准则 (Edge Folding & Consolidation)

#### 1. 现象与底层原理
在操作系统执行大量 I/O 时，底层系统调用极其细碎。例如读取一个 10MB 的脚本文件，解释器以 4KB 为缓冲区，会连续触发 2560 次 `read()`。
在没有聚合的原始图中，两个节点之间会平行拉出 2560 条结构一模一样的重复边。

#### 2. 违背公理的致命危害（存储与索引失衡 Storage Imbalance）
*   ACM CCS 2018（NodeMerge）的测量表明：未折叠的图中，**边的数量是节点的 20 到 30 倍以上**；
*   在 Neo4j 中，遍历一个拥有数万条平行边的节点，遍历性能会呈断崖式下跌，且数据库磁盘占用会成倍膨胀。

#### 3. 严格工程规矩
*   **滑窗聚合算法（Edge Folding Algorithm）**：
    *   定义聚合等价三元组：当且仅当两条边满足以下条件时，予以合并：
        $$\text{Source\_UID}_1 == \text{Source\_UID}_2 \quad \land \quad \text{Target\_UID}_1 == \text{Target\_UID}_2 \quad \land \quad \text{Relation}_1 == \text{Relation}_2$$
    *   **时间窗口阈值（Threshold）**：在固定滑动窗口内（通常取 **5 秒** 或 **单次文件打开至关闭的生命周期会话** 内），所有的细碎系统调用强制合并为一条复合边。
*   **聚合边全量属性结构规范**：
```json
{
  "relation": "write",
  "count": 2560,
  "start_time": 1718000000.000001,
  "end_time": 1718000001.005432,
  "total_bytes": 10485760
}
```
*   既保留了真实的吞吐数据和时间范围，又将边数量减少了 99.9%。

---

### 公理十四：系统噪音分级降噪与剪枝边界公理 (Noise Reduction & Trade-off)

#### 1. 现象与底层原理
*   IEEE S&P 2023 的 SoK 报告指出了整个学术界长久以来的谎言：**盲目的高比例数据压缩，往往以大幅度牺牲攻击检出率为代价**。
*   操作系统中，80% 的系统调用是由高度确定性、无攻击因果意义的系统底层行为产生的（如动态库加载、环境语言包探测、内核性能计数器读取）。

#### 2. 剪枝策略边界对照表

| 噪音类别 | 典型路径与系统调用示例 | 严格工程处理规矩 | 理论依据与理由 |
|---|---|---|---|
| **内核虚拟文件** | `/proc/meminfo`, `/proc/self/stat`, `/sys/...` | **完全阻断，绝加入图** | 纯粹的系统监控心跳，不承载任何持久化或攻击跨进程通信 |
| **共享只读动态库** | `/lib64/libc.so.6`, `/etc/ld.so.cache` | **仅在初始化时聚合一次或作为节点内联属性** | 几乎所有进程都会加载相同的 C 标准库，强行建边会把全系统进程全拉入同一星型网络 |
| **外壳终端配置** | `/etc/bash.bashrc`, `terminfo`, `locale` | **折叠或降噪丢弃** | 仅影响界面显示与环境格式，不包含攻击因果链 |
| **系统关键配置** | `/etc/passwd`, `/etc/shadow`, `/etc/hosts` | **坚决保留，绝对不可剪枝！** | **红线边界**：黑客信息搜集、提权、持久化篡改的核心目标，剪掉必将导致攻击漏报 |

---

# 第五部分：图数据库物理工程落地死线 (Graph DB Implementation)

无论图模型在纸面上多么完美，最终都要经受图数据库（Neo4j）的物理引擎拷问。

---

### 公理十五：超级节点严禁公理 (No Attribute-as-Node Anti-pattern)

#### 1. 现象与底层原理
*   一些以图神经网络（GNN）为导向的学术系统（如 ShadeWatcher）为了做邻居聚合嵌入，喜欢把节点属性抽出来建为实体节点：把用户 `root`、目录 `/bin`、权限 `0755` 统统建成独立的顶点。
*   **超级节点（Supernode / Dense Node）灾难**：在企业生产环境中，`root` 用户下可能会派生出数万个进程，数万条边同时密集连接到这单一节点上。

#### 2. 违背公理的致命危害
*   在 Neo4j 中，当 Cypher 查询尝试从一个普通进程开始向外进行 2 跳或 3 跳广度优先遍历时：
    一旦路径路过了 `root` 顶点，**遍历分支会瞬间向这数万个进程无差别扩散**！
*   结果是图数据库的内存工作集在数秒内被占满，CPU 100% 锁死，直接抛出 `OutOfMemoryError` 崩溃下线。

#### 3. 严格工程规矩
*   **实体与属性的绝对边界**：
    *   **只有具备独立行为能力的主体（Process）、能够被独立读写持久化数据的客体（File, Registry）、以及通信的边界（Network），才有资格成为图数据库中的顶点（Vertex）**；
    *   用户 ID（UID/User）、用户组（GID）、文件大小（Size）、文件路径目录层级（Directory）、访问模式（Mode），**必须作为节点的内部属性（Properties）存储，坚决不能拉成独立的图节点**！

---

### 公理十六：索引先行与参数化微批提交公理 (Unique Index & UNWIND Batching)

#### 1. 现象与底层原理
在向 Neo4j 写入海量节点与关系时：
*   **单条提交与锁机制**：如果每来一条日志就执行一次 `MERGE (p:Process {uid: ...})`，Neo4j 会为每个微小操作启动独立事务，并在全局模式（Schema）和行锁上频繁加锁解锁。
*   **无索引灾难**：如果没有在 `uid` 上预先建立唯一索引，每一次 `MERGE` 都会触发**全图遍历扫描**。当图节点达到 10 万时，写入速度会从每秒数万条跌落到每秒几条。

#### 2. 严格工程规矩
1.  **数据库冷启动第一步：必须先建全局约束（Constraints）**：
    在解析器写入任何一条数据前，必须由初始化脚本执行：
    ```cypher
    CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.uid IS UNIQUE;
    CREATE CONSTRAINT IF NOT EXISTS FOR (f:File) REQUIRE f.uid IS UNIQUE;
    CREATE CONSTRAINT IF NOT EXISTS FOR (n:Network) REQUIRE n.uid IS UNIQUE;
    CREATE CONSTRAINT IF NOT EXISTS FOR (r:Registry) REQUIRE r.uid IS UNIQUE;
    ```
2.  **严格使用官方驱动参数化微批（UNWIND Batching）**：
    *   **批次大小阈值**：设定在 **1,000 ~ 5,000 条边** 之间（太小吞吐低，太大单次事务内存过高）；
    *   **严禁裸字符串拼接**，严格将整批数据包装为字典列表通过参数（Params）传入：
    ```cypher
    UNWIND $batch AS event
    MATCH (sub:Process {uid: event.sub_uid})
    MATCH (obj:File {uid: event.obj_uid})
    CREATE (sub)-[r:p2f {
        action: event.action,
        count: event.count,
        start_time: event.start_time,
        end_time: event.end_time,
        total_bytes: event.total_bytes
    }]->(obj)
    ```

---

# 第六部分：全维度设计检查表 (Checklist)

| 判定维度 | 工业界与学术界统一标准口径 | TraceSage 落地规范要求 |
|---|---|---|
| **实体单位** | 纳秒级整数时间戳、绝对规范化路径、IP 四元组/五元组 | 时间戳统一采用 `nanos` 整数；路径严格消除 `.`、`..` 与软链接 |
| **颗粒度** | 系统调用级边界 + 进程生命周期单调分版 | 不做指令级污点，进程在 `execve` 发生时强制版本递增裂变 |
| **边界隔离** | 强制以物理主机作为数据隔离命名空间 | 所有实体 UID 统一前缀：`host_id + ...`，禁止跨机同名合并 |
| **多实例与复用** | PID 回绕、临时端口复用、Inode 回收 | 进程主键绑定 `start_time`；网络连接边附带会话生存期 |
| **流向定义** | 物理数据与控制载荷方向（非语法语序） | 读/接收：客 $\to$ 主；写/发送：主 $\to$ 客；衍生/注入：主 $\to$ 主 |
| **失败与重试** | 区分无害探测与攻击指征 | 读文件 `-ENOENT` 丢弃不建边；权限拒绝 `-EACCES` 计入属性 |
| **聚合与折叠** | 相同会话/时间窗内的同构边折叠 | 相同三元组在滑窗内合并为 1 条边，保留 `count`、`time_span`、`bytes` |
| **结构形态** | 属性属性化，严禁超级节点 | `user`、`path` 作为节点属性，坚决不建独立 `User` / `Directory` 节点 |
| **数据库优化** | 唯一约束先行，参数化微批提交 | 建立 `(:Process {uid})` 唯一约束，Cypher 严格通过 `UNWIND` 批量插入 |
| **降噪策略** | 过滤系统高频只读库与内核虚拟文件 | 拦截 `/proc`、`/sys` 轮询及静态 `.so` 加载，保留业务与安全相关配置文件 |

---

# 第七部分：权威参考学术文献 (References)

1.  **[IEEE S&P 2023]** Inam, M. A., et al. *"SoK: History is a Vast Early Warning System: Auditing the Provenance of System Intrusions."* In Proceedings of the 44th IEEE Symposium on Security and Privacy (S&P '23), 2023.
2.  **[ACM CCS 2023]** Dong, F., et al. *"Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools."* In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS '23), 2023.
3.  **[USENIX TaPP 2020]** Khoury, J., et al. *"Towards a Common Data Model for Transparent Computing."* In 12th USENIX Workshop on the Theory and Practice of Provenance (TaPP '20), 2020.
4.  **[USENIX Security 2016]** Ma, S., et al. *"ProTracer: Towards Practical Provenance Tracing by Alternating Between Taint Propagation and Event Logging."* In 25th USENIX Security Symposium (USENIX Security '16), 2016.
5.  **[USENIX Security 2018]** Ma, S., et al. *"MPI: Multiple Perspective Attack Investigation with Semantic-Aware Execution Partitioning."* In 27th USENIX Security Symposium (USENIX Security '18), 2018.
6.  **[USENIX Security 2018]** Xu, Z., et al. *"Causality Preserving Reduction for System Audit Logs."* In 27th USENIX Security Symposium (USENIX Security '18), 2018.
7.  **[USENIX Security 2018]** Liu, Y., et al. *"PrioTracker: Achieving Low-Overhead Provenance Tracking by Tracking Rarities."* In 27th USENIX Security Symposium (USENIX Security '18), 2018.
8.  **[ACM CCS 2018]** Tang, Y., et al. *"NodeMerge: Template-based Efficient Data Reduction for Big-Data Provenance."* In Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS '18), 2018.
9.  **[IEEE S&P 2018]** Hassan, W. U., et al. *"Winnower: Countering Provenance Graph Explosion via Structure-based Filtering."* In 2018 IEEE Symposium on Security and Privacy (S&P '18), 2018.
10. **[USENIX Security 2020]** Hossain, M. N., et al. *"Morse: Fine-grained Provenance Tracking for Process-centric Attack Investigation."* In 29th USENIX Security Symposium (USENIX Security '20), 2020.
11. **[IEEE S&P 2019]** Milajerdi, S. M., et al. *"HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows."* In 2019 IEEE Symposium on Security and Privacy (S&P '19), 2019.
12. **[NDSS 2019]** Hassan, W. U., et al. *"NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage."* In Network and Distributed System Security Symposium (NDSS '19), 2019.
13. **[ACM TOCS 2017]** Pasquier, T., et al. *"Practical Whole-System Provenance Capture."* ACM Transactions on Computer Systems (TOCS), 35(3), 2017. (CamFlow 系统)
14. **[SOSP 2003]** King, S. T., and Chen, P. M. *"Backtracking Intrusions."* In Proceedings of the 19th ACM Symposium on Operating Systems Principles (SOSP '03), 2003. (溯源图奠基之作)
15. **[ACM CCS 2021]** Alsaheel, A., et al. *"ALCHEMIST: Fusing Network and Host Logs for High-Fidelity Provenance Analysis."* In Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security (CCS '21), 2021.
16. **[CACM 1976]** Denning, D. E. *"A Lattice Model of Secure Information Flow."* Communications of the ACM, 19(5), 1976. (格信息流模型奠基之作)
17. **[ESD-TR 1977]** Biba, K. J. *"Integrity Considerations for Secure Computer Systems."* Electronic Systems Division, Technical Report ESD-TR-76-372, 1977. (Biba 完整性模型)
18. **[NDSS 2005]** Newsome, J., and Song, D. *"Dynamic Taint Analysis for Automatic Detection, Identification, and Signature Generation of Exploits on Commodity Software."* In Proceedings of the 12th Network and Distributed System Security Symposium (NDSS '05), 2005. (DIFT 动态污点分析开山之作)
19. **[PODS 2007]** Cheney, J., et al. *"Provenance in Databases: Why, How, and Where?"* In Foundations and Trends in Databases, 2009 / ACM PODS 2007. (数据与因果溯源传递缩约)
20. **[NDSS 2013]** Lee, K. H., et al. *"High Accuracy Attack Provenance via Bounded Execution Partitioning."* In Network and Distributed System Security Symposium (NDSS '13), 2013. (BEEP 细粒度执行单元分割与依赖爆炸阻断)

