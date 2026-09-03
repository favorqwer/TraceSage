所有 16 个 Java 源文件和 `pom.xml` 都已读完。下面我来从头到尾给你完整串一遍。

---

## 旧版 Java 解析器全流程梳理

### 一、整体架构与数据流

```
ParsersMain (入口)
  └─ MySysdigLogParser (核心解析引擎)
       ├─ 读取 JSONL 日志（Scanner 逐行）
       ├─ Utils.parseEntry() 解析原始字段
       ├─ 进入/退出记录配对
       ├─ 提取顶点（Process / FileEntity / NetworkEntity）
       ├─ 走系统调用路由 → 生成 EventEdge
       ├─ 累积到分类列表缓冲区
       └─ 达到阈值时 flush → Postgres 批量写入 PostgreSQL
```

### 二、启动入口：ParsersMain

[pom.xml](/E:/Work/TraceSage/sysdig-parser/pom.xml) 里 `maven-shade-plugin` 的 `mainClass` 指向 `parsers.ParsersMain`，所以打包后 `java -jar` 直接运行它。

命令行参数：
```
java -jar sysdig-parser.jar <logFile> postgres/<dbName> [hostId] [startUid] [startEventId]
```

- `hostId` > 0 时启用**多主机模式**（会在 SQL 中额外插入 `hostid` 列）
- `startUid` / `startEventId` 是顶点和事件边的**自增 ID 起始值**，用于避免不同主机间的 ID 冲突

ParsersMain 只做参数校验，然后把所有参数传给 `MySysdigLogParser` 并调用 `parseEntry()`。

### 三、日志行解析：Utils.java

`parseEntry()` 按空格拆分一行：

```
5620 173005.456789012 3 my_process 12345 > open cwd=/home ...
```

各字段索引逻辑：
1. `fields[0]` = **eventno**（事件序号）
2. `fields[1]` = **timestamp**（秒.纳秒，如 `173005.456789012`）
3. `fields[2]` = **cpu**（CPU 编号）
4. `fields[3]` 到 pid 标记之前 = **process**（进程名，可能含空格）
5. pid 标记（形如 `(12345)` ）= **pid**
6. `pid+1` = **direction**（`>` 进入 / `<` 退出）
7. `pid+2` = **event**（系统调用名，如 `open`、`read`）
8. `pid+3` = **cwd**（当前工作目录，去掉 `cwd=` 前缀）
9. 最后字段如果等于 `(deleted)`，则 `latency` 和 `exepath` 位置前移一位，args 截断范围相应调整
10. 倒数第二个字段（`latency=xxx`）去掉前缀 = **latency**
11. 最后一个字段（`exepath=xxx`）去掉前缀 = **exepath**
12. 中间剩余字段拼接为 **args**

此外还有三个辅助方法：
- `extractSize(args)`：从 `res=xxx` 中提取返回值（非负时作为文件操作的数据量，负值表示失败）
- `extractFileandSocket(args)`：从 `fd=...` 字段解析文件路径或网络 socket 端点（支持 `<f>path</f>` 文件描述符和 `<4t>ip:port->ip:port</4t>` 套接字描述符）
- `extractProcessFile(args)`：从 `filename=...` 字段提取文件名

### 四、系统调用配置：MetaConfig + 系统调用工厂

**MetaConfig.java** 定义了四类系统调用名列表：

| 方向 | 类型标签 | 系统调用 |
|------|---------|---------|
| P → F | `PtoF` | write, writev, rename |
| F → P | `FtoP` | read, readv, rename |
| P → N | `PtoN` | sendto, sendmsg, write, writev |
| N → P | `NtoP` | read, recvmsg, readv, recvfrom |

**Fingerprint** 是一个三元素组合键：`{事件名, 起始实体类型, 结束实体类型}`，用于在 `answering` 映射中查找匹配的系统调用处理器。

**SystemCall** 是一个事件处理器的封装：包含 `name`、`type`（方向标签）、`fingerPrint` 和 `onMatch`（Action 列表）。`react()` 方法遍历所有 Action 并依次执行。

**SystemCallFactory** 是一个工厂，用于批量创建同类系统调用处理器。你传入一个方向标签和实体类型，它自动生成自增 ID 和 Fingerprint，并附加公共 Action。

### 五、核心解析引擎：MySysdigLogParser

这是最复杂的类，约 1100+ 行，我们按阶段拆解：

#### 5.1 初始化阶段

在构造函数中：
1. 初始化所有缓冲区和计数器
2. 调用 `registerSystemCalls()` 注册所有系统调用处理器

#### 5.2 注册系统调用（registerSystemCalls）

这块是**事件路由的核心**，按类型分组：

**a) 四类通用系统调用（通过工厂批量创建）**

每个工厂先添加公共 Action：
- `updateP2PLinks`：更新 `backFlow` 和 `forwardFlow` 中已存在进程间边的结束时间（用于扩展 execve 边的生命周期）
- 方向特定的 add 方法（如 `addP2FEvent`、`addF2PEvent` 等）

对于 `PtoF`、`FtoP`、`PtoN`、`NtoP` 四类，从 MetaConfig 读取系统调用名列表，用工厂创建并注册。

**b) execve（特殊处理，内联 lambda）**

execve 的流程：
1. 提取入口进程 `pStart` 和可执行文件 `FileEntity`
2. 提取出口进程 `pEnd`
3. 如果 `args` 包含 `res=0`（成功）：
   - 生成 `file → process` 边（execve 的可执行文件到新进程）
   - 从 `args` 中正则 `ptid=(parentPID)(parentName)` 提取父进程
   - 生成**两条** `process → process` 边：
     - **正向边**（`forwardFlow`）：`parent → child`，`syntheticReverse=false`
     - **反向边**（`backFlow`）：`child → parent`，`syntheticReverse=true`
   - 反向边用于后续其他系统调用发生时，通过 `updateP2PLinks` 更新其结束时间

**c) accept（特殊处理）**

生成两条边：
- `network → process`（正向，`syntheticReverse=false`）
- `process → network`（反向，`syntheticReverse=true`）

**d) fcntl（特殊处理）**

生成一条 `network → process` 边（无反向边）。

**e) rename（特殊处理）**

从 `args` 中正则提取 `oldpath=... newpath=...`，生成两条边：
- `oldFile → process`（rename 操作的文件读取）
- `process → newFile`（rename 操作的文件写入）

#### 5.3 主解析循环（parseEntry）

1. 用 `BufferedInputStream` + `Scanner` 逐行读取
2. **行过滤**：跳过以 `....` 开头的行（Sysdig 续行标记），以及不包含 `exepath` 的行
3. 对有效行，调用 `Utils.parseEntry()` 解析为 `Map<String, String>`
4. 调用 `validateParsedEntry()` 验证字段完整性，并预解析数值类型

#### 5.4 进入/退出记录配对

这是旧版解析器最关键的机制之一：

**a) 进入记录（`>` 方向）**：调用 `storeIncompleteStart()`，以 `{startNs, tid, event}` 为 `EventKey` 存储到 `incompleteEvents` 映射中。同时以 `{tid, event}` 为 `ThreadEventKey` 存储到 `incompleteEventsByThreadAndEvent` 作为备用索引。

**b) 退出记录（`<` 方向）**：调用 `processEvent()`，尝试按以下优先级配对：

1. **精确匹配**：用相同的 `EventKey` 从 `incompleteEvents` 查找，匹配则移除并处理
2. **线程+事件名回退**：如果精确匹配失败，按 `ThreadEventKey` 从 `incompleteEventsByThreadAndEvent` 取一个待处理记录
3. **容忍回退**：如果前两步都失败，从 `incompleteEvents` 中搜索时间戳差异在 `PAIRING_FALLBACK_TOLERANCE_NANOS`（1000ns）内的记录
4. 如果所有配对都失败，生成一个**虚拟开始记录**（dummy start），用退出记录自身的时间戳作为开始时间

配对成功后，提取顶点（`extractEntities`），构造 Fingerprint，从 `answering` 映射中找到对应的 `SystemCall`，调用 `react()` 生成事件边。

#### 5.5 顶点提取（extractEntities）

`extractEntities()` 返回 `Entity[2]`：
- `res[0]` = **Process**（通过 `pid + processName` 作为唯一键，从缓存获取或创建）
- `res[1]` = 根据 args 中的描述符信息决定：
  - 优先识别文件路径 → **FileEntity**
  - 其次识别 `filename=` → **FileEntity**
  - 其次识别 `sip+sport+dip+dport` → **NetworkEntity**
  - 否则为 `null`

顶点创建时分配自增 `UID`，并累加到 `pendingFiles/pendingProcesses/pendingNetworks` 缓冲区中。

#### 5.6 事件边生成

事件边统一用 `EventEdge` 表示，包含 `source`、`sink`、`id`、`event`（系统调用名）、`size`（数据量）、`startns`、`endns`、`eventNo`、`syntheticReverse` 标记。

按方向入队到五个分类列表：
- `processFileLst`（P→F）
- `fileProcessLst`（F→P）
- `processNetworkLst`（P→N）
- `networkProcessLst`（N→P）
- `processProcessLst`（P→P，仅 execve）

#### 5.7 批量刷新（flushBufferedRecords）

每当缓冲区中边总数达到 `flushEdgeLimit`（默认 50000，可配置），就触发一次 flush：

1. 将缓冲区的数据副本传给 `Postgres` 实例
2. 调用 `insertRecords()` 执行批量写入
3. 清空所有缓冲区

最后在日志处理完毕后，再进行一次最终 flush（包含 process-process 边）。

### 六、数据模型

**Entity**（基类）：`reputation`（信誉值，始终为 0.0）、`uniqID`（自增唯一 ID）、`host`（主机标识）

**Process**：`pid`、`uid`、`groupID`、`name`、`exePath`。唯一键 = `pid + name`

**FileEntity**：`userID`、`groupID`、`path`。唯一键 = `path`

**NetworkEntity**：`srcAddress`、`dstAddress`、`sPort`、`dPort`。唯一键 = `srcIP:srcPort->dstIP:dstPort`

**EntityNode**：对 Entity 的包装，用于边中区分 source/sink 的具体类型。内部只保留一个非空引用（`f` / `n` / `p` 之一）

**EventEdge**：`source`（EntityNode）、`sink`（EntityNode）、`id`、`event`（系统调用名）、`size`、`startns`、`endns`、`eventNo`、`syntheticReverse`（布尔标记，用于标识自动生成的逆向边）、`host`

### 七、数据库持久化：Postgres.java

连接到 `jdbc:postgresql://localhost:5432/{dbName}`，用户名 `postgres`，密码 `12345678`（硬编码）。

按顺序批量写入 6 张表：

| 表 | 写入内容 | 关键列 |
|----|---------|--------|
| `file` | FileEntity | id, ownergroupid, hostname, (hostid), name, owneruserid |
| `process` | Process | id, exename, ownergroupid, hostname, (hostid), pid, owneruserid |
| `network` | NetworkEntity | id, dstip::cidr, dstport, hostname, (hostid), srcip::cidr, srcport |
| `processevent` | P→P 边 | id, starttime, endtime, srcid, dstid, optype, hostname, (hostid), eventno, is_synthetic_reverse |
| `fileevent` | P→F / F→P 边 | id, starttime, endtime, srcid, dstid, optype, hostname, (hostid), amount, eventno |
| `networkevent` | P→N / N→P 边 | id, starttime, endtime, srcid, dstid, optype, hostname, (hostid), amount, eventno, is_synthetic_reverse |

**多主机模式**（hostId > 0）：所有表额外写入 `hostid` 列；process 表使用 `ON CONFLICT ... DO UPDATE` 更新 `exename`。

**批量写入**：默认 batch size 10000，通过 `PROGQL_POSTGRES_BATCH_SIZE` 环境变量或 `progql.postgres.batch.size` 系统属性配置。

### 八、关键设计要点

1. **进入/退出配对**：通过 EventKey（时间戳+线程+事件名）实现精确匹配，多种回退策略处理乱序或丢失的日志
2. **双向边**：execve 和 accept 生成两条方向相反的边，用 `syntheticReverse` 标记系统生成的逆向边
3. **进程间边的时间扩展**：`updateP2PLinks` 在每次子进程发生新系统调用时更新 execve 边的结束时间，使其反映子进程的活跃周期
4. **ID 管理**：顶点和边使用独立的递增计数器，可通过命令行参数指定起始值
5. **流式处理**：1MB 的缓冲输入流，批量 flush 避免内存爆炸
6. **进度报告**：每 15 秒（可配置）输出处理进度、速率和 ETA，每 5000 行检查一次

---

这就是旧版 Java 解析器的完整流程。核心思路是：**逐行解析 Sysdig JSONL → 配对进入/退出记录 → 从文件描述符提取实体 → 按系统调用类型路由到对应处理器 → 生成方向化事件边 → 批量写入 PostgreSQL**。新 Python 版需要切割同样的逻辑，但改用 Python + Neo4j 驱动，并且不能直接复制这里的 SQL 表结构或 Java 类设计。