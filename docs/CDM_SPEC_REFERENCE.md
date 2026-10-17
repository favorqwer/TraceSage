# DARPA TC CDM (Common Data Model) 规范与参考指南

本目录包含美国国防高级研究计划局（DARPA）透明计算项目（Transparent Computing, TC）的官方通用数据模型（CDM）核心规范文件、官方 Schema 定义及由 BBN Technologies 发表在 USENIX TaPP 2020 上的设计论文。

---

## CDM 核心文献与规范文件清单

1. **`tapp2020-paper-khoury.pdf`**：
   - **论文标题**：*An Event-based Data Model for Granular Information Flow Tracking*
   - **发表会议**：12th International Workshop on Theory and Practice of Provenance (TaPP 2020), USENIX Association
   - **主要作者**：Joud Khoury, Timothy Upthegrove, Armando Caro, Brett Benyo, Derrick Kong (Raytheon BBN Technologies)
   - **核心价值**：官方阐述了 CDM 的设计动机、架构演进、颗粒度权衡、跨平台（Linux、Windows、BSD、Android）统一方法论以及在大规模网络攻防演练（Engagement）中的性能与经验教训。

2. **`TCCDMDatum.avsc`**：
   - **官方规范文件**：Apache Avro JSON Schema 格式的 CDM 顶层定义（版本：CDM 20）。
   - **定义内容**：包含完整的 16 个核心 Record 记录类型、枚举值及字段定义。

3. **`MULTI_OS_LOG_PARSER_DESIGN.md`**：
   - TraceSage 系统针对跨平台日志与 CDM 的**「4 类实体顶点 + 7 类因果边」**属性图落地详细主规范。

---

## CDM 20 核心模型架构概述

CDM 采用事件驱动的因果关系模型（Event-based Causal Model），其基本形式为：
$$\text{Subject} \xrightarrow{\text{Event}} \text{PredicateObject}$$

### 1. 核心记录类型（16 类 Datum Records）

在 `TCCDMDatum.avsc` 中，所有顶层记录均包装在 `TCCDMDatum` 联合体中：

| 记录类型 (Record Name) | 类型归属 | 核心职责说明 |
|---|---|---|
| **`Subject`** | 核心实体 | 操作系统中的执行活动主体，在现代 OS 中主要对应**进程（Process）**与**线程（Thread）**。包含 `cid`、`cmdLine`、`parentSubject`、`localPrincipal`、`startTimestampNanos` 等。 |
| **`FileObject`** | 客体实体 | 文件系统中的对象，包含普通文件、目录、特殊字符/块设备等。 |
| **`NetFlowObject`** | 客体实体 | 网络流对象，包含源/目的 IP、端口、传输层协议（TCP/UDP）等。 |
| **`RegistryKeyObject`** | 客体实体 | Windows 系统的特有客体，表示注册表的 Hive、Key 与 Value。 |
| **`IpcObject`** | 客体实体 | 进程间通信通道，包含匿名管道、命名管道（FIFO）、UNIX 域套接字等。 |
| **`MemoryObject`** | 客体实体 | 内存页或虚拟地址空间段，记录内存地址范围与保护权限。 |
| **`PacketSocketObject`**| 客体实体 | 原始数据包套接字（底层网络探测与抓包接口）。 |
| **`SrcSinkObject`** | 客体实体 | 传感器、外设等外部数据源与数据汇（Android/嵌入式环境扩展）。 |
| **`Host`** | 管理元数据 | 主机硬件与系统标识，包含 `hostId`、`hostName`、`osType`、`interfaces`。 |
| **`Principal`** | 身份元数据 | 用户与特权主体，包含 `userId`、`groupId`、`username`、Windows `securityIdentifier (SID)`。 |
| **`ProvenanceTagNode`** | 标签传播 | 细粒度（字节级/污点）因果标签流转节点，用于精确信息流跟踪。 |
| **`UnknownProvenanceNode`**| 兜底节点 | 未知或丢失因果链的占位节点。 |
| **`Event`** | 因果边/关系 | 系统中发生的操作事件，连接 `subject` 与 `predicateObject`，记录系统调用、时间戳、参数与字节流。 |
| **`UnitDependency`** | 单元因果 | 进程内部执行单元（如 Web 服务的单次请求处理循环）之间的依赖关系。 |
| **`TimeMarker`** | 流式辅助 | 流式日志分块与时间同步标记。 |
| **`EndMarker`** | 结束标记 | 会话或数据流结束标记。 |

---

### 2. CDM 官方定义的 56 种事件类型（`EventType` Enum）

在 `TCCDMDatum.avsc` 的 `EventType` 枚举中，官方收录了操作系统内核中的 56 种行为语义：

```text
 1. EVENT_ACCEPT                29. EVENT_MODIFY_PROCESS
 2. EVENT_ADD_OBJECT_ATTRIBUTE  30. EVENT_MOUNT
 3. EVENT_BIND                  31. EVENT_MPROTECT
 4. EVENT_BLIND                 32. EVENT_OPEN
 5. EVENT_BOOT                  33. EVENT_OTHER
 6. EVENT_CHANGE_PRINCIPAL      34. EVENT_READ
 7. EVENT_CHECK_FILE_ATTRIBUTES 35. EVENT_READ_SOCKET_PARAMS
 8. EVENT_CLONE                 36. EVENT_RECVFROM
 9. EVENT_CLOSE                 37. EVENT_RECVMSG
10. EVENT_CONNECT               38. EVENT_RENAME
11. EVENT_CORRELATION           39. EVENT_SENDTO
12. EVENT_CREATE_OBJECT         40. EVENT_SENDMSG
13. EVENT_CREATE_THREAD         41. EVENT_SERVICEINSTALL
14. EVENT_DUP                   42. EVENT_SHM
15. EVENT_EXECUTE               43. EVENT_SIGNAL
16. EVENT_EXIT                  44. EVENT_STARTSERVICE
17. EVENT_FLOWS_TO              45. EVENT_TRUNCATE
18. EVENT_FCNTL                 46. EVENT_UMOUNT
19. EVENT_FORK                  47. EVENT_UNIT
20. EVENT_LINK                  48. EVENT_UNLINK
21. EVENT_LOADLIBRARY           49. EVENT_UPDATE
22. EVENT_LOGCLEAR              50. EVENT_WAIT
23. EVENT_LOGIN                 51. EVENT_WRITE
24. EVENT_LOGOUT                52. EVENT_WRITE_SOCKET_PARAMS
25. EVENT_LSEEK                 53. EVENT_TEE
26. EVENT_MMAP                  54. EVENT_SPLICE
27. EVENT_MODIFY_FILE_ATTRIBUTES55. EVENT_VMSPLICE
28. EVENT_INIT_MODULE           56. EVENT_FINIT_MODULE
```

> **图建模工程分级**：在属性图落地时，这 56 类事件被进一步划分为：
> - **28 类因果边事件**：代表真实信息流、控制流以及关键攻击步骤（包含进程控制、文件读写/管道零拷贝、权限属主变更 `chmod`、服务端点监听 `bind` 等），在 Neo4j 中建立物理边；
> - **28 类纯粹非边事件**：包含内存 FD 句柄绑定与纯记账（如 OPEN, LSEEK, DUP, FCNTL）、状态审计（BOOT, LOGIN）、属性微调与框架标记，在解析器内存句柄表维护或转化为节点属性，严禁作为独立图边入库，从数学上杜绝依赖爆炸。
> 
> 详细映射与工程处理策略请参阅 [`MULTI_OS_LOG_PARSER_DESIGN.md`](./MULTI_OS_LOG_PARSER_DESIGN.md)。
