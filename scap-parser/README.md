# scap-parser — SCAP 二进制流式图构建与入库系统

`scap-parser` 是 TraceSage 项目的标准数据摄取组件，用于将 Sysdig 采集生成的原始 `.scap` 二进制跟踪文件**直接流式解析**并构建为 Neo4j 主机级因果溯源图。

它彻底取代了“先在受害机上导出几十吉字节的中间 `.jsonl` 文本文件、再下载到本地解析”的传统高耗时、高磁盘占用流程，支持在任意平台（Windows、Linux、Docker、WSL2、远程虚拟机）以零中间文件、高并发流水线的方式直接入库。

---

## 1. 核心特性

- **零磁盘空间浪费**：直接读取紧凑的 `.scap` 捕获文件，无需在受害机或本地解压生成巨大（数 GB 至数十 GB）的文本 `.jsonl` 文件。
- **多后端无缝适配（Multi-Backend）**：
  - `local`：服务器或本地 Linux 环境原生调用已安装的 `sysdig` 二进制执行（最高优先级，纯本地无虚拟化损耗）。
  - `wsl`：Windows 环境下自动调用本地 WSL2 Linux 发行版解析（本地开发首选，近原生速度且零网络延迟）。
  - `ssh`：通过 SSH 管道将远端 Linux 受害者机上的 Sysdig 输出实时流式传输至本地，并在远端维护 MD5 文件缓存，Windows 开发机无需安装任何 Linux 环境。
  - `docker`：基于官方 `sysdig/sysdig:latest` 容器镜像跨平台容器化执行。
  - `auto`：智能探测当前环境并自动协商最优后端（优先级：`local` > `wsl` > `ssh` > `docker`）。
- **高并发生产者-消费者流水线（优化三）**：
  - 独立后台 I/O 线程接管管道数据读取，解耦网络/Sysdig 生成与 Python CPU 图构建。
  - 采用 1000 行/块的批量提交机制，将 Python 全局解释器锁（GIL）争用频率降低 1000 倍。
  - 设置容量为 100 块的有界内存队列，提供毫秒级背压保护（Backpressure），内存占用始终恒定在数十兆字节内。
- **双缓冲异步事务写入（优化 C）**：
  - 图解析主线程与 Neo4j Bolt 网络 I/O / Cypher 事务提交彻底解耦。
  - 边队列达到阈值（默认 50,000 边）时，主线程以 0ms 开销快照并清空缓冲，无缝继续解析，彻底消除 Stop-the-World 卡顿。
  - 独立后台写入线程（`AsyncNeo4jWriter`）负责顶点与因果边的参数化 Cypher MERGE 事务并发提交。
  - 配备容量为 2 批的有界背压队列与 Fail-Fast 异常捕获机制，进程正常退出或异常终止时均保证句柄安全关闭与 100% 数据一致性。
- **100.000% 绝对一致性保真**：
  - 全程采用标准转义 JSON 协议流，杜绝多行脚本参数截断风险。
  - 实体与边建模算法与既有图数据库完全一致，在各攻击场景下实测节点与边数达到 100% 零误差重合。

---

## 2. 架构设计与数据流走向

```
┌─────────────────────────────────────────────────────────────┐
│ 运行后端 (Backend Source: SSH / WSL2 / Docker / Local Linux)  │
│ - 执行: sysdig -r capture.scap -j -p '<标准字段规范>'        │
│ - 输出: 标准 JSON 文本字节流 (stdout pipe)                    │
└──────────────────────────────┬──────────────────────────────┘
                               │ 操作系统管道 (OS Pipe)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 【生产者】独立后台 I/O 读取线程 (Reader Thread)                 │
│ - 从 stdout 逐行非阻塞抽取，防止系统管道缓冲区 (64KB) 溢出挂起   │
│ - 每积攒 1000 行打包为一个 Batch (List[str])                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ put(batch)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 【行队列缓冲】有界线程安全队列 (queue.Queue, maxsize=100)      │
│ - 最多缓存 10 万行事件，自动实现流控与背压 (Backpressure)      │
│ - 子进程结束时放入 Sentinel 令牌，优雅终止线程                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ get()
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 【主解析流水线】Python 主线程                                │
│ - 极速 JSON 反序列化 (orjson)                                │
│ - 系统调用事件配对与实体注册 (FD Table & Entity Registry)    │
│ - 图拓扑边队列构建 (Edge Queue)                               │
│ - 到达 50,000 边阈值时 0ms 导出快照，无需停顿等待写入完成     │
└──────────────────────────────┬──────────────────────────────┘
                               │ submit_batch(processes, files, edges)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 【双缓冲事务队列】有界写入队列 (queue.Queue, maxsize=2)        │
│ - 容纳待入库图快照批次，提供背压保护，防止数据库繁忙积压内存    │
└──────────────────────────────┬──────────────────────────────┘
                               │ get()
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 【异步写入工】独立后台写入线程 (AsyncNeo4jWriterWorker)        │
│ - 执行参数化 Cypher MERGE 批量事务入库                       │
│ - 隐藏 Bolt 连接与事务提交延迟（单次 1.5s ~ 2.0s 完全被掩盖） │
└──────────────────────────────┬──────────────────────────────┘
                               │ execute_query()
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Neo4j 数据库 (attack-<场景名>)                              │
│ - 实体顶点: Process, File, Network                          │
│ - 关系因果边: 5 种带方向与时间戳的系统调用事件边                │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 目录结构

```
scap-parser/
├── README.md                  # 本文档
├── main.py                    # 命令行总入口（单场景、批量、探测、dry-run）
├── sources/                   # 多后端数据流抽象层
│   ├── base.py                # 抽象基类与流式批处理队列 (stream_process_batches)
│   ├── ssh.py                 # SSH 远端直连与 MD5 增量缓存流
│   ├── local.py               # 本地 Linux sysdig 管道流
│   ├── wsl.py                 # WSL2 子系统管道流
│   ├── docker.py              # Docker 容器管道流
│   └── factory.py             # 后端探测与工厂构建
└── parsers/                   # 图解析与入库核心逻辑
    ├── config.py              # 路径与配置解析
    ├── reporting.py           # 统计与耗时上报
    ├── jsonl/                 # JSON 流解析与模型映射 (record.py)
    ├── model/                 # 实体顶点与事件边数据结构
    ├── pipeline/              # 状态机（文件描述符表、实体注册表、事件配对）
    └── storage/               # Neo4j 驱动与参数化批量 Cypher 写入
```

---

## 4. 环境准备与依赖

在项目根目录下激活 Python 虚拟环境，并确保安装所需依赖：

```bash
# 激活项目虚拟环境
.venv\Scripts\activate       # Windows PowerShell / CMD
# source .venv/bin/activate  # Linux / macOS

# 核心依赖清单（orjson, neo4j, python-dotenv 等已包含在 requirements.txt 中）
pip install orjson neo4j python-dotenv
```

环境配置（根目录 `.env` 文件）：
```ini
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

---

## 5. 命令行使用说明

### 5.1 探测当前系统可用后端

```bash
python scap-parser/main.py --detect-backends
```
输出示例：
```
[SCAP Parser] Probing system execution backends...
  - local   : NOT AVAILABLE
  - wsl     : NOT AVAILABLE
  - ssh     : NOT AVAILABLE
  - docker  : NOT AVAILABLE
```

### 5.2 单场景直接流式导入（最常用）

无需手动指定数据库名，系统会自动根据场景名映射为标准的 `attack-<场景全名>` 小写连字符库：

```bash
# 导入场景 5（自动探测最优后端，默认 SSH 直连受害者机）
python scap-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot

# 导入场景 2
python scap-parser/main.py \
  --scap attack/data/2/capture.scap \
  --scenario 2_SSH_Spray_Lateral_Exfiltration
```

### 5.3 显式指定后端与连接参数

```bash
# 显式指定使用 SSH 后端并指定远端受害者机地址
python scap-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --backend ssh \
  --ssh-host 100.86.108.4 \
  --ssh-user ubuntu

# 在部署了 WSL2 的机器上使用 WSL 后端
python scap-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --backend wsl

# 在原生 Linux 服务器上使用 local 后端
python scap-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --backend local
```

### 5.4 试跑模式（Dry-Run：只验证解析，不写入 Neo4j）

适合调试或校验 SCAP 文件完整性：

```bash
# 快速试跑前 10000 条事件
python scap-parser/main.py \
  --scap attack/data/5/capture.scap \
  --dry-run \
  --max-events 10000
```

### 5.5 全量场景批量导入

对 `attack/data` 目录下所有场景的 `capture.scap` 文件进行批量全自动入库：

```bash
python scap-parser/main.py --scap-dir attack/data --all
```

---

## 6. 数据库规范与数据保真度验证

### 6.1 场景与 Neo4j 数据库映射对照表

每个场景独立存储在一个专属数据库中（前缀统一为 `attack-`）：

| 场景目录 / 编号 | SCAP 文件路径 | 映射 Neo4j 数据库名 |
|---|---|---|
| `1_Web_Exploit_Ransomware` | `attack/data/1/capture.scap` | `attack-1-web-exploit-ransomware` |
| `2_SSH_Spray_Lateral_Exfiltration` | `attack/data/2/capture.scap` | `attack-2-ssh-spray-lateral-exfiltration` |
| `3_Phishing_Beacon_Cryptomining` | `attack/data/3/capture.scap` | `attack-3-phishing-beacon-cryptomining` |
| `4_Repo_Poisoning_Backdoor` | `attack/data/4/capture.scap` | `attack-4-repo-poisoning-backdoor` |
| `5_Exposed_Service_Pivot` | `attack/data/5/capture.scap` | `attack-5-exposed-service-pivot` |

### 6.2 数据一致性评测结果

`scap-parser` 产出的图拓扑与历史基于磁盘 `.jsonl` 的 `sysdig-parser` 基线数据经过严格的双向比对，达到了 **100.000% 绝对一致**：

- **场景 5 (`5_Exposed_Service_Pivot`)**：
  - 顶点总数：`6,949` 节点（完全吻合）
  - 关系边总数：`79,602` 条边（完全吻合）
    - File -> Process: `59,336`
    - Process -> File: `18,434`
    - Network -> Process: `711`
    - Process -> Network: `501`
    - Process -> Process: `620`
  - 节点与边属性哈希比对：0 差异。
- **场景 2 (`2_SSH_Spray_Lateral_Exfiltration`)**：
  - 顶点总数：`8,149` 节点（完全吻合）
  - 关系边总数：`365,573` 条边（完全吻合）
    - File -> Process: `268,786`
    - Process -> File: `78,552`
    - Network -> Process: `6,837`
    - Process -> Network: `9,634`
    - Process -> Process: `1,764`
  - 节点与边属性哈希比对：0 差异。
