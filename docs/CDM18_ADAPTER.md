# CDM18 数据源适配（DARPA TC Engagement 3）

## 1. 这份文档解决什么

`provenance-parser` 原本只有一个输入形态：sysdig `.scap`（`main.py --scap`）。
DARPA TC Engagement 3 的数据是 CDM18 的 Avro-JSON 行式日志，两者在字段、事件语义、
对象引用方式上完全不同。本适配把 CDM18 接进同一套图模型（3 类顶点、5 类边、同一套
`host_id` 前缀主键），不改动 sysdig 主干。

- 入口：`provenance-parser/cdm_main.py`
- 代码：`provenance-parser/provenance/adapters/cdm/`
- 映射表：`provenance-parser/data/cdm_events.toml`（事件 -> 动作的唯一转录点）
- 单测：`provenance-parser/tests/test_cdm_{decode,archive,mapping,emit}.py`（44 个用例）

## 2. 数据形态与实测规模

| | `ta1-trace-e3-official-1.json.tar.gz` | `ta1-theia-e3-official-6r.json.tar.gz` |
|---|---|---|
| 压缩 / 解压 | 1.28 GB / 20.64 GB | 1.55 GB / 48.00 GB |
| 成员数 | 7 | 13 |
| 记录数 | 32,130,374 | 63,852,494 |
| Event 数 | 21,914,150 | 59,634,578 |
| 时间范围（UTC） | 2018-04-13 13:56:26 – 21:10:05 | 2018-04-10 16:44:33 – 2018-04-13 21:04:30 |
| 主机数 | 1（`E621F964-5A66-0F89-30E0-67ADB2A5EC28`，hostName `ta1-trace`） | 1（`0A00063C-5254-00F0-0D60-000000000070`） |

每行一条 Avro-JSON 记录，`datum` 的唯一键给出记录类型，共 16 种：
`Host / Principal / ProvenanceTagNode / Subject / FileObject / UnnamedPipeObject /
RegistryKeyObject / PacketSocketObject / NetFlowObject / MemoryObject / SrcSinkObject /
Event / UnitDependency / TimeMarker / StartMarker / EndMarker`。

格式要点（`decode.py` 负责解包）：

- 联合类型带类型键：`"threadId":{"int":412}`、`"sequence":{"long":36}`、`"cmdLine":{"string":"..."}`；
- UUID 也是包装：`"subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"..."}`；
- 属性字典是 `map<string,string>`：`"properties":{"map":{"rc":"0","mode":"0644"}}`，
  值全是字符串，取整数要再转一次；
- 全零 uuid（`00000000-0000-0000-0000-000000000000`）表示「没有客体」。

## 3. 顶点身份规则

### Process ← Subject

主键 `(host_id, container_id="", pid=cid, start_ns=startTimestampNanos)`。

| 属性 | 来源 | 实测 |
|---|---|---|
| `pid` | `Subject.cid` | 100% |
| `start_ns` | `Subject.startTimestampNanos`，0 保留为 0（模型里 0 = 未知） | THEIA 493/494 非零；TRACE 461/532 非零 |
| `exe_path` | `Subject.properties.map.path` | THEIA 494/494；**TRACE 0%**（TRACE 只有 `name`，不是路径，不填） |
| `cmdline` | `Subject.cmdLine` | THEIA 有；TRACE 为 null |
| `ppid` | `properties.map.ppid` | THEIA 485/494；TRACE 532/532 |
| `uid` / `euid` | `Principal.userId` / `Principal.properties.map.euid` | 有 Principal 即可 |
| `container_id` | 恒 `""` | 两套数据都是单机裸系统 |
| `container_privileged` / `container_host_root_rw` | **不写**（未知 ≠ false） | — |

### File ← FileObject

主键 `(host_id, "", path)`。路径优先级：`baseObject.properties.map.path`（TRACE 873/873）
→ `properties.map.filename`（THEIA 1,968/1,983）→ `Event.predicateObjectPath`
（TRACE 8.9% 的事件带，THEIA 0%）→ 都没有则不建点。

`file_type` 映射：`FILE_OBJECT_FILE→file`、`FILE_OBJECT_DIR→directory`、
`FILE_OBJECT_NAMED_PIPE→pipe`、`FILE_OBJECT_UNIX_SOCKET→unix`、
`FILE_OBJECT_BLOCK/CHAR/PEFILE→unknown`（枚举里没有设备节点，写 `file` 是没有证据的结论）。

### Network ← NetFlowObject

主键 `(host_id, endpoints)`，`endpoints = "{localAddress}:{localPort}->{remoteAddress}:{remotePort}"`，
`proto` 由 `ipProtocol` 整数映射（6→tcp、17→udp、1→icmp、58→icmpv6）。

**口径声明**：这是「本机端点 -> 对端端点」，与 sysdig 里由连接元组渲染的 endpoints
不是同一口径。CDM 库里的 Network 顶点不能与既有 `attack-*-v2` 库对拍。

### 不建顶点的记录（按公理 R3：无名的对象不建顶点）

`SrcSinkObject`、`MemoryObject`、`UnnamedPipeObject`、`PacketSocketObject`、
`RegistryKeyObject`。它们只计数，报告里按类型列出。

### 3.1 成员顺序：为什么 `.1` 后面是 `.10`

THEIA 归档里的成员物理顺序是

```
ta1-theia-e3-official-6r.json
ta1-theia-e3-official-6r.json.1
ta1-theia-e3-official-6r.json.10
ta1-theia-e3-official-6r.json.11
ta1-theia-e3-official-6r.json.12
ta1-theia-e3-official-6r.json.2
ta1-theia-e3-official-6r.json.3
```

这是**归档本身**的顺序（打包时按文件名字符串排序，`"10" < "2"`），不是读取端的排序结果。
按数字后缀重排后，成员的起止时间严格首尾相接，证明数字序才是时间序：

| 序号 | 成员 | 首事件（UTC） | 末事件（UTC） |
|---|---|---|---|
| 0 | `.json` | 2018-04-10 16:44:33 | 2018-04-10 19:13:59 |
| 1 | `.json.1` | 2018-04-10 19:13:59 | 2018-04-10 22:25:18 |
| 2 | `.json.2` | 2018-04-10 22:25:18 | 2018-04-11 11:50:09 |
| 3 | `.json.3` | 2018-04-11 11:50:09 | 2018-04-11 15:14:35 |
| 4 | `.json.4` | 2018-04-11 15:14:35 | 2018-04-11 18:18:01 |
| 5 | `.json.5` | 2018-04-11 18:18:01 | 2018-04-11 22:17:07 |
| 6 | `.json.6` | 2018-04-11 22:17:07 | 2018-04-12 10:19:17 |
| 7 | `.json.7` | 2018-04-12 10:19:17 | 2018-04-12 14:35:21 |
| 8 | `.json.8` | 2018-04-12 14:35:21 | 2018-04-12 18:57:12 |
| 9 | `.json.9` | 2018-04-12 18:57:12 | 2018-04-12 23:20:43 |
| 10 | `.json.10` | 2018-04-12 23:20:43 | 2018-04-13 12:45:25 |
| 11 | `.json.11` | 2018-04-13 12:45:25 | 2018-04-13 16:12:33 |
| 12 | `.json.12` | 2018-04-13 16:12:33 | 2018-04-13 21:04:30 |

两种模式的行为：

- 默认（`member_mode=sorted`）：按数字后缀升序读，时间单调。
  代价是 tar.gz 不能随机定位，需要先建整包成员索引（THEIA 49.9 s）并在成员物理位置
  回退时重新解压（THEIA 一次回绕，约 2 分钟）。
- `--tar-order`：单趟流式按物理顺序读，最快，但时间戳不单调，且**会丢边**：
  THEIA 成员 `.10` 在 tar 里排第 3，它的事件引用 `.2`–`.9` 里发布的 Subject，
  那些成员物理上更靠后，于是 `.10` 的 70.6% 事件查不到主体。实测全量按 tar 顺序跑
  有 790 万条事件（13.25%）落「无进程归属」，按时间序跑则基本消失。
  该模式下若检测到序号回退会打印 `[warn] 成员物理顺序不是逻辑序：10 -> 2 …`，
  报告里写 `"member_order": {"mode": "tar", "time_monotonic": false}`。

实测代价（THEIA 48 GB 归档，本机）：

| 操作 | 耗时 |
|---|---|
| `getmembers()` 建整包成员索引 | 49.9 s |
| 成员 0..0、5 万事件，默认（tar 顺序） | 1.61 s |
| 成员 0..0、5 万事件，`--sort-members` | 48.45 s |
| 全量解析（THEIA 13 个成员） | 228 s |

即：窗口很小时排序的开销是主导项（30 倍），整包解析时只占约 20%。
另外 TRACE 归档只有 7 个成员（`.json`..`.6`），字典序与数字序一致，两种模式没有差别。

两种模式产出的图完全相同：THEIA §3.3 窗口用默认顺序与 `--sort-members` 各跑一次，节点 27,788、边 3,097,770、按关系类型分布、账本各桶计数全部一致。差别只在两处：时间戳是否单调，以及 `event_id` 的编号（同一条记录在两种模式下拿到的号不同，因此 `edges.csv` / `events.csv` 的 `event_id` 只能在同一模式下复现）。

## 4. 事件 -> 边

映射表逐条覆盖 schema 的 50 个 `EventType`（`tests/test_cdm_mapping.py` 校验无遗漏、无多余）。
客体类别（file / net / subject）决定分支；类别未声明时落 `NO_OBJECT` 桶。

方向：`ProcessToFile / ProcessToNetwork / ProcessToProcess` 是进程 -> 客体；
`FileToProcess / NetworkToProcess` 是客体 -> 进程。

边属性：

| 字段 | 规则 |
|---|---|
| `event_id` | 全局行号（被扫描到的第 N 条 Event，从 1 起，跨成员连续）。`--event-log` 会额外写 `events.csv` 记录 `event_id -> 成员/行号/uuid/类型/时间戳` |
| `start_ns` | `Event.timestampNanos` |
| `end_ns` | **等于 `start_ns`**：CDM 一条记录只有一个时刻，没有 `%evt.latency`，因此该字段不表示耗时 |
| `syscall` | 映射后的项目动词（`read/write/send/recv/connect/...`），family 名与 sysdig 侧对齐（`send→sendto`、`recv→recvfrom`、`mmap_*→mmap`） |
| `result` | THEIA 取 `properties.map.rc`（正=字节数、负=errno、0=实测零）；TRACE 无 `rc`，数据类退回 `Event.size`，其余**不写**。一律过 `core/results.norm_result` |
| `payload_b64` | **恒为 None**：CDM 不带载荷内容 |
| `to_path` / `mode` | 仅 `rename`/`link` 的 `to_path`、`chmod` 的 `mode` |

`gate = success` 的事件（`create` / `link` / `rename` / `umount`）在没有返回值时落
`ATTEMPT` 桶而不是建边：没有返回值就不能声称创建/重命名成功。

## 5. 口径缺口（必须随任何数字一起汇报）

| # | 缺口 | 实测 |
|---|---|---|
| 1 | 无返回值 | TRACE 窗口 2,184,188 条事件里 `result` 缺失 1,012,546 条（46%）；THEIA 4,511,919 条里缺 1,421,415 条（31%） |
| 2 | 无载荷 | 全部事件的 `payload_b64` 都是空：外泄内容无法从该数据源恢复 |
| 2b | `create/link/rename/umount` 的成败 | 有 `rc` 时按 `rc` 判定；无 `rc`（TRACE 全档没有）时仍建边、`result` 留空，计入 `gaps.result_absent_edges`，不声称成功 |
| 2c | 无名对象 vs 索引外 uuid | 报告把客体拆成 file/net/subject/memory/srcsink/pipe/unresolved/none；无名对象按 uuid 的 64 位截断索引识别（只用于计数，不建图） |
| 3 | 无 fd 表 | `EVENT_CLOSE/DUP/FCNTL/LSEEK/*_SOCKET_PARAMS` 只能落「仅句柄」桶 |
| 3b | 桶派发顺序 | 与主体无关的结论（`drop_kernel` / `handle` / `unmapped` / `blind`）不再因主体缺失被改判成「无进程归属」：改动前 THEIA 全量有 615 万条 `EVENT_MPROTECT` 被吃进「无进程归属」 |
| 4 | 客体无名 | TRACE 窗口：`EVENT_WRITE` 客体 21,607 条是 FileObject、307,508 条是索引外 uuid（多数为 SrcSinkObject）；THEIA：`EVENT_MPROTECT` 116 万条、`EVENT_MMAP` 11.9 万条客体是 MemoryObject |
| 5 | `mmap` 无底层文件 | THEIA 的 `EVENT_MMAP` 100% 指 MemoryObject，`mmap_read/mmap_write/mmap_exec` 边建不出来；TRACE 有 13,832 条 FileObject 形态可建 |
| 6 | 进程出生时刻未知 | TRACE 窗口 28,765 条 Subject 的 `startTimestampNanos` 为 0，落图后 `start_ns=0` |
| 7 | 容器维度 | 不存在，`container_id` 恒空 |
| 8 | TA1 私有事件 | `EVENT_UNIT`（TRACE 窗口 30 万条）、`EVENT_LOADLIBRARY`、`EVENT_UPDATE`、`EVENT_OTHER` 落 `UNMAPPED`，不硬塞动作名 |
| 9 | 成员物理序 ≠ 时间序 | THEIA 归档物理顺序为 `.json, .1, .10, .11, .12, .2 …`；默认单趟流式按物理顺序处理并在报告中标注 `monotonic=False`，`--sort-members` 按数字后缀重排（代价见 §3.1） |

## 6. 运行方式

```bash
# 冒烟（20 万事件，不写库）
python provenance-parser/cdm_main.py \
  --archive <归档.tar.gz> --scenario SMOKE_THEIA \
  --member-from 0 --member-to 0 --max-events 200000 \
  --out-dir tmp/cdm-smoke --dry-run

# 时间窗 + 落库
python provenance-parser/cdm_main.py \
  --archive <归档.tar.gz> --scenario TC_E3_THEIA_20180410 \
  --member-from 0 --member-to 1 \
  --time-from 2018-04-10T17:30:00Z --time-to 2018-04-10T19:30:00Z \
  --out-dir output/parser-v2/TC_E3_THEIA_20180410-cdm --event-log \
  --neo4j-database attack-e3-theia-20180410-v2
```

产物：`report.json`、`report.md`、`edges.csv`、`nodes.csv`，加 `--event-log` 时多一个 `events.csv`。

## 7. 已实测结果（2026-10-27，本机）

| 运行 | 范围 | 记录 | 事件 | 节点 | 边 | 成边率 | 耗时 |
|---|---|---|---|---|---|---|---|
| THEIA 全量 | 全部 13 成员 | 63,852,494 | 59,634,578 | 730,170 | 20,406,130 | 34.22% | 1,514 s |
| TRACE 全量 | 全部 7 成员 | 32,130,374 | 21,914,150 | 227,584 | 2,216,269 | 10.11% | 562 s |
| THEIA §3.3 窗 | 2018-04-10 17:30–19:30 | 10,000,000 | 4,511,919 | 27,788 | 3,097,770 | 68.66% | 235 s |
| TRACE §3.15 窗 | 2018-04-13 16:30–17:10 | 20,000,000 | 2,184,188 | 15,508 | 206,156 | 9.44% | 224 s |

事件为什么不成边（全量占比）：

| 桶 | THEIA | TRACE | 含义 |
|---|---|---|---|
| 边覆盖 | 34.22% | 10.11% | 落成边 |
| 显式丢弃 | 52.07% | 23.12% | `EVENT_MPROTECT` + `EVENT_SHM`：客体是内存对象，无名 |
| 属性更新 | 7.26% | 3.10% | `EVENT_OPEN` 只回填 `File.file_type`，不建边 |
| 无客体 | 5.50% | 47.74% | 客体是 MemoryObject / SrcSinkObject / UnnamedPipeObject；TRACE 的写与收包多数落在这里 |
| 仅句柄 | 0.60% | 4.79% | `CLOSE/DUP/FCNTL/LSEEK/*_SOCKET_PARAMS`，CDM 没有 fd 表 |
| 未归类 | — | 11.02% | `EVENT_UNIT` 2,395,405 + `EVENT_LOADLIBRARY` 19,566 等 TA1 私有语义 |
| 无进程归属 | 0.36% | 0.00% | 主体 uuid 在全档 Subject 记录里不存在（数据侧发布缺口） |
| 尝试未成立 | 0.00% | 0.11% | `create/link/rename` 有返回值且为负 |

两次运行的账本都平衡（接入 = 结算），产物在 `output/parser-v2/TC_E3_*_cdm/`。

与标准答案（`TC_Ground_Truth_Report_E3_Update.pdf`）对得上的物证：

- THEIA §3.3：`/home/admin/clean` 有 `write`（166,784 字节，18:35:17Z）与 `exec`（18:35:30Z），
  写入者是 pid 6244、`exe_path=/home/admin/Downloads/firefox/firefox`；`/home/admin/profile`
  同为 `write` + `exec`；`/var/log/xdev` 有 `write`。GT 记录的时刻是 14:35 ET。
- TRACE §3.15：`/tmp/ztmp` 有 `write` → `chmod` → `unlink`，与 GT 的
  「1246 ztmp / elevate ztmp / 1251 rm /tmp/ztmp」一致。
- 连接侧：THEIA 窗口内命中 GT 地址 141.43.176.203（446 条边）、146.153.68.151（187 条）、
  161.116.88.72（159 条）；TRACE 窗口内命中 162.66.239.75（60 条）、17.146.0.252（2 条）。

**数据侧缺失（不是适配器丢的）**：GT §3.3 里的 145.199.103.57、104.228.117.212、
5.214.163.155、7.149.198.40 在前两个成员的全部记录里 0 次出现（逐字节扫描确认），
因此这些连接在该归档里没有观测。

## 8. 不做的事

- 不做跨主机关联：两套归档各只有 1 台主机，且对端需要 IP/端口/时间对齐，属外部前置步骤。
- 不采信 TA1 自带的数据流推断边（`EVENT_FLOWS_TO` 落 `UNMAPPED`）：采信它等于把上游推断当观测。
- 不生成标准答案：`ground truth/` 里的 PDF 只有时间、文件名、进程名、IP 端口，没有 pid 与
  syscall；转成 `groundtruth/*.groundtruth.json` 是人工标注，属外部前置输入。
