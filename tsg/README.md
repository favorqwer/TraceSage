# TSG：单文件全属性溯源图索引引擎（`tsg-v2`）

> **模块定位**：`tsg/` 实现 TraceSage 单文件二进制溯源图索引格式（`MAGIC = b"TSG2"`，`TSG_VERSION = 2`），默认输出至 `graphs/<场景名>.tsg`，替代运行期对 Neo4j 图数据库与 `tmp/provenance/l1-index/` / `temporal_events.pkl` 的依赖。

## 1. 单文件容器布局（`TSG2`）

`TSG2` 使用纯标准库与 `mmap` + `memoryview` 零拷贝读取，头部固定 **192 字节**（`HEADER_STRUCT`），包含魔数、版本号、顶点总数、唯一边数、邻接关联总数、最大 `event_id` 与 8 个分区的偏移/长度表：

| 分区 / 记录 | 固定大小 | 结构与用途 |
|---|---|---|
| `vkeys` 字节区 | 变长 UTF-8 | 按 `(kind_code, key)` 排序的纯顶点键字节区；`find_vertex_id` 直接对字节切片二分查找（零 `json.loads`） |
| 顶点目录（`VDIR_RECORD`） | 36 字节/顶点 | 记录 `key_off/len`、`prop_off/len`、`kind_code`、`ft_code`、`host_code`、`pid`、`ppid` |
| 顶点属性区 | 变长 JSON | 完整保存 `Process`、`File`、`Network` 全量静态属性（含 `exe_path`/`cmdline`/`uid`/`euid`/`container_*`/`file_type`/`proto` 等） |
| 邻接偏移表（`ADJ_OFF_RECORD`） | 24 字节/顶点 | `Process` 合并为按 `(start_ns, event_id)` 升序的单一连续块；`File`/`Network` 拆分为 `in`（写入/发送：`p2f`/`p2n`）与 `out`（读取/接收：`f2p`/`n2p`）两块 |
| 主边记录（`EDGE_RECORD`） | 40 字节/关联 | `peer_vid`、4 字节 `event_id`、`start_ns`、`result`、4 字节 `dur_ns`、`extra_off`、`syscall_id`、`action_id`、`rel_code`、`flags`（含 `NULL` 标志、`effect`、`FLAG_IS_OUT`、`FLAG_END_OVERFLOW`） |
| 稀疏附加区（`edge_extras`） | 紧凑二进制 | 按位掩码按需存放原始载荷字节流（由 `payload_b64` 解码无损存储）、`to_path`、`mode` 与超 `uint32` 时长的 `end_ns` |
| `event_id` 倒排索引（`EID_RECORD`） | 12 字节/条 | `(event_id, block_vid, adj_index)`，支持按 `event_id` 毫秒级反查完整边与属性 |

## 2. Python 读写接口

- **导出符号**（`tsg/__init__.py`）：`TSGReader`、`TSGWriter`、`TSGEdge`、`TSG_VERSION`、`MAGIC`、`HEADER_STRUCT`、`EDGE_RECORD`、`REL_CODES`、`REL_BY_CODE`。
- **写端路径**：
  - 流式解析直出：`parser/main.py` 默认使用 `--sink tsg`，通过 `parser/provenance/adapters/tsg_writer.py`（`TSGGraphWriter`）从 `.scap` 直接构建 `graphs/<scenario>.tsg`；
  - 既有库迁移与重打包：`tools/export_neo4j_to_tsg.py` 从标准 `-v2` Neo4j 库导出或原地重打包为 `TSG2`。
- **读端接入**：
  - 研究点一：`attack_graph/closure/snapshot.py` 通过 `TSGSource` 读取 `.tsg` 展开闭包、定位 POI 并向阶段 6.5 提供只读查询；
  - 研究点二：`attack_path/_bridge.py` 提供 `open_graph(scenario)` 打开 `TSGReader`；
  - 官方评分：`tools/rules_match.py` 优先从 `graphs/<scenario>.tsg` 读取顶点标签完成 `possible` 规则端点判定。

## 3. 离线查询 CLI（`python -m tsg.query`）

用于人工审计、单事件溯源与结构核对（不依赖 Neo4j）：

```powershell
# 查看 .tsg 元数据摘要
& ./.venv/Scripts/python.exe -m tsg.query info graphs/1_Web_Exploit_Ransomware.tsg

# 按类型、进程号或正则搜索顶点
& ./.venv/Scripts/python.exe -m tsg.query find-vertex graphs/1_Web_Exploit_Ransomware.tsg --kind Process --match php-fpm

# 按 event_id 精确查询边及 payload_b64 / to_path / mode 等附加属性
& ./.venv/Scripts/python.exe -m tsg.query event graphs/1_Web_Exploit_Ransomware.tsg 7080705

# 列出指定顶点在时间窗内的入边/出边
& ./.venv/Scripts/python.exe -m tsg.query edges graphs/1_Web_Exploit_Ransomware.tsg --kind File --key /srv/data/README_RESTORE.txt --extras

# 从指定 event_id 展开 k 跳邻域（backward/forward）
& ./.venv/Scripts/python.exe -m tsg.query neighbors graphs/1_Web_Exploit_Ransomware.tsg 7080705 --hops 2 --direction backward

# 导出为只读 SQLite 便于 SQL 排查
& ./.venv/Scripts/python.exe -m tsg.query export-sqlite graphs/1_Web_Exploit_Ransomware.tsg tmp/s1.sqlite
```

## 4. 单元测试

```powershell
& ./.venv/Scripts/python.exe -m unittest discover -s tsg/tests -p "test_*.py"
```
