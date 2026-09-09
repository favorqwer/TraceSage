# TraceSage

使用 Sysdig 导出的 JSONL 日志构建**主机级溯源图**（单主机），并写入 Neo4j。
图由三类顶点（Process / File / Network）、五种方向化事件边以及顶点和事件边属性组成。

## 目录结构

```
TraceSage/
├── AGENTS.md                 # 项目约定（目录说明、Neo4j 导入约定、对比基准）
├── README.md                 # 本文件
├── requirements.txt          # Python 依赖（pipreqs 生成）
├── .env                      # 数据库连接配置（不入库）
├── input/sysdig/             # 输入数据：6 个攻击场景的 JSONL 日志与同名 .query 场景查询
├── output/                   # 运行产物：导入日志、对比报告、SQL 备份、统计输出
├── docs/                     # （预留）项目文档
├── tools/                    # 独立小工具与一次性诊断脚本
├── sysdig-parser/            # 溯源图解析导入器（JSONL → Neo4j）
│   ├── main.py               # 入口
│   ├── compare_pg_neo4j.py   # PG 基准库 vs Neo4j 正确性对比
│   └── parsers/              # 解析器包（按层分子包）
│       ├── pipeline/         # 解析管线：主循环、进出配对、实体注册、边缓冲
│       ├── model/            # 纯图模型：顶点（Process/File/Network）、EntityNode、EventEdge
│       ├── jsonl/            # Sysdig JSONL 行级解析：记录解码、args 字段抽取
│       ├── dispatch/         # 系统调用分发：Fingerprint/SystemCall、动作注册
│       ├── storage/          # Neo4j 批量写入
│       ├── config.py         # 环境变量/.env 配置（横切）
│       └── reporting.py      # 进度与跳过行上报（横切）
└── sysdig.wiki/              # Sysdig 日志格式与字段语义参考资料
```

## 攻击场景与数据库

`input/sysdig/` 中每个攻击场景为一对 `<场景名>.jsonl`（Sysdig JSONL 日志）与
`<场景名>.query`（攻击场景查询描述）。每个场景导入**独立的 Neo4j 数据库**，
库名约定为 `tracesage-<场景名小写，_ 归一化为 ->`（Neo4j 库名只允许
字母/数字/点/横线且统一小写）：

| 场景 | JSONL 日志 | Neo4j 数据库 |
|---|---|---|
| 1 Multi-Stage Data Exfiltration | `1_Multi_Stage_Data_Exfiltration.jsonl` | `tracesage-1-multi-stage-data-exfiltration` |
| 2 Masquerade Data Exfiltration | `2_Masquerade_Data_Exfiltration.jsonl` | `tracesage-2-masquerade-data-exfiltration` |
| 3 SSH Spray | `3_SSH_Spray.jsonl` | `tracesage-3-ssh-spray` |
| 4 Site Defacement | `4_Site_Defacement.jsonl` | `tracesage-4-site-defacement` |
| 5 User Timer Resource Hijack | `5_User_Timer_Resource_Hijack.jsonl` | `tracesage-5-user-timer-resource-hijack` |
| 6 SQLite Pipeline Pollution | `6_SQLite_Pipeline_Pollution.jsonl` | `tracesage-6-sqlite-pipeline-pollution` |

- 数据库选择优先级：`--neo4j-database` > `.env`/环境的 `NEO4J_DATABASE` > 默认 `neo4j`。
- 导入器不创建数据库：目标库必须已存在。多数据库需要 Neo4j Enterprise；
  Community 版只有默认 `neo4j` 库，此时只能逐场景导入（换场景前先清库）。
- 建库示例（对 `system` 库执行，横线开头的名字需反引号包裹）：

  ```cypher
  CREATE DATABASE `tracesage-1-multi-stage-data-exfiltration` IF NOT EXISTS
  CREATE DATABASE `tracesage-2-masquerade-data-exfiltration` IF NOT EXISTS
  CREATE DATABASE `tracesage-3-ssh-spray` IF NOT EXISTS
  CREATE DATABASE `tracesage-4-site-defacement` IF NOT EXISTS
  CREATE DATABASE `tracesage-5-user-timer-resource-hijack` IF NOT EXISTS
  CREATE DATABASE `tracesage-6-sqlite-pipeline-pollution` IF NOT EXISTS
  ```

- 每个场景的 event_id 从 1 开始，仅在场景自己的库内保证唯一；重复导入同一
  日志到同一库是幂等的。
- PG/Neo4j 正确性对比与调查流程回归基线目前固定只针对第 1 个场景（见
  AGENTS.md 第 4/7 节）。

## 运行环境

所有 Python 命令在项目虚拟环境中执行：

```bash
.venv/Scripts/activate        # Windows / Git Bash
pip install -r requirements.txt
```

数据库连接信息从 `.env` 读取（禁止硬编码）：
`NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE`，
对比工具另用 `PG_USER` / `PG_HOST` / `PG_PORT` / `PG_PASSWORD`。

## 常用命令

### 采集命令

```bash
sudo sysdig -w capture.scap

# 每个攻击场景单独采集并保存为 <场景名>.jsonl，例如：
sudo sysdig -r capture.scap -j -p '*%evt.num %evt.rawtime %proc.pid %proc.exepath %proc.name %proc.args %proc.cwd %fd.l4proto %evt.dir %evt.type %evt.args %evt.latency' > 1_Multi_Stage_Data_Exfiltration.jsonl
```

```bash
# 1. 检查 sysdig 导出是否完整（防止 -p 格式串问题导致事件被静默丢弃）
python tools/check_sysdig_export.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl

# 2a. 单场景导入（目标库默认取 NEO4J_DATABASE，可用 --neo4j-database 显式指定；--dry-run 只解析不写库）
python sysdig-parser/main.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl neo4j 1 \
  --neo4j-database tracesage-1-multi-stage-data-exfiltration
python sysdig-parser/main.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl neo4j 1 --dry-run

# 2b. 六个场景批量导入：input/sysdig 下全部 *.jsonl 按文件名排序逐个导入，
#     每个场景写入独立数据库 tracesage-<场景名小写>（要求各库已存在）；fail-fast
python sysdig-parser/main.py --input-dir input/sysdig --all --neo4j-database-prefix tracesage-
python sysdig-parser/main.py --input-dir input/sysdig --all --dry-run

# 3. 与 PostgreSQL 基准库对比（基准库固定为第 1 个场景 1_Multi_Stage_Data_Exfiltration）
python sysdig-parser/compare_pg_neo4j.py --pg-db 1_Multi_Stage_Data_Exfiltration
```

## 工具脚本（tools/）

| 脚本 | 用途 |
|---|---|
| `check_sysdig_export.py` | 导出文件健全性检查：统计记录数与事件类型，识别被过滤的导出 |
| `dump_parser_counters.py` | 解析等价性验证：dry-run 导出全部可观测计数（stats/逐理由跳过/配对/fd 表），`--baseline` 逐项 diff，性能重构前后必须全部一致 |
| `dump_neo4j_content.py` | 图内容等价性验证：导出指定库全部顶点/边（含属性与端点身份）为规范化 JSON，`--baseline` 逐项 diff |

## 参考文档

- `AGENTS.md` — 项目约定与 Neo4j 导入规范
- `output/neo4j-pg-comparison-20260904.md` — PG vs Neo4j 完整对比记录与差异归因
- `output/pairing_comparison/README.md` — 配对算法改造（改前/改后）统计对比
- `sysdig.wiki/` — Sysdig User Guide 与 Quick Reference Guide

## 维护

重新生成 `requirements.txt`（自动扫描项目 import）：

```bash
pipreqs . --ignore .venv,__pycache__ --force
```
