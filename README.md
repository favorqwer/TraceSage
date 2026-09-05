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
├── input/sysdig/             # 输入数据：JSONL 日志、sysdig 纯文本导出、场景查询
├── output/                   # 运行产物：导入日志、对比报告、SQL 备份、统计输出
├── docs/                     # （预留）项目文档
├── tools/                    # 独立小工具与一次性诊断脚本
├── analyze_attack_log/       # 日志统计工具（字段/事件类型/进程/FD/系统调用）
├── sysdig-parser/            # 溯源图解析导入器（JSONL → Neo4j）
│   ├── main.py               # 入口
│   ├── compare_pg_neo4j.py   # PG 基准库 vs Neo4j 正确性对比
│   └── parsers/              # 解析、建模、Neo4j 写入
└── sysdig.wiki/              # Sysdig 日志格式与字段语义参考资料
```

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

```bash
# 1. 检查 sysdig 导出是否完整（防止 -p 格式串问题导致事件被静默丢弃）
python tools/check_sysdig_export.py input/sysdig/attack.jsonl

# 2. 日志统计（字段、事件类型、进程、FD、统一系统调用）
python analyze_attack_log/analyze_attack_log.py input/sysdig/attack.jsonl

# 3. 解析并导入 Neo4j（分批幂等写入，--dry-run 只解析不写库）
python sysdig-parser/main.py input/sysdig/attack.jsonl neo4j 1
python sysdig-parser/main.py input/sysdig/attack.jsonl neo4j 1 --dry-run

# 4. 与 PostgreSQL 基准库对比（基准库固定为 1_Multi_Stage_Data_Exfiltration）
python sysdig-parser/compare_pg_neo4j.py --pg-db 1_Multi_Stage_Data_Exfiltration
```

## 工具脚本（tools/）

| 脚本 | 用途 |
|---|---|
| `check_sysdig_export.py` | 导出文件健全性检查：统计记录数与事件类型，识别被过滤的导出 |
| `compare_exepath.py` | 一次性诊断：以 exepath 粒度归一化进程身份后对比 PG vs Neo4j |
| `diag_tid_vs_pid.py` | 一次性诊断：验证对比差异是否全部来自 PG(tid) vs Neo4j(pid) |

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
