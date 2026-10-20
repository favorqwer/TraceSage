# provenance-parser

`docs/LINUX_SYSDIG_LOG_PARSER_DESIGN_V2.md` 的实现：把 Sysdig `.scap` 直接流式解析成
Neo4j 溯源图（3 类顶点、5 类边），并把"每条日志行去了哪里"记成可对账的账本。

- 状态：可运行；67 个单测；读取层融合后用场景 1 的 20k 事件小样本验证（审计/非审计图一致）。
  场景 5 全量（130 万行）与场景 9 前缀（120 万事件）是融合前的历史结果，本次未重跑全量。
- 不依赖中间 JSONL；主趟一次配对、一次分类、一次结算；审计与容器元数据是独立只读趟。
- 所有数字都能用 `report.json` 与四个 CSV 复盘；没有"凭印象"的边界。

## 快速开始

```bash
# 探测当前可用的读取后端
python provenance-parser/main.py --detect-backends

# 只解析、不写库（推荐先跑这个）
python provenance-parser/main.py \
  --scap attack/data/5/capture.scap \
  --scenario 5_Exposed_Service_Pivot \
  --dry-run

# 开发用小样本（容器/审计/主趟都只读前 N 个事件）
python provenance-parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware \
  --dry-run --max-events 20000 --out-dir tmp/parser-v2/run1

# 写库（默认清掉该 host_id 的旧图；库名默认 attack-<scenario>）
python provenance-parser/main.py \
  --scap attack/data/1/capture.scap --scenario 1_Web_Exploit_Ransomware
```

后端：`--backend auto|local|wsl|ssh|docker`。Windows 上默认走 WSL 里的 sysdig（实测可用）。
`--detect-backends` 会实际探测四个后端（含 SSH 连通性与 Docker daemon），然后打印 `auto` 的选择结果。
SSH 后端在本地有 `.scap` 时会自动上传到远端缓存；`--no-ssh-sync` 可禁止上传。

## 结构

```
main.py                  CLI
data/verbs.toml          §4.2 的 30 个动词（34 减去 4 个延后）
data/calls.toml          §4.3/§4.4 的调用 -> 账本桶 + 原因
provenance/
  config.py              附录 A 参数 + .env
  model.py               共享词汇：EventRow / Call / Decision / Outcome / 三键 / 五边
  pipeline.py            唯一知道顺序的总装
  read.py                行解码 + 两趟审计 + 容器元数据（后端在 sources/）
  sources/               SCAP 读取层：base + local/wsl/ssh/docker + 探测工厂
  args.py                evt.args 解码（纯函数）
  paths.py               路径规范化（纯函数）
  classify.py            两张表 -> Decision（纯函数）
  pair.py                进出配对、单向事件
  ledger.py              12 桶结算 + 对账等式 + 断号
  report.py              4 个 CSV + report.json + report.md
  store.py               节点登记 + 幂等批量写库
  state/                 唯一可变的一层：proc / fds / containers
  emit/                  调用 -> 图变更（base + process/file/network）
tests/                   67 个标准库 unittest
```

依赖方向是直线：`model ← 纯函数层`、`model ← state/emit ← pipeline → store/report`。
`emit` 只读 `State`，不碰账本/数据库；`ledger` 是唯一记账人。

### 读取层（`provenance/sources/`）

- `base.py`：`ScapSource` 抽象、统一命令参数、stderr 捕获、有界批处理读取。
- `local.py` / `wsl.py` / `ssh.py` / `docker.py`：四种执行后端；SSH 含远端上传与尺寸缓存。
- `factory.py`：真实可用性探测与 `auto` 优先级（非 Windows local > WSL > SSH > Docker > local）。
- `read.py` 只消费 `ScapSource`，不再自行拼 subprocess 命令。

## 实测：为什么模板是这 12 个字段

设计文档 §1.3 要求"单趟取齐 + 禁止大而全模板"。在 sysdig 0.27.1 + 场景 1 上逐字段实测
（20 万事件，`%evt.num` 为 100%）：

| 字段 | 可得率 | 结论 |
|---|---|---|
| `%evt.num` `%evt.rawtime` `%evt.dir` `%evt.type` `%thread.tid` `%evt.args` | 100% | 可用 |
| `%proc.pid` `%proc.exe` `%proc.cwd` `%proc.ppid` `%proc.args` `%user.uid` | 91.55% | **缺的行全是 `switch`**，可用 |
| `%fd.name` | 34.74% | 进模板会成行丢失 → 从 `evt.args` 解 |
| `%fd.type` | 34.65% | 同上 |
| `%evt.rawres` | 26.08% | 同上（`evt.args` 里有 `res=`） |
| `%evt.buffer` | 12.83% | 载荷在 `evt.args` 的 `data=` 里 |
| `%proc.duration` | 3.89%（且混入主模板时**整条流 0 行**） | 不放进主模板 |

所以主模板是 12 个"有进程上下文"的字段，再加上 `%container.id`（容器命名空间），
实际 13 列；其余全部从 `evt.args` 解。这不是偏好，是把"整行消失"的机制测出来之后的选择。

对账分两趟：

1. 主趟：13 列窄模板（含 `%container.id`）。
2. 审计 A：`%evt.num %evt.type`（100% 可打印）→ 每个类型总行数。
3. 审计 B：`%evt.num %evt.type %proc.pid` → 每个类型"可归属进程"行数。

`主趟接入行数 - 异常行 == 审计 B 行数`，不相等直接阻断。`审计 A - 审计 B` 按类型
给出"采集端不可打印"的精确数字（实测全部是 `switch`），不靠猜。

## 与设计文档 V2 的差异（都有实测依据）

1. **`res` 从 `evt.args` 的 `res=` 解**，不用 `%evt.rawres`（那会丢 74% 的行）。
   `openat`/`accept` 成功时采集端不给 `res=`，只给 `fd=`；这两种动词用 `fd` 判成功。
2. **`head` 是采集端对载荷的可打印渲染**（不可打印字节是 `.`），不是 base64。
3. **`proc.duration` 不可用**：实测只在 execve 行可打印，混入主模板直接 0 行；
   本版不产出 `born_src=duration`，`born_ns` 来源只有 clone / exec / unknown / collision。
4. **`logical_calls`** = 退出行 + 单向事件行；报告里给出口径。
5. **`edges.csv` 按事件顺序写出**（确定性、可 diff），未做全局排序（外部排序代价高）。
6. **`type_diff` 之外**，`gaps` 把缺号拆成"采集端不可打印"与"文件内确实不存在"两段。

## 账本与报告

每个场景输出（默认 `output/parser-v2/<scenario>/`）：

- `report.json`：账本、缺号分解、参数可得性、未归类、容器、边分布、born/fd 统计、边界清单。
- `report.md`：同一份内容的人读版。
- `nodes.csv` / `edges.csv`：逐字段可复现快照（同输入两次跑字节一致）。
- `ops.csv`：无客体动作与被合并参数（`signal:<n>`、`ioctl:<req>`、`mount:<fstype>` 等）。
- `attempts.csv`：§4.6 里"对象由本次调用产生但失败"的目标 + 错误码。

12 个桶：边覆盖 / 属性更新 / 尝试未成立 / 未归类 / 仅句柄 / 未知句柄 / 无客体 /
显式丢弃 / 未配对 / 无进程归属 / 异常行 / 其他。等式不平时进程直接报错，不写"成功"。

## 已知边界（报告里逐条列出）

- PID 命名空间未翻译：容器内 `kill(局部pid)` 在普通 pidns 里解析不到；命中失败计
  `target_unresolved`，若该 pid 在别的容器存在另计 `target_pid_other_ns`。
- 未连接 UDP 的 `sendto` 目的地址不在参数里（`tuple=NULL`）→ 无客体。
- `bind` 到端口 0 的端点不可见（真实端口只出现在被丢弃的 `getsockname`）。
- unix 套接字只认带路径的（抽象命名空间不是身份）；无路径的计无客体。
- `rename`/`link` 不迁移历史（五边约束）；同路径删除后重建视为同一节点。
- 匿名 IPC（eventfd/signalfd/timerfd/inotify/netlink/无路径 unix）不建节点，计无客体。
- `bpf`/`module`/`io_uring`/`shm` 四个内核对象动词按约定延后（客体无稳定名字）。
- 节点登记表超过 `node_registry_max`（默认 300 万）立即阻断，不静默吞。
- 写库默认只删 `host_id` 相同的旧图；老解析器写入的节点没有这个属性，不会被清掉。
- SSH 远端缓存按文件大小判断是否复用（与 scap-parser 一致）；同尺寸替换不会触发重新上传。

## 测试

```bash
python -m unittest discover -s provenance-parser/tests -v
```

覆盖：动词表 34 个（30 生效 + 4 延后）、openat 分流、unix/网络改投、成功门与
attempts、自环、线程 clone、账本互斥穷尽、exec 分裂、pid 复用/撞键、fd 覆盖/CLOEXEC、
容器占位、写库 Cypher 参数名、每条边两端节点都已登记、后端命令构造与优先级、
批处理读取的 stderr/退出码。
