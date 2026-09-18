# 改动记录（CHANGELOG）

本文件记录**每次修改的说明**：改了什么、为什么改、改前改后的数字、验证方式与结论。

## 约定

- **`AGENTS.md` 只写“当前确定的事实”**（现状、约定、口径、不变式、命令），不写过程与“改了之后变成多少”。
- **过程写在本文件**：新增/修改/删除了什么，以及支撑它的数字与验证结论。
- 每条记录包含：主题 / 改动内容 / 「改前 → 改后」（可量化处必须给数）/ 验证方式与结论 / 产物路径。
- 条目**按新→旧排列，不标日期**；同一主题被后续改动覆盖时只保留**最新一条**（旧口径的数字不重复留档），历史细节查 `tmp/` 或会话记录。
- 产物只写**当前仍存在**的 `output/` 或 `docs/` 路径；临时文件写 `tmp/`，且不在此处引用其路径。
- 找不到某条历史（例如某个修复为什么被删、某份产物为什么不见了）时，先查本文件；本文件没有的即为无留档。

---

## 记录

### send / recv 进图、open 只注册不建边（家族基本名缺口）

**问题**：`CANONICAL_SYSCALL_MAP` 与家族元组只收录了带后缀的变体（`sendto`/`sendmsg`/`sendmmsg`、`recvfrom`/`recvmsg`/`recvmmsg`），裸名 `send`/`recv` 未登记
——直连内核调 `send(2)`/`recv(2)` 的主机上这两类数据流会整类落 `Unmatched fingerprint` 丢边（属「家族基本名漏登记」一类缺陷）；`open` 同样未登记（按设计不建边，但会落 unmatched、且不延长 `p2p`，与 `openat` 口径不一致）。

**改动**

- `dispatch/meta_config.py`：`CANONICAL_SYSCALL_MAP` 增 `"send": "sendto"` / `"recv": "recvfrom"`（边的 `syscall` 写家族基本名；Java 侧 `LlmEdgePrefilter` / `LlmRepairCandidateScorer` 等按 `sendto`/`recvfrom` 匹配，故 Java 零改动）；`_SEND_FAMILY` / `_RECV_FAMILY` 补裸名。
- `dispatch/handlers.py`：`_OPEN_NO_EDGE_EVENTS` 增 `"open"`（动作仍为 `_make_open_link_extension_action`）。
- 方向与动作**零新增代码**：四个方向的 handler 由家族元组派生（`_GENERIC_SYSCALL_DIRECTIONS` 不动）。
- `AGENTS.md` §8.4：四个方向行、归一表行、「只注册、不建边」行同步。

**改前 → 改后**

| 指标 | 改前 | 改后 |
|---|---|---|
| handler 指纹数 | 68 | **73**（新增 `sendNetworkEntitynull` p2n / `sendFileEntitynull` p2f / `recvNetworkEntitynull` n2p / `recvFileEntitynull` f2p / `opennullFileEntity`），与既有键 **0 冲突** |
| 六份全量日志清单里的 `send`/`recv`/`open` 记录数 | 0 | 0（六场景本就没有这三类事件）→ **六库内容零影响，不需重导** |
| 场景 4 切片 dry-run 全量计数器（修复后 vs 删掉 5 个新指纹） | — | 逐项一致（仅耗时不同） |
| 合成日志（6 对事件）边计数 | p2n/p2f/n2p/f2p = 0/0/0/0，5 条 unmatched，`open` 不延长 p2p | **p2n/p2f/n2p/f2p = 1/1/1/1**（send→IP、send→unix、recv←IP、recv←unix），边 `syscall`= `sendto`/`recvfrom`；`open` **0 条边、不落 unmatched、把 p2p 边 endtime 从 clone 退出时间延长到 open 退出时间** |

**证据等级（重要）**：仅有的不确定性是 `send`/`recv` 在 sysdig 事件表里的存在与否——本机无网络，无法核对 sysdig 源码/官方事件清单，只能靠同族事件形态推断：
库内 `sendto`/`recvfrom`/`sendmsg`/`recvmsg` 的进入记录均为 `fd=N(<4t>…) size=…`、退出记录为 `res=N data=…`，`send`/`recv` 属同一 socket 数据事件族。
首份含这两类事件的真实日志到手后，用 `tools/check_sysdig_export.py` + `tools/run_coverage.py` 复核（工具已能如实报「未建模 / 已建模但 0 边」）；
若其 fd 注记出现在**退出**记录而非进入记录，再补 `(send/recv, None, Entity)` 指纹 + 一个从退出记录取端点的动作（照拄 `_accept_action`）。

**验证脚本**：`tmp/verify_bug3.py`（合成 5 用例，含「模拟修复前」对照）、`tmp/verify_bug3_slice.py`（六日志零命中 + 切片计数器等价）。**产物**：无（不改图）。

---

### fcntl 不建边 + unix 正则去重 + 账目/产物卫生 + 四库重导

**改动**

- **fcntl 不进图**（`dispatch/handlers.py`）：删除 `_fcntl_action` 里的 `n2p` 建边分支，只保留指纹注册、`record_failed` 失败判据与「socket 注记无四元组」审计计数（审计口径与 accept 一致，未变）。
  同步：`AGENTS.md` §8.4 把 `fcntl` 从 `n2p` 列表移出、归入「只注册、不建边」（`bytes` 行也去掉 fcntl）；`tools/coverage_spec.json` 的 `declared_no_edge_events.fcntl` 注明「建边分支已删除」。
- **unix 路径正则收敛到一处**（`jsonl/fields.py`）：新增 `UNIX_PATH_IN_ENDPOINT_RE` / `UNIX_PATH_IN_FD_NOTE_RE` / `UNIX_PATH_IN_CONNECT_TUPLE_RE` / `UNIX_PATH_IN_BIND_ADDR_RE` 与 `unix_path_from_endpoint()`；
  `pipeline/fd_table.py`、`dispatch/handlers.py` 改为 import（此前同一语义三份实现，handlers 与 fd_table 还有两份同名同款正则）。
  顺带修正：fd 身份学习原先只认裸 `fd=`，`fd_table` 的负向环视排除了 `in_fd=`/`out_fd=`，现按字段名显式纳入（`UNIX_PATH_IN_FD_NOTE_RE` 的 `(?:fd|in_fd|out_fd)=`）。
- **账目/产物卫生**：`tools/coverage_gap.py` 新增 `display_path()`——产物中项目内路径统一写相对 POSIX 路径（此前写死 `E:\Work\TraceSage\…`，跨机器无法逐字比对）；
  `CHANGELOG.md` 修正 G1/G2 的顶点合计行（旧值 64,572 → 64,909 与自身分项 +117/+127=+244 矛盾，实测重导前为 70,309：Process 18,321 / File 45,133 / Network 6,855）；
  修正 fcntl 条目的过期待办句（F_DUPFD* 的 unix 身份传播已由 G1 实现）；`fd_table._pending_path_event_fd` 补注释（每 pid 单槽位，后续同族进入记录直接覆盖，非无界泄漏，无需代码改动）。

**改前 → 改后（等价性自证）**

| 检查 | 改前 | 改后 |
|---|---|---|
| 场景 4 切片（100,001 行）dry-run 全量计数器：新实现 vs「旧正则 + 还原 fcntl 建边分支」 | — | 仅 `elapsed_seconds` 不同，其余逐项一致 |
| 合成：fcntl 退出记录带完整四元组（`fd=5(<4t>10.0.0.1:1000->10.0.0.2:80) res=0`） | n2p = 1 | **n2p = 0** |
| 合成：sendfile `out_fd=<u>/tmp/sock` + 后续裸 `<u>` 的 sendmsg | `fdtableResolved=0 / unresolved=1`，sendmsg 边丢失（p2f 1） | **`fdtableResolved=1 / unresolved=0`**，sendmsg 边保住（p2f 2） |
| 六份覆盖度报告重生成 | — | 与旧产物仅三类差异：相对路径、fcntl A1c 文案、四场景图规模 |
| `FULL-REPORT.md` 按原格式重建 | — | 与旧版 diff 60 行，全部落在上述三类（无拼接边界差异） |

**四库重导（DROP/CREATE + 逐场景导入，`--neo4j-database` 显式指定）**

| 场景 | 顶点 | 边 | unix File 顶点 | 耗时 | batchErrors / skippedMissing |
|---|---|---|---|---|---|
| 1 Multi-Stage Data Exfiltration | 1,989 → **1,988** | 213,459（不变） | 11 → **10** | 2m29s | 0 / 0 |
| 3 SSH Spray | 24,514 → **24,513** | 1,050,305（不变） | 25 → **24** | 6m27s | 0 / 0 |
| 4 Site Defacement | 16,772 → **16,771** | 450,657（不变） | 23 → **22** | 5m09s | 0 / 0 |
| 5 User Timer Resource Hijack | 14,199 → **14,198** | 750,973（不变） | 29 → **28** | 5m01s | 0 / 0 |
| 六库合计 | 70,309 → **70,305** | 3,735,140（不变） | 122 → **118** | — | — |

**重导校验**（重导前/后逐库快照对比，）

- Process / Network 顶点数与**身份集合哈希**逐库不变；File 顶点恰 −1（被归并的 `unix:[/run/user/1000/snap.firefox/../pulse/native]`）。
- per-rel 边数、per-(rel,syscall) 边数与字节和**逐项不变**；**重导后的原样边哈希 == 重导前把 unix 路径归一后的边哈希**（sc1 `f46b7446…`、sc3 `24e3516a…`、sc4 `e3e5059f…`、sc5 `8b011f73…`）。
- `MATCH (f:File) WHERE f.file_id CONTAINS '/../'` 在六个库里均为 **0**；场景 4 `unix:[/run/user/1000/pulse/native]` 度数 46 → **48**（吸收分裂顶点的 2 条边）；场景 4 sendfile 边 f2p 7 / p2n 7 不变。

**产物**：`output/inventory/{1,3,4,5}_*.db-inventory.json`、`output/coverage/`（六份报告 + `SUMMARY.md` + `FULL-REPORT.md`）。

**未做**：引擎基线与 GT 评分未重跑（本次图内容变化仅在 File 顶点身份，边多重集不变）。

---

### unix 合成顶点路径归一（G1 修正）

**问题**：`unix:[<path>]` 合成 File 键被 `_SYNTHETIC_VERTEX_PREFIXES` 豁免、不喂 `posixpath.normpath`，但括号内是真文件系统路径。
同一 socket 的 `..` / `./` / 内部 `//` 写法因此裂成多个顶点。

**改动**

- `jsonl/fields.py`：`unix:[` 从 `_SYNTHETIC_VERTEX_PREFIXES` 移出（该元组只留 `pipe:[` / `socket:[` / `netlink:[`），新增 `_UNIX_VERTEX_PREFIX` / `_UNIX_VERTEX_SUFFIX`；
  `normalize_file_path()` 增加 unix 分支：**只对括号内以 `/` 开头的路径**做 `posixpath.normpath`，合成前缀与 `]` 原样保留（非绝对路径与空内容原样返回）。
- `AGENTS.md` §8「字段恢复关系」：口径句由「`pipe:[…]`/`socket:[…]`/`unix:[…]`/空串不喂 normpath」改为「`pipe:`/`socket:`/`netlink:` 不喂，`unix:[…]` 只归一括号内路径」。

**改前 → 改后**

| 指标 | 改前 | 改后 |
|---|---|---|
| `normalize_file_path("unix:[/run/user/1000/snap.firefox/../pulse/native]")` | 原样返回 | `unix:[/run/user/1000/pulse/native]` |
| 合成日志（两次 connect 分别用 `..` 与规范写法 + 一次裸 `<u>` sendmsg）File 顶点 | 2 | **1** |
| 场景 4 切片（行 2,000,001–2,100,001，含该写法 1 次）dry-run 全量计数器 | — | 仅 `stats.vertices.file` **579 → 578** 与 `elapsed_seconds` 变化；五类边（pf/fp/pn/np/pp）、跳过、配对、fd 表、registry 审计**逐项不变** |
| 六库现存 `unix:[…]` File 顶点 | 122 个，其中 4 个含 `/../`（场景 1/3/4/5 各 1，deg 1/1/2/1） | 待重导归并（见「未做」） |

**验证**

- 单测 14 例：`..`/`./`/内部 `//`/尾斜杠折叠、`/` 与 `unix:[]` 原样、非绝对路径不归一、`pipe:[…]`/`socket:[…]`/`netlink:[…]`/`//usr/...`/空串全部零变化；两种写法落到**同一个 `FileEntity` 对象**。
- 端到端对照（同一切片与合成日志跑两次，一次 monkeypatch 还原修复前的 `normalize_file_path`）：合成日志 `f:2 → f:1`；切片唯一实质差异是 File 顶点 −1。
- `tools/coverage_gap.py` 重生成六份报告与现有 `output/coverage/` 产物逐字相同（除日志清单路径写法）。

**未做**：六库重导、`output/coverage/` 与 `output/baseline/` 刷新（会改图内容，需用户决定何时跑）。

---

### 覆盖度工具：事件建模反查改为读 `Fingerprint.event`

**问题**：指纹字符串是「事件名 + 实体类名 + 实体类名」**无分隔符**拼接，`coverage_gap.modeled_events` 用宽松后缀正则
`^(?:\w+Entity|null){2}$` 反推事件名，会把已注册名的**真前缀**误判为已建模（`sendtoFileEntitynull` 的后缀 `toFileEntitynull` 也匹配）。

**改动**

- `dispatch/system_call.py`：`Fingerprint` 新增 `self.event`（构造时已知的原事件名）；`_fingerprint_string` 与哈希/相等语义不变，事件分发零影响。
- `tools/coverage_gap.py`：`modeled_events` 改为 `{fp.event for fp in build_handlers(...)}`，删除 `SUFFIX_RE` 与已无用的 `import re`。

**改前 → 改后**

| 输入 | 改前 | 改后 |
|---|---|---|
| 合成 `['send','recv','open']` | 误判 `['recv','send']` 为已建模 | `{}`（如实报未建模） |
| 六份日志建模集合大小 | 28/26/31/34/33/33 | 逐份**不变**（当前日志无 `send`/`recv`，改前 0 假阳性） |

**验证**：六份报告重生成后与 `output/coverage/` 现有产物逐字相同（除日志清单路径写法）；合成用例由「误报」变「不报」。

**未做**：注册 `send`/`recv`（家族基本名）与 `open` 的 handler——工具侧现在会如实报为「未建模」，属待决缺口。

---

### GT 口径与 agent / 引擎指标（当前口径）

**GT（六场景合计 407 条）**

- 噪音清理：删除 143 条与攻击目标无因果、良性基线同样会产生、或只是进程内部记账的边（认证/会话常规、shell 命令替换与终端回显、工具内部访问、shell 内务管道、实验准备动作）；场景 1、2 逐条复核为零噪音，未改动。
- 孤岛补边：补 5 条把两处弱连通分量接回主链 —— 场景 4 P0/P9 的 `/srv/progql-web/current/{index.html, assets/site.css, release.txt, COMPROMISED_MARKER.txt}` `--sendfile--> /usr/sbin/nginx`（库里 `File --sendfile--> nginx` 共 7 条）；
  场景 6 P2 的 `/bin/bash --clone--> /usr/bin/bash`（pid 9283→9284，`$(dirname …)` 命令替换子 shell）。
- 另删除场景 6 因删边而**变空的相位**「P0 提权与 root 会话建立」（删掉其 22 条边后只剩相位头，属残留）。
- 收录口径：**与攻击者 IP 之间的全部网络事件边均收录**（场景 2 的 145B `wget --write--> net` 保留不删，与载荷 `read` 边构成字节守恒链）；痕迹清理边（`rm --execve-->`、`unlink`）**不收录**。

| 场景 | GT 边数 | 相位 | 弱连通分量 | 入口→POI 可达 |
|---|---|---|---|---|
| 1 Multi-Stage Data Exfiltration | 32 → 32 | 4 → 4 | [21] → [21] | ✓ → ✓ |
| 2 Masquerade Data Exfiltration | 32 → 32 | 6 → 6 | [18] → [18] | ✓ → ✓ |
| 3 SSH Spray | 48 → 32 | 9 → 9 | [31] → [18] | ✓ → ✓ |
| 4 Site Defacement | 118 → 93 | 11 → 11 | [60, 8] → [48] | ✓ → ✓ |
| 5 User Timer Resource Hijack | 128 → 88 | 8 → 8 | [78] → [53] | ✓ → ✓ |
| 6 SQLite Pipeline Pollution | 187 → 130 | 8 → 7 | [85, 3] → [58] | ✓ → ✓ |
| 合计 | **545 → 407** | — | — | — |

**指标（改前 = 旧 GT 545 条，改后 = 新 GT 407 条；均未重跑引擎）**

| 场景 | GT | Agent 召回 | Agent 查准 | 引擎 召回 | 引擎 查准 |
|---|---|---|---|---|---|
| 1 Multi-Stage Data Exfiltration | 32 → 32 | 100.0% → 100.0% | 76.2% → 76.2% | 93.8% → 93.8% | 33.3% → 33.3% |
| 2 Masquerade Data Exfiltration | 32 → 32 | 96.9% → 96.9% | 73.8% → 73.8% | 75.0% → 75.0% | 68.6% → 68.6% |
| 3 SSH Spray | 48 → 32 | 62.5% → **87.5%** | 19.9% → 18.5% | 54.2% → **59.4%** | 1.2% → 0.9% |
| 4 Site Defacement | 118 → 93 | 67.0% → **82.8%** | 91.9% → 89.5% | 15.3% → **7.5%** | 3.9% → 1.5% |
| 5 User Timer Resource Hijack | 128 → 88 | 54.7% → **63.6%** | 37.2% → 29.8% | 74.2% → **88.6%** | 31.7% → 26.0% |
| 6 SQLite Pipeline Pollution | 187 → 130 | 54.0% → **62.3%** | 85.6% → 68.6% | 77.0% → **89.2%** | 34.0% → 27.4% |
| **合计（micro）** | 545 → 407 | 62.9% → **74.9%**（305/407） | 54.7% → **48.6%**（305/627） | 61.8% → **67.3%**（274/407） | 9.6% → **7.8%**（274/3506） |

严格口径（未做内容归一）：agent 召回 59.3% → 70.3%、查准 49.8% → 44.1%。

**GT 编辑与评分验证**

- 6 份 GT 均通过 JSON 解析；编辑脚本对每份按「三元组多重集」自证不变式（旧集 − 删除集 + 补集 = 新集），
  保留原有缩进与行尾（场景 2、3 为 CRLF）；场景 1、2 编辑前后逐字节相同。
- 删后 6 场景**均为单一弱连通分量**、无空相位，且「攻击入口 → POI」有向可达均为真；场景 4/6 原有的两处孤岛消失。
- 相位链复核：场景 1/2/5/6 相邻相位均共享顶点；场景 3（P8 心跳 ↔ P9 尾部失败爆破）与场景 4
  （P0 基线抓取 ↔ P1 SSH 登录、P3 校验 ↔ P4 部署、P7 覆盖 ↔ P8 写标记、P9 回显 ↔ P10 归档）
  有 5 处相邻相位无共享顶点 —— 均属不同会话/不同服务，全局连通性由跨相位公共顶点（如 `/bin/bash`）保证，不是断链。
- 噪音复查：用同一套规则对改动后的六份 GT 重跑分类器，T1/T2 候选均为 **0**；对仍触及系统文件/管道/特权进程的边逐条复核，均为攻击链上的真实数据流或攻击动作
  （场景 1 `/etc/passwd --read--> /usr/bin/cp`、场景 3 `find|head` 枚举管道、场景 5 `/dev/zero|/dev/urandom --read--> dd`）。
- 刷新只重算评分，**未重跑 Java 引擎**：`baseline.json` 六份与改动前逐字节一致（阶段规模、入口排名、最终图均未变）。
- 删掉的 143 条里，现有引擎最终图命中了 64 条 —— 它们从「命中」改判为「多出边」，故 micro 查准 9.6% → 7.8%；
  场景 4 召回 15.3% → 7.5% 是因为原 18 个命中里 11 个是噪音边（MOTD 刷新 5 条 + `$(date)` 命令替换管道 6 条）。
- 两个方向的变动均符合预期：删掉的 138 条噪音边里 agent 原命中 38 条（场景 5 的 14、场景 6 的 20），
  但分母跌幅更大（545 → 407）故召回升；这 38 条转为「多出边」而报告三元组数不变（627），故查准降。
- **已知缺口（未补）**：场景 1、2 的 md 都写了「删除入口/暂存文件」这一步（场景 1 `rm /tmp/.system_service.sh` 等 4 条 unlink、
  场景 2 `rm /tmp/update_patch.sh` 等 2 条），库里 `unlink` 边存在但 GT 从未登记；场景 1 的 md 自述该步为「增加额外的文件操作噪音」，
  是否入 GT 需先定口径，故未补。

**agent 报告内容归一规则（只用图内容、不用 GT）**

① `event_id` 唯一对齐到库中同 syscall 且端点按内容或进程名匹配的边 → 用库中实际内容（45 条）；
② 未对齐时裸进程名若在库中只对应唯一 `exepath` → 归一（4 条）；③ 其余保持原样。
合计修正 **49/823** 条（场景 5 的 19、场景 6 的 30，其余 0）。

- 回库逐条核对 823 条报告边：`event_id` 存在 823/823、`syscall` 一致 823/823（无伪造）；
  归一后仍有 **12** 个三元组在库中找不到（同类实例间 `event_id` 错配，已按错误计入）。
- 修正只影响 Process 内容写法，不改变事件语义；修正后 agent 召回 +3.6pp、查准 +4.9pp。
- 用旧 GT 重跑两条口径，**逐字复现了历史数字**（严格 323/545 = 59.3%、归一 343/545 = 62.9%，查准 49.8% / 54.7%）；
  据此确认新旧数字的差异来自 GT 而非工具。
- 内容归一（49/823 条）只用图内容、不用 GT，故归一产物可直接复用。
- 结论：查准 agent 全面领先（micro 5.7 倍），召回 micro 反超（62.9% vs 61.8%）但分场景互补 ——
  agent 在场景 1/2/3/4 更高（场景 4 差距最大 66.9% vs 15.3%），引擎在 5/6 更高；
  agent 的缺口集中在同会话里高度重复的例行命令段（场景 6 的压缩归档 20/51、场景 5 的归档阶段 3/21）。

**产物**

- `output/agent-vs-engine/agent-metrics-20260917.json`（严格口径）、`agent-metrics-normalized-20260917.json`（主口径）、
  `agent-vs-engine-six-scenarios-20260917.md`（含逐场景逐相位命中表）；
- `output/agent-vs-engine/normalized/<场景>.json`：agent 报告本身（与 GT 版本无关），被评估复用；
- `output/baseline/<场景>/baseline.json`（六份）、`output/baseline/<场景>/groundtruth-eval.txt`（六份）、
  `output/baseline/metrics-six-scenarios.json`、`output/baseline/SUMMARY-six-scenarios.md`
  （后两者说明「GT 口径 545 → 407，与旧口径不可直接比较」）。

> 旧 GT 口径的四份产物（`agent-metrics-20260916.json`、`agent-metrics-normalized-20260916.json`、
> `agent-vs-engine-six-scenarios-20260916.md`、更早的单场景 `agent-vs-engine-comparison-20260907.md`）已**移出 `output/`**，
> 暂存于工作区临时目录（未入库，可恢复或清理）。

---

### 引擎基线运行器：File POI、入口上限与边事实内嵌

**改动**

- `progql-local/baseline/BaselineRunner.java`：
  - 新增 `--poi-file <绝对路径>`：POI dst 标签由 `Network` 切换为 `File`（属性 `name`，经
    `Neo4jServerTraversal` 兼容层映射到 `File.path`），用于场景 3-6 的
    `(p:Process)-[st:FileEvent{optype:"write"}]->(f:File{name:"..."})`；参数校验同步放开该选项。
  - 新增 `--entry-limit N`（`entryLimit`，默认 5）：场景 5 的 query 用 `LIMIT 10`。
  - `final_edges` 每条内嵌 `syscall` / `starttime` / `endtime`（秒，浮点，取自事件边），使产物自足；
    `tools/evaluate_gt.py` 因此直接读产物评分，不再连库反查（此前其反查固定读 `.env` 的 `NEO4J_DATABASE=neo4j`，
    对六场景独立库会 0 命中）。
- `progql-local/baseline/README.md`：补记上述选项与 `final_edges` 内嵌事实。

**验证**

- 改动只加两个选项与三个 JSON 字段，不改流程：场景 1 改前/改后逐字段 diff，只有 `final_edges` 变化，
  且每条的 `key` 与 `weight` 逐条相同（阶段计数、入口排名、最终图顶点全部一致）。
- 六场景各跑一次写 `output/baseline/<场景>/`，阶段规模与改前用临时目录预跑的结果一致
  （b_raw/b_cpr/forward_union/final 逐场景相同）；产物可逐字节重跑复现。

**未修的问题**：场景 4/6 的低召回集中在 POI 反向锥之外的 GT 阶段（同会话但非 POI 数据流祖先的 tar/cp/归档/回显边），
机制为 `INTERSECT(b_cpr, forward_union)` 单侧切除；证据（场景 4 final 图无任何 tar/cp/nginx 顶点）与逐条未召回边见产物。

**产物**：`output/baseline/<场景>/baseline.json`、`output/baseline/<场景>/groundtruth-eval.txt`（六份）、
`output/baseline/metrics-six-scenarios.json`、`output/baseline/SUMMARY-six-scenarios.md`。

---

### agent 六场景调查工作区与 agent 评分工具

**工作区**（`C:\Users\Favor\Desktop\pi test`，独立于本仓库、不在版本控制内）

- **删除剧透文件**：`edges_params.json`（攻击实体全集）、`final_table.py`（51 个攻击路径 `event_id`）、
  `dump_edges.py`、`edges_proc.cypher`（后两者绑定前两个 + 只对旧 `neo4j` 库快照成立）。
- **重写 `q.py`**：`--database`（或 `NEO4J_DATABASE`）、`session.execute_read()` 只读（服务器侧拒绝写）、
  关键字黑名单（先剔字符串字面量再匹配）、`--json`、`--param`、`--params-json`、
  `--max-rows`（超出截断并提示）、`--list-databases`、UTF-8 输出。
- **新增**：`AGENTS.md`（任务契约：全程只读、只用六个 `tracesage-*` 库、只在本目录内活动、所有查询带 `LIMIT`）、
  `GRAPH-SCHEMA.md`（三类顶点/五种关系/属性/id 口径/纳秒时间 + 数据可用性限制清单）、
  `SCENARIOS.md` + `scenarios.json`（场景→库→POI→采集窗口→图规模）、`REPORT-FORMAT.md`（产出 schema 与实体内容口径）、`results/`。
- 工作区内不出现：`.query` 文本、调查流程描述、引擎与产物、GT 与收录/评分口径、覆盖率/缺陷文档、本仓库路径。

**本仓库**：新增 `tools/eval_agent_attack_path.py`（agent 报告 vs GT 的召回/查准，与 `evaluate_gt.py` 同口径）。

**验证**

- 六场景 POI 均在对应库命中（场景 1/2/3/4/5/6 分别 1/1/5/1/5/4 条边），确认 POI 表未过期（用当前库实测）。
- `q.py` 只读：`SET` 查询被拒（`REFUSED`）；`--params-json` 参数生效。发现并已标注一个环境陷阱：
  Git Bash/MSYS 会把 `--param path=/etc/passwd` 改写成 `C:/Program Files/Git/etc/passwd`，
  故帮助与 `AGENTS.md` 要求绝对路径直接写进 Cypher 字符串或用 `--params-json`。
- 评分工具自证（临时区造合成报告，不连库）：① 报告 = GT 自身 → 32/32 = 100.0% / 100.0%；
  ② 报告 = 场景 2 引擎最终图内容三元组 → 24/32 = 75.0%、24/35 = 68.6%，与引擎主口径逐项一致；
  `--all` / `--json-out` / `--min-confidence` 均验证可用。
- 泄露自查（`grep -rniE` 工作区，排除 `venv`）：无本仓库路径、无方法/口径词。唯一命中是受害者侧文件路径里的字符串
  `progql`（如 `/srv/progql-web/...`）与库名里的 `tracesage`；二者来自数据本身，不暴露方法，不改图与 GT 则无法消除。
- **未做**（用户确认无需）：运行层隔离（只需文件层 + 上下文层，越界风险靠工作区 `AGENTS.md` 约束）、新建只读账号（沿用现有账号 + 只读事务）；
  场景 5 的入口规模（query 为 10）本次刻意不给。

---

### `fcntl` 口径收口：决策不建边，覆盖度哨兵归零

**改动**

- `tools/coverage_spec.json`：新增 `declared_no_edge_events`（当前仅 `fcntl`，字段内写明决策、依据与「解析器保留注册」的说明）；
  从 `event_precondition` 移除 `fcntl` 条目。
- `tools/coverage_gap.py`：`declared_no_edge_events` 里的事件从「已建模」摘出、归入「内部支撑（不建边）」（不参与哨兵判定）；
  事件行新增 `declared_no_edge` 字段；报告 JSON 新增 `declared_no_edge_events` 段；单场景报告新增 **A1c 已决策不建边**小节。
- 重生成 `output/coverage/` 全部产物（六份单场景报告 + `SUMMARY.md` + `FULL-REPORT.md`），复用已有 log/db 清单，**未重导、未改图内容**。
- 文档：`AGENTS.md`（覆盖度缺口里「`fcntl` 未建模（待决缺口）」→「已决策不建边（口径收口）」）、
  `docs/log-db-coverage-gap.md`（§5.1 重写为决策记录、§6 待办改写、新增 §6.1 哨兵口径变化、§7.3 表、§4 加「以 SUMMARY 为准」提示）、
  `docs/unix-sendfile-20260916.md` §8.5 第 5 条。
- **未改解析器**（`handlers.py` 的 fcntl 注册保留）、**未重导任何库**。

**改前 → 改后（`output/coverage/SUMMARY.md` 总览）**

| 场景 | 已建模 | 内部支撑 | 哨兵（可疑丢边） |
|---|---|---|---|
| 1 Multi-Stage Data Exfiltration | 28 → **27** | 3 → **4** | 0 → 0 |
| 2 Masquerade Data Exfiltration | 26 → **25** | 3 → **4** | 0 → 0 |
| 3 SSH Spray | 31 → **30** | 3 → **4** | 1 → **0** |
| 4 Site Defacement | 34 → **33** | 3 → **4** | 1 → **0** |
| 5 User Timer Resource Hijack | 33 → **32** | 3 → **4** | 0 → 0 |
| 6 SQLite Pipeline Pollution | 33 → **32** | 3 → **4** | 0 → 0 |

图规模、未建模数、参数名/未消费参数、fd 类型符、图中 syscall 全集均未变（如场景 1 仍 1,989 顶点 / 213,459 边；场景 3 仍 24,514 / 1,050,305）。

**决策依据（实测）**

- fcntl 是 fd 记账调用：六场景 157,347 次调用中 `F_GETFL`/`F_SETFL`/`F_GETFD`/`F_SETFD` 占 **72.5%**、
  `F_SETLK`/`F_SETLKW`/`F_GETLK` 19.8%、`F_DUPFD`/`F_DUPFD_CLOEXEC` 7.4%；不搬数据、不带路径、无 bytes。
- 哨兵点名的 Network 侧（场景 3 的 550 次 / 109 连接，场景 4 的 20 次 / 4 连接）共 **219 个 (Process, Network) 组合，
  库中已全部存在 `n2p` 边**（accept/read）→ 新增连通性 **0**；其余四场景的 socket 注记无四元组，修了也是 0 条边。
- 把 File/unix 形态一并修的上限：全库新增 ≈**14,896 条边 / 816 个路径**，与图中任何边都不重叠的「新邻接」仅 ≈6,004 对
  （含 4,327 对连顶点都不存在）；Top 增量全为噪声（`unix:[/run/systemd/journal/stdout]`、snapd assertions、
  字体 `F_SETFD`、`/dev/null`、`/proc/<pid>/status`、证书库 `F_SETLK`），攻击相关 0 条。
- 六场景 GT 中 `fcntl` 出现 0 次；且边模型只有 `bytes`/`syscall`，修好也分不清 `F_GETFL` 与 `F_SETLK`（唯一有对抗语义的加锁）。

**验证**

- 重跑 `tools/run_coverage.py` + `tools/coverage_summary.py`：六场景均输出「声明建模但 0 边 = 0、图有日志无的 syscall = 0」；
  未消费参数名 88/87/97/99/97/97 与改前一致。
- `FULL-REPORT.md` 按原格式重新拼接后与改前逐行 diff：仅 83 行变化，全部落在总览计数、§2 哨兵段落、
  A1b（删 fcntl 行）、A1c（新增）、A4（删 fcntl 行），无其他差异。

**产物**：`output/coverage/` 六份 `*.coverage-gap.md|json`、`SUMMARY.md`、`FULL-REPORT.md`。

**后续（已由 G1 实现）**：fd 表已接入 `dup` / `fcntl(F_DUPFD*)` / `clone` 的 unix 身份传播（`unix_dup_copied`，六场景 11,662 次），用于回填裸 `<u>` 注记；该改动会改图内容（新增 unix 路径顶点/边），已随 G1 重导落地，不在本次「口径收口」范围内。

---

### `AGENTS.md` 口径与结构整理

**改动**

- `sysdig-parser/parsers/jsonl/record.py`：删除 `parse_jsonl_entry` 返回 dict 里的 `"cpu": "0"`。
  该键在 JSONL 导出中无对应列、值恒为常量，全仓库（`tools/`、`sysdig-parser/`、`progql-local/`、`docs/`）无任何读取点，
  也无代码遍历 record 键；同步删除 docstring 的字段映射行；`validate_parsed_entry` docstring 的「14 个规范键」更正为「13 个规范键（不含 `raw`）」。
- **去编号引用**：未建模缺陷的 G1–G5 编号（7 处）改为描述性名称（非 IP 传输端点 / `sendfile` 零拷贝 / 失败的生命周期调用 /
  路径身份归一 / unix socket 顶点）；15 处「第 N 节」「§5.1」「见本节」「见 9.6」类引用改为节标题或文件路径；
  因「调查流程基线」一节已删，修掉两处悬空引用（`output/baseline/<outDir>/baseline.json` 改指 `progql-local/baseline/README.md`，
  `groundtruth/` 条目删去指向已删小节的口径句子）。
- **结构**：章节 1–7、9 → 1–8（「字段与数据模型详细设计」由第 9 节改为第 8 节），子节 8.1–8.6 连续：
  8.1 导出字段与规范记录字段（**已合并为一张表**：JSONL 键 → 规范键 → 作用/说明 → 是否必填）、8.2 字段恢复关系、
  8.3 顶点、8.4 关系（EventEdge）、8.5 关系属性、8.6 Schema 与写入不变式。
- **§7 去过程化**：`fcntl` 决策与实测数字压成一行（指向 `coverage_spec.json` 与 `docs/log-db-coverage-gap.md` §5.1）、
  已知边界与覆盖度命令块压短、工具表「用途」去掉施工记录式措辞（保留 `dump_parser_counters.py` 的
  `diff()` 按键名忽略 `file`、会连带跳过 `stats.vertices.file` 这一坑）。
- **工具表**：补 `evaluate_gt.py` 行（引擎 `baseline.json` vs GT 的召回/查准，`--window` 模拟 POI 时间窗）；
  删除僵尸脚本 `tools/measure_backward_cone.py`（全仓零引用 —— 只有它自己提到自己，且其引用的
  `docs/agent-design-llm-provenance.md` 已不存在），其回溯锥结论仅存于本文件与 `output/` 历史产物。

**改前 → 改后**

| 指标 | 改前 | 改后 |
|---|---|---|
| `parse_jsonl_entry` 返回键数（含 `raw`） | 15 | 14 |
| 不含 `raw` 的规范键数 | 14 | 13 |
| `AGENTS.md` 章节号 / 编号引用 / G1–G5 编号 | 1–7、9 / 15 处 / 7 处 | 1–8 / 0 处 / 0 处 |
| `AGENTS.md` 字段表 | 导出字段、规范记录字段两张 | 合并为 1 张 |
| `tools/` 脚本 | 11 个 `.py`（含 1 个零引用僵尸，且工具表漏记 `evaluate_gt.py`） | 10 个 `.py`（删僵尸；工具表补 `evaluate_gt.py` 行） |

**验证**

- 解析等价性：用与场景 1 同一日志的前 40 万行做 `--dry-run` 计数导出，改前、改后逐项 diff 结果为 `EQUIVALENT`
  （stats / 逐理由跳过 / 配对 / fd 表 / registry audit 全等）；该 dump 自身连跑两次也逐项一致（先证明基线确定性，再比对改动）。
  此改动只删一个无人读取的 dict 键，不触碰任何解析、配对、建边分支。
- 文档：`grep` `AGENTS.md` 的 `第 [0-9] 节` / `§` / `见本节` / `G[1-5]` / `9\.[1-9]` 均无命中；标题序列 1–8 连续、子节 8.1–8.6 连续；
  删脚本后全仓（除 `tmp/`）无 `measure_backward_cone` 引用。
- 未跑：六库全量重导与调查流程基线回归（本次改动不涉及图内容与引擎）。

---

### 目录与文档整理：删除 PG 对比栈、`output/` 清理、`tmp/` 约定

**删除（PG 基准库对比相关，已确认不再使用）**

- 工具：`sysdig-parser/compare_pg_neo4j.py`、`tools/compare_pg_neo4j_scenarios.py`、`tools/compare_baseline_pg_neo4j.py`（及 `__pycache__`）。
- 依赖与配置：`requirements.txt` 的 `psycopg2-binary`；`.env` 的 `PG_USER` / `PG_HOST` / `PG_PORT` / `PG_PASSWORD`。
- 产物：`output/reimport-20260910/`、`output/g34-fix/cmp/`、`output/neo4j-pg-comparison-20260904.md`、
  `output/neo4j-baseline-comparison-20260906.md`、`output/db_backup_1_Multi_Stage_Data_Exfiltration.sql`、
  `output/baseline/1_Multi_Stage_Data_Exfiltration/`。
- 后果：`AGENTS.md` §4「对比分层判据 / 总口径 / 四条原因」与四条**解析器修复记录**一并移除，
  已从会话历史重建并补录到本文件（见「失败判据整类丢边」「G3/G4 顶点身份归一」「家族变体整类未注册」三条）。
- 保留（有意，勿误删）：`progql-local/` 的 Java 代码与别名兼容层；`input/sysdig/*.query`
  （含 `optype`/`srcip` 等兼容层别名，是当前基线流程的输入）。

**删除（`output/` 清理，用户执行）**

- `output/archive/`、`output/unix-sendfile-20260916/`、`output/reimport-20260915-variants/`、`output/reimport-diff-20260909/`、
  `output/g34-fix/`、`output/connect-fix-20260911/`、`output/accept-fix/`、`output/pathnorm-scan/`、`output/g1-sizing/`、
  `output/review-20260907/`、`output/cone-analysis/`、`output/gt-scenario2/`、`output/gt-scenario4-20260912/`、
  `output/gt-scenario5-20260912/`、`output/gt-scenario6-20260914/`、`output/ssh-spray-gt-20260911/`、
  `output/pairing_comparison/`、`output/baseline/`（全部 15 组）、`output/README.md`。
- 后果：① 六个库**当前内容（含 G1/G2）的重导日志** `output/unix-sendfile-20260916/reimport.log` 已消失，
  「库里现在的数据是怎么来的」不留档；② `output/pairing_comparison/` 内含**未入 git 历史的旧/新解析器快照**，已不可恢复；
  ③ 调查流程回归的参照系为空。
- `output/` 现存子目录：`inventory/`、`coverage/`、`baseline/`、`agent-vs-engine/`。

**悬空引用清理**：删除所有指向上述已删路径的句子（`AGENTS.md` 4 处、`docs/` 9 处；
`output/agent-vs-engine/` 报告中 6 处改为泛化 `output/baseline/<outDir>`）。

**文档结构改造**

- `AGENTS.md` §2 重写：补全**每个目录**的作用（含 `docs/`、`groundtruth/`、`paper/`、`progql-local/`、`sysdig.wiki/`、`tmp/`），并明确入库边界。
- `AGENTS.md` 去过程化：所有「某年某月改了什么、由 X 变成 Y、实测如何」的叙述改写为**当前确定的事实**
  （删除 G1/G2 变更流水；确定性/跨环境/引擎修复/GT 补齐等记录改写为口径与不变式；去掉日期与「曾导致」「由 0 变 7」等过程措辞）。
- 新增 `tmp/` 约定：agent 工作时的临时文件一律写 `tmp/`；`output/` 只放产出结果；`AGENTS.md` 的目录说明与「修改边界」写明。
- `.gitignore` 已包含 `tmp/`，临时文件不会被 git 跟踪。

---

### G1/G2：unix socket 文件系统路径建模 + `sendfile` 零拷贝

**改动**

- `jsonl/fields.py`：`extract_file_and_socket` 泛化出可指定字段名（支持 `in_fd=`/`out_fd=`），新增 `unix_path` / `unix_abstract` / `fd_type_raw`。
- `pipeline/entity_registry.py`：描述符→实体链抽成唯一 chokepoint `entity_from_descriptor`（新增 `unix_path` 分支）。
- `pipeline/fd_table.py`：新增 `(pid,fd) → unix 路径`（connect/bind 的进入 fd 与退出 `tuple=`/`addr=` 对齐、close 失效、dup/clone 传播）。
- `dispatch/handlers.py`：新增 `_make_sendfile_action`（指纹 `(sendfile, None, None)`）；send/recv 家族在 FileEntity 方向注册；`connect` 加 unix 路径分支。

**改前 → 改后（六库合计，DROP/CREATE 后全量重导）**

| 指标 | 改前 | 改后 | 差 |
|---|---|---|---|
| 边 | 3,460,719 | 3,735,140 | **+274,421**（f2p +117,920 / p2f +156,494 / p2n +7；n2p、p2p 不变） |
| 顶点（六库合计） | 旧库已 DROP，无法复测 | **70,309**（Process 18,321 / File 45,133 / Network 6,855；孤立顶点 0） | 口径修正：原记「64,572 → 64,909（+337）」，与自身分项（+117/+127=+244）矛盾，且与重导前实测不符（见「账目与产物卫生」条） |
| `incomplete_network` | — | −421,338 | = −(unix_path 420,776 + fdtable_resolved 562)，逐场景精确成立 |

**验证与结论**

- 逐库 `batchErrors=0`、`skippedMissing=0`。
- 场景 4 `nginx` 的 `sendfile` read 边 0 → **7**（含 POI 文件 `COMPROMISED_MARKER.txt` 37 B）。
- 场景 5 `systemctl --connect--> unix:[/run/user/1000/systemd/private] --> systemd(--user) --execve--> worker.sh` 共 **3 跳**（G1 判据 ≤4）。
- 覆盖度报告已重生成：`output/coverage/FULL-REPORT.md`。

**未做**：场景 4 审计链仍不连通（符号链接别名 + rsyslogd 线程名分叉）、场景 6 终端面/pty、netlink、抽象命名空间。

**文档**：`docs/unix-sendfile-20260916.md`。

---

### 家族变体整类未注册（裸 `chmod` / `symlinkat`）

**问题**：`handlers.py` 按手写事件名名单注册家族，而 `CANONICAL_SYSCALL_MAP` 已把 `chmod`、`symlinkat` 归到 `chmod` / `symlink`，
注册表没跟上 → 这两类退出记录落入 `Unmatched fingerprint`，边整类丢失（场景 3/4/5/6 共 **5,138** 条 `p2f`）。

**改动**

- 新增 `handlers._family(canonical...)`：从归一表反查家族的全部事件名。
- `_CHMOD_FAMILY` / `_RENAME_FAMILY` / `_SPAWN_FAMILY` / `_EXIT_PATH_FAMILY` 全部改为**派生**
  （生命周期按 canonical 家族给基准字段；`unlinkat` / `mkdirat` 保留字段序覆盖）。
- 归一表补 `fchmodat2 -> chmod`（内核 6.5+ / glibc 2.39 起 `fchmodat()` 走它，否则同一 bug 会在新主机重现）。

**改前 → 改后（dry-run 逐场景计数器，场景 1→6）**

| 指标 | 改后增量 |
|---|---|
| 新增边 | 0 / 0 / 1,396 / 2,512 / 1,224 / 6（= **5,138**，全部 `p2f`：chmod 209 + symlink 4,929） |
| File 顶点 | +0 / 0 / 1,212 / 2,278 / 1,190 / 0（= 4,680） |
| `p2p` / `f2p` / `p2n` / `n2p`、Process / Network 顶点 | 逐项不变 |
| unmatched 跳过行 | 减少 1,459 / 2,525 / 1,231 / 10 |
| 场景 1 | 逐项与修前完全一致（该日志里无这两类记录） |

**重导**：六库 DROP/CREATE 后批量全量重导（`--input-dir input/sysdig --all`），逐库 `batchErrors=0`、`skippedMissing=0`、无重复 `event_id`。
sc1/sc2 内容与重导前**逐字节一致**（含 event_id）；sc3/4/5/6 与中间「增量追加」阶段的内容多重集**完全一致**，仅有 event_id 重新密编号。
`p2f/chmod` 与 `p2f/symlink` 现为 2/2、11/1、582/2,065、144/2,564、20/1,289、18/19（= 日志侧独立期望值）。

**GT / 基线**：GT 不受影响（GT 的 chmod/symlink 边本就由 `fchmod` / `fchmodat` / `symlink` 产出且已在图中，逐条查库确认）；
场景 1 基线重跑与修复前内容级完全一致（b_raw 167v/1975e、b_cpr 167v/344e、entry candidates network=1/file=46/process=0、final 52v/94e）。

---

### G3/G4 顶点身份归一

**问题**（详见 `docs/graph-defects-20260913.md` 的 G3/G4）：`filename=` 通道不剥内核 `原始名(/绝对路径)` 注记；File 键不做词法归一。

**改动**

- 新增 `jsonl/fields.py` 的 `strip_path_annotation()`（括号内以 `/` 开头才剥，判据与旧实现逐字一致）与
  `normalize_file_path()`（剥壳 + `posixpath.normpath`；`pipe:[…]` / `socket:[…]` / `unix:[…]` / 空串不喂 normpath）。
- 两者挂在 `pipeline/entity_registry.get_or_create_file()` 这个**唯一 chokepoint**（File 的 MERGE 键就是 `path`，所以键与实体属性一起归一）。
- `dispatch/handlers.py` 的 `_normalize_exit_path` / `_normalize_rename_path` 收敛为调用共用函数
  （此前三份近似实现导致「某条通道忘了归一」）。

**改前 → 改后（六库 DROP/CREATE 重导后）**

| 指标 | 改前 | 改后 |
|---|---|---|
| File 顶点 | 40,381 | 40,318（−63；逐库 sc2 −1 / sc3 −26 / sc4 −23 / sc5 −13 / sc1·sc6 0，与预测吻合） |
| 边多重集（关系类型×syscall 的条数 / 字节和 / 最早最晚时间） | — | 逐库 **0 差异** |
| 括号注记 / `/./` / 内部 `//` / 尾斜杠 顶点 | 3 / 1 / 100 / 1 | 0 / 0 / 0 / 0 |
| 行首 `//` 顶点 | 1,085 | 1,085（**不变**：POSIX 保留行首双斜杠，snap-confine 顶点未被误并） |

**验证**：GT 已同步改写（场景 2/4/5 各 1 行括号路径）。

---

### 失败判据整类丢边：`accept` 与 `connect EINPROGRESS`

两条同源缺陷：`extract_size()` 把「`res=` 字段缺失」与「`res<0`」合并返回 -1，而 handler 用它判调用失败；现改为区分三者并给非阻塞 connect 单独的判据。

**问题一：`n2p/accept` 整类缺失** —— PG 基准库有 122 条（场景 3 为 110、场景 4 为 12），新导入器为 0。
本导出格式下 accept 的退出记录只给 `fd=N(<4t>ip:port->ip:port) tuple=...`、**不带 `res=`**（场景 3 实测 12,208 条 accept 退出记录带 `res=` 的为 0 条），于是整类被无差别丢弃。

**问题二：非阻塞 connect 丢边** —— 退出记录为 `res=-115(EINPROGRESS)`（连接已发起、四元组已由内核分配，语义上不是失败），
被「失败则不建边」判据当失败丢弃 → 外传 socket 在图中只剩 sendto 一条边、出度 0（场景 2 的 `curl→192.168.122.128:4444` 即此类）。

**改动**

- 新增 `fields.extract_res()`（仅在字段缺失时返回 `None`）+ `record.record_res()` / `record_failed()` 区分「字段缺失」与「失败」；
  6 处「失败则不建边」判据改用 `record_failed()`；`_make_edge_action`（read/write 族，res 即 bytes）与
  `_execve_action`（res=0 才算成功）仍用 `record_size()`。
- 新增 `record.record_in_progress()` / `record_connect_failed()`，**仅 `connect` 家族**改用后者（`record_failed` 本体与其余 6 处调用不动）。
- `entity_registry` 新增 `connect_in_progress_count` 审计计数。

**改前 → 改后**

| 指标 | 改前 | 改后 |
|---|---|---|
| 场景 3 `n2p` | 8,322 | **8,432** |
| 场景 4 `n2p` | 11,847 | **11,859** |
| 场景 2 `p2n` | 6,467 | **6,773**（+ 新增计数 `connect_in_progress=306`） |
| 其余四类边（accept 修复） | — | 计数一字不变 |

**验证**

- accept 修复：改前改后全量计数器 diff 仅 `edges.n2p` 一项（切片 A/B 验证）；场景 1/2/5/6 全量 dry-run 复验与入库值逐项一致。
- connect 修复：六个场景 `EINPROGRESS` 只出现在 connect 退出记录中（45/306/95/248/732/305 条，无例外）；
  `-101` / `-111` / `-2` / `-13` 仍是真失败、不建边。场景 2 全量计数器 diff 仅 `edges.p2n` 6,467 → **6,773** 与新增计数 `connect_in_progress=306`。
- 重导：六库 DROP/CREATE 后重导，新增边 45/306/95/248/732/305 条**全部是 `p2n/connect`**（合计 **+1,731**，删除 0），
  新增 Network 顶点 3/152/1/85/468/158（合计 +867）；Process/File 内容与其余边多重集完全一致。
- 基线影响：场景 1 基线重跑与修复前**内容级完全一致**（剥 id 前缀后逐字段对比），GT 评分不变。

---

### 引擎基线：非有限权重修复、排名权重标准与确定性验证

**`getFeatureWeight` 非有限结果修复**

- 问题：`GQLBackwardPropagate.getFeatureWeight` 的 time 特征在事件边与 POI 边 endtime 相同时求值为 `1/0` → Infinity，
  经出边归一化变为 NaN，导致 KMeans 空簇异常（`ConvergenceException`）。
- 改动：该分支对非有限结果回落到引擎自带的 `getTimeWeight` 伪最小差处理（`pseudoMinDiff=1e-10`）。修复后基线可跑通。
- 该不变式原写在 `AGENTS.md` §7「调查流程基线」；该节已删（见「目录与文档整理」），**当前只在 `progql-local/` 代码与本文件留有落档**。

**排名权重标准**

- 与另一环境引擎产物逐项对比后，将入口排名权重统一定为**影响 0.55 / 最早因果时间 0.45**，其他环境运行同一流程时使用同一配置。
- 依据：各阶段图规模、最终图顶点/边、事件分布、候选集合、声誉值完全一致；入口排序差异经反解验证源于该环境权重为 0.55/0.45（残差 ≤1e-9）。
- 产物：权重固定在 `progql-local/baseline/progql-llm.properties`。

**基线确定性验证**

- 以 0.7/0.3 与 0.55/0.45 两种权重先后各连跑多次，`baseline.json` 均逐字节一致（权重融合的 multiKMeans 在该数据上收敛同一划分）。
- 结论：同一输入连跑产物可逐字节 diff，这是所有「解析/导入/引擎改动前后比对」成立的前提。
