# 日志 vs 图 覆盖度缺口工具链

> 面向后续接手的人。目标：直接用原始 JSONL 判断
> "日志里有的信息，Neo4j 图里缺了哪些"，用于以后往图里增加顶点/边/属性/系统调用时
> 快速定位缺口。
>
> 生成日期 2026-09-16；六场景产物在 `output/inventory/` 与 `output/coverage/`。

## 1. 定位与边界

本工具链**不做边级等价性对比**，而做**信息清单的不漏项对账**：日志侧清单由原始 JSONL
直接扫出，图侧清单由库内容与解析器契约对账，两侧都不是"把解析器跑两遍"。它的能量
边界也在于此——只能证明"日志里有、图里没有"（漏项），不能证明图里多出来的边方向/语义正确：

| 层 | 工具 | 产出 |
|---|---|---|
| 日志侧全量清单 | `tools/log_inventory.py` | `output/inventory/<场景>.log-inventory.json` |
| 图侧清单 | `tools/db_inventory.py` | `output/inventory/<场景>.db-inventory.json` |
| 当前解析器契约 | `tools/coverage_spec.json` | 消费了哪些参数名 / fd 类型 |
| 缺口报告 | `tools/coverage_gap.py` | `output/coverage/<场景>.coverage-gap.md|json` |
| 跨场景汇总 | `tools/coverage_summary.py` | `output/coverage/SUMMARY.md` |
| 批量驱动 | `tools/run_coverage.py` | 串联以上流程 |

## 2. 用法

```bash
# 单场景（已有清单时复用，不重复扫日志）
python tools/run_coverage.py --scenario 1
# 指定几个场景 / 全部重跑
python tools/run_coverage.py --only 2,3
python tools/run_coverage.py --force
# 汇总
python tools/coverage_summary.py

# 底层工具可单独用
python tools/log_inventory.py input/sysdig/3_SSH_Spray.jsonl -o output/inventory/3_SSH_Spray.log-inventory.json
python tools/db_inventory.py tracesage-3-ssh-spray -o output/inventory/3_SSH_Spray.db-inventory.json
python tools/coverage_gap.py --log <log-inv.json> --database tracesage-3-ssh-spray --out-dir output/coverage
```

扫描吞吐约 39k 行/秒（六场景日志 2.3–7.2 GB，单场景 3–10 分钟）。

## 3. `log_inventory.py`：不遗漏的三道保证

1. **维度从数据里长出来**：顶层 JSON 键、`evt.args` 参数名、fd 类型符、errno 名、注解
   枚举名（`O_DIRECTORY`/`PROT_READ`/`FUTEX_WAIT`…）全部是扫出来的 Counter，不依赖
   预置清单；采集格式串以后加字段，重扫即自动出现。
2. **`evt.args` 分段自证**：每个空格分隔 token 必须归入
   `pair`（`k=v`）/ `continuation`（前一键的多 token 取值）/ `data_payload`
   （`data=` 之后整段载荷）三类。输出里 `accounting.unclassified` 必须为 0，
   且 `accounted == tokens_seen`。六场景实测均为 0 / 相等。
3. **高基数不静默丢弃**：值集合能全枚举就全枚举，超 `--value-cap`（默认 50 万）则标记
   `capped=true` 只留 TopN。六场景实测无键触发上限。

两个已确认的边界（输出里显式记录了 note，不算遗漏）：

- `data=` 载荷按不透明值处理（不解内部伪 `k=v`）。**载荷在日志里本身就只有 ≤80 字节**：
  采集用的是 sysdig 默认 snaplen（`-s` 未设），六场景 `max_bytes` 均为 81。载荷内容
  超出 80 字节的部分在 `.scap` 里就不存在，重导出无法恢复。
- `evt.num` 有缺口：场景 1 缺失 47,814 / 跨度 9,361,909（0.51%，20 段）。缺口是采集期
  丢事件还是导出过滤尚未定性，但**任何"日志全量"结论都应带上这个 0.5% 的不确定度**。

`evt.args` 扫描器要处理三个实测形态（都已在代码里处理）：

- `data=` 是终止符；只有 `recvmsg/sendmsg` 会在其后追加 ` tuple=...`（实测一一对应）。
- 多 token 取值：`fds=42:e1 43:p1`（poll 的 fd:events 列表）、`clone` 退出的
  `exe=<路径> <裸 argv 带空格>`。
- fd 注记内含空格与嵌套括号，必须**按括号配平**取 token，不能按空格截断
  （`fd=3(<u>ffff...->ffff... )`、`fd=124(<f>/memfd:mozilla-ipc (deleted))`）。

## 4. 六场景结果（2026-09-16）

> 下表为 2026-09-16 某一轮的旧数字（早于 G2/unix-socket 重导与 fcntl 口径收口），
> **以 `output/coverage/SUMMARY.md` 为准**（最新一轮：已建模 27/25/30/33/32/32，内部支撑均 4，
> 哨兵均 0）。

| 场景 | 日志行 | 事件类型 | 已建模 | 未建模 | 参数名 | 未消费参数 | 图顶点 | 图边 | 可疑丢边 |
|---|---|---|---|---|---|---|---|---|---|
| 1 Multi-Stage Data Exfiltration | 9,314,095 | 142 | 28 | 111 | 104 | 88 | 1,975 | 212,202 | 0 |
| 2 Masquerade Data Exfiltration | 14,367,390 | 138 | 26 | 109 | 106 | 90 | 4,542 | 1,000,961 | 0 |
| 3 SSH Spray | 22,014,963 | 191 | 31 | 157 | 130 | 114 | 24,417 | 842,338 | 1 |
| 4 Site Defacement | 23,479,509 | 197 | 33 | 161 | 134 | 118 | 16,728 | 415,430 | 1 |
| 5 User Timer Resource Hijack | 17,638,112 | 182 | 33 | 146 | 127 | 111 | 14,157 | 731,518 | 0 |
| 6 SQLite Pipeline Pollution | 6,991,472 | 181 | 33 | 145 | 128 | 112 | 8,246 | 258,270 | 0 |

## 5. 已由本工具查出的缺口

### 5.1 【已决策：不建边】`fcntl` 整族 0 条边（六个库全部）

- **现象与根因（仍成立）**：六个库 `fcntl` 边数全为 0，而日志退出记录 2,261 / 5,985 / 85,401 /
  29,360 / 20,923 / 13,417 条；场景 3/4 的 fd 注记里明确带完整四元组
  （`events.fcntl.fd_forms` 场景 3：`4t/quad=550`）。根因：`handlers.py` 注册的指纹是
  `Fingerprint("fcntl", None, NetworkEntity)`（实体在**退出**记录），但 fcntl 的 fd 注记在
  **进入**记录 `> fcntl fd=15(<f>/usr/share/...ttf) cmd=3(F_SETFD)`，退出记录只有
  `res=0(<f>/dev/null)`（注记嵌在 `res=` 里，而 `fields.extract_file_and_socket` 只扫 `fd=`
  token）→ 实际指纹是 `fcntlNetworkEntitynull` / `fcntlFileEntitynull`，注册表里没有 →
  全部落入 `Unmatched fingerprint` → 不建边。
- **2026-09-16 决策：不建边（口径收口）。** 修复前先量化了收益，结论是溯源价值≈0：
  1. fcntl 是 fd 记账调用。六场景 157,347 次调用中 `F_GETFL`/`F_SETFL`/`F_GETFD`/`F_SETFD`
     占 **72.5%**（查/改 fd 标志位）、`F_SETLK`/`F_SETLKW`/`F_GETLK` 19.8%（文件锁）、
     `F_DUPFD`/`F_DUPFD_CLOEXEC` 7.4%（fd 复制）；**不搬数据、不带路径、无 bytes**。
  2. 哨兵点名的 Network 侧修了也是 0 条新连通性：场景 3 的 550 次带四元组调用（109 个连接，
     调用者是 `sshd` 监听进程与各 sshd 子进程）、场景 4 的 20 次（4 个连接），其 **219 个
     (Process, Network) 组合在库中已全部存在 `n2p` 边**（accept/read）；其余四场景的 socket
     注记根本没有四元组，修了也是 0 条边。
  3. 把 File/unix 一并修的上限也全是噪声：全库新增 ≈14,896 条边 / 816 个路径，与图中任何边
     都不重叠的"新邻接"仅 ≈6,004 对（含 4,327 对连顶点都不存在）。Top 增量是
     `unix:[/run/systemd/journal/stdout]`、snapd assertions、字体 `.ttc` 的 `F_SETFD`、
     `/etc/localtime`、`/dev/null`、`/proc/<pid>/status`、证书库 `F_SETLK`——攻击相关 0 条。
  4. 即使修好也丢失语义：边只有 `syscall="fcntl"`、`bytes=0`，图里分不清 `F_GETFL`（无害）
     与 `F_SETLK`（加锁，仅有的对抗意义）；六场景 GT 里 `fcntl` 出现 0 次。

  因此 fcntl 不再作为待修缺口：写入 `tools/coverage_spec.json` 的 `declared_no_edge_events`，
  报告里归入 **A1c 已决策不建边**（不计入"已建模（建边）"、不进哨兵）；解析器保留注册，
  供后续 fd 表 `F_DUPFD` 传播与失败审计复用。
- **保留的两条真建边修法（备查，当前不采纳）**：① 注册 `Fingerprint("fcntl", NetworkEntity, None)`
  并让 `_fcntl_action` 用 `start_entities[1]`（与 bind 的写法一致，bind 是对的）；
  ② 让字段抽取也识别 `res=N(<...>)` 形态的注记。两者都需重导，且必须同时把 `cmd` 写成边属性
  （否则新增边没有语义）。
- **为什么只有本工具能发现**：`fcntl` 边数为 0 而日志退出记录数不为 0，正好命中本工具链
  的哨兵列"声明建模但 0 条边"；若不走这一列，整族缺失在图里没有任何痕迹。

### 5.2 未建模实体种类（G1，已知未修）

未建模 fd 类型符（跨场景合计）：`<u>`（unix socket）、`<e>`、`<i>`、`<n>`（netlink）、
`<t>`、`<d>` 等。这直接解释了 `recvmsg` 场景 1 有 98 万条退出记录、`recvfrom` 边却只有
6,360 条——绝大多数是 unix socket，按 §9.9 的 G1 口径不建顶点不建边。

### 5.3 未消费参数名（按跨场景次数降序，Top 项）

| 参数 | 说明 |
|---|---|
| `size` | 请求字节数（图里 `bytes` 用的是 `res`）；可作为新增边属性 |
| `data` | 载荷（受 snaplen 80 限制） |
| `dirfd` | `*at` 变体的相对路径基准目录；当前**只取 args 里第一个 `fd=` token，不读 `dirfd`** |
| `cmd` | fcntl 的命令；可作为边属性记录"对套接字做了什么" |
| `offset` / `length` / `whence` / `pos` | pread/pwrite/lseek 的偏移语义 |
| `mode` / `uid` / `gid` / `dev` | 权限与属主 |
| `vm_*` / `pgft_*` | 来自 `switch`（无进程上下文，解析器按 §9.2 整行跳过） |

## 6. 待办

1. ~~**`fcntl` 修复**~~ → **已关闭（2026-09-16 决策：不建边）**，见 §5.1。留在台面上的只剩一个可选小项：
 **fd 表 `F_DUPFD` 传播**——把 fcntl 的 `F_DUPFD*`（六场景 11,662 次）接入 `pipeline/fd_table.py`
 的 `(pid, fd) -> unix 路径` 传播（与现有 `dup`/`clone` 钩子同形），用于回填裸 `<u>` 注记。
 注意：这会改变图内容（新增 unix:[path] 顶点/边），属 G1 范畴、需重导，不在本次口径收口内。
2. **哨兵做强**：当前"可疑丢边"靠日志侧 fd 形态启发式判定，只能在日志里出现过完整端点
 形态时命中。可接入解析器 dry-run 的 `Unmatched fingerprint` 计数
 （`tools/dump_parser_counters.py` 已导出 `skip_reason_counts`）做交叉验证，
 就能把"整族未匹配"的缺口无遗漏地列出来——代价是每个场景多跑一次解析（约等于一次
 log_inventory 扫描）。

### 6.1 哨兵列的口径变化（2026-09-16）

`tools/coverage_spec.json` 新增 `declared_no_edge_events`：这些事件解析器仍注册，但已决策
不建边，既不计入"已建模（建边）"也不进哨兵，而是在单场景报告里单列 **A1c 已决策不建边**。
当前仅 `fcntl`。改前改后：场景 3/4 哨兵 `1 → 0`（六场景均 0）、已建模计数各 `-1`、
内部支撑 `3 → 4`；图内容未变（本次未改解析器、未重导）。

## 7. 三张对照表（读报告时用）

### 7.1 未建模事件类型按组归类（六场景合计 5,962 万条 / 164 类）

| 组 | 类数 | 记录数 | 溯源价值 |
|---|---|---|---|
| 调度/同步/等待（futex/switch/sched_yield/poll/epoll_*/eventfd/timerfd/nanosleep/…） | 38 | 34,965,011 | **无**（无对象语义；`switch` 是 sysdig 调度伪事件） |
| 只读元数据/侦察（newfstatat/fstat/access/readlink*/getdents64/statfs/getxattr*/getcwd/chdir） | 18 | 16,844,241 | **有，需控规模**：`getdents64` 目录枚举、`access`/`newfstatat` 探测、`readlink` 追链 |
| 文件改动/篡改持久化（chown 族/utimensat/setxattr 族/ftruncate/mknodat/link/chroot/mount/umount/pivot_root/finit_module） | 18 | 68,540 | **高**：篡改与持久化的直接痕迹 |
| 内存管理（mmap/munmap/mprotect/madvise/brk/mremap/msync/fsync/flock/fadvise64） | 12 | 1,485,577 | **无**（`mmap PROT_EXEC` 例外，但信噪比差） |
| 进程/权限/信号/内核对抗（prctl/seccomp/bpf/capset/setns/unshare/kill/setuid 族/…） | 63 | 2,216,061 | **部分高**：prctl/seccomp/bpf/capset/setns/unshare 强信号；getpid/getuid 族是噪声 |
| 网络控制面（getpeername/socket/setsockopt/getsockopt/listen/shutdown/socketpair） | 7 | 1,312,560 | **中**：`listen` 补服务端语义、`getpeername` 确认对端 |
| 其他/采集层（ioctl/`<unknown>`/sendfile） | 3 | 2,140,881 | `sendfile` 高（G2）；`<unknown>` 待查；ioctl 基本无 |
| 未归类（lseek/inotify_* 族/shm*/clock_adjtime） | 9 | 587,484 | lseek 无；`inotify_add_watch` 弱-中 |

### 7.2 fd 类型符（含义由 sysdig wiki `fd.typechar` + 实测样本确定）

| 类型符 | 含义 | 六场景合计 | 溯源价值 |
|---|---|---|---|
| `<u>` | unix domain socket（抽象 `@…` / 文件系统路径 / 内核地址对） | 5,964,648 | **高**（G1 的核心：systemd/dbus/journald 控制面与审计面） |
| `<e>` | eventfd | 2,267,980 | 无 |
| `<(annot)>` | fd 位置实际是 errno 注记（`-100(AT_FDCWD)`/`-2(ENOENT)`…） | 1,578,223 | 非实体；其中 `AT_FDCWD` 是路径解析关键信息 |
| `<(no-paren)>` | 裸 fd 编号，无类型 | 1,559,221 | 非实体；可供 fd 生命周期表推断 |
| `<d>` | 目录 | 967,662 | 中（目录顶点可把枚举行为与目录内文件连起来） |
| `<X>` | sysdig 未识别的 fd 类型符 | 383,592 | 待查（多在 fcntl/flock 等） |
| `<i>` | inotify | 91,008 | 弱-中（结合 watch 目标路径才有用） |
| `<t>` | timerfd | 41,279 | 无 |
| `<n>` | netlink socket | 22,602 | 中（`ss`/路由/防火墙枚举） |
| `<s>` / `<l>` | signalfd / eventpoll | 1,095 / 5 | 无 |
| `<6t>` `<4i>` `<6r>` | IPv6+TCP / IPv4+ICMP / IPv6+raw | 616 / 91 / 4 | `6t` 已建模（解析器正则 `[46u][tu]?`）；`4i`/`6r` 无端口、不成四元组 |

### 7.3 参数名分类（溯源价值）

| 组 | 代表参数 | 溯源价值 |
|---|---|---|
| at 变体基准目录 | `dirfd` `linkdirfd` `newdirfd` `olddirfd` | **高**（相对路径解析；当前只取第一个 `fd=` token，合计 175 万次） |
| 零拷贝两端 | `in_fd` `out_fd`（sendfile） | **高**（G2 的两个端点） |
| 请求量 | `size`（对比 `res` 的实际字节数） | 中-高（区分"想传"与"传成功"） |
| 权限/身份 | `mode` `uid` `gid` `euid` `egid` `ruid` `suid` `rgid` `sgid` `mask` `nstype` | `mode` 高（权限位/setuid）；uid 族中 |
| 进程上下文 | `exe` `cwd` `env` `comm` `loginuid` `tty` `pgid` `cgroups` | 中-高（会话/终端归属、`LD_PRELOAD` 类环境注入） |
| fcntl/ioctl 语义 | `cmd` `request` `argument` | 无（fcntl 已决策不建边，见 §5.1；`request` 弱） |
| socket 参数 | `domain` `proto` `type` `level` `optname` `optlen` `val` `peer` `source` `backlog` `how` | `domain`/`proto`/`backlog` 中；其余弱 |
| 轮询 fd 集合 | `fds`（poll/ppoll） | 中（进程在等哪些 fd） |
| 偏移/长度 | `offset` `length` `pos` `whence` | 弱 |
| 内存/映射 | `addr` `prot` | 无 |
| 进程元信息噪声 | `vm_size` `vm_rss` `vm_swap` `pgft_maj` `pgft_min` `fdlimit` `initval` `interval` `resource` | 无 |
| 采样噪声（已单列） | `LOG.*` `Reports.*` `Pings.*` `found` `prefix` `rel` `snap` `ts` `sep` `indefault` `z.` | 非字段（`env=`/argv 空格分隔区里的 `NAME=value`） |

