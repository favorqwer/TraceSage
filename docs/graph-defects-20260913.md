# 溯源图建边缺口清单（场景 4 Site Defacement + 场景 5 User Timer Resource Hijack + 场景 6 SQLite Pipeline Pollution，已整合去重）

> 面向后续接手实现的 agent。本文只描述"日志里有事件、但解析器没有建边/建错了顶点"的缺口，
> 每项都给了可复现证据、根因代码位置、期望修后图形态、实现建议、风险与验收判据。
> 生成日期 2026-09-13（场景 4/5）；2026-09-14 合入场景 6 证据并将原 X1 升级为缺陷 G5。
>
> **修复状态（2026-09-15）**：**G3 + G4 已修完并重导六库**（实现于 `jsonl/fields.py normalize_file_path()`，挂在 `pipeline/entity_registry.get_or_create_file()` 唯一 chokepoint）。
> 实测结果：六库边多重集 0 差异、File 顶点 40,381→40,318（−63）、括号注记/`/./`/内部 `//`/尾斜杠 均归零、行首 `//` 1,085 个不变；
> 场景 2 基线 final 39→40 边、execve 7→8、假入口消失，GT 召回 23/32→24/32=75.0%。其余 **G1/G2/G5 未动**（本文对它们的定级保留，但 G1 的规模构成已按档重测）。

## 0. 口径与背景

- 数据源：Sysdig JSONL（`input/sysdig/4_Site_Defacement.jsonl` 23,479,509 条 / `5_User_Timer_Resource_Hijack.jsonl` 约 17.6M 条 /
  `6_SQLite_Pipeline_Pollution.jsonl` 约 7.0M 条）
  → `sysdig-parser/main.py` 导入 Neo4j 库 `tracesage-4-site-defacement`（14,470 顶点 / 412,918 边）、
  `tracesage-5-user-timer-resource-hijack`（12,978 顶点 / 730,294 边）、
  `tracesage-6-sqlite-pipeline-pollution`（8,246 顶点 / 258,264 边）。
- 顶点身份：Process = `(pid, name)`，签名取 `coalesce(exepath,name)`；File = `path`；Network = `lip:lport->rip:rport`。
  **File 顶点身份就是路径字符串本身**，所以"同一对象、不同写法"= 图上两个互不相连的节点（G3/G4 的本质）。
- 边的 `syscall` 写家族基本名（`CANONICAL_SYSCALL_MAP`）：`readv/pread/preadv/preadv2→read`、
  `writev/pwrite/pwritev/pwritev2→write`、`sendmsg/sendmmsg→sendto`、`recvmsg/recvmmsg→recvfrom`、
  `renameat/renameat2→rename`、`unlinkat→unlink`、`mkdirat→mkdir`、`symlinkat→symlink`、
  `fchmod/fchmodat→chmod`、`openat/openat2/creat→open`、`fork/vfork→clone`。
- 参考产物：`groundtruth/4_Site_Defacement.groundtruth.json` / `.notes.md`、
  `groundtruth/5_User_Timer_Resource_Hijack.groundtruth.json` / `.notes.md`、
  `groundtruth/6_SQLite_Pipeline_Pollution.groundtruth.json` / `.notes.md`、
  分析脚本 `docs/pathnorm_impact.py`；
  本文配套件 `docs/graph-defects-20260913.md` + `docs/pathnorm_impact.py`。
- 注意：`0.0.0.0:0->0.0.0.0:0` 这类退化 Network 顶点在新图里由 connect/bind 正常建立，
  **"顶点是否存在"不能当作判据**，要用边的多重集/连通性判定。

## 1. 总表

### 1.1 需要修（5 项）

| ID | 缺口 | 受影响场景 | 证据规模（实测） | 缺的边 / 错的结构 | 优先级 |
|---|---|---|---|---|---|
| **G1** | 非 IP 传输端点（unix socket、pty 无名注记、netlink）不建顶点也不建边 | 4、5、6（全场景通用） | 场景4 `/dev/log` 99 条记录、`(<n>)` 2,816 条；场景5 `/run/user/1000/systemd/private` **8,236 条**、`/run/systemd/journal/syslog` 389 条、`(<n>)` 2,884 条；场景6 `/dev/log`（sudo 审计）、裸 `fd=N(<u>)` **353,051 条**（场景5 同类 1,033,675 条）；导入审计计数 `incomplete network` 场景4 537,103 / 场景5 1,534,430（含 G1 与 §7 既有待办两类） | 控制面：`systemctl ↔ systemd`；审计面：`sshd/sudo ↔ rsyslogd/journald`；**终端面：命令 → pty 的输出回显（场景6 整类丢失）**；采集面：`ss ↔ 内核路由/netlink` | **P0**（决定场景 5/6 召回上限） |
| **G2** | `sendfile`（零拷贝）不建模 | 4（六库中只有场景 4 有 web 服务器；其余 5 库 nginx/apache/httpd 进程数 = 0） | 全日志 `sendfile` 14 条记录 = **7 次调用**（5 次攻击者请求 + 2 次本机回环），nginx 315 条记录中 `read/readv/pread` = **0** | 每次调用应得 2 条边：`File --read--> Process` + `Process --write--> Network`；合计 14 条边，其中 10 条属攻击流程（723 B 响应体） | **P0**（"篡改后对外发布"目前只能靠响应头+access.log 侧面证明） |
| **G3** | `filename=` 通道不剥 `原始名(/绝对路径)` 注记 → 顶点挂错 | 2、4、5（**6 不受影响**） | 六库共 **3 个**此类顶点：`./update_patch.sh(/tmp/update_patch.sh)`（场景2 execve）、`.(/srv/progql-web/releases/release_20260531-211727)`（场景4 chmod）、`.(/tmp/diag_update)`（场景5 chmod）；三处度数均为 1。边界条件（场景6 实测）：同一 `tar --chmod` 在参数已是绝对路径时不漏注记（`/tmp/progql_sync/install_sync.sh` 等 6 条干净边），即只在**参数本身是相对名（`.`）**时才泄露 | 边本身在，但端点是孤立顶点；任何按目录/前缀的遍历取不到（实测 `.(/srv/...)` 与 `/srv/.../release_20260531-211727` 是两个节点） | **P1**、**已修（2026-09-15）**（同时清掉一个挂错的 execve 端点） |
| **G4** | 路径未做词法归一（`/./` 段、内部 `//`） | 3、4、5（**6 为 0**） | 场景4 `/./` 顶点 **1 个**（`.../current_before_20260531-211727/./assets`）；六库内部 `//` 顶点 **100 个**（场景3 44、场景4 36、场景5 20）；归一后 **126 个原键合并 + 42 个纯改名**（场景1、6 各 0） | 同一目录/文件出现两种顶点，父子链断裂（`.../current_before_..././assets` 与 `.../current_before_.../assets/site.css` 不同父链） | **P1**（与 G3 同一批改动，必须一起验证）、**已修（2026-09-15）** |
| **G5** | 失败的生命周期调用（`mkdir -p` 逐级 `EEXIST` 等）**不留任何痕迹**，导致目录顶点缺失 | 4、5、6（**6 后果最实质**） | 场景6：`mkdir res=-17(EEXIST) path=progql-sync(/root/.local/share/progql-sync)` 等逐级失败 → 实测 `/root/.local/share/progql-sync` 与 `.../state` **两个 File 顶点不存在**（查返回空集）；场景4 `mkdir -p /srv/progql-web/current/assets`、场景5 `mkdir -p ~/.config/systemd/user` 同现象（仅影响单个子目录） | 攻击者工具/持久化根目录在图上没有节点；`state/install.log`、`state/install.complete`、`state/activity.log` 三个留痕无父目录可聚合，也无法回答"该目录谁建、何时建" | **P1**（原列为 X1“不修”，场景 6 证据将其升级） |

### 1.2 明确判定"不修"（3 项，避免后续 agent 误动）

| ID | 现象 | 为什么不修 |
|---|---|---|
| X1 | （已作废）**已升级为缺陷 G5**：原写"EEXIST 不建边属语义正确"，场景 6 证据表明它会让持久化根目录连顶点都不存在，见 §1.1 与 §6 | 不再作为"不修"项；保留编号以免交叉引用失效 |
| X2 | 攻击机侧链路缺失（Kali 的 `sshpass/scp/curl/python3 -m http.server 8084·8085/payload 与 tar 包构建`） | 单主机建模范围（AGENTS §1）。攻击入口只能是 `192.168.122.128:*` 这类 Network 顶点 |
| X3 | `nmap -p 22,8081` 扫描无顶点无边 | 采集层限制：全日志 `evt.type` 集合中**没有 `drop`/`conntrack`**（采集未加载 iptables/conntrack 探针），SYN 半开也不产生 `accept`/`connect`。要痕迹须重新采集或引防火墙日志 |
| X4 | "网络字节 = 文件字节"守恒边不可用（SSH 信道、tar/gzip 解压） | 信道分片与文件写不成 1:1（场景4 载荷 687 B ↔ SSH 帧 1112/1564/1672 B）。属固有性质，任何逐字节判据在此类边上都会假失败 |

## 2. G1 —— 非 IP 传输端点未建模（P0）

### 2.1 症状与证据

场景 5 的持久化控制链在图上**完全断开**（本项影响最大）：

```
# pid 4723 = systemctl --user daemon-reload（由 install.sh 派生）
> connect fd=3(<u>)
< connect res=0 tuple=ffff8b7f87f08800->ffff8b7f87f0a000 /run/user/1000/systemd/private | fd.l4proto=<NA>
> sendmsg fd=3(<u>ffff8b7f87f08800->ffff8b7f87f0a000 /run/user/1000/systemd/private) size=48
< sendmsg res=48 data=.AUTH EXTERNAL..DATA..NEGOTIATE_UNIX_FD..BEGIN..
> sendmsg ... size=160
< sendmsg res=160 data=.../org/freedesktop/systemd1.........s.....Reload...
```

实测这些 systemctl 顶点在库中的邻居：

| pid | args | 度数 | 邻居（去重前 4 个） |
|---|---|---|---|
| 4723 | `--user daemon-reload` | 18 | bash(clone/execve) + 若干 lib 读 |
| 4735 | `--user start progql-helper.service` | 18 | 同上；除 lib 读外无任何文件/网络语义边 |
| 4728 | `--user enable --now progql-helper.timer` | 19 | + `/dev/pts/0` 写 |
| 8575/8576 | `--user stop` / `--user disable` | 18/19 | 同上 |

后果链：图里 `cat --write--> progql-helper.timer`（安装器写 unit）与
`systemd --read--> progql-helper.timer`、`systemd --execve--> worker.sh`（systemd 加载并执行）之间
**没有任何边**，只有时间先后。反向因果遍历从 POI（`gzip --write--> archive/run_*.tar.gz`）追到
`systemd`（入度 0）即触底，永远追不到 P2/P3 的安装链 → 直接压低本场景召回上限。

场景 4 同类问题（审计面）：

```
# pid 6966 = sshd 会话子进程（弱口令登录成功）
< connect res=0 tuple=ffff8939144a3c00->ffff893807256000 /dev/log
> sendto fd=5(<u>ffff8939144a3c00->ffff893807256000 /dev/log) size=97
> close fd=5(<u>... /dev/log)
```
库里 `/var/log/auth.log` 顶点存在、`rsyslogd --write--> /var/log/auth.log` 有 50 条实例边，
但与 4 次 sshd 登录**不连通**。场景 5 里 rsyslog 走 `/run/systemd/journal/syslog`（389 条记录），同理断开。

netlink（采集面）：

```
# pid 8554 = ss -tunap（场景5 每轮 1 次）
> socket domain=16(AF_ROUTE) type=524291 proto=4
< socket fd=3(<n>)
> bind fd=3(<n>)   /  < bind res=0 addr=NULL
（该 pid 记录分布：readlink 2198、openat 1496、close 1002、getxattr 964、read 828、
  newfstatat 328、getdents64 320、mmap 72、recvmsg 40、setsockopt 24、sendmsg 12）
```
`<n>` 注记没有任何名字 → "攻击者枚举主机全部连接/监听端口"这一行为在图上只剩
`ss --write--> socket_snapshot.txt` 一条产物边。

pty 回显（终端面，**场景 6 整类丢失**）：

```
# pid 9282 = ls --color=auto -l /tmp/progql_sync（场景6 阶段1；9292 同）
> write fd=1(<u>) size=9    /  < write res=9  data=total 12.
> write fd=1(<u>) size=75   /  < write res=75 data=-rwxr-xr-x 1 root root 415 ... install_sync.sh ...
```

对比场景 5 的同一条命令：`> write fd=1(<f>/dev/pts/0) size=9` → 有顶点有边。
差异原因：场景 6 的 root shell 由 `sudo su` 产生，sudo 自行 `openat(/dev/ptmx)` + `ioctl` 分配了**新的 pty 对**，
sysdig 把该 slave fd 的类型符报成 `u` 且不带名字 → 与 unix socket 落入同一丢弃分支。
规模：场景 6 日志裸 `fd=N(<u>)` **353,051** 条（场景 5 为 1,033,675 条）。
后果：攻击者"在终端上看到了什么"（列出解包脚本、确认落地结果）图上不可见，`ls` 只剩 `bash --execve--> ls` 一条边。

### 2.2 根因（代码位置）

1. `sysdig-parser/parsers/jsonl/fields.py:99 extract_file_and_socket()`
   —— 只有 `fd=<f>路径` → `path`、`<p>pipe:[N]` → `pipe`、能解出 `lip:lport->rip:rport` 的 → `sip/sport/dip/dport`。
   unix/netlink 的 `ffff...->ffff...` 走 `fields.py:151`（`"ffff" not in socket_ep` 判定）→ 只留
   `{'socket': '<u>ffff8b7f87f08800->ffff8b7f87f0a000 /run/user/1000/systemd/private', 'fd_type':'u', 'fd_num':'3'}`，
   **socket 路径其实还在 `socket` 串里**，只是没被拆成字段。
2. `sysdig-parser/parsers/pipeline/entity_registry.py:114-122`
   ```python
   elif "socket" in file_socket:
       # socket 但无完整四元组（如 unix socket `ffff->ffff`、内核 fd 地址）
       self._incomplete_network_count += 1
       entities[1] = None          # ← unix / netlink 在此被丢弃
   elif "fd_num" in file_socket:
       self._no_object_count += 1  # ← 无名注记在此被丢弃：fd=3(<n>)、场景6 的 fd=1(<u>)(pty slave)
       entities[1] = None
   ```
   注：场景 6 的 pty 输出与 unix socket 落在**同一个丢弃分支**（`<u>` 但括号内无名字），
   所以修 G1 时一并解决终端回显面；但名字本身不在日志里，需额外的 pty 还原（见 §2.4 第 6 点）。
3. `sysdig-parser/parsers/dispatch/handlers.py:16-17`（connect 注记）、`:22-23`（bind：
   "本采集全为 netlink socket 的 addr=NULL，不建边"）、`:571`/`:604`（accept/fcntl 的
   `note_incomplete_network()`）——设计上是有意为之，不是 bug。

### 2.3 期望修后图形态

场景 5（新增语义边，方向按现有 p2f/f2p 约定）：
```
/usr/bin/systemctl --connect--> unix:[/run/user/1000/systemd/private]
/usr/bin/systemctl --sendto---> unix:[/run/user/1000/systemd/private]      （daemon-reload/enable/start/list-timers/status/stop/disable）
/usr/lib/systemd/systemd --recvfrom--> unix:[/run/user/1000/systemd/private]
/run/user/1000/systemd/private --recvfrom--> /usr/bin/systemctl            （回包）
```
连通性判据：`/usr/bin/bash --execve--> /usr/bin/systemctl` 到 `/usr/lib/systemd/systemd --execve--> .../worker.sh`
之间的最短跳数 ≤ 4（当前为不可达）。

场景 4：
```
/usr/sbin/sshd --sendto--> unix:[/dev/log]
/usr/sbin/rsyslogd --recvfrom--> unix:[/dev/log]
```
连通性判据：`/usr/sbin/sshd` 与 `/var/log/auth.log` 在 ≤ 3 跳内连通（当前不可达）。

netlink：
```
/usr/bin/ss --sendto--> netlink:[AF_ROUTE] ；  netlink:[AF_ROUTE] --recvfrom--> /usr/bin/ss
```

场景 6（sudo 审计 + pty 回显）：
```
/usr/bin/sudo --sendto--> unix:[/dev/log]        （data=<85>Jun  2 16:19:02 sudo: ubuntu : TTY=pts/3 ; PWD=/home/ubuntu/Desktop ; USER ...）
/usr/sbin/rsyslogd --recvfrom--> unix:[/dev/log]  → 再接现有的 rsyslogd --write--> /var/log/auth.log
ls --write--> unix:[/dev/pts/N]                   （需先从 ptmx 的 ioctl(TIOCGPTN) 还原编号，否则只能按匿名哨兵分桶）
```
连通性判据：`/usr/bin/sudo` 与 `/var/log/auth.log` 在 ≤ 3 跳内连通（当前不可达）；
交互命令（`ls`/`cat`/`grep`）至少各有一条输出边（当前为 0 条）。

### 2.4 实现建议（复用管道先例，最小侵入）

解析器已有完全同构的成功先例：**匿名管道**。`entity_registry.py:76-100` 的处理是
"用 `fd_table` 记住 `pipe()` 退出记录登记的 inode，在后续裸 `fd=N(<p>)` 上还原 `pipe:[ino]`，
还原失败退到按秒分桶哨兵 `pipe:[anonymous@<sec>]`"，并且**把管道建成合成 File 顶点**，
于是"写家族 → p2f、读家族 → f2p"自动命中现有通用 handler，引擎无感。建议照抄这套结构：

1. `extract_file_and_socket()` 增两个返回键：
   - `unix_path`：从 `<u>` 注记的 `...->... /path` 尾部取路径（正则 `\s(/[^\s]+)$`）；
     抽象命名空间（`@/tmp/.X11-unix/X0`、`unix:abstract=...`）取 `@...` 段并加前缀区分。
   - `netlink_domain`：**不来自 fd 注记**，需从同一 fd 的 `socket` 进入记录 `domain=16(AF_ROUTE)` 学（见 3）。
2. `fd_table.py` 扩展：在 `connect`/`bind`/`sendmsg`/`recvmsg` 的**退出记录**上登记
   `(pid, fd) -> unix:[<path>]` 或 `netlink:[<domain名>]`；`close` 失效；`dup`/`fcntl(DUPFD)`/`clone` 传播
   —— 这些钩子 `observe_start/observe_end` 已经存在，直接复用。
   这一步是关键：`sendto fd=5(<u>ffff..->ffff.. /dev/log)` 的名字在 enter/exit 记录里都有，而
   `recvmsg fd=3(<u>)` 这种裸注记只能靠 fd 表还原。
3. `entity_registry.py:114` 之前插入新分支：`unix_path`/fd 表命中 → `get_or_create_file("unix:[...]", "unix:[...]")`
   （**沿用 File 标签，不新增标签**，与管道一致，写入层/约束/对比工具零改动）；
   无法还原时按哨兵 `unix:[anonymous@<sec>]`，并计数上报。
4. `NetworkEntity` 保持不变；不要试图把 unix socket 塞进四元组模型（`get_or_create_network` 的键是
   `ip:port->ip:port`，塞进去会污染 `tracesage-*` 的 Network 顶点集）。
5. **细分审计计数**（强烈建议，否则无法验收）：把现有单一 `incomplete_network_count`
   拆成 `unix_unresolved` / `netlink_unresolved` / `halfbound_ip_socket`（后者对应 §7 既有待办），
   并在 `tools/dump_parser_counters.py` 的导出键里加上。

命名建议理由：`unix:` / `netlink:` 前缀与 `pipe:[...]` 同族，一眼可辨合成顶点；避免与真实
`/dev/log` 之类设备文件路径直接同名（虽然同名会 MERGE 成一个顶点、语义上也可接受，但会改变既有
`/dev/urandom` 等顶点的度数，回归面难判）。若你更希望"同 inode 即同顶点"，用裸路径命名亦可，
但必须接受该选择带来的合并，并在验收里逐条列。

6. **pty 回显（场景 6 整类丢失的面）**：`fd=1(<u>)` 不带名字，无法从该条记录直接得到终端身份。
   两条可行路径，按优先级：
   - 用同一会话里 sudo 的 `openat fd=9(<f>/dev/ptmx)` + `ioctl request=80045430(TIOCGPTN)` 退出记录还原 pty 编号，
     归一为 `unix:[/dev/pts/N]`（需确认 sysdig 是否把 ioctl 参数回写为编号；若否，退下一种）；
   - 退而求其次：按 `(pid, fd)` 建会话级哨兵顶点 `unix:[anonymous-pty@<pid>:<fd>]`，
     至少让"谁向终端输出过什么"成为边（代价：跨会话不可聚合，需在 notes 里声明）。
   不得把无名 `<u>` 一律归入全局单点 `unix:[anonymous]`：那会把所有会话的回显合流成一个 hub，
   直接污染度数特征与入口排序。

### 2.5 风险与必须做的回归

- **hub 顶点**：全主机的 systemd 控制面都落到 `unix:[/run/user/1000/systemd/private]` 一个节点，
  度数很高。而调查引擎的 projection 第三特征是 `count(out(v))/count(in(v))`、入口打分是
  `count(in(n))=0 ORDER BY n.rel DESC`（见 `input/sysdig/*.query`）→ **顶点度数分布会被改变**，
  基线的 `entry_ranking`、`b_score_edges`、`final_edges` 都可能变。因此 G1 落地后必须重跑基线并逐条归因。
- 场景 3（SSH Spray）里 `sshd`/`sudo`/`su` 的 tty/ptmx/utmp 分支会被 journald/dbus 边影响，需一并复核。
- 抽象 unix socket（X11、dbus）数量大，若不做 fd 表还原、全部退到按秒哨兵，会造成
  **同秒不同 socket 合流**（管道哨兵已有同样权衡，见 `entity_registry.py:87-89` 注释），必须显式记录。

## 3. G2 —— `sendfile` 零拷贝未建模（P0）

### 3.1 症状与证据

场景 4 阶段 1/4 的 6 次攻击者 HTTP 请求，图里**只有头、没有体**：

| 连接 | 已有边 | 已有边字节 | 缺失（原始日志实测） |
|---|---|---|---|
| `192.168.122.128:56600->...:8081` | accept / recvfrom / write | 84 / 247 | `index.html --read--> nginx` 266 B |
| `:57028` | 同上 | 99 / 244 | `assets/site.css --read--> nginx` 67 B |
| `:57034` | 同上 | 95 / 246 | `release.txt --read--> nginx` 22 B |
| `:60934`（`HEAD /`） | accept / recvfrom / write | 85 / 247 | 无（HEAD 本就没有 body） |
| `:50418` | 同上 | 84 / 247 | `index.html --read--> nginx` 331 B（**被篡改后的首页**） |
| `:50422` | 同上 | 106 / 246 | `COMPROMISED_MARKER.txt --read--> nginx` 37 B（**POI 文件被外发**） |

原始记录（evt.num 68521-68530）：
```
< openat  fd=15(<f>/srv/progql-web/current/index.html) dirfd=-100(AT_FDCWD) name=/srv/progql-web/current/index.html flags=65(O_NONBLOCK|O_RDONLY)
> writev  fd=14(<4t>192.168.122.128:56600->192.168.122.129:8081) size=247
> sendfile out_fd=14(<4t>...) in_fd=15(<f>/srv/progql-web/current/index.html) offset=0 size=266
< sendfile res=266 offset=266
```
nginx 全部 315 条记录的 `evt.type` 分布：newfstatat 62、epoll_wait 48、recvfrom 32、close 32、
setsockopt 30、switch 17、writev 16、write 16、openat 16、epoll_ctl 16、accept 16、**sendfile 14**
——**没有任何 read/readv/pread**，所以不是"边被丢弃"，而是该家族整体未建模。

### 3.2 根因

- `sysdig-parser/parsers/dispatch/meta_config.py:59-67` 的四个方向名单不含 `sendfile`：
  ```python
  _READ_FAMILY = ("read","readv","pread","preadv","preadv2")
  _WRITE_FAMILY = ("write","writev","pwrite","pwritev","pwritev2")
  _SEND_FAMILY = ("sendto","sendmsg","sendmmsg");  _RECV_FAMILY = ("recvfrom","recvmsg","recvmmsg")
  ptof_system_calls = _WRITE_FAMILY + ("rename",)   # 通用 handler：两端都取"进入记录的 fd 注记"
  ```
  通用 `_make_edge_action()`（`handlers.py:188`）只认 `start_entities[1]`（单个 fd），
  而 `sendfile` 的进入记录同时带 **两个 fd**（`in_fd` 文件 + `out_fd` 套接字），
  所以它既进不了 `_READ_FAMILY` 也进不了 `_WRITE_FAMILY`，`CANONICAL_SYSCALL_MAP` 里也没有它 → 无 handler → 静默忽略。
- `handlers.py` 顶部注释与 `meta_config.py` 的"仅收录已注册 handler 的名字"说明，这类
  双 fd 系统调用需要专用 handler，不能靠归一表解决。

### 3.3 期望修后图形态与实现建议

每次 `sendfile` 建 **2 条边**，bytes 取退出记录 `res=`（= 实际传输字节）：
```
(FileEntity(in_fd路径) --read--> Process)          # 归一 syscall 建议 write 家族侧另计：见下
(Process --write--> NetworkEntity(out_fd四元组))
```
- 建议 syscall 属性直接用 `sendfile`（**不要**伪装成 `read`/`write`）：
  一是伪装成 `read`/`write` 会让 syscall 家族语义失真（后续按类型剔除/统计都不可信）；
  二是调查权重 `1/(abs(r.amount-st.amount))` 依赖 bytes，语义上 `sendfile` 的 bytes 与 read/write 同源，
  但保留真名便于后续按类型剔除。若你希望它直接参与 read/write 族评分，再单独加开关。
- 实现路径：`handlers.py` 里仿照 `_rename_action`（同一进程 → 两个实体的双端操作先例，
  `p2f`+`f2p` 各一条）注册 `_sendfile_action`：进入记录解析 `in_fd=` / `out_fd=` 两个注记
  （`extract_file_and_socket()` 可复用，但要按 `in_fd=`/`out_fd=` 分别切 token，
  现有 `record_file_socket()` 只取第一个 `fd=`）；退出记录用 `record_res()`/`record_failed()` 判失败
  （`res<0` 不建边），`res>=0` 作 bytes。**不要用 `record_size()`**（AGENTS §9.4 已记录过
  "res 缺失与 res<0 合并返回 -1"导致整类丢边的教训）。
- 同类待评估（本次日志未出现，避免将来漏）：`splice`、`tee`、`copy_file_range`、`sendfile64`
  —— 本导出 `evt.type` 集合中计数为 0，实现时可一并注册，但**不要**为它们做无证据的口径变更。

### 3.4 验收

- 场景 4 重导后应新增：`f2p read` 5 条（攻击者请求）+ `p2n write` 5 条；全库边数 412,918 → 412,928（含 2 条回环请求则 +4）。
- `MATCH (f:File)-[r:read]->(p:Process {exepath:'/usr/sbin/nginx'}) RETURN count(r)` 由 **0 变 >0**。
- GT 影响：`groundtruth/4_Site_Defacement.groundtruth.json` 的 P0/P9 需要各补 4/3 条 read 边
  （当前按"库里没有"故未登记），修后要**同时更新 GT 与 notes 的 M1 段**。

## 4. G3 —— `filename=` 括号注记未剥壳（P1）

### 4.1 症状与证据

```
< fchmodat res=0 dirfd=4(<d>/srv/progql-web/releases/release_20260531-211727)
           filename=.(/srv/progql-web/releases/release_20260531-211727) mode=0755(...)
```
入库边 `/usr/bin/tar --chmod--> .(/srv/progql-web/releases/release_20260531-211727)`，
而真正的目录顶点 `/srv/progql-web/releases/release_20260531-211727` 是另一个节点（只连着 mkdir 那条边）。
同类：场景 5 `tar --chmod--> .(/tmp/diag_update)`；场景 2 `./update_patch.sh(/tmp/update_patch.sh) --execve--> /tmp/update_patch.sh`
（后者已由 G3 路径归一修复）。

### 4.2 根因（为什么同一份日志里 mkdirat 归一了、fchmodat 没归一）

```
9133668 < mkdirat res=0 dirfd=4(<d>...) path=./assets(/srv/.../release_20260531-211727/assets)   → 入库为干净绝对路径 ✓
9133741 < fchmodat res=0 dirfd=4(<d>...) filename=.(...)                                          → 保留原始注记 ✗
```
- `mkdir/unlink/symlink` 家族：`handlers.py:294 _make_exit_path_action()` 用
  `handlers.py:277 _normalize_exit_path()`，规则"括号内以 `/` 开头才剥壳" → 归一成功。
- `fchmod/fchmodat`：`handlers.py:224 _make_chmod_action()` 取 `end_entities[1]`，即
  通用实体抽取的结果；而通用抽取在 `entity_registry.py:70` 调 `fields.py:184 extract_process_file()`，
  该函数**有意不剥括号**（注释：`filename=` 是字面路径，括号属于文件名本身，
  否则会撕碎 `/tmp/foo (bar)`），并且 `filename=` 分支的优先级高于 fd 注记
  （`entity_registry.py:69-73`：`if "path" in file_socket ... elif process_file is not None`）。
  对 `fchmodat` 而言 `dirfd=4(<d>...)` 是目录注记、不产出 `path`，于是落到 `filename=`。

### 4.3 实现建议与风险

- 最小改动：在 `extract_process_file()` 里套用与 `_normalize_exit_path()` **完全相同**的守卫
  （`^(?P<raw>[^()]*)\((?P<abs>/[^)]*)\)$` 才取 `abs`）。
  该守卫对 `(deleted)`（括号内不以 `/` 开头）与 `/tmp/a (copy).txt` 都不生效，
  所以原注释担心的场景不受影响。
- 更彻底（可选）：把这条"括号注记有条件剥壳"规则收敛成单一工具函数，`extract_process_file` /
  `_normalize_exit_path` / `_normalize_rename_path`（`handlers.py:139`，三份近似实现）统一调用，
  避免下次再出现"某条通道忘了归一"。
- 回归面：六库共 3 个顶点、3 条边的 dst 改写（不新增不删除边），风险低。
  必须同步修改的 GT：场景 2 GT 中 `./update_patch.sh(/tmp/update_patch.sh)` 那 1 行、
  场景 4 GT P6 的 `tar --chmod--> .(...)`、场景 5 GT P1 的 `tar --chmod--> .(/tmp/diag_update)`。

## 5. G4 —— 路径词法归一（P1）

- 证据 1（`/./`）：`< mkdir res=0 path=/srv/progql-web/releases/current_before_20260531-211727/./assets`
  —— `cp -a /srv/progql-web/current/. "$snap"/` 自己拼的路径，sysdig 原样给出、无括号可剥；
  库里因此**不存在** `.../current_before_20260531-211727/assets` 顶点，而同目录下的
  文件写边用的是 `.../current_before_20260531-211727/assets/site.css`（来自 `fd=<f>` 注记，内核已归一）
  → 快照目录的父节点与子文件节点接不上。
- 证据 2（内部 `//`）：`/home/labweb/snap/.../fontconfig//36c5...cache-9` 与
  `/home/labweb/snap/.../fontconfig/36c5...cache-9` 在场景 4 库里是**两个顶点**（同一文件两种拼写）。
- 实现建议：在 File 顶点键生成处（`entity_registry.py:181 get_or_create_file()`）做一次
  `posixpath.normpath()`，**放在 G3 的剥壳之后**。实测 `posixpath.normpath` 的行为对本项目是安全的：
  `//usr/share/fonts` → 保持 `//usr/share/fonts`（POSIX 保留行首双斜杠，snap-confine 在 chroot 下
  mkdirat 的 1,185 个 `//...` 顶点**不会被误并进真实系统路径**），
  `/tmp/a (copy).txt` 不变，`pipe:[123]` 不变。
- 回归面（实测，脚本 `docs/pathnorm_impact.py`）：

  | 库 | 归一后合并顶点组 | 参与合并的原键 | 纯改名 |
  |---|---|---|---|
  | tracesage-1 | 0 | 0 | 0 |
  | tracesage-2 | 1 | 2 | 1 |
  | tracesage-3 | 26 | 52 | 18 |
  | tracesage-4 | 23 | 46 | 15 |
  | tracesage-5 | 13 | 26 | 8 |
  | tracesage-6 | 0 | 0 | 0 |
  | **合计** | **63** | **126** | **42** |

  即 G4 的真实影响面是 **168 个 File 顶点**（不是"只动 4 条边"），全部是
  fontconfig/桌面缓存类噪声顶点的合并 + 场景 4 快照目录归一。场景 1、6 完全不受影响。
- 若想控制风险，可分两档发布：**G4-a** 只折叠 `/./`（六库仅 1 个顶点，场景 4 攻击链），
  **G4-b** 再折叠内部 `//`（100 个顶点）。建议 G3+G4-a+G4-b 一次做完，反正重导与复核成本是固定的。

## 6. G5 —— 失败的生命周期调用不留痕，导致目录顶点缺失（P1，由原 X1 升级）

### 6.1 证据

场景 6（后果最实质）：`install_sync.sh` 的 `mkdir -p "$BASE" "$STATE"` 逐级返回 EEXIST（目录在 sysdig 启动前已由准备命令建好）：

```
< mkdir res=-17(EEXIST) path=/root
< mkdir res=-17(EEXIST) path=.local(/root/.local)
< mkdir res=-17(EEXIST) path=share(/root/.local/share)
< mkdir res=-17(EEXIST) path=progql-sync(/root/.local/share/progql-sync)
```

实测：
`/root/.local/share/progql-sync` 与 `/root/.local/share/progql-sync/state` **两个 File 顶点不存在**（查询返回空集）。

同现象的另两例（影响面较小，只缺一个子目录）：
- 场景 4：`mkdir -p /srv/progql-web/current/assets`（pid 8643，EEXIST）→ 无 `mkdir --mkdir-->` 边；
- 场景 5：`mkdir -p ~/.config/systemd/user`（pid 4717，EEXIST）→ 无边（同批的 `progql-helper`、`.../logs` 是本轮新建，故有边）。

### 6.2 后果

- 攻击者的**工具/持久化根目录在图上没有节点**：`state/install.log`、`state/install.complete`、`state/activity.log`
  这三个留痕无法按目录树聚合（只能靠 `path STARTS WITH` 字符串前缀），也无法回答"该目录是谁、什么时候建的"。
- 对入口评分有影响：projection 用 `count(out(v))/count(in(v))`，目录顶点缺失会改变其下文件的度分布，修后需重新归因。

### 6.3 实现建议（方案 1 优先，方案 2 可选）

1. **失败也要建顶点（不建边）**：`mkdir`/`rmdir`/`symlink`/`unlink` 失败时，先对归一后的绝对路径调
   `ctx.get_or_create_file(path, path)` 再早退，这样目录树不出现空洞，且不改变任何边的多重集（幂等安全）。
   改动点：`handlers.py:294 _make_exit_path_action()` 里 `record_failed()` 早退分支前插入建顶点；
   同时新增审计计数（如 `lifecycle_failed_vertex`）便于归因。
2. **区分 `mkdir -p` 的逐级 EEXIST**：若同一命令序列中存在更深层级的成功 mkdir（场景6 的
   `incoming`/`work`/`reports`/`archive`/`final` 均新建成功），可考虑为中间的 EEXIST 级补建 `mkdir` 边并带
   `errno="EEXIST"` 属性。风险：给边加属性会改变 `dump_neo4j_content.py` 的内容指纹，必须跟一次内容等价 diff；
   且不得把失败当成功（AGENTS §9.4 已记录过把"res 缺失"当失败的整类丢边教训）。
3. 不要把失败调用直接当成功建边（会破坏基线的边语义）。

### 6.4 验收

- 重导后 `MATCH (f:File) WHERE f.path IN ['/root/.local/share/progql-sync','/root/.local/share/progql-sync/state'] RETURN count(f)` 应为 **2**（当前 0）。
- 方案 1 不改边数：各库边总数应与改前**完全相等**（只允顶点数上升），否则为回归。
- 方案 2 则逐条列出新增边并归因。

## 7. 相关既有待办（不在本文三场景的新增发现里，但同属"应建边而未建"，勿重复立项）

AGENTS §9.9 已记录且**未完成**：数据流族（`sendmsg/recvmsg/writev/sendto`）在 fd 注记只给
**单端点/半绑定**（如 `fd=13(<4u>127.0.0.53:53)`、`fd=59(<4>0.0.0.0:0)`）时不产出 NetworkEntity 就不建边；
已按 starttime 回查实测其中 **94 条**可在同一记录的 `tuple=` 字段兜底恢复，
建议实现时与 G1 共用同一处改动（`extract_file_and_socket()` 增加 `tuple=` 回退 + 细分审计计数）。
证据：按 starttime 回查原始日志逐条实测（复现方式见 §10）。

## 8. 实施顺序、打包与成本

**固定成本是一次"重导 + 等价性验证 + 基线复核"**，所以五项建议一次做完，分三个 PR 提交：
- PR-1 = G3 + G4 + **G5 方案 1**（纯归一 + 失败建顶点，不改变任何边的多重集，风险最低）
- PR-2 = G1（非 IP 端点建模，需 `fd_table` 扩展与命名约定评审）
- PR-3 = G2（`sendfile` 双端 handler）

实测成本（可直接引用）：

| 步骤 | 工具 | 耗时 |
|---|---|---|
| 六库 dry-run 计数 baseline diff | `tools/dump_parser_counters.py --baseline` | 约 24 分钟（六库解析 ≈ 1,413.8s） |
| 六库 DROP/CREATE + 重导 | `sysdig-parser/main.py --input-dir input/sysdig --all --neo4j-database-prefix tracesage-` | 约 24 分钟（逐库 132.6/260.2/340.2/287.6/277.4/115.8s） |
| 图内容等价性 diff | `tools/dump_neo4j_content.py --baseline` | 分钟级~十分钟级（边数最大的库 1.0M 边） |
| 场景 1 基线重跑 + 逐字段比对 | `bash progql-local/baseline/run-baseline.sh` | 数分钟；**G1 会改动场景 1**（该库有 sudo / dbus-daemon / rsyslogd 顶点，日志中 `/dev/log` 18 条、netlink `(<n>)` 467 条；`sendfile` 与 `systemd/private` 为 0），预期基线发生变化并逐条归因；G2 与 G3/G4 在场景 1 无触发点 |
| 场景 2 基线重跑 | 同上（POI 参数化） | 数分钟；预期 `p2n/connect` 与 G3 改名生效 |

## 9. 验收清单（逐项判据，必须全部留档）

1. **计数只增不减、且可归因**：改前改后 `dump_parser_counters.py` 全量计数 diff，
   允许变化的项：`edges.p2f`、`edges.f2p`、`edges.p2n`、`incomplete network`（拆分为
   `unix_unresolved` / `netlink_unresolved` / `halfbound_ip_socket` 三项新键）；
   顶点计数应**只降不升**（G3/G4 是合并）。任何未预期项变化 = 回归，停下归因。
2. **G2 专项**：`tracesage-4-site-defacement` 中 `MATCH (:File)-[r:read|sendfile]->(:Process {exepath:'/usr/sbin/nginx'}) RETURN count(r)` > 0；
   且 6 次攻击者请求中 5 次有 body 边（`HEAD /` 本就无 body）。
3. **G1 专项**：
   - 场景 5：`/usr/bin/systemctl` 顶点与 `/usr/lib/systemd/systemd` 顶点**图上连通**（最短跳数 ≤4）；
   - 场景 4：`/usr/sbin/sshd` 与 `/var/log/auth.log` 连通（≤3 跳）；
   - 场景 6：`/usr/bin/sudo` 与 `/var/log/auth.log` 连通（≤3 跳）；`ls`(9282/9292) 至少各有一条输出边（当前为 0）。
4. **G5 专项**：场景 6 重导后 `MATCH (f:File) WHERE f.path IN ['/root/.local/share/progql-sync','/root/.local/share/progql-sync/state'] RETURN count(f)` = **2**（当前 0）；
   且方案 1 下六库**边总数与改前完全相等**（只允许顶点数上升）。
5. **G3/G4 专项**：重导后全库扫描 `paren-annotated` 顶点数 = **0**、`/./` = **0**
   （复扫），内部 `//` 顶点数由 100 降为 0、
   行首 `//`（snap 类）保持 **1,185 个不变**（这是"没误伤"的关键反例）。
6. **基线归因**：`output/baseline/...` 新旧 `baseline.json` diff，若 `stages`/`entry_ranking`/
   `entry_candidate_lists`/`final_edges`/`b_score_edges`/`b_raw_edge_keys`/`forward_union_edge_keys`
   任一变化，必须逐条写明是"预期改进"（如 systemd 边接通）还是回归。
   特别注意 projection 的度数特征 `count(out(v))/count(in(v))` 会被 G1 的 hub 顶点改变。
7. **GT 与文档同步**：
   - `groundtruth/2_...groundtruth.json`：`./update_patch.sh(/tmp/update_patch.sh)` 行改写；
   - `groundtruth/4_...groundtruth.json`：chmod 行改写 + P0/P9 补 sendfile 读边；notes 的 M1/M7/M8 段作废改写；
   - `groundtruth/5_...groundtruth.json`：`.(/tmp/diag_update)` 行改写，notes 的 N1/N2/N5 段作废改写；
   - `groundtruth/6_...groundtruth.json`：本文场景无 paren/`/./` 顶点（G3/G4 不改本库 GT），
     但 G1 修后需补 `ls`/`cat` 的输出边与 `sudo→/dev/log` 边，notes 的 S6-1/S6-2/S6-3 段作废改写；
   - `AGENTS.md` §9.9：`incomplete network` 口径与数据流族四元组不全整段、
     以及 §8 tools 表（若新增脚本）需要同步。
8. **确定性**：同一份新库连跑基线 ≥3 次，`baseline.json` 逐字节一致（AGENTS §7 的既有口径）。

## 10. 证据复现命令

```bash
# 未归一路径顶点扫描（六库）与 normpath 回归面模拟
.venv/Scripts/python.exe docs/pathnorm_impact.py

# 场景 4：nginx 为何没有读边（read=0、sendfile=14）
grep -E '"proc.pid":5691[,}]' input/sysdig/4_Site_Defacement.jsonl \
  | grep -o '"evt.type":"[^"]*"' | sort | uniq -c | sort -rn
# 场景 4：unix syslog socket
grep -m6 -F '/dev/log' input/sysdig/4_Site_Defacement.jsonl
# 场景 5：systemctl↔systemd 控制面、ss 的 netlink
grep -c -F '/run/user/1000/systemd/private' input/sysdig/5_User_Timer_Resource_Hijack.jsonl   # 8236
grep -E '"proc.pid":(4723|4735|8575)[,}]' input/sysdig/5_User_Timer_Resource_Hijack.jsonl | grep -E '"evt.type":"(connect|sendmsg|recvmsg)"'
grep -E '"proc.pid":8554[,}]' input/sysdig/5_User_Timer_Resource_Hijack.jsonl | grep -E 'AF_ROUTE|<n>'
# 场景 6：sudo 审计 socket、pty 无名注记、mkdir -p 逐级 EEXIST
grep -E '"proc.pid":(9017|9018)[,}]' input/sysdig/6_SQLite_Pipeline_Pollution.jsonl | grep -E '/dev/log|/dev/ptmx'
grep -E '"proc.pid":(9282|9292)[,}]' input/sysdig/6_SQLite_Pipeline_Pollution.jsonl | grep '"evt.type":"write"'   # 看到 fd=1(<u>)
grep -E '"proc.pid":(9286|9300)[,}]' input/sysdig/6_SQLite_Pipeline_Pollution.jsonl | grep -E '"evt.type":"mkdir"' # 看到 res=-17(EEXIST)
grep -c -E 'fd=[0-9]+\(<u>\)' input/sysdig/6_SQLite_Pipeline_Pollution.jsonl   # 353051（场景5 为 1033675）
# 全量 evt.type 计数（判定 nmap/conntrack、sendfile、mmap、getdents64 是否可建模）

# Cypher 侧核查（库名按需替换）
# G3 孤立顶点：
MATCH (f:File) WHERE f.path CONTAINS '(' AND f.path ENDS WITH ')'
  OPTIONAL MATCH (f)-[r]-() RETURN f.path, count(r);
# G1 连通性（场景5，修后应变为可达）：
MATCH (a:Process {exepath:'/usr/bin/systemctl'}), (b:Process {exepath:'/usr/lib/systemd/systemd'})
MATCH p=shortestPath((a)-[*..8]-(b)) RETURN length(p) LIMIT 1;
# G5 目录顶点缺失（场景6，修后 count 应为 2）：
MATCH (f:File) WHERE f.path IN ['/root/.local/share/progql-sync','/root/.local/share/progql-sync/state'] RETURN count(f);
# G1 终端面（场景6，修后应 >0）：
MATCH (p:Process {exepath:'/usr/bin/ls'})-[r:write]->() RETURN r.bytes, count(r);
# 场景4 nginx 文件读边（当前为 0）：
MATCH (:File)-[r]->(:Process {exepath:'/usr/sbin/nginx'}) RETURN type(r), r.syscall, count(r);
```

## 11. 一句话结论

- 三场景的共同根子是 **G1（非 IP 传输端点不建模）**：它让"持久化控制面"（场景5 `systemctl↔systemd`、
  场景6 `sudo→systemd`）、"审计留痕面"（场景4 sshd→auth.log、场景6 sudo→auth.log）、
  "终端回显面"（场景6 `ls` 输出）与"采集面"（`ss` 的 netlink）整类断链，
  是场景 5/6 召回上限的主要压制因素；场景 1 也有 `/dev/log`（18 条）与 netlink（467 条）触发点，
  六库完整受影响清单需接手者用 `grep -c` 自行确认（本轮未做全量扫描）；
- 场景 4 独有的是 **G2（sendfile）**，直接把"篡改内容被对外发布"这条最贴合攻击意图的证据链抹掉；
- **G5（原 X1）已改判为缺陷**：失败的生命周期调用不留痕，在场景 6 造成工具/持久化根目录连顶点都没有；
  方案 1（失败建顶点、不建边）风险几乎为零，应随 PR-1 一并做掉；
- **G3/G4** 是顶点身份归一问题（六库共 3 个括号注记 + 1 个 `/./` + 100 个内部 `//` 顶点，
  归一后 168 个顶点受影响、63 组合并；**场景 6 两者均为 0**），改动小但必须与 G1/G2 一起承担同一次重导与基线复核；
- 仍判为"正确/超范围、不要动"的只剩 **X2（Kali 侧链路）、X3（nmap 无 conntrack 采集）、X4（加密信道字节不守恒）**；
  另有场景 6 的 8 个"只读端"悬空管道顶点（shell 内务管道）属已知噪声，不建边也不入 GT，
  但排查引擎入口候选异常时应先看它（详见 `groundtruth/6_...notes.md` §S6-5）。
