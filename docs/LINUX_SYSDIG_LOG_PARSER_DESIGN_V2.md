# TraceSage Linux/Sysdig 溯源图设计规范 V2

- **版本**：v2.1（设计定稿，未实现；本版修订：失败调用的建节点条件、pid→节点解析、行级账本、边身份与去重、`born_ns` 推算回填、地址类返回值的 `res` 语义）
- **验证基线**：`attack/data/1,2,3,4,5,6,7,9,10/capture.scap` 共 9 个捕获，读取与采集端均为 sysdig 0.27.1；本文所有"实测"数字均出自这批文件，复现命令见附录 C。
- **框架约束**：三类顶点（`:Process` / `:File` / `:Network`）、五种边（`p2p` / `p2f` / `f2p` / `p2n` / `n2p`）**不变**。

---

# 0. 术语

| 术语 | 含义 |
|---|---|
| 顶点 / 边 | 顶点是图里的实体（进程、文件客体、网络会话或端点）；边是两个顶点之间的关系 |
| 主键 | 唯一确定一个顶点的字段组合（本文不用额外的"键串"属性） |
| fd（文件描述符） | 进程打开文件/套接字后领到的号码，**只在它自己的进程内有意义** |
| 泛型事件 | 日志里只有调用名、参数与返回值栏目全空的记录 |
| 视图 | 同一路径在不同容器上下文里的身份；本文用 `container_id` 表达 |
| 台账 | 不进图但必须逐项计数、随报告输出的记录 |

---

# 1. 设计原则

## 1.1 五条不变量

| # | 不变量 | 判定方式 |
|---|---|---|
| 1 | **只放有客体的事实**：图上每条边都能指到两端真实实体，没有"自己指向自己"的边 | 按 §3.3 逐条核查 |
| 2 | **节点只存身份**：每个节点 ≤ 8 个属性，且不含无界列表 | 逐节点类型核对属性表（§2） |
| 3 | **客体名用数据源原生形态**，禁止发明 | 抽查节点 `path`/`tuple` 能否在原始日志中逐字找到 |
| 4 | **结果单轨**：失败与取值只由 `res` 一个字段表达 | 边上只有一个结果字段 `res` |
| 5 | **不丢账**：每条日志行的去处只有 §6-1 列出的若干桶（边覆盖 / 属性更新 / 尝试未成立 / 显式丢弃 / 仅句柄 / 无客体 / 未知句柄 / 未配对 / 未归类 / 无进程归属 / 异常行 / 其他） | 行级两层账本差额为 0，且未归类逐名披露 |

## 1.2 统一降级规则（替代一切"某调用天生没有客体"的硬编码结论）

| 规则 | 内容 |
|---|---|
| **R1** | 客体可解析（fd 有可用名字，或参数里有路径）→ 建边；**对象由本次调用产生时还须调用成功，见 §4.6** |
| **R2** | 无客体可指的动作（主体自身的状态/属性变更、参数缺失、客体不可标识）→ **记账**（按 进程 + 调用名）写入 `ops.csv`，**不进图**；报告同时输出"参数可得性报告" |
| **R3** | 客体名一律采用数据源原生形态；名字里没有可区分标识 → **不建边**（禁止拿 fd 号、内核地址、自造前缀当身份） |
| **R4** | "本批捕获未出现 / 未解码" **不等于**"数据源不支持"：对应动词与客体位**保留**并标注"未验证"，不得据此删除设计 |
| **R5** | 容器元数据**分次到达**（先占位、后补全）：后到者补全，并**回填**此前已建节点；占位值（空挂载表、`privileged=false`）不得作为结论 |

## 1.3 字段清单纪律

- **无条件字段**（每条事件必须取；缺失即为解析错误）：`evt.num` `evt.rawtime` `evt.dir` `evt.type` `proc.pid` `thread.tid`。
- **条件字段**（必须逐事件类型实测其上下文存在后再使用）：`proc.ppid` `proc.exepath` `proc.cmdline` `proc.args` `proc.duration`（**捕获内创建的进程每条事件都有**；捕获前已存在则无；唯一用途是 §2.1 的 `born_ns` 推算回填）、`user.uid`（每事件，语义为真实 UID）、`container.id` `container.name` `container.image` `container.privileged` `container.mounts`（仅容器元数据事件）、`fd.num` `fd.name` `fd.type` `fd.l4proto`、`evt.rawres`、`evt.buffer`（配 `-b`）、`evt.arg[0..N]`。
- **禁止项**：
  1. 把 `%evt.buflen` 混入取值模板——该字段在 `read` 退出行无上下文，会让**整行消失**；
  2. 用"大而全"的单一模板混取条件字段（任一字段缺上下文即丢整行，且是**按事件类型成批**丢，不报错）；
  3. 字段清单里出现没有消费者的字段（每加一个字段必须指明它落到哪个属性或参与哪条推导）。
- **单趟取齐**：字段必须在一次读取内取齐；禁止分趟取字段再按事件号合并（会破坏事件全序与对账）。唯一例外是纯计数核对（不取语义字段）。

---

# 2. 三类顶点

## 2.1 `:Process`

**主键**：`host_id` + `container_id` + `pid` + `born_ns`

| 属性 | 必/条 | 来源 | 说明 |
|---|---|---|---|
| `host_id` | 必 | 配置（每场景一个） | 多主机命名空间前缀 |
| `container_id` | 必 | 逐事件 `container.id` | 无容器为字面量 `host`；这是 **cgroup 归属**，不是路径/挂载视图 |
| `pid` | 必 | `proc.pid` | |
| `born_ns` | 必 | 见下 | **本段身份起点时刻** |
| `born_src` | 必 | 解析器推导 | 身份起点来源：`clone` / `exec` / `duration` / `unknown`；`duration` 表示由 `proc.duration` 回填（推算值，非实测） |
| `exe` | 条 | `proc.exepath` | 最后观测值 |
| `cmdline` | 条 | `proc.cmdline` / `proc.args` | 最后观测值 |
| `ppid` | 条 | `proc.ppid` | **首次观测值**（避免父进程先退出、ppid 被 reparent 成 1 的误导）；克隆边缺失时补父子线索 |
| `uid` / `ruid` | 条 | `uid`（euid）：`geteuid`/`setuid`/`setresuid` 等；`ruid`：**每事件 `user.uid`** | `ruid` 稠密（每条事件都有，实测语义为真实 UID）；`uid`（euid）稀疏，未出现相关调用则留空（禁止用空值断言"无提权"） |
| `privileged` | 条 | `container.privileged` | 所属容器是否特权 |
| `host_root_rw` | 条 | `container.mounts` | 所属容器是否**持有宿主根的写权限** |

**`born_ns` 定义**（每种来源同时写入 `born_src`）：
- 进程由 `clone`/`fork`/`vfork` 创建 → 取该事件时刻，`born_src=clone`；
- `execve`/`execveat` 换程序 → 取该 execve 事件时刻（**这保证"换程序=新节点"不会与旧节点撞键**），`born_src=exec`；
- 捕获内创建但创建事件丢失（该 pid 段第一次出现时没有任何 clone/exec 记录，且该事件 `proc.duration` 有值——`0` 也算有值）→ `born_ns = 事件时刻 − proc.duration`，`born_src=duration`；以该 pid 段**首次**观测的推算值为准，后续观测与首值相差超过 1 毫秒时计 `born_estimate_jitter` 并写入报告（不阻断）；
- 捕获开始前已存在（`proc.duration` 取不到）→ `0`（表示未知，**禁止当成 1970 年**），`born_src=unknown`。

`born_src=duration` 的 `born_ns` 是**推算值**：只用于排序与 pid 解析，不参与"攻击发生在何时"的结论，报告与查询必须能把它和实测值区分开。推算到的是 **fork 时刻**（`proc.duration` 自进程创建起算）；若该 pid 段的 exec 事件同时丢失，该节点会同时覆盖 exec 前后的两段身份且无法切分，需在报告标注。

## 2.2 `:File`

**主键**：`host_id` + `container_id` + `path`

| 属性 | 必/条 | 来源 |
|---|---|---|
| `path` | 必 | 优先 `fd.name`（内核真实路径，**不含容器视图前缀**）；回退到参数里的路径（相对路径按 §5.4 解析） |
| `kind` | 条 | **数据源原生 `fd.type`**：`file` / `directory` / `pipe` / `unix` / `netlink` / `event` / `inotify` / `timerfd` / `signalfd` / `eventpoll` / `unknown`；路径类事件（`unlink`/`rename`/`mkdir`/`chmod`/`access`）无 fd，先记 `unknown`，首次拿到 `fd.type` 时回填 |

**命名规则**：
1. 路径类：原样使用解析后的路径；匿名文件/无路径句柄按数据源当次给出的形态使用（渲染为 `<UNKNOWN><n>` 时计入"路径无法解析"，不建边）。
2. 管道：`pipe:[<inode>]`（`pipe` 事件给出 inode）。
3. 套接字：本地域（`unix`/`netlink`）落 `:File`，名字用数据源给的形态；**AF_INET/AF_INET6 且能构成良构元组者落 `:Network`**，否则不建节点。
4. **视图**：`container_id` 进主键。理由：`fd.name` 是内核真实路径，跨视图同名可能不同物，只能靠 `container_id` 区分。注意 `container_id` 是**进程归属**（cgroup 级，数据源逐事件给出），**不等于**进程的挂载/命名空间视图——同一容器内的进程也可能看到宿主路径（实测场景 9 的逃逸容器即可执行宿主二进制、写宿主路径）。
5. **跨视图同名**：路径字符串相同、`container_id` 不同的一对节点是**同名候选**（查询期匹配，见附录 B-9），报告中必须标注"候选"，**不得当作同一性证明**。**禁止用"容器路径拼宿主前缀"生成别名**（会造出不存在的路径）。

## 2.3 `:Network`

**主键**：`host_id` + `tuple`

| 属性 | 必/条 | 来源 |
|---|---|---|
| `tuple` | 必 | `fd.name` **原样字符串**，两种形态：会话 `客户端IP:端口->服务端IP:端口`；端点 `IP:端口` |
| `proto` | 条 | `fd.l4proto`（`tcp`/`udp`/…）。**不进主键** |

**良构判据**（不满足 → 不建节点，计 `tuple_unusable`）：
- 会话：两端端口 > 0，且两端 IP 均非通配（`0.0.0.0` / `::`）；
- 端点（`bind`/`listen`）：端口 > 0，允许通配 IP（如 `0.0.0.0:8443`）。

**语义**：
- 节点身份是"日志给出的元组标识"，**不保证会话已建立**：`connect` 失败（`res<0`）仍建节点与边（对象产生条件见 §4.6），查询必须用 `res` 区分"已建立"与"被拒/不可达"；
- `tuple` 左端恒为客户端、右端恒为服务端；
- 因此**跨主机缝合 = `tuple` 字符串相等**；
- **本机角色**由动作决定（`connect`=客户端，`accept`=服务端），不存属性；
- 会话与监听端点的关联**不建结构关系**：用"服务端 `ip:端口` 后缀相等"或"仅端口相等"在查询期匹配。

## 2.4 明确不建节点的东西

主机（`host_id` 属性）、线程（归所属进程）、身份（进程属性）、内存区间（地址/长度不落图）、容器本身（`container_id` 属性 + 进程上的两个布尔位）、裸 `socket()`（无对端 → 记账）、无可区分名字的匿名 IPC（eventfd/signalfd/timerfd/inotify/epoll/socketpair）、bpf 对象（按 R3：数据源给不出可区分名字时不建节点）、内核密钥（无 serial）、挂载点以外的一切"配置项"。

---

# 3. 五种边

## 3.1 方向语义与端点约束

| 边 | 语义 | 端点 |
|---|---|---|
| `p2p` | 进程影响进程：派生、镜像替换、退出、信号、内存读写/注入 | `:Process` → `:Process` |
| `p2f` | 进程作用于客体：写、创建、改名、删除、截断、权限、挂载、命名空间、内核对象、ioctl | `:Process` → `:File` |
| `f2p` | 客体流入进程：读、映射、镜像加载、探测 | `:File` → `:Process` |
| `p2n` | 进程作用于网络：连接、绑定、监听、发送 | `:Process` → `:Network` |
| `n2p` | 网络流入进程：接受、接收 | `:Network` → `:Process` |

**归类唯一规则**：客体类型决定边类（`:File` → `p2f`/`f2p`；`:Network` → `p2n`/`n2p`）；动词只描述语义，成功/失败/零字节由 `res` 表达（`mmap`/`mmap2`/`shmat` 成功时无 `res`，见 §3.2），**不改变动作名**；**对象是否成立（是否建节点）另由 §4.6 判定**。

## 3.2 边属性（统一 10 个语义属性 + 1 个身份字段）

| 属性 | 必/条 | 口径 |
|---|---|---|
| `evt` | 必 | 进入行 `evt.num`（回原始日志核对的锚点；孤儿退出行独立成边时取该退出行事件号，见 §5.2）。**不唯一**：一个事件可产出多条边，须与 `seq` 联合使用 |
| `ts_ns` / `te_ns` | 必 | 进入行/退出行时刻（单点事件两者相等） |
| `action` | 必 | §4.2 动词表中的一个 |
| `res` | 条 | `evt.rawres` 原样：数据类=字节数、失败=负错误码、零字节=0。**全局唯一结果字段**；缺失留空不补。`mmap`/`mmap2`/`shmat` 这类**成功时返回地址**的调用例外：**失败时写入负错误码，成功时不写**（成功返回值是地址，不入图） |
| `flags` | 条 | 解码后的关键标志集合（`O_*` / `PROT_*` / `MAP_*` / `CLONE_*` / `AT_*` / `RENAME_*` / `MS_*`） |
| `head` | 条 | 载荷前若干字节的 base64（取法：`-p "%evt.buffer" -b`；本批快照上限 80 字节） |
| `old_path` | 条 | `rename` 的源路径（参数 `oldpath`）。5 类边里没有"文件→文件"，这是它唯一的落点 |
| `target_path` | 条 | `link`/`linkat` 的源文件路径（`oldpath`）；`symlink`/`symlinkat` 的目标字符串（`target`）——目标可以是相对路径或不存在，不一定是图上的节点 |
| `mode` | 条 | `chmod`/`fchmod`/`fchmodat` 的权限位，八进制字符串（如 `"0700"`） |

**身份字段 `seq`**：同一事件号产出多条边时的序号（0 起）。与 `evt` 一起构成边的唯一身份（§5.9-5），不承载语义，不进上表。

**三态语义**：有值 = 实测；无属性 = 未观测；`0` = 实测零。

## 3.3 禁止事项

1. **禁止自环边**（`src = dst`）。无客体动作走 §4.3 记账（不进图），不走边。
2. **禁止人工补边**：拼前缀、猜对端、把同名当同一物，一律不许写进图。
3. **禁止把解析器内部状态写进图**（如"参数没取到"这类标记 → 进台账）。

---

# 4. 系统调用 → 动词

## 4.1 分类规则

1. 先判"谁把数据给了谁"，再判"谁改了什么"，最后才判纯行为。
2. 分类函数的输入是**调用名 + 关键标志 + 两端客体类型**；同名不同参数可落不同动词（例：`openat` 带 `O_CREAT`/`O_TRUNC` → `create`，否则不建边）。
3. 映射不上的调用 → 未归类桶（记账 + 逐名披露），**禁止静默丢弃**。
4. **作用于已有对象的失败调用照常建边**：读、写、改名源、删除、截断、权限、探测、收发、`ioctl`、`mount` 等动作的对象在调用前已存在，成功失败都建边，动作名不变，失败由 `res<0` 表达；失败不传播数据流（不写 `head`），但**禁止丢弃**（扫描、爆破、被拒写入的证据全在这里）。
5. **对象由本次调用产生时，只有成功才落节点**：`clone`/`exec`/`create`/`link`/`rename` 的新路径/`bind`/`listen`/`accept` 失败时**不建节点、不建边**，改记"尝试未成立"（§6-1，落 `attempts.csv`：目标串 + 错误码 + 次数 + 首末时刻）。逐动词判据见 §4.6。

## 4.2 动词表（34 个，唯一枚举）

状态列按**动词级**判定：**已产出** = 本批该动词下至少一个调用能生成边；**部分** = 部分调用能生成；**本批不产出** = 调用了但采集端未给参数/客体无可标识名（按 R2 记账）；**未出现** = 本批 0 次，设计位保留待验证（R4）。同一动词内仍属未验证的调用（如 `create` 里的 `memfd_create`）见本节末。

各动词的**建节点条件**（成功判据、失败去向）统一见 §4.6；下表只描述语义与客体来源。

| 动词 | 边 | 适用调用 | 客体/取值来源 | 本批状态 |
|---|---|---|---|---|
| `clone` | p2p | `clone`/`clone3`/`fork`/`vfork`（含 `CLONE_THREAD` 不建边） | 子进程（`res>0` 时取该返回值） | 已产出 |
| `exec` | p2p | `execve`/`execveat` | 旧节点→新身份节点（同 pid，`born_ns`=本事件时刻；仅成功，失败不分裂） | 已产出 |
| `exit` | p2p | `exit`/`exit_group`/`procexit` | 父进程（克隆边优先，回退 `ppid`；解析规则见 §5.7；无父记录则不建边） | 已产出 |
| `signal` | p2p | `kill`/`tgkill`/`tkill`/`pidfd_send_signal` | 目标进程（按 §5.7 解析；信号号不落图，按 `signal:<n>` 记账） | 已产出 |
| `ptrace` | p2p | `ptrace`(ATTACH/SEIZE) | 目标进程 | 未出现 |
| `mem_read` | p2p | `process_vm_readv`、`/proc/<pid>/mem` 读 | 目标进程 | 未出现（`/proc` 派生除外） |
| `mem_write` | p2p | `process_vm_writev`、`ptrace`(POKE)、`/proc/<pid>/mem` 写 | 目标进程 | 未出现 |
| `pidfd_getfd` | p2p | `pidfd_getfd` | 目标进程 | 未出现 |
| `wait` | p2p | `wait4`/`waitid` | 子进程（按 §5.7 解析） | 本批不产出 |
| `create` | p2f | `openat`/`open`/`creat`(带 `O_CREAT`/`O_TRUNC`)、`mkdir(at)`、`mknodat`、`memfd_create` | 路径参数 / fd 名（失败不建，见 §4.6） | 已产出 |
| `link` | p2f | `link`/`linkat`/`symlink(at)` | 新路径（失败不建，见 §4.6）；`target_path`=源文件路径 / 符号链接目标 | 已产出 |
| `rename` | p2f | `rename`/`renameat`/`renameat2` | 新路径（失败不建，见 §4.6）；`old_path`=源路径 | 已产出 |
| `unlink` | p2f | `unlink`/`unlinkat`/`rmdir` | 路径参数 | 已产出 |
| `truncate` | p2f | `truncate`（`ftruncate`/`fallocate` 本批无参数 → 记账） | 路径参数 | 部分 |
| `write` | p2f | `write`/`writev`/`pwrite`/`pwritev` + 零拷贝出向（`splice`/`sendfile`/`tee`/`copy_file_range`） | 由句柄表解析；套接字改投 `send` | 已产出 |
| `chmod` | p2f | `chmod`/`fchmod`/`fchmodat` | 路径或 fd；`mode`=权限位（八进制串） | 已产出 |
| `mount` | p2f | `mount` | 挂载点（`fstype`/`dev` 不落图；`umount2` 不建边，见 §4.4） | 已产出 |
| `chroot` | p2f | `chroot`/`pivot_root` | 新根目录 | 已产出 |
| `ns` | p2f | `setns`（`unshare` 无客体 → 记报告） | 命名空间文件路径 | 已产出 |
| `module` | p2f | `finit_module`/`init_module`/`delete_module` | 模块文件 | 本批不产出 |
| `bpf` | p2f | `bpf` | fd 名 | 本批不产出 |
| `io_uring` | p2f | `io_uring_setup`/`_enter`/`_register` | 环 fd 名 | 未出现 |
| `shm` | p2f | `shmget`/`shmat`/`shmdt`/`shmctl` | 段标识；`shmat` 按 `mmap` 同一 `res` 规则（失败写负错误码，成功不写） | 本批不产出 |
| `ioctl` | p2f | `ioctl` | fd 客体（请求码不落图，按 `ioctl:<req>` 记账） | 已产出 |
| `read` | f2p | `read`/`readv`/`pread`/`preadv` + 零拷贝入向 | 由句柄表解析；套接字改投 `recv` | 已产出 |
| `load_image` | f2p | `execve`/`execveat` | 镜像文件（起点=新身份节点） | 已产出 |
| `mmap` | f2p | `mmap`/`mmap2`（文件后备）、`shmat` | 文件；`flags=PROT_*/MAP_*`；`res` 仅失败时写负错误码（成功返回地址，不写） | 已产出 |
| `probe` | f2p | `access`/`faccessat`/`getdents64`/`statfs`/`readlink(at)`/`newfstatat`… | 有客体才建边 | 部分（本批仅 `access`/`getdents64` 有客体） |
| `connect` | p2n | `connect` | 会话/端点节点（元组良构才建；失败照建，见 §2.3） | 已产出 |
| `bind` | p2n | `bind` | 监听端点（失败不建，见 §4.6） | 已产出 |
| `listen` | p2n | `listen` | 监听端点（失败不建，见 §4.6） | 已产出 |
| `send` | p2n | `sendto`/`sendmsg`/`sendmmsg` + 套接字上的 `write` | 会话/端点；`res`=字节 | 已产出 |
| `accept` | n2p | `accept`/`accept4` | 会话节点（`res≥0` 且元组良构；失败不建） | 已产出 |
| `recv` | n2p | `recvfrom`/`recvmsg`/`recvmmsg` + 套接字上的 `read` | 会话；`res`=字节 | 已产出 |

**`openat` 分流**：带 `O_CREAT`/`O_TRUNC` → `create`；其余（只读/只写打开）**不建边**，读写由后续 `read`/`write` 边体现（代价见 §8 边界 7）。

**无独立动词的未验证调用**：`memfd_create`（客体并入 `create`）、`userfaultfd`、`kexec_load`、`open_by_handle_at` —— 本批未出现或无可标识客体，按 R3 记账；换采集端或合成场景后再验证。

## 4.3 无客体动作：写报告，不进图

**格式**：以下调用不进图、不落节点属性；与本表同样写入 `ops.csv` 的还有"边上有、但未落图的枚举参数"（信号号、ioctl 请求码、mount 文件系统类型），按 `调用名:取值` 记账（如 `signal:9`、`ioctl:TIOCSTI`、`mount:tmpfs`）。表内所有条目均为 `进程 + 调用名 + 次数 + 首次时刻 + 末次时刻`；下表分组仅用于报告阅读。

| 报告分组 | 覆盖调用 | 攻击含义 |
|---|---|---|
| `priv` | `setuid`/`setgid`/`setresuid`/`setreuid`/`setregid`/`setfsuid`/`setfsgid`/`setgroups`/`capset`/`prctl`/`personality`/`setrlimit`/`prlimit`/`ioprio_set`/`sched_setscheduler`/`sched_setaffinity`/`setpriority`/`setsid`/`setpgid`/`umask`/`arch_prctl`/`chdir`/`fchdir`/`sethostname`/`quotactl` | 提权/能力变更 |
| `utimes` | `utimensat` | 时间戳篡改（目标不可知） |
| `chown` | `chown`/`fchown`/`lchown`/`fchownat`/`setxattr`/`lsetxattr`/`fsetxattr`/`removexattr` | 属主/扩展属性篡改 |
| `ns` | `unshare` | 命名空间创建（逃逸） |
| `seccomp` | `seccomp` | 沙箱设置 |
| `syslog` | `syslog` | 内核日志操作 |
| `timer` | `setitimer`/`alarm`/`timerfd_settime`/`timer_settime` | C2 心跳 |
| `exec_mem` | 匿名 `mmap` 且带 `PROT_EXEC` | 可执行匿名内存（注入）。匿名但非 `PROT_EXEC` → 无客体，进"无客体"桶 |
| `kernel` | `bpf`/`finit_module`/`init_module`/`delete_module`/`keyctl`/`add_key`/`request_key`/`kexec_load`（**仅当客体不可得时**） | 内核对象操作（rootkit/逃逸） |

## 4.4 完全不进图的调用（按 R2 记账，按调用名逐项计数）

**纯等待/轮询/调度**：`poll` `select` `pselect6` `ppoll` `epoll_wait` `epoll_pwait` `epoll_ctl` `futex` `switch` `sched_yield` `nanosleep` `clock_nanosleep` `times` `clock_gettime` `clock_getres` `clock_adjtime` `gettimeofday` `timer_create` `timer_delete` `restart_syscall`

**内存管理噪声**：`brk` `munmap` `mremap` `madvise` `mincore` `mprotect`

**信号配置与投递**：`rt_sigaction` `rt_sigprocmask` `rt_sigpending` `rt_sigtimedwait` `sigaltstack` `signaldeliver` `sigreturn`

**文件监视配置**：`inotify_add_watch` `inotify_rm_watch`

**自我查询与调度查询**：`getpid` `gettid` `getppid` `getgid` `getegid` `getresgid` `getgroups` `getrusage` `getrandom` `getrlimit` `getpriority` `ioprio_get` `capget` `sched_getaffinity` `sched_getparam` `sched_getscheduler` `sched_get_priority_min` `sched_get_priority_max` `set_tid_address` `set_robust_list`

**套接字选项与关闭**：`shutdown` `setsockopt` `getsockopt` `getsockname` `getpeername`

**属性读取与建议**：`getxattr` `lgetxattr` `fgetxattr` `flistxattr` `flock` `fadvise64`

**数据流已被覆盖**：`fsync` `fdatasync` `msync`（由 `write` 边覆盖）

**低价值动作**：`umount2`（卸载只按调用名记账，不建边）

**无可标识客体**：`socket`（裸建）、`socketpair`、`eventfd`、`signalfd`、`timerfd_create`、`inotify_init`、`epoll_create`、`epoll_create1`、`pidfd_open`、`open_by_handle_at`（打开本身；后续读写照常）、`userfaultfd`（其数据流由 `read`/`write` 覆盖）

**只维护句柄表**：`close` `dup` `dup2` `dup3` `fcntl` `lseek`

## 4.5 合并关系（不是删除，是并级）

| 原动作 | 并入 | 区分方式 |
|---|---|---|
| `symlink` | `link` | `target_path`（链接目标） |
| `kill`/`tgkill`/`tkill`/`pidfd_send_signal` | `signal` | 信号号不落图（按 `signal:<n>` 记账） |
| `mkdir`/`mkdirat`/`mknodat`/`openat(O_CREAT,O_TRUNC)`/`memfd_create` | `create` | `flags` |
| `shmat` | `mmap`（文件/内存映射）或 `shm` | 由 fd 名形态判定 |
| `sendfile`/`splice`/`tee`/`vmsplice`/`copy_file_range` | `read`/`write` | 方向由 `fd_in`/`fd_out` 决定 |
| `read`/`write`（套接字上） | `recv`/`send` | 客体类型判定 |

## 4.6 建节点条件（成功才建的动词）

判据一律取**退出行** `evt.rawres`；进入行没有结果，不得据进入行建节点。未列出的动词按"对象在调用前已存在"处理（§4.1-4）。

| 动词 | 本次调用产生的对象 | 成功判据 | 失败去向 |
|---|---|---|---|
| `clone` | 子进程节点 | `res > 0`（返回值即子 pid） | 尝试未成立 |
| `exec` | 新身份进程节点 | `res ≥ 0` | 尝试未成立；**旧节点继续存活，不分裂身份** |
| `create` | 新文件路径 | `res ≥ 0` | 尝试未成立 |
| `link` | 新路径 | `res ≥ 0` | 尝试未成立 |
| `rename` | 新路径 | `res ≥ 0` | 尝试未成立 |
| `bind` / `listen` | 监听端点 | `res ≥ 0` | 尝试未成立 |
| `accept` | 会话节点 | `res ≥ 0` 且元组良构 | 尝试未成立 |
| `connect` | 会话/端点节点 | 元组良构即可（**不看 `res`**） | 照常建边，`res<0` 表示被拒/不可达 |

**失败不得进图的原因**：这些动作在失败时不产生对象；建节点等于宣告一个从未存在的进程、文件或监听状态。被拒的执行、创建、绑定同样有取证价值，但它们的准确形态是"目标 + 错误码"，由 `attempts.csv` 承载（§6-11），不需要也不允许伪装成实体。`rename` 失败时源路径按 `oldpath:<路径>` 另记 `ops.csv`；`clone` 失败没有子进程、`accept` 失败没有对端，目标串均记 `-`（监听端点若可得另记 `ops.csv`）。

判据字段缺失（如某场景 `execve` 没有退出行）→ 该动词状态记"未验证"并在报告披露，**禁止改用其它信号推断成功**。

---

# 5. 解析流水线

## 5.1 接入

1. **直读捕获**：解析器启动一个 sysdig 进程读 `.scap`，把输出当**事件流**逐条消费；**不得**先把捕获整体翻译成中间文件再解析。
2. **对账（必经）**：`独立计数 == 接入累计事件数`；两者均为**日志行数**（一个事件一行），行级账本等式见 §6-1。差额非 0 → 阻断。独立计数必须来自解析器之外（同一捕获上只取事件序号的纯计数）。**对账只覆盖读取侧**——两侧读的是同一个文件，采集阶段的丢失由 §5.1-3 的断号统计发现。
3. **事件号断号统计**：记录 `实存条数`、`末事件号`、`断号总数`、`断号段数`、`最大单段`；采集侧丢失不可补（实测值见 §7）。
4. **通道**：本机 / WSL2 / SSH 远端 / 容器四选一；通道不可用（无 sysdig、读不到文件、无权限）→ **立即阻断**并说明缺哪一环，禁止降级去读历史中间文件。
5. **字段分隔符**：解析输出必须用**制表符**（`|` 是 sysdig 多值字段的内部隔符，会把列冲掉）。
6. **事件序号校验**：事件号必须单调递增；出现回退 → 阻断（捕获损坏或读取拼接错误）。
7. **异常行**：解析失败或字段类型异常的行走台账后跳过，计入 §6 的"异常行数"；连续异常超过阈值 → 阻断。

## 5.2 配对

- 键：`(host, container, pid, tid, 调用名)`；同键内**先进先出**。
- 进入行给参数、退出行给结果；阻塞类（`accept`/`read`/`recv*`/`wait*`）超时不淘汰，只保留进入行等待配对。
- 孤儿退出行：自带全部参数**且满足 §4.6 建节点条件**者独立成边，行计入"边覆盖"，并以该退出行事件号作为 `evt` 锚点；不能独立成边者计"未配对"。流结束时配对池必须排空，仍在池中的进入行（含阻塞类）统一计"未配对（stream_end）"，禁止残留。

## 5.3 句柄表

- `(host, container, pid, fd) → 客体引用`；容量上限 `fd_table_max`（默认 4096，超限淘汰最早登记并计数）。
- 必须支持：`clone`/`fork` 时**整表复制**并继承 `cwd`、`dup` 别名（**不继承** `CLOEXEC`）、`close` 注销、`exec` 时按 `CLOEXEC` 裁剪、`pipe` 的 `fd1/fd2/ino` 登记。
- 未命中 → 不建数据流边，计 `unknown_fd`。

## 5.4 路径解析与规范化

1. **优先 `fd.name`**（内核真实路径）；`fd.name` 为空或 `-1` 时回退到参数路径。
2. 仅有参数路径时：绝对路径直接用；相对路径先用 `dirfd` 在句柄表中解析出的目录路径拼接，回退进程 `cwd`；两者都不可得 → `path_unresolved`，节点 `path` 记 `?<原始串>`。
3. 规范化：合并连续 `/`；解析 `.` 与 `..`（纯字符串，不访问文件系统）；去末尾 `/`（根除外）；**不做大小写折叠**；**不解析符号链接**。
4. `<UNKNOWN><n>` 占位 → 计入 `path_unresolved`，不建边（R3）。
5. **cwd 与根**：cwd 是解析器状态（初值取 `proc.cwd`，由 `chdir`/`fchdir` 更新，不落节点属性）；`chroot`/`pivot_root` 后按新根规范化。

## 5.5 容器与视图

1. 逐事件读 `container.id`（**cgroup 归属，不是路径视图**）；缺失 → `host`，计 `container_attribution_missing`。
2. **容器元数据取法**：
   - `container.id` `container.name` `container.image` `container.privileged`；
   - 首选带序号字段 `container.mount.source[i]` / `.dest[i]` / `.rdwr[i]` / `.mode[i]` / `.propagation[i]`：从 `i=0` 递增到取不到为止（实测可用；`container.mount[N]` 形式无上下文，禁止使用）；
   - 备选 `container.mounts` 复合串：多条用 `,` 分隔，每条 `源:目标:模式:可写:传播`（例：`/:/host::true:rslave`、`/usr/sbin/svc-watchdog:/usr/sbin/svc-watchdog:ro:false:rprivate`；路径含 `:` 时不可用）。
3. **分次到达（R5）**：同一容器先出现占位事件（`mounts` 空、`privileged=false`、`name` 空），后出现完整事件；占位不得当结论；完整事件到达时必须**回填**此前已建节点，计 `container_meta_backfills`。
4. `host_root_rw`：存在 `source = /` 且可写的挂载 → `true`；元数据缺失 → 留空（见 §8-19）。
5. 视图不合并（§2.2 规则 4/5）。

## 5.6 `/proc/<pid>/…` 派生边

访问 `/proc/<pid>/(mem|maps|environ|cmdline|fd/*)` 时，除 `:File` 上的边外，**另派生一条 `p2p` 边**指向该 pid 的进程（`mem_read`/`mem_write`/探测）；目标 pid 按 §5.7 解析，无对应节点则不派生。

## 5.7 pid → 节点解析（全局唯一规则）

所有需要把 pid 换成图节点的动作（`signal` 目标、`exit` 父进程、`ptrace`/`process_vm_*` 目标、`pidfd_getfd` 目标、§5.6 的 `/proc/<pid>/` 派生边）共用同一条规则，禁止各动词自行实现：

1. 候选集 = 同 `host_id`、同 `container_id`、同 `pid`，且 `born_ns ≤ 事件时刻` 的全部节点（`born_src=unknown` 的 `0` 视为最早；`born_src=duration` 的推算值正常参与比较）。
2. 剔除在该时刻之前已退出的候选；退出时刻由解析器在内存中维护，不落节点属性。
3. 剩余候选中取 `born_ns` 最大者；仍并列取事件号更大者，计 `pid_resolve_tie`。
4. 无候选 → 不建边，计 `target_unresolved`，报告写明"目标 pid 在捕获范围内无对应节点"。
5. 目标 pid ≤ 0（`kill(-1)`/`kill(0)` 这类组播或自身信号）→ 不建边，按 `signal:<n>` 记账并注明"组播信号"。
6. 解析时刻统一取**进入行**时刻，与边的 `ts_ns` 对齐，保证结果与到达顺序无关、同输入重跑一致。
7. `clone` 成功后把"该 pid 段的父节点"记入内存索引，`exit` 优先用它；无记录时按本规则解析 `ppid`。

## 5.8 进程身份分裂

- `execve`/`execveat` **成功时**（`res ≥ 0`）→ 旧节点结束于 `p2p exec` 边时刻；新建 `:Process`（`born_ns`=execve 事件时刻，`born_src=exec`）；同时建 `f2p load_image`（新节点→镜像文件）。
- `execve`/`execveat` **失败时**（`res < 0`）→ **不分裂身份、不建节点、不建边**，旧节点继续存活；写"尝试未成立"并落 `attempts.csv`（目标路径 + 错误码）。
- `clone(CLONE_THREAD)` → 不建边、不建节点，动作归所属进程；`clone` 失败（`res ≤ 0`）同样不建节点（§4.6）。
- pid 复用 → 由 `born_ns` 天然区分；若同一 pid 出现"退出后又以同 pid 创建"，计 `pid_reuse_anomaly` 并正常分裂。

## 5.9 写库

1. **唯一约束**（多属性复合）：`:Process(host_id, container_id, pid, born_ns)`、`:File(host_id, container_id, path)`、`:Network(host_id, tuple)`。
2. **索引**：`File.kind`、`Process.container_id`、`Network.tuple`、边 `action`、边 `ts_ns`、边 `(evt, seq)`（幂等合并用；Neo4j 版本支持时用关系属性唯一约束）。
3. **批量与背压**：顶点每批 `vertex_batch`（默认 5,000），边每批 `edge_batch`（默认 10,000）或 `flush_interval_ms`（默认 500）；待写批次超 `backpressure_batches`（默认 5）暂停读取。
4. **重试**：锁冲突按 100→200→400→800→1600 毫秒（±20% 抖动）重试 `retry_max`（默认 5）次；仍失败 → 阻断并输出冲突主键。
5. **幂等**：边的唯一身份 = `(evt, seq, 源主键, 目标主键, action)`，写库以此为合并键，**禁止按 `evt` 单键去重**（一个事件可产出 p2p + f2p、read + write 等多条边，由 `seq` 区分）。同一事件产生的全部边必须在同一事务或同一批次边界内提交。默认按场景清库后整批导入；增量导入的水位 = **最后一个完整提交的事件号**，续跑从该事件重放（**水位只用于写库去重**，接入永远从头直读，见 §5.1-1），重复边由唯一身份吸收。
6. **图快照**：`nodes.csv` 列为 `label` + 该类主键 + 该类属性并集（空值留空），按 `(label, 主键)` 排序；`edges.csv` 列为 `edge_class` + `seq` + 两端主键 + §3.2 十个语义属性，按 `(源, edge_class, 宿, evt, seq)` 排序；用于逐字段可复现比对（§6-7）。

---

# 6. 审计与报告（每个场景必须输出）

1. **两层账本（行级）**
   - **接入层**：独立计数、接入累计、差额，三者均为**日志行数**（一个事件一行）。
   - **解析层按行记账**：每行在结算时（单行事件即时结算；配对调用在配对完成时结算；未配对在流结束时结算）按"异常行 → 属性更新 → 无进程归属 → 边覆盖 → 尝试未成立 → 未归类 → 仅句柄 → 未知句柄 → 无客体 → 显式丢弃 → 未配对 → 其他"的顺序判定，**第一个成立者**即该行的桶（互斥且穷尽）。
   - **对账等式**：`接入累计行数 = 待定行数 + 各桶行数之和`。`待定` = 仍在配对池、等待退出行或流结束的进入行；每个检查点校验，流结束时先排空配对池（§5.2）使 `待定=0` 再校验；任一差额非 0 → 阻断。
   - **调用级视图**（仅供阅读，不参与阻断）：`逻辑调用数 = 配对成功调用数 + 单行事件数 + 孤儿行数`；配对成功按"进入行 + 退出行 = 1 次"计，报告必须写明该口径。
   - **桶定义**：`边覆盖` = 该行所属动作最终产出至少一条边；`属性更新` = 只改写节点属性（容器元数据、R5 回填）且不产边；`尝试未成立` = §4.6 中对象由调用产生而失败的调用（另落 `attempts.csv`，按调用计次，§6-11）；`无客体数` = R2 的无客体动作（按进程 + 调用名计数）；`显式丢弃数` 按调用名逐项计数；`未配对` 在流结束时统一结算（含阻塞类）；`异常行数` 按异常类型列出；`其他` 必须逐类说明。
2. **事件号断号**：实存条数、末事件号、断号总数、段数、最大单段（§5.1）。
3. **参数可得性报告**：逐调用名列出"事件数 / 能定位客体的条数 / 能取到返回值的条数"。这是**划边界的唯一依据**，也是判断采集端是否升级的信号。
4. **未归类清单**：逐名 + 次数；`<unknown>` 单独统计。非空必须披露，禁止宣称"映射表完整"。
5. **容器清单**：id / 名称 / 镜像 / `privileged` / 挂载表 / 占位事件数 / 回填次数 / 跨视图同名候选对数量（标注为候选）。
6. **边数统计**：边总数、按 `action` 的分布、最大出度进程与最大入度客体。
7. **快照**：`nodes.csv` / `edges.csv`，同输入重跑必须逐字段一致。
8. **参数快照**：本次运行的附录 A 全部参数、字典版本、代码版本。
9. **无客体动作与未落图参数表**（`ops.csv`）：进程 × 调用名 / `调用名:取值` × 次数 × 首次时刻 × 末次时刻（清单见 §4.3、§4.4）。
10. **身份起点来源**：按 `born_src` 统计进程段数（`clone` / `exec` / `duration` / `unknown`），单列 `born_src=duration` 与 `unknown` 的进程列表，并输出 `born_estimate_jitter` 次数。
11. **尝试未成立表**（`attempts.csv`）：进程 × 动词 × 目标串（路径或元组）× 错误码 × 次数 × 首次时刻 × 末次时刻；次数按调用计（配对行只算 1 次）。

---

# 7. 实测依据

| # | 事实 | 数字 |
|---|---|---|
| 1 | 场景 1 规模与丢号 | 实存 12,924,107 条；末事件号 13,091,733；断 167,626 个号（1.3%，683 段，最大 253） |
| 2 | 场景 1 事件类型 | 173 种；`read` 1,642,412、`newfstatat` 1,418,850、`openat` 1,322,922、`switch` 1,176,943、`close` 1,149,862 |
| 3 | 行内信息密度（场景 1 前约 100 万条事件，输出 952,175 行） | 无参数 31.5%、有返回值 26.9%、带 fd 22.9%、带路径 4.5% |
| 4 | 泛型事件 | `newfstatat` 1,418,772 行**参数与返回值全空**（100%）；`readlink`/`readlinkat`/`statfs`/`fstatfs`/`mprotect`/`chown`/`utimensat`/`setxattr`/`wait4`/`fdatasync`/`ftruncate`/`fallocate` 同样全空 |
| 5 | 结果双轨一致性 | 2 万条退出行：`false\|正` 8445、`true\|负` 4352、`false\|零` 2487，零矛盾 |
| 6 | 协议可得性 | 良构元组的 `connect` 行协议空缺数 = 0（记法 `良构条数/空缺数`；场景 1: 126/0、场景 2: 151/0、场景 3: 1800/0、场景 10: 207/0）；空缺全落在不良构元组（286/242、544/456、502/290、344/266） |
| 7 | 会话方向 | accept 行 `fd.name` 与 `cip/cport/sip/sport` 完全一致（`100.74.213.15:50574->100.86.108.4:6379`） |
| 8 | 载荷 | `%evt.buffer -b` 可用；长度上限 80 字节 |
| 9 | 进程启动时长 | `execve` 行 1974/1974 有值；`read` 行 2000 条仅 110 条有值 |
| 10 | 容器 | 场景 9 有 7 个容器，全部 `privileged=true`、镜像 `alpine:3.19`、`/host ← /` RW；元数据每容器 2 条（占位 → 完整），占位数在 966,775、完整在 1,063,482 |
| 11 | 容器事件量 | 宿主 5,382,087 条；7 个容器合计 393,725 条（最大 72,597，最小 40,327） |
| 12 | 客体类别分布（场景 1 前 300 万条采样） | `file` 649,144 / `event` 215,053 / `unix` 162,766 / `directory` 54,092 / `pipe` 42,732 / 空 36,904 / `inotify` 12,101 / `timerfd` 5,677 / `ipv4` 4,104 / `netlink` 2,487 / `ipv6` 367 / `signalfd` 93 / `eventpoll` 2 |
| 13 | 管道身份 | `pipe` 结束行给 `fd1=3 fd2=5 ino=127813` |
| 14 | 命名空间与挂载 | `setns fd=8(<f>/run/snapd/ns/xxx.mnt) nstype=32(CLONE_NEWNS)`；`mount res=0 dev=tmpfs dir=... type=tmpfs` |
| 15 | 内核对象参数 | `bpf` 仅 `cmd=5`，结束行 fd 名 5/5 为空；`finit_module`（场景 9，4 行）含 `fd=` 的行数为 0；`keyctl`/`add_key`/`shmget`/`shmat` 参数全空 |
| 16 | 容器闭环（场景 9） | 容器 `533ccab15096` 的 `ld` 在事件号 1,279,420 以 `O_TRUNC\|O_CREAT\|O_RDWR` 创建 `/usr/lib/libdbus-helper.so`；宿主进程自 1,316,644 起以 `O_RDONLY\|O_CLOEXEC` 加载**同一路径字符串**（runc/iptables/systemd-sysctl/sh/flock/nm-dispatcher/sadc） |
| 17 | 路径不带视图前缀 | 容器侧 14,504 条文件操作中，`arg.name` 含 `/host` 的为 **0**；同一宿主文件在容器侧与宿主侧给出**同一路径字符串** |
| 18 | 多值字段分隔符 | `%evt.arg.flags` 渲染为 `O_TRUNC\|O_CREAT\|O_RDWR`（`\|` 为内部分隔符） |
| 19 | `<unknown>` 事件 | 场景 1 共 71,388 条（0.55%） |
| 20 | `user.uid` 与 `proc.duration` 的可得性 | `user.uid` 每事件都有，语义为 **ruid**（sshd 子进程 `setresuid(euid=root)` 后仍为 129）；`proc.duration` 在**捕获内创建的进程**上每条事件都有（shred pid 18645：clone 13,607ns → `execve` 77,608ns …），捕获前已存在则取不到（pid 1 无值） |

---

# 8. 边界声明（逐条勾选，报告必须原样列出）

1. **属主 / 时间戳 / 扩展属性篡改不能按文件查**：本批采集端未解码这些调用的参数，只能按 进程 + 调用名 计数（`ops.csv`）。
2. **`mprotect` 不可见**：其客体是内存区间，本设计不把内存区间当节点；本批参数也缺失 → 无法回答"哪块内存区间后来被执行"。
3. **载荷只有前 80 字节**：这是**采集端快照配置**，不是数据源上限；是否截断按"`res` 与 base64 解码长度比较"现算。
4. **匿名通道**（`socketpair`/`eventfd`/`signalfd`/`timerfd`/`inotify`/`epoll`）上的数据流不落图：fd 名是类型代号（`<e>`/`<t>`/`<i>`）或内核地址，无可区分身份。
5. **容器视图不合并**：跨视图同名只有"候选链"，不是同一性证明；容器 overlay 与宿主同名不同物。
6. **采集侧丢失必须报**：每个场景现算断号（实测值见 §7-1）。
7. **打开意图不落图**：只读/只写 `openat` 不建边 → "只打开不读"的静默探测不可见。
8. **零拷贝与普通读写不再区分**：`splice`/`sendfile`/`tee`/`copy_file_range` 统一并入 `read`/`write` → "未落盘直接转发"这一特征不可见。
9. **`fsync` 族不落图** → "写完立刻落盘"的节奏特征不可查。
10. **`sigreturn` 不落图** → SROP 这类靠信号返回异常识别的攻击丢失检测面。
11. **线程创建不落图**：`clone(CLONE_THREAD)` 不建边、不建节点。
12. **未验证调用**（清单见 §4.2 状态列与其后的"无独立动词的未验证调用"）：换采集端或合成场景采集后必须重新验证客体形态。
13. **本批"无参数"调用**（清单见 §7-4 与 §7-15）：只计数，不建边。
14. **跨主机缝合要求同一采集端版本**（靠 `tuple` 字符串相等）。
15. **内核级盲区**：继承《多主机环境系统调用图物理级不可见与拓扑盲区攻击清单》的 25 + 7 条。
16. **符号链接不解析**：同一文件经不同软链接会成为多个节点。
17. **同路径"删除后重建"视为同一节点**：数据源无 inode/版本号。
18. **时间戳来自被测主机时钟**：跨主机比较前必须核对时钟一致性。
19. **容器元数据缺失时 `privileged`/`host_root_rw` 为空（未知）**，禁止当作 `false`。
20. **`SCM_RIGHTS` fd 传递不可见**：`sendmsg`/`recvmsg` 只给返回值与载荷，不带 fd 列表 → 不建 fd 传递边；跨进程传 fd 的链只能在套接字两端各自可见。
21. **`unshare` 的命名空间种类与 `bpf` 命令号不落图**：只记报告计数（按调用名），无法区分 `CLONE_NEWNS` 还是 `CLONE_NEWPID`、`BPF_PROG_LOAD` 还是 `BPF_MAP_CREATE`；需区分时在报告里附位图（当前不做）。
22. **`ioctl` 请求码、`mount` 的 `fstype`/`dev`、信号号、`umount2` 不落图**：只能在报告里按 `ioctl:<req>` / `mount:<fstype>` / `signal:<n>` 检索；卸载动作本身不建边。
23. **`born_src=duration` 的时间是推算值**（事件时刻 − 进程已运行时长，推算到 fork 时刻）：只用于排序与 pid 解析，不得当作攻击发生时刻引用；若该 pid 段的 exec 事件同时丢失，节点覆盖 exec 前后两段身份，无法切分。
24. **失败的对象创建/执行/绑定不落图**：这些动作失败时不产生对象，按 §4.6 只记 `attempts.csv`；图上 `action` 为 `create`/`exec`/`accept` 等的边全部对应成功调用（`connect` 除外，其失败边由 `res<0` 标识）。

---

# 9. 验证计划

**未验证与"本批不产出"的清单见 §4.2 状态列与其后的"无独立动词的未验证调用"**（按 R4 保留设计位）。

**验证手段**：
1. **合成场景**（隔离测试机，各采一次）：起一个容器（记录完整挂载表）、跑一次 `io_uring` 读写、`memfd_create` + `execveat`、`ptrace` attach、`keyctl`、`finit_module`、共享内存读写。
2. **采集端升级后重跑**：逐场景输出"参数可得性报告"，对比"能定位客体/不能定位"的比例，判断哪些调用从"无参数"变成"可归属"。
3. **容器闭环端到端**（场景 9）：容器 id 归属 → 挂载表 → `host_root_rw` → 容器写宿主文件 → 宿主进程加载同一路径（同名候选链）；补齐容器侧写型操作清单与外泄容器的读取清单。
4. **容器事件全量核对**：8 个场景逐一全量扫描（禁止用采样结论代替）。
5. **特殊打开方式**：`openat(O_TMPFILE)`、`openat(O_PATH)`、`execveat(AT_EMPTY_PATH)` 各采一次，确认数据源给出的客体名形态（当前按原生形态处理，未验证）。

---

# 附录 A · 配置参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `host_id` | 必填 | 每场景一个 |
| `pair_timeout_ns` | 5 s | 进入行超时淘汰（阻塞类不淘汰） |
| `pair_pool_max` | 100,000 | 配对池上限 |
| `fd_table_max` | 4,096 | 单进程句柄表上限 |
| `keep_payload` | 开 | 是否保留载荷 |
| `payload_max_bytes` | 80 | 采集端快照上限（配置项） |
| `vertex_batch` | 5,000 | 顶点批量 |
| `edge_batch` | 10,000 | 边批量 |
| `flush_interval_ms` | 500 | 边写入时间触发 |
| `write_buffer_max` | 50,000 | 待写边缓冲 |
| `backpressure_batches` | 5 | 背压触发批次数 |
| `retry_max` | 5 | 写冲突重试次数 |
| `memory_target_gb` | 6 | 峰值内存目标 |

# 附录 B · 参考查询（Cypher，变量为时间窗/容器）

1. **初始访问**：`MATCH (n:Network)-[r:n2p {action:'accept'}]->(p:Process)-[w:p2f {action:'create'}]->(f:File) WHERE r.ts_ns>=$t0 RETURN n.tuple, p.exe, f.path, w.ts_ns LIMIT 50`
2. **执行链**：`MATCH (a:Process)-[r:p2p {action:'exec'}]->(b:Process)-[l:f2p {action:'load_image'}]->(f:File) WHERE r.ts_ns>=$t0 RETURN a.exe, b.exe, f.path, b.cmdline`
3. **持久化**：`MATCH (p:Process)-[r:p2f]->(f:File) WHERE f.path CONTAINS 'cron' OR f.path CONTAINS 'systemd/system' OR f.path CONTAINS 'authorized_keys' RETURN p.exe, f.path, r.action, r.ts_ns ORDER BY r.ts_ns`
4. **提权**：`MATCH (p:Process) WHERE p.uid<>p.ruid RETURN p.exe, p.uid, p.ruid`
5. **凭据读取**：`MATCH (f:File)-[r:f2p]->(p:Process) WHERE f.path IN ['/etc/shadow','/etc/passwd'] RETURN p.exe, f.path, r.ts_ns`
6. **出站连接 / 横向移动**：`MATCH (p:Process)-[r:p2n {action:'connect'}]->(n:Network) WHERE n.tuple ENDS WITH ':22' OR n.tuple ENDS WITH ':445' RETURN p.exe, n.tuple, r.res, r.ts_ns`
7. **外泄量**：`MATCH (p:Process)-[r:p2n {action:'send'}]->(n:Network) WHERE r.res>0 RETURN p.exe, n.tuple, sum(r.res) AS bytes ORDER BY bytes DESC LIMIT 20`
8. **C2 周期性**：`MATCH (p:Process)-[r:p2n {action:'send'}]->(n:Network) WITH p,n,count(r) AS c, min(r.ts_ns) AS t0, max(r.ts_ns) AS t1 RETURN p.exe, n.tuple, c, t0, t1 ORDER BY c DESC`
9. **跨视图同名候选**：`MATCH (a:File),(b:File) WHERE a.host_id=b.host_id AND a.path=b.path AND a.container_id<>b.container_id RETURN a.path, a.container_id, b.container_id LIMIT 100`
10. **容器写宿主文件（逃逸）**：`MATCH (p:Process)-[r:p2f]->(f:File) WHERE p.container_id<>'host' AND p.host_root_rw=true AND r.action IN ['create','write','rename'] RETURN p.container_id, p.exe, f.path, r.action, r.ts_ns ORDER BY r.ts_ns`
11. **进程隐藏（/proc 扫描）**：`MATCH (p:Process)-[r:f2p]->(f:File) WHERE f.path STARTS WITH '/proc/' AND (f.path ENDS WITH '/comm' OR f.path ENDS WITH '/cmdline') RETURN p.container_id, p.exe, count(*) AS n ORDER BY n DESC`
12. **内存注入**：`MATCH (p:Process)-[r:f2p {action:'mmap'}]->(f:File) WHERE 'PROT_EXEC' IN r.flags RETURN p.exe, f.path, r.flags, r.ts_ns` 与 `MATCH (a:Process)-[r:p2p]->(b:Process) WHERE r.action IN ['mem_write','ptrace'] RETURN a.exe,b.exe,r`;
13. **勒索/擦除**：`MATCH (p:Process)-[r:p2f]->(f:File) WHERE r.action IN ['rename','unlink','write'] RETURN p.exe, r.action, count(DISTINCT f) AS files ORDER BY files DESC`
14. **信号投递分布**：`MATCH (a:Process)-[r:p2p {action:'signal'}]->(b:Process) RETURN a.exe, b.exe, count(*) AS c ORDER BY c DESC LIMIT 50`（信号号不落图；按信号类型检索需查报告 `signal:<n>`）

# 附录 C · 复现命令

```bash
S=/path/to/capture.scap

# 事件总数（对账分母）与丢号
sysdig -r $S -p "%evt.num" | awk '{n=$1+0; if(NR>1){d=n-prev; if(d!=1){g++; s+=d-1; if(d-1>m){m=d-1}}} prev=n; c++} END{printf "实存=%d 末号=%d 断号=%d 段=%d 最大段=%d\n", c, prev, s, g, m}'

# 事件类型直方图（内存有界）
sysdig -r $S -p "%evt.type" | awk '{c[$0]++} END{for(k in c) printf "%10d %s\n", c[k], k}' | sort -rn

# 行内信息密度（前 N 行）
sysdig -r $S -n 1000000 | awk '{ if (NF<=7) bare++; else { if (index($0," res=")>0) res++; if (index($0,"fd=")>0) fd++; if (index($0,"name=")>0||index($0,"path=")>0) pth++ } n++ } END{printf "行=%d 无参数=%.1f%% 有返回值=%.1f%% 带fd=%.1f%% 带路径=%.1f%%\n", n, 100*bare/n, 100*res/n, 100*fd/n, 100*pth/n}'

# 网络：元组与协议（注意用制表符分隔，不要用 |）
sysdig -r $S "evt.type=accept and evt.dir=<" -p "%fd.name|cip=%fd.cip cport=%fd.cport sip=%fd.sip sport=%fd.sport|%fd.l4proto" -n 5

# 良构元组 vs 不良构元组的协议空缺对比
sysdig -r $S "evt.type=connect and evt.dir=< and fd.type=ipv4" -p "%fd.name|%fd.l4proto" -n 3000

# 载荷（只取 buffer，配 -b；禁止混入 evt.buflen）
sysdig -r $S "evt.type=read and evt.dir=<" -p "%evt.buffer" -b -n 3

# 容器元数据（复合串 + 带序号字段）
sysdig -r $S "evt.type=container" -p "%evt.num|%container.id|%container.name|%container.privileged|%container.mounts" -n 5
sysdig -r $S "evt.type=container" -p "%container.mount.source[0]|%container.mount.dest[0]|%container.mount.rdwr[0]" -n 5

# 容器归属分布
sysdig -r $S -p "%container.id" | awk '{c[$0]++} END{for(k in c) printf "%8d %s\n", c[k], k}' | sort -rn

# 关键调用参数可得性（逐调用名）
for t in openat renameat2 unlink chmod access getdents64 kill mount setns chroot setresuid bpf finit_module newfstatat chown utimensat; do
  a=$(sysdig -r $S "evt.type=$t and evt.dir=<" -p "%evt.type" -n 200000 | wc -l)
  b=$(sysdig -r $S "evt.type=$t and evt.dir=<" -p "%evt.rawres" -n 200000 | wc -l)
  printf "%-14s 退出行=%-8s 有返回值=%-8s\n" "$t" "$a" "$b"
done
```
