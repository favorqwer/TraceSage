"""边界穿越故事通道（Boundary-Story Channel）

定位
----
与 `rules/matcher.py`（基模匹配 + 血缘/敏感读取闭环）、`orchestrator/bridge.py`（会话桥接 +
双端诱导闭环）并列的**第三条符号促进通路**：同样把候选边提升为「已确认」，但判据不同。
它不调用大模型，**只增不减**（由调用方与其已确认集合合并），并且：

  1. 不含任何名单、阈值、时间窗；
  2. 不引用标准答案（本文件不出现 groundtruth/GT 字样，也不读取任何标注文件）；
  3. 判据只来自两类事实：
     · 图内事实——连接对象上 `connect`/`accept` 是否成对（判断对端是否在观测窗口内）、
       谁写出了什么对象、谁消费了它、两个主体的可执行程序是否相同；
     · 操作系统本体事实——哪些对象是内核按需生成的伪文件（`/sys`、`/proc`、`/dev` 下的
       设备与终端节点、`memfd:`、匿名 IPC），它们不承载内容，不能算落地物。

原理（六步）
------------
  ① 边界穿越：同一个连接对象上若同时出现 connect 与 accept，说明两端都在本机、都被观测到；
     只出现其中之一，则另一端在观测窗口之外 → 它是候选入口（不假设入站或出站）。
  ② 现学对手指纹：从「锚点边 + 高精度家族边（MINED_* / REFINED_ACTIVE_BRIDGE）+ 涉及窗口内
     新造对象的确认边」里提取对端 IP。指纹是数据里现学的，不是名单。
  ③ 攻击主体与攻击产物：与带指纹对端的连接打过交道的进程 = 攻击主体；它们写出的非伪文件对象
     = 攻击产物；再沿「消费攻击产物 / 被攻击主体派生」继续扩散。
  ④ 严格成因：只确认满足以下之一的边——走在带指纹对端的连接上 / 攻击产物被写出-读取-执行 /
     跨程序（注意：不是跨进程号）的管道交接 / 攻击主体读取窗口内新造的非伪文件对象。
  ⑤ 伪文件排除：内核按需生成的伪对象不计为攻击产物（`/dev/shm` 等可写内存文件系统保留）。
  ⑥ 链条继续：攻击主体消费攻击产物后继续产出，覆盖「外部数据流入 → 落地 → 被接手 → 再落地」
     这类非入站型入口（如钓鱼投递）。

边界（务必随代码一起声明）
--------------------------
  · 内存型入口（mmap/memfd/ptrace 无文件落地）观测不到，本通道不覆盖；
  · 窗口开始前已落地的载荷，其「谁写的」在窗口外，链条会在这里断开；
  · 「对端不可归因」只说明对方不在本机图里，不能说明对方是恶意的——恶意与否仍需由
    锚点与高精度家族给出的指纹来限定，这也是本通道必须依赖调查锚点的原因（锚点为外部前置输入）。
"""
from collections import defaultdict

# ── 系统调用语义分类（图内事实，非名单） ───────────────────────────────────────────
WRITE_SC = frozenset({'write', 'create', 'mkdir', 'rename', 'chmod', 'chown', 'symlink'})
READ_SC = frozenset({'read', 'open', 'sendfile', 'recvfrom'})
SPAWN_SC = frozenset({'execve', 'clone', 'fork'})

# ── 内核按需生成、不承载内容的伪对象前缀（操作系统本体事实） ────────────────────────
# 注意：/dev/shm、/run/shm、/tmp、/var/tmp 属于可写内存/临时文件系统，真实攻击常在此落地载荷，
#       因此**故意不排除**它们。
PSEUDO_PREFIXES = ('/sys/', '/proc/', 'pipe:', 'memfd:', 'tmpfile:', 'socket:', 'unix:', 'anon:')
PSEUDO_DEV_EXACT = frozenset({'/dev/null', '/dev/zero', '/dev/urandom', '/dev/random',
                              '/dev/full', '/dev/tty', '/dev/ptmx', '/dev/console'})

# ── 高精度家族（离线准入已按训练期精度把关的家族；用于学指纹，避免把基线自身错误学成指纹） ──
HIGH_PRECISION_MOTIFS = frozenset({'REFINED_ACTIVE_BRIDGE'})


def _pid(edge):
    return str(edge.get('process_id') or '')


def _is_socket(node):
    return '->' in str(node)


def _socket_ips(node):
    """从连接对象字符串 'a:1->b:2' 里取出两端的 IP。"""
    s = str(node)
    out = set()
    if '->' not in s:
        return out
    for part in s.split('->'):
        ip = part.split(':')[0] if ':' in part else part
        if ip and not ip.startswith(('unix:', 'pipe:', 'socket:')):
            out.add(ip)
    return out


def _program(node):
    """可执行程序名（跨程序判据用）。"""
    s = str(node)
    return s.split('/')[-1] if '/' in s else s


def _is_pseudo_object(obj):
    """内核按需生成、不承载内容的伪对象？"""
    o = str(obj)
    if o.startswith(PSEUDO_PREFIXES):
        return True
    if o.startswith('/dev/'):
        return (o in PSEUDO_DEV_EXACT) or o.startswith('/dev/pts/') or o.startswith('/dev/fd/')
    return False


def _key(edge):
    return (edge.get('src'), edge.get('syscall'), edge.get('dst'))


class BoundaryStoryOperator:
    """边界穿越故事通道（见模块 docstring）。默认参数即离线验证过的配置。"""

    def __init__(self, fresh_only=True, use_iteration=False, use_time=True, use_ancestry=True,
                 chain_rounds=2):
        self.fresh_only = fresh_only          # 指纹来源限定为「涉及窗口内新造对象的确认边」
        self.use_iteration = use_iteration    # 自洽迭代（离线实测无增益，默认关闭）
        self.use_time = use_time              # 边不得晚于锚点最后实例（离线实测零效果，保留）
        self.use_ancestry = use_ancestry      # 指纹连接的本地主体须在锚点祖先链上（离线实测零效果，保留）
        self.chain_rounds = chain_rounds

    # ── 索引 ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def _index(pool):
        idx = {'writers_pid': defaultdict(set), 'writers_prog': defaultdict(set),
               'fresh': set(), 'local_ip_counts': defaultdict(int)}
        for e in pool:
            sc = e.get('syscall')
            if sc in WRITE_SC:
                dst = str(e.get('dst'))
                if not _is_pseudo_object(dst):
                    idx['fresh'].add(dst)
                if dst.startswith('pipe:'):
                    idx['writers_pid'][dst].add(_pid(e))
                    idx['writers_prog'][dst].add(_program(e.get('src')))
                if sc in ('rename', 'symlink'):
                    src = str(e.get('src'))
                    if not _is_pseudo_object(src):
                        idx['fresh'].add(src)
            for node in (e.get('src'), e.get('dst')):
                for ip in _socket_ips(node):
                    if not ip.startswith(('127.', '0.0.')):
                        idx['local_ip_counts'][ip] += 1
        idx['local_ip'] = (max(idx['local_ip_counts'].items(), key=lambda kv: kv[1])[0]
                           if idx['local_ip_counts'] else None)
        return idx

    @staticmethod
    def _boundary_sockets(pool):
        """对端在观测窗口之外的连接对象：connect/accept 只出现其一。"""
        has_accept, has_connect = set(), set()
        for e in pool:
            if e.get('syscall') == 'accept' and _is_socket(e.get('src')):
                has_accept.add(str(e.get('src')))
            if e.get('syscall') == 'connect' and _is_socket(e.get('dst')):
                has_connect.add(str(e.get('dst')))
        return (has_accept - has_connect) | (has_connect - has_accept)

    @staticmethod
    def _reach_to(pool, target):
        """在 src->dst 有向图上，求能到达 target 的节点集合（锚点祖先链）。"""
        frontier = {target}
        for _ in range(60):
            added = set()
            for e in pool:
                if e.get('dst') in frontier and e.get('src') not in frontier:
                    added.add(str(e.get('src')))
            if not added:
                break
            frontier |= added
        return frontier

    # ── 主流程 ───────────────────────────────────────────────────────────────────
    def promote(self, pool, confirmed_map):
        """返回 { (src, syscall, dst): 提升边记录 }；不修改入参。"""
        if not pool:
            return {}
        promoted = {}
        idx = self._index(pool)
        local_ip = idx['local_ip']
        boundary = self._boundary_sockets(pool)

        anchors = [e for e in confirmed_map.values() if e.get('class') == 'anchor']
        anchor_t1 = int((anchors[0].get('t1') or 0)) if anchors else 0
        anc_node = str(anchors[0].get('src')) if anchors else None
        ancestry = self._reach_to(pool, anc_node) if anc_node else set()

        def learn_fingerprints(source_keys):
            ips = set()
            for e in pool:
                k = _key(e)
                if k not in source_keys:
                    continue
                dst = str(e.get('dst'))
                if self.fresh_only and e.get('class') != 'anchor':
                    touches_fresh = ((e.get('syscall') in WRITE_SC and dst in idx['fresh'])
                                     or (e.get('syscall') in READ_SC and str(e.get('src')) in idx['fresh']))
                    if not touches_fresh:
                        continue
                for node in (e.get('src'), e.get('dst')):
                    for ip in _socket_ips(node):
                        if ip != local_ip and not ip.startswith(('127.', '0.0.')):
                            ips.add(ip)
            return ips

        def is_fingerprint_source(e):
            if e.get('class') == 'anchor':
                return True
            motif = str(e.get('motif') or '')
            return motif.startswith('MINED') or motif in HIGH_PRECISION_MOTIFS

        source_keys = {_key(e) for e in confirmed_map.values() if is_fingerprint_source(e)}

        for _round in range(2 if self.use_iteration else 1):
            fp_ips = learn_fingerprints(source_keys)
            # ③ 攻击主体：与带指纹对端的连接打过交道的进程
            actors = set()
            for e in pool:
                src, dst = e.get('src'), e.get('dst')
                if ((_is_socket(src) and (_socket_ips(src) & fp_ips))
                        or (_is_socket(dst) and (_socket_ips(dst) & fp_ips))):
                    p = _pid(e)
                    if p:
                        actors.add(p)
            # 攻击产物 + 链条继续
            for _ in range(self.chain_rounds):
                products = {str(e['dst']) for e in pool
                            if e.get('syscall') in WRITE_SC and _pid(e) in actors
                            and not _is_pseudo_object(e['dst'])}
                if not products:
                    break
                new_actors = set()
                for e in pool:
                    p = _pid(e)
                    if not p or p in actors:
                        continue
                    if e.get('syscall') in READ_SC and str(e.get('src')) in products:
                        new_actors.add(p)
                    elif e.get('syscall') in SPAWN_SC:
                        if any(p.startswith(x) or x.startswith(p) for x in actors) or str(e.get('dst')) in products:
                            new_actors.add(p)
                if not new_actors:
                    break
                actors |= new_actors
            products = {str(e['dst']) for e in pool
                        if e.get('syscall') in WRITE_SC and _pid(e) in actors
                        and not _is_pseudo_object(e['dst'])}

            # ④ 严格成因判定
            for e in pool:
                k = _key(e)
                if k in confirmed_map or k in promoted:
                    continue
                sc = e.get('syscall')
                src, dst = str(e.get('src')), str(e.get('dst'))
                if self.use_time and anchor_t1:
                    t0 = int(e.get('t0') or 0)
                    if t0 and t0 > anchor_t1:
                        continue
                reason = None
                # (a) 走在带指纹对端的连接上
                if _is_socket(src) and (_socket_ips(src) & fp_ips):
                    local_side = dst
                    if (not self.use_ancestry) or (local_side in ancestry):
                        reason = 'BOUNDARY_FP_SOCKET'
                elif _is_socket(dst) and (_socket_ips(dst) & fp_ips):
                    local_side = src
                    if (not self.use_ancestry) or (local_side in ancestry):
                        reason = 'BOUNDARY_FP_SOCKET'
                # (b) 攻击产物被写出 / 被执行
                elif sc in WRITE_SC and dst in products:
                    reason = 'BOUNDARY_PRODUCT_WRITE'
                elif sc in SPAWN_SC and dst in products:
                    reason = 'BOUNDARY_PRODUCT_EXEC'
                elif sc in READ_SC:
                    if src in products:
                        reason = 'BOUNDARY_PRODUCT_READ'
                    elif src.startswith('pipe:'):
                        # (c) 跨程序（不是跨进程号）的管道交接
                        writers_pid = idx['writers_pid'].get(src, set())
                        writers_prog = idx['writers_prog'].get(src, set())
                        if (writers_pid & actors) and _pid(e) and _pid(e) not in writers_pid:
                            if any(wp != _program(dst) for wp in writers_prog):
                                reason = 'BOUNDARY_HANDOFF_PIPE'
                    elif _pid(e) in actors and src in idx['fresh']:
                        reason = 'BOUNDARY_ACTOR_READ_FRESH'
                if not reason:
                    continue
                rec = dict(e)
                rec['origin'] = 'confirmed'
                rec['class'] = 'story'
                rec['motif'] = reason
                rec['motif_name'] = '边界穿越故事通道'
                rec['reason'] = f"边界穿越故事通道：{reason}（对手指纹 {sorted(fp_ips)}）"
                promoted[k] = rec

            if not self.use_iteration:
                break
            source_keys = set(confirmed_map) | set(promoted)

        return promoted
