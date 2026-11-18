#!/usr/bin/env python3
"""
mine_benign_subgraph_motifs.py
TraceSage 良性因果子图基模挖掘引擎
基于全新角色分类与锚点扩展算法，从 nodes.csv / edges.csv 中提取业务基模
"""

import os
import sys
import csv
import json
import time
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Set, Any
from role_classifier import RoleClassifier

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

class BenignMotifMiner:
    def __init__(self, nodes_csv: str, edges_csv: str, out_dir: str):
        self.nodes_csv = nodes_csv
        self.edges_csv = edges_csv
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)

        # 节点映射: node_key -> dict of attrs & role
        self.nodes = {}
        # 进程索引: pid -> list of node_keys
        self.pid_to_node = defaultdict(list)
        # 边统计与锚点事件集合
        self.anchor_subgraphs = []

    def load_nodes(self):
        log(f"加载节点元数据: {self.nodes_csv}")
        with open(self.nodes_csv, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lbl = row.get("label")
                cid = row.get("container_id", "host") or "host"
                pid = row.get("pid", "")
                st = row.get("start_ns", "")
                path = row.get("path", "")
                ep = row.get("endpoints", "")
                proto = row.get("proto", "tcp")
                exe = row.get("exe_path", "")
                cmd = row.get("cmdline", "")
                uid = row.get("uid", "")
                euid = row.get("euid", "")
                ft = row.get("file_type", "file")

                if lbl == "Process":
                    role = RoleClassifier.classify_process(exe, cmd, uid, euid, cid)
                    key = ("Process", cid, pid, st)
                    self.nodes[key] = {
                        "label": "Process", "cid": cid, "pid": pid, "start_ns": st,
                        "exe": exe, "cmd": cmd, "role": role
                    }
                    if pid:
                        self.pid_to_node[pid].append(key)
                elif lbl == "File":
                    role = RoleClassifier.classify_file(path, ft)
                    key = ("File", cid, path)
                    self.nodes[key] = {
                        "label": "File", "cid": cid, "path": path, "file_type": ft, "role": role
                    }
                elif lbl == "Network":
                    role = RoleClassifier.classify_network(ep, proto)
                    key = ("Network", ep)
                    self.nodes[key] = {
                        "label": "Network", "endpoints": ep, "proto": proto, "role": role
                    }
        log(f"节点加载完成: 进程 {len(self.pid_to_node)} 个 PID, 总节点数 {len(self.nodes)}")

    def extract_subgraphs(self):
        log(f"开始流式扫描边数据并提取业务因果链: {self.edges_csv}")

        # 为每个进程实体收集邻接关系
        # proc_key -> { "in_net": set, "out_net": set, "child_procs": set, "files_read": set, "files_written": set, "events": list }
        proc_contexts = defaultdict(lambda: {
            "in_net": set(), "out_net": set(),
            "child_procs": set(), "parent_proc": None,
            "files_read": set(), "files_written": set(),
            "actions": Counter(), "syscalls": Counter(),
            "sample_events": []
        })

        edge_count = 0
        with open(self.edges_csv, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                edge_count += 1
                if edge_count % 250000 == 0:
                    log(f"已流式处理 {edge_count} 条因果边...")

                eclass = row.get("edge_class")
                action = row.get("action")
                syscall = row.get("syscall")
                eid = row.get("event_id")
                start_ns = row.get("start_ns")

                src_lbl = row.get("src_label")
                src_cid = row.get("src_container") or "host"
                src_pid = row.get("src_pid")
                src_st = row.get("src_start_ns")
                src_path = row.get("src_path")

                dst_lbl = row.get("dst_label")
                dst_cid = row.get("dst_container") or "host"
                dst_pid = row.get("dst_pid")
                dst_st = row.get("dst_start_ns")
                dst_path = row.get("dst_path")

                # 构建键
                if eclass == "NetworkToProcess":
                    net_key = ("Network", src_path) # endpoints in path col for net
                    proc_key = ("Process", dst_cid, dst_pid, dst_st)
                    ctx = proc_contexts[proc_key]
                    ctx["in_net"].add((net_key, action, syscall))
                    ctx["actions"][action] += 1
                    if len(ctx["sample_events"]) < 5:
                        ctx["sample_events"].append({"eid": eid, "action": action, "syscall": syscall, "src": str(net_key), "dst": str(proc_key), "ns": start_ns})

                elif eclass == "ProcessToNetwork":
                    proc_key = ("Process", src_cid, src_pid, src_st)
                    net_key = ("Network", dst_path)
                    ctx = proc_contexts[proc_key]
                    ctx["out_net"].add((net_key, action, syscall))
                    ctx["actions"][action] += 1

                elif eclass == "ProcessToProcess":
                    src_proc = ("Process", src_cid, src_pid, src_st)
                    dst_proc = ("Process", dst_cid, dst_pid, dst_st)
                    proc_contexts[src_proc]["child_procs"].add((dst_proc, action, syscall))
                    proc_contexts[dst_proc]["parent_proc"] = (src_proc, action, syscall)
                    proc_contexts[src_proc]["actions"][action] += 1

                elif eclass == "ProcessToFile":
                    proc_key = ("Process", src_cid, src_pid, src_st)
                    file_key = ("File", dst_cid, dst_path)
                    ctx = proc_contexts[proc_key]
                    ctx["files_written"].add((file_key, action, syscall))
                    ctx["actions"][action] += 1

                elif eclass == "FileToProcess":
                    proc_key = ("Process", dst_cid, dst_pid, dst_st)
                    file_key = ("File", src_cid, src_path)
                    ctx = proc_contexts[proc_key]
                    ctx["files_read"].add((file_key, action, syscall))
                    ctx["actions"][action] += 1

        log(f"边流式读取完成，累计处理 {edge_count} 条因果边，构建 {len(proc_contexts)} 个活跃进程因果上下文")
        return proc_contexts

    def mine_motifs(self, proc_contexts: Dict):
        log("开始基于 7 大核心服务原型挖掘因果连通子图基模...")
        motif_clusters = defaultdict(list)

        for proc_key, ctx in proc_contexts.items():
            node_info = self.nodes.get(proc_key)
            if not node_info:
                continue

            role = node_info.get("role", "")
            exe = node_info.get("exe", "")

            # 过滤高噪声无意义的底层扫描进程，聚焦核心原型
            is_anchor = False
            for archetype in ["WEB_SERVER", "INTERPRETER", "DATABASE_ENGINE", "DATABASE_CLIENT",
                              "MAIL_SERVICE", "DNS_RESOLVER", "TRANSFER_SERVICE", "ADMIN_SERVICE",
                              "BUILD_TOOL", "CONTAINER_ENGINE", "SYSTEM_UTILITY", "INTERACTIVE_SHELL"]:
                if f"P.{archetype}." in role:
                    is_anchor = True
                    break

            if not is_anchor:
                continue

            # 抽取并归一化以当前进程为中心的子图
            motif_spec = self._synthesize_motif(proc_key, node_info, ctx, proc_contexts)
            if motif_spec:
                sig = motif_spec["signature"]
                motif_clusters[sig].append(motif_spec)

        log(f"初筛归纳出 {len(motif_clusters)} 类唯一因果拓扑签名")
        return self._consolidate_motifs(motif_clusters)

    def _synthesize_motif(self, proc_key, node_info, ctx, all_contexts):
        proc_role = node_info["role"]
        exe_name = os.path.basename(node_info["exe"] or "unknown")

        # 归一化节点集与边列表
        roles_in_motif = set()
        edges_in_motif = []
        hop_chains = []

        roles_in_motif.add(proc_role)

        # 1. 网络入站
        for net_key, act, sc in ctx["in_net"]:
            net_node = self.nodes.get(net_key)
            net_role = net_node["role"] if net_node else "N.INBOUND_SERVICE.TCP"
            roles_in_motif.add(net_role)
            edges_in_motif.append((net_role, act, proc_role))
            hop_chains.append(f"{net_role} --({act}:{sc})--> {proc_role}")

        # 2. 网络出站
        for net_key, act, sc in ctx["out_net"]:
            net_node = self.nodes.get(net_key)
            net_role = net_node["role"] if net_node else "N.SERVICE_TRAFFIC.TCP"
            roles_in_motif.add(net_role)
            edges_in_motif.append((proc_role, act, net_role))
            hop_chains.append(f"{proc_role} --({act}:{sc})--> {net_role}")

        # 3. 核心文件交互 (按 File Role 聚合去重)
        written_roles = set()
        for file_key, act, sc in ctx["files_written"]:
            f_node = self.nodes.get(file_key)
            f_role = RoleClassifier.classify_file(file_key[2], f_node["file_type"] if f_node else "file", act)
            if f_role not in written_roles:
                written_roles.add(f_role)
                roles_in_motif.add(f_role)
                edges_in_motif.append((proc_role, act, f_role))
                hop_chains.append(f"{proc_role} --({act}:{sc})--> {f_role}")

        read_roles = set()
        for file_key, act, sc in ctx["files_read"]:
            f_node = self.nodes.get(file_key)
            f_role = RoleClassifier.classify_file(file_key[2], f_node["file_type"] if f_node else "file", act)
            if f_role not in read_roles:
                read_roles.add(f_role)
                roles_in_motif.add(f_role)
                edges_in_motif.append((f_role, act, proc_role))
                hop_chains.append(f"{f_role} --({act}:{sc})--> {proc_role}")

        # 4. 子进程衍生
        for child_key, act, sc in ctx["child_procs"]:
            c_node = self.nodes.get(child_key)
            if c_node:
                c_role = c_node["role"]
                roles_in_motif.add(c_role)
                edges_in_motif.append((proc_role, act, c_role))
                hop_chains.append(f"{proc_role} --({act}:{sc})--> {c_role}")

                # 追溯子进程的关键行为（如 shell 派生 utility 读写日志）
                c_ctx = all_contexts.get(child_key)
                if c_ctx:
                    for cf_key, c_act, c_sc in list(c_ctx["files_written"])[:3]:
                        cf_role = RoleClassifier.classify_file(cf_key[2], "file", c_act)
                        roles_in_motif.add(cf_role)
                        edges_in_motif.append((c_role, c_act, cf_role))
                        hop_chains.append(f"{c_role} --({c_act}:{c_sc})--> {cf_role}")

        # 如果没有形成多跳因果交互，跳过单点噪音
        if len(edges_in_motif) < 2:
            return None

        # 拓扑签名: 排序后的 (src, act, dst) 元组串
        sorted_edges = tuple(sorted(set(edges_in_motif)))
        sig = ";".join([f"{s}-{a}->{d}" for s, a, d in sorted_edges])

        return {
            "signature": sig,
            "anchor_role": proc_role,
            "exe_name": exe_name,
            "roles": sorted(list(roles_in_motif)),
            "edges": list(sorted_edges),
            "hop_chains": sorted(list(set(hop_chains))),
            "sample_events": ctx["sample_events"]
        }

    def _consolidate_motifs(self, clusters: Dict) -> List[Dict]:
        log("开始对拓扑签名进行业务语义提炼与等价合并...")
        consolidated = []
        motif_id_counter = 1

        # 按聚类规模排序
        sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)

        for sig, instances in sorted_clusters:
            support = len(instances)
            rep = instances[0]

            anchor_role = rep["anchor_role"]
            exe = rep["exe_name"]
            roles = rep["roles"]
            edges = rep["edges"]
            hops = rep["hop_chains"]

            # 根据业务语义模式自动归类生成高可读性规范名称与描述
            category, title, desc, condition = self._infer_semantics(anchor_role, exe, roles, edges)

            motif_entry = {
                "motif_id": f"BENIGN_MOTIF_{motif_id_counter:03d}",
                "category": category,
                "title": title,
                "description": desc,
                "precondition": condition,
                "support_instances": support,
                "anchor_role": anchor_role,
                "representative_exe": exe,
                "roles": roles,
                "edges": [{"src": s, "action": a, "dst": d} for s, a, d in edges],
                "hop_chains": hops,
                "sample_event": rep["sample_events"][0] if rep["sample_events"] else {}
            }
            consolidated.append(motif_entry)
            motif_id_counter += 1

        log(f"基模合并与语义提炼完成，共生成 {len(consolidated)} 个标准化良性基模")
        return consolidated

    def _infer_semantics(self, anchor_role: str, exe: str, roles: List[str], edges: List[Tuple]) -> Tuple[str, str, str, str]:
        # 1. Web 动态请求与静态分发
        if "WEB_SERVER" in anchor_role:
            if any("INTERPRETER" in r for r in roles) or any("IPC_SOCKET" in r for r in roles):
                return (
                    "WEB_APPLICATION_DYNAMIC",
                    "Web 服务接收外部入站请求并经由 IPC 转发至动态解释器",
                    f"外部网络客户端连入 Web 服务端口，{exe} 进程通过 UNIX Socket 触发解释器处理动态业务并读写临时/会话存储",
                    "网络入站目标端口为 80/8080，IPC 通道属于合法本地套接字"
                )
            else:
                return (
                    "WEB_APPLICATION_STATIC",
                    "Web 服务处理静态资源分发与日志记录",
                    f"{exe} 进程响应外部 HTTP 请求，读取本地网站静态资源或用户数据，并将请求记录追加至访问日志",
                    "操作文件位于 /var/www 或 /var/log/nginx/，动作为只读及日志写入"
                )

        # 2. 数据库事务与持久化
        elif "DATABASE_ENGINE" in anchor_role:
            if "redis" in exe.lower():
                return (
                    "CACHE_LIFECYCLE_PERSISTENCE",
                    "内存缓存键值服务生命周期与后台快照持久化",
                    "Redis 响应套接字客户端操作，修改内存结构并定期触发子进程将内存镜像以 BGSAVE 形式刷盘至 dump.rdb",
                    "操作仅限于 /var/lib/redis/dump.rdb 与本地 IPC 套接字"
                )
            else:
                return (
                    "DATABASE_TRANSACTION_WAL",
                    "关系数据库事务处理与数据/归档文件维护",
                    f"{exe} 接收本地或远程 SQL 业务操作，向数据表堆块读写记录，并向日志目录写入重做/WAL 归档日志",
                    "操作集中于 /var/lib/mysql 或 /var/lib/postgresql 数据目录"
                )

        # 3. 管理员运维与增量备份
        elif "ADMIN_SERVICE" in anchor_role or ("INTERACTIVE_SHELL" in anchor_role and any("ADMIN_REMOTE" in r for r in roles)):
            return (
                "ADMIN_REMOTE_MAINTENANCE",
                "合法管理员通过 SSH 登录执行系统健康巡检与日志同步",
                "外部管理员工作站通过 22 端口建立 SSH 认证会话，派生 Shell 并调度系统工具读取状态与日志归档",
                "入站源地址为已登记的管理员工作站 IP (100.64.216.52)，执行只读巡检与 SCP 备份"
            )

        # 4. 容器任务调度
        elif "CONTAINER_ENGINE" in anchor_role or any("CONTAINER" in r for r in roles):
            return (
                "CONTAINER_MICRO_TASK",
                "容器运行时隔离执行微任务与数据卷挂载处理",
                "容器守护进程配置隔离命名空间，派生微容器挂载宿主目录执行数据排序计算后正常退出释放",
                "使用标准隔离镜像（如 Alpine），挂载路径受限为指定数据卷目录"
            )

        # 5. 代码编译与构建
        elif "BUILD_TOOL" in anchor_role:
            return (
                "SOFTWARE_BUILD_PIPELINE",
                "软件工程代码编译、汇编与链接生成二进制",
                "构建工具链（gcc/as/ld）读取用户源代码及系统头文件，编译生成目标文件并链接为本地可执行程序",
                "输入输出限于工程开发目录，无网络异常外联"
            )

        # 6. 系统日常运维与守护
        elif "SYSTEM_UTILITY" in anchor_role:
            return (
                "SYSTEM_ROUTINE_UTILITY",
                "系统后台例行工具作业（文件校验/邮件通知/DNS）",
                f"{exe} 工具由系统排程调用，执行合规的本地文件校验归档、状态邮件投递或正向域名解析",
                "无异常特权提升或非法路径改写"
            )

        return (
            "SYSTEM_GENERAL_OPERATION",
            f"常规系统运行因果链 ({exe})",
            f"{exe} 进程与系统资源发生的合法因果调用链",
            "符合 Linux 标准系统调用行为"
        )

    def save_knowledge_base(self, motifs: List[Dict]):
        out_file = os.path.join(self.out_dir, "benign_motif_library.json")
        log(f"保存标准化良性基模知识库 -> {out_file}")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_dataset": "0_Benign_Baseline-v1",
                    "total_motifs": len(motifs),
                    "coverage_categories": list(set([m["category"] for m in motifs]))
                },
                "motifs": motifs
            }, f, indent=2, ensure_ascii=False)

        # 同时生成一份人类可读的知识库文档
        doc_file = os.path.join(self.out_dir, "BENIGN_MOTIFS_SPEC.md")
        log(f"生成基模规格说明书 -> {doc_file}")
        with open(doc_file, "w", encoding="utf-8") as f:
            f.write("# TraceSage 良性子图基模知识库规格说明书\n\n")
            f.write(f"- 生成时间：`{time.strftime('%Y-%m-%d %H:%M:%S')}`\n")
            f.write(f"- 基模总数：`{len(motifs)}` 个核心业务基模\n")
            f.write(f"- 覆盖业务范式：`{', '.join(set([m['category'] for m in motifs]))}`\n\n")
            f.write("## 基模清单与语义定义\n\n")

            for m in motifs:
                f.write(f"### [{m['motif_id']}] {m['title']} ({m['category']})\n\n")
                f.write(f"* **业务描述**：{m['description']}\n")
                f.write(f"* **前提条件**：`{m['precondition']}`\n")
                f.write(f"* **核心程序**：`{m['representative_exe']}`（锚点角色：`{m['anchor_role']}`）\n")
                f.write(f"* **基模内实体角色**：`{', '.join(m['roles'])}`\n")
                f.write(f"* **支持度实测频次**：`{m['support_instances']}` 次\n")
                f.write("* **因果跳链（Hop Chains）**：\n")
                for h in m["hop_chains"]:
                    f.write(f"  - `{h}`\n")
                f.write("\n---\n\n")

if __name__ == "__main__":
    nodes = "output/parser-v2/0_Benign_Baseline-v1/nodes.csv"
    edges = "output/parser-v2/0_Benign_Baseline-v1/edges.csv"
    out = "output/rule-kg/benign_motifs"

    miner = BenignMotifMiner(nodes, edges, out)
    miner.load_nodes()
    contexts = miner.extract_subgraphs()
    motifs = miner.mine_motifs(contexts)
    miner.save_knowledge_base(motifs)
