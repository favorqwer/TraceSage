import json
import os
from pathlib import Path
from typing import Any, Dict, List

from prouter.layers.l1_reach.topology_indexer import TopologyFacts


class OfflineDistiller:
    """
    离线知识蒸馏器（数据驱动因果拓扑基模自动归纳与编译引擎）：
    
    核心机制：
    1. 候选因果基模库定义：涵盖载荷落地、入站派生、特权工具、网络工具、持久化、批量覆写等通用图拓扑；
    2. 实体角色去字面化抽象：剥离具体文件名与网络地址，映射为客观系统拓扑角色；
    3. 判别式统计双向打分：在输入的训练场景集上，计算每个基模的跨场景正向支持度与背景负向误报率；
    4. 自动剪枝与编译：严格筛选出高置信度模式，动态输出给模式匹配器使用。
    """

    CANDIDATE_MOTIFS = [
        {
            "id": "DIST_01_EXEC_TAINTED_OBJ",
            "name": "受污染客体派生执行",
            "syscalls": ["execve"],
            "src_role": "TAINTED_OBJ",
            "proc_role": "ANY",
            "require_delivery": False,
        },
        {
            "id": "DIST_02_INBOUND_NET_ACCEPT",
            "name": "入站网络端点会话接收",
            "syscalls": ["accept", "recvfrom"],
            "src_role": "INBOUND_NET",
            "proc_role": "ANY",
            "require_delivery": False,
        },
        {
            "id": "DIST_03_INBOUND_INTERPRETER_EXEC",
            "name": "入站会话派生命令解释器",
            "syscalls": ["execve"],
            "dst_role": "INTERPRETER",
            "proc_role": "INBOUND_PROC",
            "require_delivery": True,
        },
        {
            "id": "DIST_04_TAINTED_NET_TOOL",
            "name": "受污染进程执行网络外联工具",
            "syscalls": ["execve"],
            "dst_role": "NET_TOOL",
            "proc_role": "TAINTED_PROC",
            "require_delivery": True,
        },
        {
            "id": "DIST_05_TAINTED_PRIV_TOOL",
            "name": "受污染进程执行权限提升工具",
            "syscalls": ["execve"],
            "dst_role": "PRIV_TOOL",
            "proc_role": "TAINTED_PROC",
            "require_delivery": False,
        },
        {
            "id": "DIST_06_TAINTED_ARCHIVE_TOOL",
            "name": "受污染进程执行文件归档工具",
            "syscalls": ["execve"],
            "dst_role": "ARCHIVE_TOOL",
            "proc_role": "TAINTED_PROC",
            "require_delivery": True,
        },
        {
            "id": "DIST_07_TAINTED_PERSISTENCE",
            "name": "受污染进程修改开机自启动配置",
            "syscalls": ["write", "symlink", "create"],
            "dst_role": "PERSISTENCE",
            "proc_role": "TAINTED_PROC",
            "require_delivery": False,
        },
        {
            "id": "DIST_08_TAINTED_TEMP_CHMOD",
            "name": "对临时目录或受污染客体赋予权限",
            "syscalls": ["chmod"],
            "dst_role": "TEMP_DIR",
            "proc_role": "TAINTED_PROC",
            "require_delivery": False,
        },
        {
            "id": "DIST_09_TAINTED_AUTH_READ",
            "name": "受污染进程读取凭据密钥客体",
            "syscalls": ["read"],
            "src_role": "SENSITIVE_AUTH",
            "proc_role": "TAINTED_PROC",
            "require_delivery": True,
        },
        {
            "id": "DIST_10_TAINTED_BATCH_MUTATION",
            "name": "受污染进程批量破坏或重命名",
            "syscalls": ["rename", "unlink"],
            "proc_role": "TAINTED_PROC",
            "min_batch": 4,
            "require_delivery": True,
        },
    ]

    def __init__(self, candidate_motifs: List[Dict[str, Any]] = None):
        self.candidate_motifs = candidate_motifs or list(self.CANDIDATE_MOTIFS)

    @staticmethod
    def check_entity_role(role: str, val: str, tf: TopologyFacts) -> bool:
        val = str(val)
        if role == "TAINTED_OBJ":
            return tf.is_tainted(val)
        if role == "INBOUND_NET":
            return val in tf.inbound_net_endpoints or (
                "->" in val and any(val.endswith(p) for p in [":22", ":80", ":443", ":8443", ":8080", ":5432", ":6379"])
            )
        if role == "OUTBOUND_NET":
            return "->" in val and not (val in tf.inbound_net_endpoints)
        if role == "PIPE":
            return val.startswith("pipe:")
        if role == "PERSISTENCE":
            return any(
                val.startswith(p)
                for p in [
                    "/etc/systemd/system",
                    "/lib/systemd/system",
                    "/etc/init.d",
                    "/etc/cron",
                    "/var/spool/cron",
                    "/etc/rc.local",
                ]
            )
        if role == "TEMP_DIR":
            return any(val.startswith(p) for p in ["/tmp/", "/var/tmp/", "/dev/shm/"])
        if role == "SENSITIVE_AUTH":
            return any(val.startswith(p) for p in ["/etc/sudoers", "/etc/shadow", "/etc/passwd"]) or ".ssh" in val or ".key" in val
        name = val.split("/")[-1]
        if role == "INTERPRETER":
            return name in ["sh", "bash", "dash", "zsh", "python", "python3", "perl", "php"]
        if role == "NET_TOOL":
            return name in ["curl", "wget", "ssh", "socat", "nc", "netcat", "rsync"]
        if role == "PRIV_TOOL":
            return name in ["sudo", "chmod", "chown", "su"]
        if role == "ARCHIVE_TOOL":
            return name in ["tar", "gzip", "unzip"]
        return True

    @classmethod
    def match_motif(cls, motif: Dict[str, Any], e: Dict[str, Any], tf: TopologyFacts) -> bool:
        sc = e.get("syscall", "")
        src = str(e.get("src", ""))
        dst = str(e.get("dst", ""))
        pid = str(e.get("process_id", ""))

        if motif.get("syscalls") and sc not in motif["syscalls"]:
            return False
        proc_role = motif.get("proc_role")
        if proc_role == "TAINTED_PROC" and not tf.is_tainted_proc(pid):
            return False
        if proc_role == "INBOUND_PROC" and (src not in tf.inbound_processes and not tf.is_tainted_proc(pid)):
            return False
        if motif.get("require_delivery") and not tf.has_delivery(pid):
            return False
        if motif.get("src_role") and not cls.check_entity_role(motif["src_role"], src, tf):
            return False
        if motif.get("dst_role") and not cls.check_entity_role(motif["dst_role"], dst, tf):
            return False
        if motif.get("min_batch") and tf.process_modifies_batch.get(pid, 0) < motif["min_batch"]:
            return False
        return True

    def distill(self, train_scenarios: List[str]) -> List[Dict[str, Any]]:
        """
        根据给定的训练场景列表，真实提取抽象图因果基模。
        在每个折次中，严格仅从给定的训练场景历史数据中提炼。
        """
        if not train_scenarios:
            return list(self.candidate_motifs)

        # 1. 载入所有训练场景的正样本真值与候选池
        train_data = []
        repo_root = Path(__file__).resolve().parents[2]

        for sc in train_scenarios:
            gt_file = repo_root / "groundtruth" / f"{sc}.groundtruth.json"
            if not gt_file.exists():
                continue
            with open(gt_file, "r", encoding="utf-8") as f:
                gt = json.load(f)
            pos_triples = set()
            for ph in gt.get("attack_path", []):
                for e in ph.get("edges", []) or []:
                    pos_triples.add((e.get("src"), e.get("syscall"), e.get("dst")))

            # 读取候选边全集（优先读历史基线，兜底自主展开闭包）
            cands = []
            cand_file = repo_root / "output" / "router-baseline" / "rules" / f"{sc}.json"
            if not cand_file.exists():
                cand_file = repo_root / "tmp" / "provenance_router_runs" / f"rules_{sc}.json"
            if cand_file.exists():
                with open(cand_file, "r", encoding="utf-8") as f:
                    rep = json.load(f)
                cands = rep.get("edges", []) + rep.get("unexcluded", [])

            if not cands:
                # 若无文件则即时从 Neo4j 展开闭包
                from prouter.layers.l1_reach import extract_raw_closure
                cands, _ = extract_raw_closure(sc)

            tf = TopologyFacts(cands)
            train_data.append({"scenario": sc, "pos": pos_triples, "cands": cands, "tf": tf})

        if not train_data:
            return list(self.candidate_motifs)

        # 2. 遍历候选基模，计算双向支持度与特异度得分
        distilled_motifs = []
        for motif in self.candidate_motifs:
            tot_pos = 0
            tot_neg = 0
            sc_hits = 0

            for item in train_data:
                pos = item["pos"]
                cands = item["cands"]
                tf = item["tf"]
                p_hit = 0
                n_hit = 0

                for e in cands:
                    if self.match_motif(motif, e, tf):
                        k = (e.get("src"), e.get("syscall"), e.get("dst"))
                        if k in pos:
                            p_hit += 1
                        else:
                            n_hit += 1

                if p_hit > 0:
                    sc_hits += 1
                tot_pos += p_hit
                tot_neg += n_hit

            precision = tot_pos / (tot_pos + tot_neg) if (tot_pos + tot_neg) > 0 else 0.0

            # 3. 双向剪枝门限：正样本有命中，且查准率 >= 10%（或背景误报小于等于 30 条）
            if tot_pos >= 1 and (precision >= 0.10 or tot_neg <= 30):
                distilled = dict(motif)
                distilled["train_support_scenarios"] = sc_hits
                distilled["train_positive_hits"] = tot_pos
                distilled["train_negative_alarms"] = tot_neg
                distilled["train_precision"] = precision
                distilled_motifs.append(distilled)

        return distilled_motifs
