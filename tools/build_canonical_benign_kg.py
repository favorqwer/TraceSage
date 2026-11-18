#!/usr/bin/env python3
"""
build_canonical_benign_kg.py
TraceSage 层次化良性基模知识库构建与语义蒸馏引擎
将细粒度拓扑变体归纳为高内聚、抗过度泛化的经典业务基模（Canonical Motifs）
"""

import os
import json
import time
from collections import defaultdict
from typing import Dict, List, Any

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

ARCHETYPE_ANCHORS = {
    "ARCH_WEB_DYNAMIC": ["P.WEB_SERVER", "P.INTERPRETER"],
    "ARCH_WEB_STATIC": ["P.WEB_SERVER"],
    "ARCH_ADMIN_SSH_INSPECT": ["P.ADMIN_SERVICE"],
    "ARCH_ADMIN_SCP_BACKUP": ["P.ADMIN_SERVICE", "P.TRANSFER_SERVICE"],
    "ARCH_DB_MARIADB_TX": ["P.DATABASE_ENGINE", "P.DATABASE_CLIENT"],
    "ARCH_DB_POSTGRES_MAINT": ["P.DATABASE_ENGINE", "P.DATABASE_CLIENT"],
    "ARCH_CACHE_REDIS_LIFECYCLE": ["P.DATABASE_ENGINE", "P.DATABASE_CLIENT"],
    "ARCH_CONTAINER_MICRO_TASK": ["P.CONTAINER_ENGINE"],
    "ARCH_BUILD_GCC_TOOLCHAIN": ["P.BUILD_TOOL"],
    "ARCH_FILE_FTP_ARCHIVE": ["P.TRANSFER_SERVICE"],
    "ARCH_MAIL_POSTFIX_ALERT": ["P.MAIL_SERVICE"],
    "ARCH_DNS_SYSTEM_QUERY": ["N.OUTBOUND_DNS", "P.DNS_RESOLVER"]
}

# 12 大经典良性业务范式定义
CANONICAL_ARCHETYPES = {
    "ARCH_WEB_DYNAMIC": {
        "title": "Web 动态业务请求与 FastCGI 协同处理",
        "category": "WEB_APPLICATION_DYNAMIC",
        "description": "外部 HTTP 客户端通过端口 80/8080 请求 Web 服务，Web 容器通过 UNIX 域套接字或内部 IPC 调度动态脚本解释器（PHP-FPM/Python），执行业务逻辑并读写临时会话及应用日志。",
        "condition": "网络入站目标端口为 80/8080；IPC 通道属于合法本地 socket；会话文件操作限定于 /var/lib/php/sessions 或 /tmp。",
        "risk_boundary": "禁止解释器派生具有交互式特权的 shell（如 bash/sh 执行未知命令）或向网站根目录写入可执行脚本。",
        "forbidden_roles": ["P.INTERACTIVE_SHELL", "F.AUTH_KEY"]
    },
    "ARCH_WEB_STATIC": {
        "title": "Web 静态资源请求分发与访问审计",
        "category": "WEB_APPLICATION_STATIC",
        "description": "Web 服务守护进程接收客户端 HTTP 请求，以只读方式映射读取 /var/www/ 下的静态资源与图片文件，并向 /var/log/nginx/access.log 顺序追加访问日志。",
        "condition": "文件访问仅限合法网站文档目录；操作模式严格为只读（read/mmap_read）及日志文件追加（write）。",
        "risk_boundary": "禁止 Web 服务向 Web 目录执行写/创建/重命名操作。",
        "forbidden_roles": ["P.INTERACTIVE_SHELL", "F.AUTH_KEY"]
    },
    "ARCH_ADMIN_SSH_INSPECT": {
        "title": "合法管理员 SSH 远程运维与系统巡检",
        "category": "ADMIN_REMOTE_MAINTENANCE",
        "description": "已登记的管理员工作站通过 22 端口建立 SSH 认证连接，派生无特权或受控 Shell，执行系统健康指标采样（uptime/free/vmstat/df）。",
        "condition": "来源必须为合法管理连接；执行命令限定于无害只读监控工具链；会话退出时正常清理子进程。",
        "risk_boundary": "禁止私钥凭据窃取与管道数据外传。",
        "forbidden_roles": ["F.AUTH_KEY.READ", "F.AUTH_KEY.WRITE"]
    },
    "ARCH_ADMIN_SCP_BACKUP": {
        "title": "跨主机自动化日志增量归档与同步",
        "category": "ADMIN_REMOTE_BACKUP",
        "description": "管理员控制端通过 SSH 会话派生 scp/rsync 子进程，对受害者机 /var/log/ 下的应用审计日志进行只读读取并通过加密网络流传回控制端。",
        "condition": "目标文件为已存在的系统或服务日志文件；传输动作为只读（read），无任何本地文件篡改。",
        "risk_boundary": "禁止利用 scp/sftp 替换系统二进制库或上传未知脚本。",
        "forbidden_roles": ["F.AUTH_KEY.READ"]
    },
    "ARCH_DB_MARIADB_TX": {
        "title": "关系数据库 MariaDB 事务增删改查与重做日志",
        "category": "DATABASE_TRANSACTION_WAL",
        "description": "业务进程通过本地套接字连接 MariaDB，执行具有事务一致性保证的批量业务表写入（INSERT/UPDATE）与带索引查询，并将事务记录落地至 ibdata1 与 redo log。",
        "condition": "操作集中于授权业务库；通信通过本地 mysqld.sock；严格遵循事务生命周期（START TRANSACTION -> COMMIT）。",
        "risk_boundary": "禁止执行未授权的 DROP DATABASE、高危 UDF 扩展加载或 into outfile 导出。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_DB_POSTGRES_MAINT": {
        "title": "PostgreSQL 企业级数据库审计写入与 pg_dump 备份",
        "category": "DATABASE_MAINTENANCE_BACKUP",
        "description": "PostgreSQL 引擎写入系统审计记录，后台 worker 定期执行 VACUUM ANALYZE 空间整理，并由合法作业调度 pg_dump 导出逻辑备份至指定归档路径后安全清理。",
        "condition": "运行身份为 postgres 或授权系统角色；备份目标限定于 /tmp 或专用备份存储目录。",
        "risk_boundary": "禁止通过 COPY ... TO PROGRAM 执行系统任意命令。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_CACHE_REDIS_LIFECYCLE": {
        "title": "Redis 高速缓存键值操作与 BGSAVE 内存快照持久化",
        "category": "CACHE_LIFECYCLE_PERSISTENCE",
        "description": "Redis 响应本地回环客户端高频键值与数据结构读写，维持 TTL 自动过期机制，并定期 fork 子进程执行 BGSAVE 将内存镜像原子刷盘至 dump.rdb。",
        "condition": "连接源限于 127.0.0.1 回环接口；磁盘写入严格限制为 /var/lib/redis/dump.rdb 文件。",
        "risk_boundary": "严禁未授权外部裸奔端口访问、严禁通过 CONFIG SET 更改 dbfilename 覆盖系统敏感文件。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_CONTAINER_MICRO_TASK": {
        "title": "Docker/Containerd 微容器计算生命周期与卷挂载",
        "category": "CONTAINER_MICRO_TASK",
        "description": "容器守护进程（dockerd/containerd）配置独立命名空间，拉起无特权容器（如 Alpine），挂载宿主特定数据目录执行数值计算或排序过滤，任务完成后正常回收。",
        "condition": "容器以非特权模式运行（container_privileged=false）；挂载路径仅限指定数据卷；镜像来源可信。",
        "risk_boundary": "严禁特权容器（--privileged）、严禁挂载宿主机根目录（/）或 /proc、严禁利用 cgroups 进行逃逸。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_BUILD_GCC_TOOLCHAIN": {
        "title": "GCC 软件工程多模块编译与二进制构建",
        "category": "SOFTWARE_BUILD_PIPELINE",
        "description": "编译工具链（gcc/cc1/as/ld）顺序读取项目源码与标准系统头文件，编译生成中间对象文件并链接输出 ELF 本地二进制工具，随后由受控上下文执行验证。",
        "condition": "输入输出严格限定于工程构建工作区（如 /tmp/c_build_ws）；无任何未经允许的外联网络套接字。",
        "risk_boundary": "严禁在临时目录直接编译并加载 rootkit 内核模块或隐藏注入共享库。",
        "forbidden_roles": ["F.AUTH_KEY", "N.REMOTE_SSH"]
    },
    "ARCH_FILE_FTP_ARCHIVE": {
        "title": "vsftpd 业务数据交换、校验与安全归档",
        "category": "FILE_EXCHANGE_ARCHIVE",
        "description": "文件传输服务（vsftpd）处理合法客户端上传的报表或文档，由本地排程调用 md5sum 进行完整性校验，确认无误后通过 rename 安全转移至归档目录。",
        "condition": "上传路径受限于隔离目录（/srv/ftp/incoming/）；文件类型为合规文档格式，不具备执行权限（非 ELF/可执行脚本）。",
        "risk_boundary": "严禁向 Web 可访问的脚本目录上传 PHP/JSP 等 WebShell 文件。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_MAIL_POSTFIX_ALERT": {
        "title": "Postfix 本地系统健康监控告警邮件派发",
        "category": "MAIL_LOCAL_DELIVERY",
        "description": "系统监控工具调用 sendmail 生成系统运行状态报告，Postfix master 守护进程调度 qmgr 和 local 模块将邮件投递至本地用户邮箱（/var/mail/）。",
        "condition": "投递目标为本地账户（@localhost）；使用合规标准协议，不充当未授权的开放邮件中继。",
        "risk_boundary": "严禁向外部未知地址进行高频垃圾邮件滥发。",
        "forbidden_roles": ["F.AUTH_KEY"]
    },
    "ARCH_DNS_SYSTEM_QUERY": {
        "title": "系统解析器正向与 DNSSEC 域名合规解析",
        "category": "DNS_RESOLUTION_QUERY",
        "description": "系统客户端或本地 DNS 解析器向 127.0.0.1 或公共合规 DNS 发送 UDP 53 查询数据报文，接收正向解析与 DNSSEC 安全校验记录。",
        "condition": "目标端口为 53；报文交互符合标准 DNS 规范；解析频次处于合规区间。",
        "risk_boundary": "严禁通过异常大体积 TXT 记录或极高频异常子域名构建 DNS 隧道隐蔽通道。",
        "forbidden_roles": ["F.AUTH_KEY"]
    }
}

class CanonicalKGBuilder:
    def __init__(self, raw_motifs_path: str, out_kg_path: str):
        self.raw_motifs_path = raw_motifs_path
        self.out_kg_path = out_kg_path

    def build(self):
        log(f"加载细粒度基模库: {self.raw_motifs_path}")
        with open(self.raw_motifs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw_motifs = data["motifs"]
        log(f"共加载 {len(raw_motifs)} 个原始基模")

        # 映射细粒度基模到 12 大经典业务范式
        archetype_map = defaultdict(list)
        unmapped = []

        for m in raw_motifs:
            cat = m["category"]
            anchor = m["anchor_role"]
            exe = m["representative_exe"].lower()

            mapped_arch = None
            if "WEB_APPLICATION_DYNAMIC" in cat or ("WEB_SERVER" in anchor and any("INTERPRETER" in r for r in m["roles"])):
                mapped_arch = "ARCH_WEB_DYNAMIC"
            elif "WEB_APPLICATION_STATIC" in cat or "nginx" in exe:
                mapped_arch = "ARCH_WEB_STATIC"
            elif "ADMIN_REMOTE" in cat or "REMOTE_SSH" in cat or "sshd" in exe or any("REMOTE_SSH" in r or "ADMIN_REMOTE" in r for r in m["roles"]):
                if any("scp" in r.lower() or "scp" in exe for r in m["roles"]) or "scp" in exe:
                    mapped_arch = "ARCH_ADMIN_SCP_BACKUP"
                else:
                    mapped_arch = "ARCH_ADMIN_SSH_INSPECT"
            elif "redis" in exe or "CACHE" in cat:
                mapped_arch = "ARCH_CACHE_REDIS_LIFECYCLE"
            elif "mariadb" in exe or "mysql" in exe:
                mapped_arch = "ARCH_DB_MARIADB_TX"
            elif "postgres" in exe or "DATABASE_TRANSACTION" in cat:
                mapped_arch = "ARCH_DB_POSTGRES_MAINT"
            elif "CONTAINER" in cat or "docker" in exe or "containerd" in exe:
                mapped_arch = "ARCH_CONTAINER_MICRO_TASK"
            elif "BUILD" in cat or "gcc" in exe or "as" in exe or "ld" in exe:
                mapped_arch = "ARCH_BUILD_GCC_TOOLCHAIN"
            elif "ftp" in exe or "md5sum" in exe:
                mapped_arch = "ARCH_FILE_FTP_ARCHIVE"
            elif "postfix" in exe or "sendmail" in exe:
                mapped_arch = "ARCH_MAIL_POSTFIX_ALERT"
            elif "dig" in exe or "named" in exe or "DNS" in cat:
                mapped_arch = "ARCH_DNS_SYSTEM_QUERY"
            else:
                unmapped.append(m)

            if mapped_arch:
                archetype_map[mapped_arch].append(m)

        log(f"已成功将细粒度基模映射至 12 大经典范式: 覆盖 {len(raw_motifs) - len(unmapped)} 个基模，未单独归类常规操作系统调用 {len(unmapped)} 个")

        # 构建最终规范化知识库
        canonical_entries = []
        for arch_id, defn in CANONICAL_ARCHETYPES.items():
            instances = archetype_map.get(arch_id, [])
            total_support = sum(m["support_instances"] for m in instances)

            # 聚合代表性跳链并应用锚点向心纯度过滤
            anchors = ARCHETYPE_ANCHORS.get(arch_id, [])
            all_hops = set()
            all_roles = set()
            for m in instances:
                for h in m.get("hop_chains", []):
                    if "--(" in h and ")-->" in h:
                        parts = h.split(" --(")
                        src = parts[0].strip()
                        rest = parts[1].split(")--> ")
                        dst = rest[1].strip()
                        # 锚点向心纯度约束：跳链两端必须至少有一端直连该范式的核心锚点实体
                        if any(anc in src or anc in dst for anc in anchors):
                            all_hops.add(h)
                            all_roles.add(src)
                            all_roles.add(dst)

            # 选取高频因果跳（Top-15）
            sorted_hops = sorted(list(all_hops))[:15]

            canonical_entries.append({
                "archetype_id": arch_id,
                "title": defn["title"],
                "category": defn["category"],
                "description": defn["description"],
                "precondition": defn["condition"],
                "security_boundary": defn["risk_boundary"],
                "forbidden_roles": defn.get("forbidden_roles", []),
                "total_support_frequency": total_support,
                "variant_patterns_count": len(instances),
                "core_roles": sorted(list(all_roles)),
                "canonical_hop_chains": sorted_hops,
                "representative_variants": [
                    {
                        "motif_id": m["motif_id"],
                        "exe": m["representative_exe"],
                        "support": m["support_instances"],
                        "edges": m["edges"]
                    } for m in instances[:5]
                ]
            })

        # 输出知识库
        final_kg = {
            "metadata": {
                "title": "TraceSage Canonical Benign Subgraph Knowledge Base",
                "version": "2.0.0",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_canonical_archetypes": len(canonical_entries),
                "total_subgraph_variants": len(raw_motifs) - len(unmapped),
                "total_support_events_analyzed": sum(m["support_instances"] for m in raw_motifs)
            },
            "canonical_motifs": canonical_entries
        }

        os.makedirs(os.path.dirname(self.out_kg_path), exist_ok=True)
        with open(self.out_kg_path, "w", encoding="utf-8") as f:
            json.dump(final_kg, f, indent=2, ensure_ascii=False)
        log(f"经典良性基模知识库保存成功 -> {self.out_kg_path}")

        # 生成精炼交付说明文档
        md_path = os.path.join(os.path.dirname(self.out_kg_path), "CANONICAL_BENIGN_KG.md")
        self._write_markdown_summary(final_kg, md_path)
        log(f"交付文档保存成功 -> {md_path}")

    def _write_markdown_summary(self, kg: Dict, md_path: str):
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# TraceSage 经典良性因果子图基模知识库 (Canonical Benign KG)\n\n")
            f.write(f"- 版本：`{kg['metadata']['version']}`\n")
            f.write(f"- 生成时间：`{kg['metadata']['created_at']}`\n")
            f.write(f"- 经典业务范式：`{kg['metadata']['total_canonical_archetypes']}` 大类\n")
            f.write(f"- 聚合细粒度子图变体：`{kg['metadata']['total_subgraph_variants']}` 个\n\n")
            f.write("## 12 大经典业务基模全景\n\n")

            f.write("| 范式编号 | 业务范式名称 | 核心业务类别 | 涵盖子图变体 | 累计支持频次 |\n")
            f.write("|---|---|---|---|---|\n")
            for c in kg["canonical_motifs"]:
                f.write(f"| **{c['archetype_id']}** | {c['title']} | `{c['category']}` | {c['variant_patterns_count']} 个 | {c['total_support_frequency']} 次 |\n")
            f.write("\n---\n\n")

            f.write("## 范式详解与因果安全边界\n\n")
            for c in kg["canonical_motifs"]:
                f.write(f"### [{c['archetype_id']}] {c['title']}\n\n")
                f.write(f"* **行为语义描述**：{c['description']}\n")
                f.write(f"* **适用判定前提**：`{c['precondition']}`\n")
                f.write(f"* **安全判决红线**（防过度泛化）：`{c['security_boundary']}`\n")
                f.write(f"* **基模涵盖核心角色**：`{', '.join(c['core_roles'][:8])}`\n")
                f.write("* **标准因果跳链（Canonical Hop Chains）**：\n")
                for h in c["canonical_hop_chains"]:
                    f.write(f"  - `{h}`\n")
                f.write("\n---\n\n")

if __name__ == "__main__":
    src = "output/rule-kg/benign_motifs/benign_motif_library.json"
    dst = "output/rule-kg/canonical_benign_kg.json"
    builder = CanonicalKGBuilder(src, dst)
    builder.build()
