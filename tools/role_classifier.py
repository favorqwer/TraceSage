import re

class RoleClassifier:
    PROCESS_ARCHETYPES = [
        ("WEB_SERVER", re.compile(r"/(nginx|httpd|apache2|tomcat|catalina)")),
        ("INTERPRETER", re.compile(r"/(php-fpm|php\d*|python\d*|perl|ruby)")),
        ("DATABASE_ENGINE", re.compile(r"/(mariadbd|mysqld|postgres|redis-server|mongod)")),
        ("DATABASE_CLIENT", re.compile(r"/(mysql|redis-cli|psql|mongo)\b")),
        ("MAIL_SERVICE", re.compile(r"/(postfix|sendmail|qmgr|pickup|cleanup|master|trivial-rewrite)")),
        ("DNS_RESOLVER", re.compile(r"/(named|dig|systemd-resolved)")),
        ("TRANSFER_SERVICE", re.compile(r"/(vsftpd|rsync|scp|sftp-server)")),
        ("ADMIN_SERVICE", re.compile(r"/(sshd|sudo|systemd|cron|crond|logrotate|rsyslogd)")),
        ("INTERACTIVE_SHELL", re.compile(r"/(bash|sh|zsh|dash)")),
        ("BUILD_TOOL", re.compile(r"/(gcc|cc1|as|ld|collect2|make|cmake|ninja)")),
        ("CONTAINER_ENGINE", re.compile(r"/(dockerd|docker|containerd|containerd-shim|runc)")),
        ("SYSTEM_UTILITY", re.compile(r"/(md5sum|sort|uniq|awk|sed|grep|cat|ls|free|uptime|df|vmstat|tar|gzip|find|cut|stat|date|uname|id|expr)"))
    ]

    FILE_CATEGORIES = [
        ("AUTH_KEY", re.compile(r"/(id_rsa|id_dsa|id_ecdsa|id_ed25519|id_[a-zA-Z0-9_]+|authorized_keys|known_hosts|\.ssh/|shadow)\b")),
        ("CONF", re.compile(r"^/etc/|\.(conf|ini|xml|cnf|yaml|yml)$")),
        ("DB_STORE", re.compile(r"^/(var/lib/(mysql|postgresql|redis)|srv/labdata)")),
        ("APP_LOG", re.compile(r"^/var/log/|\.log$")),
        ("TEMP_SPOOL", re.compile(r"^/(tmp|var/tmp|run|dev/shm)/")),
        ("BIN_LIB", re.compile(r"^/(bin|usr/bin|usr/sbin|sbin|lib|usr/lib|lib64)/|\.(so|so\..*)$")),
        ("USER_DATA", re.compile(r"^/(var/www|srv|home)/")),
        ("SYSTEM_PSEUDO", re.compile(r"^/(proc|sys|dev)/"))
    ]

    @classmethod
    def classify_process(cls, exe_path: str, cmdline: str, uid: str, euid: str, container_id: str) -> str:
        exe = (exe_path or "").lower()
        cmd = (cmdline or "").lower()
        combined = f"{exe} {cmd}"

        archetype = "SYSTEM_UTILITY"
        if not exe and not cmd:
            archetype = "UNKNOWN_PROC"
        else:
            for name, pattern in cls.PROCESS_ARCHETYPES:
                if pattern.search(combined) or pattern.search(exe):
                    archetype = name
                    break
        
        try:
            effective_uid = int(euid) if euid and euid != "<NA>" else (int(uid) if uid and uid != "<NA>" else 0)
        except ValueError:
            effective_uid = 0
        priv = "ROOT" if effective_uid == 0 else "USER"
        scope = "CONTAINER" if (container_id and container_id != "host" and container_id != "<NA>") else "HOST"

        return f"P.{archetype}.{priv}.{scope}"

    @classmethod
    def classify_file(cls, path: str, file_type: str, action: str = "") -> str:
        p = path or ""
        ft = (file_type or "file").lower()

        if ft in ("unix", "pipe", "memfd") or p.endswith(".sock"):
            cat = "IPC_SOCKET"
        else:
            cat = "USER_DATA"
            for name, pattern in cls.FILE_CATEGORIES:
                if pattern.search(p):
                    cat = name
                    break

        act = (action or "").lower()
        if act in ("write", "create", "truncate", "mmap_write", "rename", "chmod", "unlink"):
            access = "WRITE"
        elif act in ("read", "stat", "mmap_read", "mmap_exec", "exec"):
            access = "READ"
        else:
            access = "RW"

        return f"F.{cat}.{access}"

    @classmethod
    def classify_network(cls, endpoints: str, proto: str = "tcp") -> str:
        ep = endpoints or ""
        pr = (proto or "tcp").upper()

        if "127.0.0.1" in ep or "::1" in ep:
            return f"N.LOOPBACK_IPC.{pr}"
        if ":53" in ep:
            return f"N.OUTBOUND_DNS.{pr}"

        # 通用管理端口 (SSH 22)
        if ":22" in ep:
            return f"N.REMOTE_SSH.{pr}"

        # 通用 Web / 数据库标准入站服务端口
        if re.search(r"->.*:(80|8080|3306|5432|6379|21)\b", ep):
            return f"N.INBOUND_SERVICE.{pr}"

        # 客户端对外 HTTP/HTTPS 访问
        if re.search(r":\d+->.*:(80|443)\b", ep):
            return f"N.OUTBOUND_CLIENT.{pr}"

        return f"N.SERVICE_TRAFFIC.{pr}"
