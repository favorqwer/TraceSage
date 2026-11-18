"""公理推断与因果纯化阶段针对多进程隔离与缓存目录写入的单元测试。"""
import pathlib
import sys
import unittest
from typing import Any, Dict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core.axioms import heal_and_purify_causal_closure
from core.stages.s5_causal_heal import run as run_s5_causal_heal


class TestAxiomsAndCausalHeal(unittest.TestCase):
    def test_server_process_network_instance_isolation(self):
        """测试服务进程入站网络公理：只绑定发生突变调用的特定进程实例及其套接字，隔离同程序的其他良性 Worker。"""
        # 初始确诊集合：Nginx Worker 1024 发生了变异（执行了 write 篡改文件）
        mutating_edge: Dict[str, Any] = {
            "src": "/usr/sbin/nginx",
            "syscall": "write",
            "dst": "/var/www/html/shell.php",
            "process_id": "test_host|nginx|1024|1000000000",
            "member_processes": ["test_host|nginx|1024|1000000000"],
            "rels": ["p2f"],
        }
        initial_confirmed = {
            (mutating_edge["src"], mutating_edge["syscall"], mutating_edge["dst"]): mutating_edge
        }

        # 候选未排除集合：
        # 1. 攻击流：Worker 1024 在外部套接字 1.2.3.4:1234->10.0.0.1:80 上的网络读取
        attacker_net_read: Dict[str, Any] = {
            "src": "1.2.3.4:1234->10.0.0.1:80",
            "syscall": "read",
            "dst": "/usr/sbin/nginx",
            "process_id": "test_host|nginx|1024|1000000000",
            "member_processes": ["test_host|nginx|1024|1000000000"],
            "rels": ["n2p"],
        }
        # 2. 攻击流连接建立：Master 进程 PID 1 对该套接字的 accept
        attacker_net_accept: Dict[str, Any] = {
            "src": "1.2.3.4:1234->10.0.0.1:80",
            "syscall": "accept",
            "dst": "/usr/sbin/nginx",
            "process_id": "test_host|nginx|1|0",
            "member_processes": ["test_host|nginx|1|0"],
            "rels": ["n2p"],
        }
        # 3. 良性业务流：未失陷的 Worker 1025 在另一外部套接字 5.6.7.8:5678->10.0.0.1:80 上的正常读取
        benign_net_read: Dict[str, Any] = {
            "src": "5.6.7.8:5678->10.0.0.1:80",
            "syscall": "read",
            "dst": "/usr/sbin/nginx",
            "process_id": "test_host|nginx|1025|1000000000",
            "member_processes": ["test_host|nginx|1025|1000000000"],
            "rels": ["n2p"],
        }
        # 4. 良性业务连接建立：Master 进程 PID 1 对良性套接字的 accept
        benign_net_accept: Dict[str, Any] = {
            "src": "5.6.7.8:5678->10.0.0.1:80",
            "syscall": "accept",
            "dst": "/usr/sbin/nginx",
            "process_id": "test_host|nginx|1|0",
            "member_processes": ["test_host|nginx|1|0"],
            "rels": ["n2p"],
        }

        clean_unexcluded = [
            attacker_net_read,
            attacker_net_accept,
            benign_net_read,
            benign_net_accept,
        ]

        purified, unpromoted = heal_and_purify_causal_closure(
            initial_confirmed=initial_confirmed,
            clean_unexcluded=clean_unexcluded,
            excluded_edges=[],
            anchor_keys=set(),
        )

        purified_keys = set(purified.keys())

        # 验证：攻击者连接的读取和 accept 边被精准提拔
        self.assertIn(
            (attacker_net_read["src"], attacker_net_read["syscall"], attacker_net_read["dst"]),
            purified_keys,
        )
        self.assertIn(
            (attacker_net_accept["src"], attacker_net_accept["syscall"], attacker_net_accept["dst"]),
            purified_keys,
        )

        # 验证：同为 /usr/sbin/nginx 的良性 Worker 1025 会话严格隔离，禁止提拔
        self.assertNotIn(
            (benign_net_read["src"], benign_net_read["syscall"], benign_net_read["dst"]),
            purified_keys,
        )
        self.assertNotIn(
            (benign_net_accept["src"], benign_net_accept["syscall"], benign_net_accept["dst"]),
            purified_keys,
        )

    def test_xdg_cache_write_mutation_preserved(self):
        """测试阶段 5：用户缓存目录发生真实写入变异时保留确认，未写入的纯只读缓存边正常降噪。"""
        # 攻击载荷写操作：向 ~/.cache/evil.sh 写入内容
        evil_cache_write: Dict[str, Any] = {
            "src": "/bin/bash",
            "syscall": "write",
            "dst": "/home/user/.cache/evil.sh",
            "process_id": "host|bash|2000|1",
            "member_processes": ["host|bash|2000|1"],
            "rels": ["p2f"],
            "reason": "攻击脚本写入缓存目录",
        }
        # 攻击载荷读操作：随后执行/读取 ~/.cache/evil.sh
        evil_cache_read: Dict[str, Any] = {
            "src": "/home/user/.cache/evil.sh",
            "syscall": "read",
            "dst": "/bin/bash",
            "process_id": "host|bash|2001|2",
            "member_processes": ["host|bash|2001|2"],
            "rels": ["f2p"],
            "reason": "执行缓存目录载荷",
        }
        # 系统良性只读缓存访问：某进程读取未被写入过的 ~/.cache/gstreamer.bin
        benign_cache_read: Dict[str, Any] = {
            "src": "/home/user/.cache/gstreamer.bin",
            "syscall": "read",
            "dst": "/usr/bin/app",
            "process_id": "host|app|3000|1",
            "member_processes": ["host|app|3000|1"],
            "rels": ["f2p"],
            "reason": "良性应用读取缓存",
        }

        llm_confirmed = [evil_cache_write, evil_cache_read, benign_cache_read]

        purified, unpromoted_llm = run_s5_causal_heal(
            llm_confirmed=llm_confirmed,
            final_confirmed={},
            clean_unexcluded=[],
            excluded_edges=[],
            anchor_keys=set(),
        )

        purified_dsts = {e.get("dst") for e in purified.values()}
        purified_srcs = {e.get("src") for e in purified.values()}

        # 验证：发生过真实写入的 evil.sh 及其写/读边保留在确认结果中
        self.assertIn("/home/user/.cache/evil.sh", purified_dsts | purified_srcs)

        # 验证：从未被写入过的良性 gstreamer.bin 被移入 unpromoted_llm 降噪
        unpromoted_srcs = {e.get("src") for e in unpromoted_llm}
        self.assertIn("/home/user/.cache/gstreamer.bin", unpromoted_srcs)
        self.assertNotIn("/home/user/.cache/gstreamer.bin", purified_srcs)


if __name__ == "__main__":
    unittest.main()
