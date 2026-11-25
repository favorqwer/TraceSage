"""验证研究点二里程碑 A：无效事件清洗、路径规约、外网拆向与 poi 反向线性裁剪。"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attack_path.loader import EntityAttr, RawEvent, ScenarioEvents  # noqa: E402
from attack_path.preprocess import (  # noqa: E402
    canonicalize_file_key,
    is_loopback_network_key,
    preprocess_scenario,
)


def _mk_event(
    eid: int,
    rel: str,
    action: str,
    src_kind: str,
    src_key: str,
    dst_kind: str,
    dst_key: str,
    start_ns: int | None,
    *,
    end_ns: int | None = None,
    result: int | None = 16,
    host: str = "h1",
    report_status: str = "confirmed",
) -> RawEvent:
    rel_full_map = {
        "p2p": "ProcessToProcess",
        "p2f": "ProcessToFile",
        "f2p": "FileToProcess",
        "p2n": "ProcessToNetwork",
        "n2p": "NetworkToProcess",
    }
    rel_full = rel_full_map[rel]
    return RawEvent(
        id=f"{rel_full}:{eid}:{action}",
        event_id=eid,
        rel=rel,
        rel_full=rel_full,
        action=action,
        syscall=action,
        start_ns=start_ns,
        end_ns=start_ns if end_ns is None else end_ns,
        result=result,
        bytes=max(0, result) if isinstance(result, int) else 0,
        effect="success",
        src_kind=src_kind,
        src_key=src_key,
        src_host=host,
        src_file_type="file" if src_kind == "File" else None,
        dst_kind=dst_kind,
        dst_key=dst_key,
        dst_host=host,
        dst_file_type="file" if dst_kind == "File" else None,
        agg_edge_index=0,
        report_status=report_status,
        verdict="all",
        verdict_reason="test",
        origin="confirmed",
        edge_class="test",
        reason="test",
        bundle_triple=("p", action, "o"),
    )


def _mk_scenario(events: list[RawEvent], poi_ids: list[str]) -> ScenarioEvents:
    entities: dict[str, EntityAttr] = {}
    for ev in events:
        for kind, key, host, ftype in (
            (ev.src_kind, ev.src_key, ev.src_host, ev.src_file_type),
            (ev.dst_kind, ev.dst_key, ev.dst_host, ev.dst_file_type),
        ):
            eid = f"{kind}:{key}"
            if eid not in entities:
                entities[eid] = EntityAttr(
                    entity_id=eid, kind=kind, key=key, content=key, host_id=host, file_type=ftype
                )
    return ScenarioEvents(
        scenario="test_scenario",
        database="attack-test-v2",
        poi_events=tuple(poi_ids),
        events=tuple(events),
        entities=entities,
        stats={},
    )


class TestPreprocessAndPrune(unittest.TestCase):
    def test_canonicalize_file_key_preserves_container_and_special_prefixes(self) -> None:
        self.assertEqual(canonicalize_file_key("/var//www/./html/../shell.php"), "/var/www/shell.php")
        self.assertEqual(canonicalize_file_key("f8734eba|/proc/self/../self/maps"), "f8734eba|/proc/self/maps")
        self.assertEqual(canonicalize_file_key("pipe:[22156]"), "pipe:[22156]")
        self.assertEqual(canonicalize_file_key("unix:/run/php.sock"), "unix:/run/php.sock")

    def test_loopback_detection(self) -> None:
        self.assertTrue(is_loopback_network_key("127.0.0.1:45120->127.0.0.1:9000"))
        self.assertTrue(is_loopback_network_key("[::1]:45120->[::1]:9000"))
        self.assertFalse(is_loopback_network_key("100.74.213.15:59360->100.86.108.4:22"))

    def test_filter_invalid_events_and_backward_prune_side_branches(self) -> None:
        evs = [
            _mk_event(1, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_web", 100),
            # 失败读，应被过滤
            _mk_event(2, "f2p", "read", "File", "/etc/shadow", "Process", "p_web", 110, result=-13),
            # 0 字节读，应被过滤
            _mk_event(3, "f2p", "read", "File", "/tmp/empty", "Process", "p_web", 120, result=0),
            # 进程退出，应被过滤
            _mk_event(4, "p2p", "exit", "Process", "p_old", "Process", "p_web", 125, result=0),
            # 合法因果链
            _mk_event(5, "p2f", "write", "Process", "p_web", "File", "/var/www//shell.php", 130),
            _mk_event(6, "f2p", "read", "File", "/var/www/shell.php", "Process", "p_web", 140),
            _mk_event(7, "p2p", "exec", "Process", "p_web", "Process", "p_sh", 150, result=0),
            # 旁支命令（无法到达 poi）
            _mk_event(8, "p2p", "exec", "Process", "p_sh", "Process", "p_whoami", 160, result=0),
            # poi 之后的事件（无法到达 poi）
            _mk_event(10, "p2f", "write", "Process", "p_sh", "File", "/tmp/after.txt", 300),
            # 告警终点 poi
            _mk_event(9, "p2f", "write", "Process", "p_sh", "File", "/srv/data/README.txt", 200),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:9:write"])
        out = preprocess_scenario(sc)

        kept_ids = {e.event_id for e in out.events}
        self.assertEqual(kept_ids, {1, 5, 6, 7, 9})
        self.assertEqual(out.stats.dropped_failed, 1)
        self.assertEqual(out.stats.dropped_zero_read, 1)
        self.assertEqual(out.stats.dropped_termination, 1)
        self.assertEqual(out.stats.normalized_file_refs, 1)
        self.assertEqual(out.stats.dropped_unreachable_from_poi, 2)
        # 外网入站应拆成 NetworkIn
        ev1 = next(e for e in out.events if e.event_id == 1)
        self.assertEqual(ev1.src_kind, "NetworkIn")

    def test_external_network_split_blocks_self_loopback_while_keeping_local_loopback(self) -> None:
        evs = [
            # 外部发包不经外网回连本机收包
            _mk_event(1, "p2f", "write", "Process", "p_noise", "File", "/tmp/noise", 10),
            _mk_event(2, "p2n", "send", "Process", "p_web", "Network", "10.0.0.9:50000->10.0.0.1:80", 20),
            _mk_event(3, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_web", 30),
            # 本机回环通信应保持连通
            _mk_event(4, "p2n", "send", "Process", "p_web", "Network", "127.0.0.1:40000->127.0.0.1:9000", 40),
            _mk_event(5, "n2p", "recv", "Network", "127.0.0.1:40000->127.0.0.1:9000", "Process", "p_php", 50),
            _mk_event(6, "p2f", "write", "Process", "p_php", "File", "/srv/ransom.txt", 60),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:6:write"])
        out = preprocess_scenario(sc)
        kept_ids = {e.event_id for e in out.events}
        # 2(外网 send) 指向 NetworkOut，不会被 3(外网 recv 从 NetworkIn) 拉入；4/5(回环) 完整连通
        self.assertEqual(kept_ids, {3, 4, 5, 6})

    def test_stateless_hub_blocks_cross_process_chaining(self) -> None:
        evs = [
            _mk_event(1, "p2f", "write", "Process", "p_unrelated", "File", "/dev/null", 10),
            _mk_event(2, "f2p", "read", "File", "/dev/null", "Process", "p_att", 20),
            _mk_event(3, "p2f", "write", "Process", "p_att", "File", "/srv/ransom.txt", 30),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:3:write"])
        out = preprocess_scenario(sc)
        kept_ids = {e.event_id for e in out.events}
        self.assertEqual(kept_ids, {3})
        self.assertIn("File:/dev/null", out.blocked_hub_entity_ids)

    def test_unlink_truncates_old_writes_only_when_recreated(self) -> None:
        # 场景 A：旧写入 -> unlink -> 重建写入 -> 读取 -> poi（旧写入应被截断）
        evs_recreate = [
            _mk_event(1, "p2f", "write", "Process", "p_old", "File", "/tmp/a.sh", 10),
            _mk_event(2, "p2f", "unlink", "Process", "p_old", "File", "/tmp/a.sh", 20, result=0),
            _mk_event(3, "p2f", "create", "Process", "p_new", "File", "/tmp/a.sh", 30, result=0),
            _mk_event(4, "p2f", "write", "Process", "p_new", "File", "/tmp/a.sh", 35),
            _mk_event(5, "f2p", "read", "File", "/tmp/a.sh", "Process", "p_sh", 40),
            _mk_event(6, "p2f", "write", "Process", "p_sh", "File", "/srv/poi.txt", 50),
        ]
        out_a = preprocess_scenario(_mk_scenario(evs_recreate, ["ProcessToFile:6:write"]))
        self.assertEqual({e.event_id for e in out_a.events}, {3, 4, 5, 6})
        self.assertGreaterEqual(out_a.stats.unlink_truncations, 1)

        # 场景 B：旧写入 -> unlink -> 无重建直接通过已开句柄读取 -> poi（旧写入应保留）
        evs_open_fd = [
            _mk_event(1, "p2f", "write", "Process", "p_old", "File", "/tmp/b.sh", 10),
            _mk_event(2, "p2f", "unlink", "Process", "p_old", "File", "/tmp/b.sh", 20, result=0),
            _mk_event(3, "f2p", "read", "File", "/tmp/b.sh", "Process", "p_sh", 30),
            _mk_event(4, "p2f", "write", "Process", "p_sh", "File", "/srv/poi.txt", 40),
        ]
        out_b = preprocess_scenario(_mk_scenario(evs_open_fd, ["ProcessToFile:4:write"]))
        self.assertEqual({e.event_id for e in out_b.events}, {1, 3, 4})

    def test_chroot_alias_resolution_without_corrupting_preopened_log(self) -> None:
        evs = [
            _mk_event(1, "p2f", "chroot", "Process", "p_ftp", "File", "/srv/www/uploads", 10, result=0),
            # 模拟 chroot 后的监禁路径 /cache.php，同场景存在 /srv/www/uploads/cache.php
            _mk_event(2, "p2f", "write", "Process", "p_ftp", "File", "/cache.php", 20),
            # chroot 前已打开的日志文件，不应被误加前缀
            _mk_event(3, "p2f", "write", "Process", "p_ftp", "File", "/var/log/vsftpd.log", 25),
            # Web 服务按宿主机绝对路径读取
            _mk_event(4, "f2p", "read", "File", "/srv/www/uploads/cache.php", "Process", "p_php", 30),
            _mk_event(5, "p2f", "write", "Process", "p_php", "File", "/srv/poi.txt", 40),
        ]
        out = preprocess_scenario(_mk_scenario(evs, ["ProcessToFile:5:write"]))
        kept_ids = {e.event_id for e in out.events}
        self.assertEqual(kept_ids, {2, 4, 5})
        self.assertEqual(out.stats.chroot_aliases_resolved, 1)
        ev2 = next(e for e in out.events if e.event_id == 2)
        self.assertEqual(ev2.dst_key, "/srv/www/uploads/cache.php")
        ev3 = next(e for e in out.cleaned_events if e.event_id == 3)
        self.assertEqual(ev3.dst_key, "/var/log/vsftpd.log")

    def test_nonblocking_connect_einprogress_is_preserved_while_real_failure_dropped(self) -> None:
        evs = [
            _mk_event(1, "p2p", "exec", "Process", "p_sh", "Process", "p_curl", 10, result=0),
            # 非阻塞 connect 返回 -115 (-EINPROGRESS)：应保留在 cleaned_events 中
            _mk_event(2, "p2n", "connect", "Process", "p_curl", "Network", "10.0.0.1:40000->10.0.0.9:80", 20, result=-115),
            # 真正连接拒绝 -111 (-ECONNREFUSED)：应被过滤
            _mk_event(3, "p2n", "connect", "Process", "p_curl", "Network", "10.0.0.1:40001->10.0.0.9:81", 25, result=-111),
            _mk_event(4, "p2n", "send", "Process", "p_curl", "Network", "10.0.0.1:40000->10.0.0.9:80", 30, result=64),
        ]
        out = preprocess_scenario(_mk_scenario(evs, ["ProcessToNetwork:4:send"]))
        cleaned_ids = {e.event_id for e in out.cleaned_events}
        self.assertIn(2, cleaned_ids)
        self.assertNotIn(3, cleaned_ids)
        self.assertEqual(out.stats.dropped_failed, 1)


if __name__ == "__main__":
    unittest.main()
