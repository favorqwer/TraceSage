"""验证研究点二里程碑 B：实体版本有向无环图（去环、合并、成对双边、守护进程切分与 0 环校验）。"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attack_path.dag import DAGBuildConfig, build_versioned_dag  # noqa: E402
from attack_path.loader import EntityAttr, RawEvent, ScenarioEvents  # noqa: E402
from attack_path.preprocess import preprocess_scenario  # noqa: E402


def _mk_event(
    eid: int,
    rel: str,
    action: str,
    src_kind: str,
    src_key: str,
    dst_kind: str,
    dst_key: str,
    start_ns: int,
    *,
    end_ns: int | None = None,
    result: int | None = 32,
    host: str = "h1",
    report_status: str = "confirmed",
) -> RawEvent:
    rel_full = {
        "p2p": "ProcessToProcess",
        "p2f": "ProcessToFile",
        "f2p": "FileToProcess",
        "p2n": "ProcessToNetwork",
        "n2p": "NetworkToProcess",
    }[rel]
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


def _mk_scenario(
    events: list[RawEvent],
    poi_ids: list[str],
    *,
    proc_exes: dict[str, str] | None = None,
) -> ScenarioEvents:
    proc_exes = proc_exes or {}
    entities: dict[str, EntityAttr] = {}
    for ev in events:
        for kind, key, host, ftype in (
            (ev.src_kind, ev.src_key, ev.src_host, ev.src_file_type),
            (ev.dst_kind, ev.dst_key, ev.dst_host, ev.dst_file_type),
        ):
            eid = f"{kind}:{key}"
            if eid not in entities:
                exe = proc_exes.get(key, "") if kind == "Process" else ""
                entities[eid] = EntityAttr(
                    entity_id=eid,
                    kind=kind,
                    key=key,
                    content=exe or key,
                    host_id=host,
                    exe_path=exe,
                    file_type=ftype,
                )
    return ScenarioEvents(
        scenario="test_dag",
        database="attack-test-v2",
        poi_events=tuple(poi_ids),
        events=tuple(events),
        entities=entities,
        stats={},
    )


class TestVersionedDAG(unittest.TestCase):
    def test_bidirectional_file_cycle_eliminated_and_consecutive_writes_merged(self) -> None:
        # 复现典型双向环 + 连续重复写入：
        # php-fpm 接收攻击包 -> 连续 5 次 write shell.php -> read shell.php -> exec sh -> write poi
        evs = [
            _mk_event(1, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_php", 100),
            _mk_event(2, "p2f", "create", "Process", "p_php", "File", "/var/www/shell.php", 110, result=0),
            _mk_event(3, "p2f", "write", "Process", "p_php", "File", "/var/www/shell.php", 111),
            _mk_event(4, "p2f", "write", "Process", "p_php", "File", "/var/www/shell.php", 112),
            _mk_event(5, "p2f", "write", "Process", "p_php", "File", "/var/www/shell.php", 113),
            _mk_event(6, "f2p", "read", "File", "/var/www/shell.php", "Process", "p_php", 120),
            _mk_event(7, "p2p", "exec", "Process", "p_php", "Process", "p_sh", 130, result=0),
            _mk_event(8, "p2f", "write", "Process", "p_sh", "File", "/srv/ransom.txt", 140),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:8:write"], proc_exes={"p_php": "/usr/sbin/php-fpm8.1", "p_sh": "/bin/sh"})
        pre = preprocess_scenario(sc)
        dag = build_versioned_dag(pre)

        self.assertTrue(dag.stats.is_acyclic)
        # php-fpm 在 write 之后又 read，应分裂出 @v0 和 @v1 两个版本，消除环
        php_versions = sorted(n.version for n in dag.nodes.values() if n.entity_id == "Process:p_php")
        self.assertEqual(php_versions, [0, 1])
        # create + 3 次 write 落在同一对 (p_php@v0, shell.php@v0) 上，自动合并为 1 条逻辑边
        write_edges = [
            e for e in dag.edges.values()
            if e.edge_kind == "op" and e.src_node_id == "Process:p_php@v0" and e.dst_node_id == "File:/var/www/shell.php@v0"
        ]
        self.assertEqual(len(write_edges), 1)
        self.assertEqual(write_edges[0].event_count, 4)
        self.assertEqual(set(write_edges[0].actions), {"create", "write"})
        self.assertEqual(dag.stats.companion_edges_merged, 1)
        # 唯一候选入口应为外部入站网络
        self.assertEqual(dag.candidate_entry_ids, ("NetworkIn:10.0.0.9:50000->10.0.0.1:80@v0",))

    def test_406_consecutive_sendto_folds_to_single_poi_edge(self) -> None:
        evs = [_mk_event(1, "p2p", "exec", "Process", "p_sh", "Process", "p_curl", 100, result=0)]
        poi_ids: list[str] = []
        for i in range(406):
            ev = _mk_event(
                100 + i, "p2n", "send", "Process", "p_curl", "Network", "10.0.0.9:443->10.0.0.1:50000", 200 + i
            )
            evs.append(ev)
            poi_ids.append(ev.id)
        sc = _mk_scenario(evs, poi_ids)
        dag = build_versioned_dag(preprocess_scenario(sc))

        self.assertTrue(dag.stats.is_acyclic)
        self.assertEqual(dag.stats.poi_edges, 1)
        poi_edge = dag.edges[dag.poi_edge_ids[0]]
        self.assertEqual(poi_edge.event_count, 406)
        self.assertEqual(len(poi_edge.raw_event_ids), 406)

    def test_paired_same_event_id_exec_and_rename(self) -> None:
        # 同一 event_id=20 的 rename（f2p + p2f）与同一 event_id=30 的 exec（p2p + f2p）
        evs = [
            _mk_event(10, "p2f", "write", "Process", "p_up", "File", "/tmp/a.tmp", 100),
            # 故意把 p2f 放在 f2p 前面，验证排序规则仍能保证 OldFile -> p_up -> NewFile
            _mk_event(20, "p2f", "rename", "Process", "p_up", "File", "/tmp/run.sh", 200, result=0),
            _mk_event(20, "f2p", "rename", "File", "/tmp/a.tmp", "Process", "p_up", 200, result=0),
            _mk_event(30, "p2p", "exec", "Process", "p_up", "Process", "p_run", 300, result=0),
            _mk_event(30, "f2p", "exec", "File", "/tmp/run.sh", "Process", "p_run", 300, result=0),
            _mk_event(40, "p2f", "write", "Process", "p_run", "File", "/srv/poi.txt", 400),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:40:write"])
        dag = build_versioned_dag(preprocess_scenario(sc))

        self.assertTrue(dag.stats.is_acyclic)
        # 两条 exec 边都汇合到同一个 Process:p_run@v0
        exec_edges = [e for e in dag.edges.values() if e.primary_action == "exec"]
        self.assertEqual(len(exec_edges), 2)
        self.assertEqual({e.dst_node_id for e in exec_edges}, {"Process:p_run@v0"})
        self.assertTrue(all(30 in e.paired_kernel_event_ids for e in exec_edges))
        # rename 形成无环链且保留原文件写入源头
        rename_edges = [e for e in dag.edges.values() if e.primary_action == "rename"]
        self.assertEqual(len(rename_edges), 2)
        self.assertTrue(all(20 in e.paired_kernel_event_ids for e in rename_edges))

    def test_companion_accept_and_recv_merge_without_arbitrary_time_cutoff(self) -> None:
        sec = 1_000_000_000
        evs = [
            _mk_event(1, "n2p", "accept", "Network", "10.0.0.9:50001->10.0.0.1:80", "Process", "p_nginx", 10 * sec, result=0),
            _mk_event(2, "n2p", "recv", "Network", "10.0.0.9:50001->10.0.0.1:80", "Process", "p_nginx", 10 * sec + 100),
            # 隔 120 秒后的后续落盘操作仍应保持连通，不因固定时间窗被切断
            _mk_event(3, "p2f", "write", "Process", "p_nginx", "File", "/srv/poi.txt", 130 * sec),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:3:write"], proc_exes={"p_nginx": "/usr/sbin/nginx"})
        dag = build_versioned_dag(preprocess_scenario(sc))

        self.assertTrue(dag.stats.is_acyclic)
        self.assertEqual(dag.candidate_entry_ids, ("NetworkIn:10.0.0.9:50001->10.0.0.1:80@v0",))
        recv_edges = [e for e in dag.edges.values() if e.rel == "n2p"]
        self.assertEqual(len(recv_edges), 1)
        self.assertEqual(set(recv_edges[0].actions), {"accept", "recv"})

    def test_file_truncate_breaks_old_content_carry(self) -> None:
        evs = [
            _mk_event(1, "p2f", "write", "Process", "p_benign", "File", "/tmp/data.txt", 10),
            _mk_event(2, "p2f", "truncate", "Process", "p_att", "File", "/tmp/data.txt", 20, result=0),
            _mk_event(3, "p2f", "write", "Process", "p_att", "File", "/tmp/data.txt", 25),
            _mk_event(4, "f2p", "read", "File", "/tmp/data.txt", "Process", "p_reader", 30),
            _mk_event(5, "p2f", "write", "Process", "p_reader", "File", "/srv/poi.txt", 40),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:5:write"])
        dag = build_versioned_dag(preprocess_scenario(sc))

        self.assertTrue(dag.stats.is_acyclic)
        self.assertEqual(dag.stats.file_carry_breaks, 1)
        # truncate 之前的 p_benign 写入被断开并二次修剪清除
        self.assertNotIn("Process:p_benign@v0", dag.nodes)
        self.assertIn("Process:p_att@v0", dag.nodes)

    def test_streaming_chunk_pipeline_collapses_to_single_version_per_entity(self) -> None:
        # 模拟 tar | gzip | sshd 100 轮分块读写循环
        evs: list[RawEvent] = []
        poi_ids: list[str] = []
        eid = 1
        ts = 1000
        for _ in range(100):
            evs.append(_mk_event(eid, "f2p", "read", "File", "/srv/data.csv", "Process", "p_tar", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "p2f", "write", "Process", "p_tar", "File", "pipe:[1]", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "f2p", "read", "File", "pipe:[1]", "Process", "p_gzip", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "p2f", "write", "Process", "p_gzip", "File", "pipe:[2]", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "f2p", "read", "File", "pipe:[2]", "Process", "p_sshd", ts))
            eid += 1; ts += 10
            send_ev = _mk_event(eid, "p2n", "send", "Process", "p_sshd", "Network", "10.0.0.9:22->10.0.0.1:50000", ts)
            evs.append(send_ev)
            poi_ids.append(send_ev.id)
            eid += 1; ts += 10

        dag = build_versioned_dag(preprocess_scenario(_mk_scenario(evs, poi_ids)))
        self.assertTrue(dag.stats.is_acyclic)
        # 600 条原始分块事件应收缩为 7 个版本节点（每个实体仅 1 版）和 6 条逻辑操作边
        self.assertEqual(dag.stats.version_nodes, 7)
        self.assertEqual(dag.stats.op_edges, 6)
        self.assertEqual(dag.stats.carry_edges, 0)
        self.assertEqual(dag.stats.retained_raw_events, 600)

    def test_bidirectional_unix_socket_pingpong_collapses_without_cycles(self) -> None:
        # 模拟 apache2 <-> mysqld.sock <-> mysqld 100 轮往返查询
        evs: list[RawEvent] = [
            _mk_event(1, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_apache", 10),
        ]
        eid = 2
        ts = 100
        for _ in range(100):
            evs.append(_mk_event(eid, "p2f", "send", "Process", "p_apache", "File", "/var/run/mysqld/mysqld.sock", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "f2p", "recv", "File", "/var/run/mysqld/mysqld.sock", "Process", "p_mysqld", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "p2f", "send", "Process", "p_mysqld", "File", "/var/run/mysqld/mysqld.sock", ts))
            eid += 1; ts += 10
            evs.append(_mk_event(eid, "f2p", "recv", "File", "/var/run/mysqld/mysqld.sock", "Process", "p_apache", ts))
            eid += 1; ts += 10
        poi_ev = _mk_event(eid, "p2n", "send", "Process", "p_apache", "Network", "10.0.0.9:50000->10.0.0.1:80", ts + 10)
        evs.append(poi_ev)

        dag = build_versioned_dag(preprocess_scenario(_mk_scenario(evs, [poi_ev.id])))
        self.assertTrue(dag.stats.is_acyclic)
        # 402 条原始往返事件压缩到不超过 12 个版本节点，且全部 402 条原始事件 100% 保留可回溯
        self.assertLessEqual(dag.stats.version_nodes, 12)
        self.assertEqual(dag.stats.retained_raw_events, 402)
        self.assertEqual(dag.candidate_entry_ids, ("NetworkIn:10.0.0.9:50000->10.0.0.1:80@v0",))

    def test_indirect_new_input_is_never_falsely_folded(self) -> None:
        # 严格防误合并反例：
        # t1: C -> A -> /tmp/shared -> p_early -> poi_early；
        # 随后 t4: Attacker -> C -> A -> /tmp/shared -> p_late -> poi_late。
        # 必须保证 Attacker 能到达 poi_late，同时 /tmp/shared 分裂出 @v1 绝不误折叠回早期 @v0 污染 p_early。
        evs = [
            _mk_event(1, "p2p", "signal", "Process", "p_c", "Process", "p_a", 10),
            _mk_event(2, "p2f", "write", "Process", "p_a", "File", "/tmp/shared", 20),
            _mk_event(3, "f2p", "read", "File", "/tmp/shared", "Process", "p_early", 30),
            _mk_event(9, "p2f", "write", "Process", "p_early", "File", "/srv/poi_early.txt", 35),
            # 新的外部攻击输入进入 p_c，再经 p_a 写入 /tmp/shared，最后被 p_late 读取并触发 poi_late
            _mk_event(4, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_c", 40),
            _mk_event(5, "p2p", "signal", "Process", "p_c", "Process", "p_a", 50),
            _mk_event(6, "p2f", "write", "Process", "p_a", "File", "/tmp/shared", 60),
            _mk_event(7, "f2p", "read", "File", "/tmp/shared", "Process", "p_late", 70),
            _mk_event(8, "p2f", "write", "Process", "p_late", "File", "/srv/poi_late.txt", 80),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:9:write", "ProcessToFile:8:write"])
        dag = build_versioned_dag(preprocess_scenario(sc))
        self.assertTrue(dag.stats.is_acyclic)
        self.assertIn("NetworkIn:10.0.0.9:50000->10.0.0.1:80@v0", dag.candidate_entry_ids)
        # /tmp/shared 必须分裂出至少 2 个版本（@v0 供 p_early，@v1 供 p_late）
        shared_vers = sorted(n.version for n in dag.nodes.values() if n.entity_id == "File:/tmp/shared")
        self.assertGreaterEqual(len(shared_vers), 2)
        # 验证从 Attacker 出发可达 poi_late，且不可达 poi_early（绝无虚假时间倒流污染）
        from collections import deque
        q = deque(["NetworkIn:10.0.0.9:50000->10.0.0.1:80@v0"])
        seen = set(q)
        while q:
            u = q.popleft()
            for eid in dag.out_edges.get(u, ()):
                v = dag.edges[eid].dst_node_id
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        self.assertIn("File:/srv/poi_late.txt@v0", seen)
        self.assertNotIn("File:/srv/poi_early.txt@v0", seen)

    def test_fold_never_orphans_third_party_write_into_new_pipe_version(self) -> None:
        # 复现场景 2 pipe:[224880] 回归用例：
        # p_parent 先 clone p_child（导致 p_child 的传递祖先已包含 p_parent）；
        # t1: pipe@v0 -> p_child (read)
        # t2: p_parent -> pipe@v1 (write，创建 pipe 新版本)
        # t3: pipe@v1 -> p_child (read) -> poi
        # 必须保证 t3 不会误折回 pipe@v0，从而保留 p_parent -> pipe@v1 -> p_child。
        evs = [
            _mk_event(1, "p2p", "clone", "Process", "p_parent", "Process", "p_child", 10, result=None),
            _mk_event(2, "f2p", "read", "File", "pipe:[224880]", "Process", "p_child", 20),
            _mk_event(3, "p2f", "write", "Process", "p_parent", "File", "pipe:[224880]", 30),
            _mk_event(4, "f2p", "read", "File", "pipe:[224880]", "Process", "p_child", 40),
            _mk_event(5, "f2p", "read", "File", "pipe:[224880]", "Process", "p_child", 50),
            _mk_event(6, "p2f", "write", "Process", "p_child", "File", "/srv/poi.txt", 60),
        ]
        sc = _mk_scenario(evs, ["ProcessToFile:6:write"])
        dag = build_versioned_dag(preprocess_scenario(sc))

        self.assertTrue(dag.stats.is_acyclic)
        all_raw_ids = {rid for e in dag.edges.values() for rid in e.raw_event_ids}
        self.assertIn("ProcessToFile:3:write", all_raw_ids)
        # t4 与 t5 两次连续读应落在 pipe@v1 -> p_child@v0 上并合并为 1 条边
        v1_reads = [
            e for e in dag.edges.values()
            if e.edge_kind == "op" and e.src_node_id == "File:pipe:[224880]@v1" and e.dst_node_id == "Process:p_child@v0"
        ]
        self.assertEqual(len(v1_reads), 1)
        self.assertEqual(v1_reads[0].event_count, 2)

    def test_third_party_input_prevents_pingpong_back_fold_and_keeps_pingpong_events_on_peer_poi(self) -> None:
        # 场景 A：A@v0 -> B@v0 -> C@v0 -> poi_c；B@v0 -> A@v1；第三方 X -> B@v1；A@v1 -> B -> poi_b
        # 必须保证 A@v1 -> B 不误折回 A@v0 -> B@v0，保留 B@v0 -> A@v1 -> B@v1 -> poi_b
        evs_a = [
            _mk_event(1, "p2f", "write", "Process", "p_a", "File", "/tmp/b", 10),
            _mk_event(2, "f2p", "read", "File", "/tmp/b", "Process", "p_c", 20),
            _mk_event(3, "p2f", "write", "Process", "p_c", "File", "/srv/poi_c.txt", 22),
            _mk_event(4, "f2p", "read", "File", "/tmp/b", "Process", "p_a", 25),
            _mk_event(5, "p2f", "write", "Process", "p_x", "File", "/tmp/b", 30),
            _mk_event(6, "p2f", "write", "Process", "p_a", "File", "/tmp/b", 40),
            _mk_event(7, "f2p", "read", "File", "/tmp/b", "Process", "p_out", 50),
            _mk_event(8, "p2f", "write", "Process", "p_out", "File", "/srv/poi_b.txt", 60),
        ]
        dag_a = build_versioned_dag(preprocess_scenario(
            _mk_scenario(evs_a, ["ProcessToFile:3:write", "ProcessToFile:8:write"])
        ))
        self.assertTrue(dag_a.stats.is_acyclic)
        self.assertEqual(dag_a.stats.retained_raw_events, 8)
        self.assertIn("Process:p_a@v1", dag_a.nodes)
        self.assertTrue(any(
            e.edge_kind == "op" and e.src_node_id == "Process:p_a@v1" and e.dst_node_id == "File:/tmp/b@v1"
            for e in dag_a.edges.values()
        ))

        # 场景 B：apache <-> mysqld.sock <-> mysqld 多轮往返后，poi 落在 mysqld 外联而非 apache
        # 二次反向修剪不得因 apache@v1 被折叠而误删 sock@v1 -> apache@v1 事件
        evs_b: list[RawEvent] = [
            _mk_event(1, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_apache", 10),
        ]
        eid = 2
        ts = 100
        for _ in range(10):
            evs_b.append(_mk_event(eid, "p2f", "send", "Process", "p_apache", "File", "/var/run/mysqld/mysqld.sock", ts))
            eid += 1; ts += 10
            evs_b.append(_mk_event(eid, "f2p", "recv", "File", "/var/run/mysqld/mysqld.sock", "Process", "p_mysqld", ts))
            eid += 1; ts += 10
            evs_b.append(_mk_event(eid, "p2f", "send", "Process", "p_mysqld", "File", "/var/run/mysqld/mysqld.sock", ts))
            eid += 1; ts += 10
            evs_b.append(_mk_event(eid, "f2p", "recv", "File", "/var/run/mysqld/mysqld.sock", "Process", "p_apache", ts))
            eid += 1; ts += 10
        poi_ev = _mk_event(eid, "p2n", "send", "Process", "p_mysqld", "Network", "10.0.0.9:3306->10.0.0.1:50000", ts + 10)
        evs_b.append(poi_ev)
        pre_b = preprocess_scenario(_mk_scenario(evs_b, [poi_ev.id]))
        dag_b = build_versioned_dag(pre_b)
        self.assertTrue(dag_b.stats.is_acyclic)
        self.assertEqual(pre_b.stats.pruned_events, len(evs_b) - 2)
        self.assertEqual(dag_b.stats.retained_raw_events, pre_b.stats.pruned_events)
        self.assertIn("Process:p_apache@v1", dag_b.nodes)


if __name__ == "__main__":
    unittest.main()
