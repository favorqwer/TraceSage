"""验证研究点二里程碑 C：候选入口分类、物理断链连通分量归因与汇总格式化。"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attack_path.dag import build_versioned_dag  # noqa: E402
from attack_path.diagnose import diagnose_scenario, format_diagnosis_table  # noqa: E402
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
        end_ns=start_ns,
        result=32,
        bytes=32,
        effect="success",
        src_kind=src_kind,
        src_key=src_key,
        src_host="h1",
        src_file_type="file" if src_kind == "File" else None,
        dst_kind=dst_kind,
        dst_key=dst_key,
        dst_host="h1",
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


def _mk_entities(
    events: list[RawEvent],
    *,
    containers: dict[str, str] | None = None,
) -> dict[str, EntityAttr]:
    containers = containers or {}
    ents: dict[str, EntityAttr] = {}
    for ev in events:
        for kind, key, ftype in (
            (ev.src_kind, ev.src_key, ev.src_file_type),
            (ev.dst_kind, ev.dst_key, ev.dst_file_type),
        ):
            eid = f"{kind}:{key}"
            if eid not in ents:
                ents[eid] = EntityAttr(
                    entity_id=eid,
                    kind=kind,
                    key=key,
                    content=key,
                    host_id="h1",
                    container_id=containers.get(key, "host"),
                    exe_path=key if kind == "Process" else "",
                    file_type=ftype,
                )
    return ents


class TestDiagnose(unittest.TestCase):
    def test_entry_categories_and_three_disconnected_causes(self) -> None:
        evs = [
            # 主链（可达 poi）：外网入站 + 静态脚本 -> p_web -> p_sh -> poi
            _mk_event(1, "n2p", "recv", "Network", "10.0.0.9:50000->10.0.0.1:80", "Process", "p_web", 100),
            _mk_event(2, "f2p", "read", "File", "/var/www/index.php", "Process", "p_web", 110),
            _mk_event(3, "p2p", "exec", "Process", "p_web", "Process", "p_sh", 120),
            _mk_event(4, "p2f", "write", "Process", "p_sh", "File", "/srv/poi.txt", 200),
            # 断链类型 1：独立扫描连接（早于 poi，同宿主机，与 poi 物理断开）
            _mk_event(5, "n2p", "recv", "Network", "10.0.0.9:44444->10.0.0.1:22", "Process", "p_sshd", 50),
            # 断链类型 2：跨容器隔离事件（container_id = "ctr_abc"，与 host 上的 poi 隔离）
            _mk_event(6, "p2f", "write", "Process", "p_ctr", "File", "ctr_abc|/tmp/esc.sh", 80),
            # 断链类型 3：poi 之后的旁支清理命令（晚于 poi）
            _mk_event(7, "p2f", "write", "Process", "p_sh", "File", "/tmp/cleanup.log", 300),
        ]
        sc = ScenarioEvents(
            scenario="test_diag",
            database="attack-test-v2",
            poi_events=("ProcessToFile:4:write",),
            events=tuple(evs),
            entities=_mk_entities(evs, containers={"p_ctr": "ctr_abc", "ctr_abc|/tmp/esc.sh": "ctr_abc"}),
            stats={},
        )
        pre = preprocess_scenario(sc)
        dag = build_versioned_dag(pre)
        diag = diagnose_scenario(pre, dag, build_seconds=0.01)

        # 入口应识别出 1 个 external_network 与 1 个 static_file
        self.assertEqual(diag.entry_category_counts["external_network"], 1)
        self.assertEqual(diag.entry_category_counts["static_file"], 1)
        self.assertEqual(diag.confirmed_total_cleaned, 7)
        self.assertEqual(diag.confirmed_in_dag, 4)
        self.assertEqual(diag.confirmed_unreachable, 3)

        causes = {c.likely_cause for c in diag.disconnected_components}
        self.assertEqual(
            causes,
            {"disconnected_session_or_side_branch", "cross_container_boundary", "post_poi"},
        )
        table = format_diagnosis_table([diag])
        self.assertIn("test_diag", table)
        self.assertIn("4/7", table)


if __name__ == "__main__":
    unittest.main()
