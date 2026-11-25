"""研究点二零查库事件加载器：直接读取研究点一阶段 7 导出的 *.events.json.gz。"""
from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import json
from pathlib import Path
from typing import Any, Optional

SUPPORTED_EVENTS_FORMAT_VERSION = 1


@dataclass(frozen=True)
class RawEvent:
    """单条完整原始审计事件（已附带研究点一聚合判定标签）。"""

    id: str
    event_id: int
    rel: str
    rel_full: str
    action: str
    syscall: str
    start_ns: Optional[int]
    end_ns: Optional[int]
    result: Optional[int]
    bytes: int
    effect: str
    src_kind: str
    src_key: str
    src_host: str
    src_file_type: Optional[str]
    dst_kind: str
    dst_key: str
    dst_host: str
    dst_file_type: Optional[str]
    agg_edge_index: int
    report_status: str
    verdict: str
    verdict_reason: str
    origin: str
    edge_class: str
    reason: str
    bundle_triple: tuple[str, str, str]
    dist: int = 0
    via_kind: str = ""
    via_key: str = ""
    support: int = 0
    llm_verdict: str = ""
    decision_source: str = ""
    llm_bundle_id: str = ""
    llm_bundle_level: Optional[int] = None
    llm_bundle_size: Optional[int] = None
    rag_rules: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    memberships: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def src_entity_id(self) -> str:
        return f"{self.src_kind}:{self.src_key}"

    @property
    def dst_entity_id(self) -> str:
        return f"{self.dst_kind}:{self.dst_key}"


@dataclass(frozen=True)
class EntityAttr:
    """按实体主键去重后的顶点静态属性。"""

    entity_id: str
    kind: str
    key: str
    content: str
    host_id: str = ""
    container_id: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    name: str = ""
    exe_path: str = ""
    cmdline: str = ""
    uid: Optional[int] = None
    euid: Optional[int] = None
    file_type: Optional[str] = None
    protocol: str = ""
    container_privileged: Optional[bool] = None
    container_host_root_rw: Optional[bool] = None


@dataclass(frozen=True)
class ScenarioEvents:
    """单个场景的事件级只读数据集（由研究点一伴生事件文件直接加载，零数据库查询）。"""

    scenario: str
    database: str
    poi_events: tuple[str, ...]
    events: tuple[RawEvent, ...]
    entities: dict[str, EntityAttr]
    stats: dict[str, Any]

    def entity_of(self, kind: str, key: str) -> Optional[EntityAttr]:
        return self.entities.get(f"{kind}:{key}")


def _read_json_payload(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"事件明细文件不存在：{path}")
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_event(item: dict[str, Any]) -> RawEvent:
    triple_raw = item.get("bundle_triple") or ["", "", ""]
    if len(triple_raw) != 3:
        raise ValueError(f"事件 {item.get('id')!r} 的 bundle_triple 长度不为 3：{triple_raw!r}")
    start_ns = item.get("start_ns")
    end_ns = item.get("end_ns")
    if start_ns is not None and end_ns is None:
        end_ns = start_ns
    return RawEvent(
        id=str(item["id"]),
        event_id=int(item["event_id"]),
        rel=str(item["rel"]),
        rel_full=str(item["rel_full"]),
        action=str(item.get("action") or ""),
        syscall=str(item.get("syscall") or ""),
        start_ns=int(start_ns) if start_ns is not None else None,
        end_ns=int(end_ns) if end_ns is not None else None,
        result=int(item["result"]) if item.get("result") is not None else None,
        bytes=int(item.get("bytes") or 0),
        effect=str(item.get("effect") or ""),
        src_kind=str(item["src_kind"]),
        src_key=str(item["src_key"]),
        src_host=str(item.get("src_host") or ""),
        src_file_type=item.get("src_file_type"),
        dst_kind=str(item["dst_kind"]),
        dst_key=str(item["dst_key"]),
        dst_host=str(item.get("dst_host") or ""),
        dst_file_type=item.get("dst_file_type"),
        agg_edge_index=int(item["agg_edge_index"]),
        report_status=str(item["report_status"]),
        verdict=str(item.get("verdict") or ""),
        verdict_reason=str(item.get("verdict_reason") or ""),
        origin=str(item.get("origin") or ""),
        edge_class=str(item.get("class") or ""),
        reason=str(item.get("reason") or ""),
        bundle_triple=(str(triple_raw[0]), str(triple_raw[1]), str(triple_raw[2])),
        dist=int(item.get("dist") or 0),
        via_kind=str(item.get("via_kind") or ""),
        via_key=str(item.get("via_key") or ""),
        support=int(item.get("support") or 0),
        llm_verdict=str(item.get("llm_verdict") or item.get("verdict") or ""),
        decision_source=str(item.get("decision_source") or ""),
        llm_bundle_id=str(item.get("llm_bundle_id") or ""),
        llm_bundle_level=(int(item["llm_bundle_level"]) if item.get("llm_bundle_level") is not None else None),
        llm_bundle_size=(int(item["llm_bundle_size"]) if item.get("llm_bundle_size") is not None else None),
        rag_rules=tuple(dict(r) for r in (item.get("rag_rules") or ())),
        memberships=tuple(dict(m) for m in (item.get("memberships") or ())),
    )


def _parse_entity(entity_id: str, item: dict[str, Any]) -> EntityAttr:
    return EntityAttr(
        entity_id=entity_id,
        kind=str(item["kind"]),
        key=str(item["key"]),
        content=str(item.get("content") or item["key"]),
        host_id=str(item.get("host_id") or ""),
        container_id=str(item.get("container_id") or ""),
        pid=int(item["pid"]) if item.get("pid") is not None else None,
        ppid=int(item["ppid"]) if item.get("ppid") is not None else None,
        name=str(item.get("name") or ""),
        exe_path=str(item.get("exepath") or item.get("exe_path") or ""),
        cmdline=str(item.get("args") or item.get("cmdline") or ""),
        uid=int(item["uid"]) if item.get("uid") is not None else None,
        euid=int(item["euid"]) if item.get("euid") is not None else None,
        file_type=item.get("file_type"),
        protocol=str(item.get("protocol") or item.get("proto") or ""),
        container_privileged=item.get("container_privileged"),
        container_host_root_rw=item.get("container_host_root_rw"),
    )


def load_scenario_events(
    path: str | Path,
    *,
    require_v2_database: bool = True,
) -> ScenarioEvents:
    """加载并校验研究点一导出的事件级明细文件（*.events.json.gz）。"""
    payload = _read_json_payload(Path(path))
    fmt = int(payload.get("format_version") or 0)
    if fmt != SUPPORTED_EVENTS_FORMAT_VERSION:
        raise ValueError(f"不支持的事件明细格式版本：{fmt}（期望 {SUPPORTED_EVENTS_FORMAT_VERSION}）")
    scenario = str(payload.get("scenario") or "").strip()
    database = str(payload.get("database") or "").strip()
    if not scenario:
        raise ValueError("事件明细文件缺少 scenario 字段")
    if require_v2_database and not database.endswith("-v2"):
        raise ValueError(f"仅允许加载标准 -v2 图数据库导出的事件明细，当前为：{database!r}")

    raw_events = [_parse_event(item) for item in (payload.get("events") or ())]
    entities = {
        str(eid): _parse_entity(str(eid), item)
        for eid, item in (payload.get("entities") or {}).items()
    }
    poi_events = tuple(str(x) for x in (payload.get("poi_events") or ()))

    event_ids = {ev.id for ev in raw_events}
    missing_pois = [pid for pid in poi_events if pid not in event_ids]
    if missing_pois:
        raise ValueError(f"事件明细文件中缺少告警终点事件：{missing_pois}")

    for ev in raw_events:
        if ev.src_entity_id not in entities:
            raise ValueError(f"事件 {ev.id} 的源实体 {ev.src_entity_id} 在 entities 表中缺失")
        if ev.dst_entity_id not in entities:
            raise ValueError(f"事件 {ev.id} 的目标实体 {ev.dst_entity_id} 在 entities 表中缺失")

    return ScenarioEvents(
        scenario=scenario,
        database=database,
        poi_events=poi_events,
        events=tuple(raw_events),
        entities=entities,
        stats=dict(payload.get("stats") or {}),
    )
