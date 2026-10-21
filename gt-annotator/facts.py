"""Pure graph facts: schema constants, vertex keys, 4-tuples, time, evidence."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
from typing import Any

from common import fail

REL_TYPES = (
    "ProcessToProcess",
    "ProcessToFile",
    "FileToProcess",
    "ProcessToNetwork",
    "NetworkToProcess",
)

PROCESS_REQUIRED = {"host_id", "container_id", "pid", "start_ns"}
PROCESS_OPTIONAL = {
    "exe_path", "cmdline", "ppid", "uid", "euid",
    "container_privileged", "container_host_root_rw",
}
FILE_REQUIRED = {"host_id", "container_id", "path", "file_type"}
NETWORK_REQUIRED = {"host_id", "endpoints"}
NETWORK_OPTIONAL = {"proto"}
EDGE_REQUIRED = {"event_id", "action", "start_ns", "end_ns", "syscall"}
EDGE_OPTIONAL = {"result", "payload_b64", "to_path", "mode"}
LEGACY_PROPS = {
    "evt", "ts_ns", "te_ns", "res", "head", "old_path", "kind", "tuple",
    "born_ns", "file_type_old", "from_path", "lip", "lport", "rip", "rport",
    "network_id", "file_id", "process_id", "exepath", "name", "args", "cwd",
}

def _local_tz() -> Any:
    return datetime.now().astimezone().tzinfo

def _iso(ns: Any, *, utc: bool = False) -> str | None:
    if ns is None:
        return None
    try:
        dt = datetime.fromtimestamp(int(ns) / 1_000_000_000,
                                    tz=timezone.utc if utc else _local_tz())
        return dt.isoformat(timespec="microseconds")
    except (TypeError, ValueError, OSError):
        return None

def ns_info(ns: Any) -> dict[str, Any] | None:
    if ns is None:
        return None
    return {"ns": int(ns), "local": _iso(ns), "utc": _iso(ns, utc=True)}

def db_bounds_ns(db: "DB") -> tuple[int, int]:
    rows = db.run("MATCH ()-[r]->() RETURN min(r.start_ns) AS t0, "
                  "max(r.start_ns) AS t1")
    if not rows or rows[0].get("t0") is None:
        fail("库里没有边，无法取时间范围")
    return int(rows[0]["t0"]), int(rows[0]["t1"])

def parse_clock_ns(db: "DB", clock: str, date: str | None = None) -> int:
    text = str(clock).strip()
    parts = text.split(":")
    if len(parts) != 3:
        fail(f"--clock 格式应为 HH:MM:SS[.mmm]，收到 {clock!r}")
    try:
        hour, minute = int(parts[0]), int(parts[1])
        second = float(parts[2])
    except ValueError:
        fail(f"--clock 不是合法时间：{clock!r}")
    t0, t1 = db_bounds_ns(db)
    local_tz = _local_tz()
    if date:
        try:
            day = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            fail(f"--date 格式应为 YYYY-MM-DD，收到 {date!r}")
    else:
        d0 = datetime.fromtimestamp(t0 / 1e9, tz=local_tz).date()
        d1 = datetime.fromtimestamp(t1 / 1e9, tz=local_tz).date()
        if d0 != d1:
            fail(f"库跨天（{d0} ~ {d1}），请给 --date YYYY-MM-DD")
        day = d0
    base = datetime(day.year, day.month, day.day, hour, minute,
                    tzinfo=local_tz)
    dt = base + timedelta(seconds=second)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt.astimezone(timezone.utc) - epoch
    return ((delta.days * 86400 + delta.seconds) * 1_000_000_000
            + delta.microseconds * 1000)

def resolve_time_args(db: "DB", args: argparse.Namespace) -> None:
    for side in ("from", "to"):
        clock = getattr(args, f"{side}_clock", None)
        ns = getattr(args, f"{side}_ns", None)
        if not clock:
            continue
        if ns is not None:
            fail(f"--{side}-clock 与 --{side}-ns 不能同时用")
        setattr(args, f"{side}_ns",
                parse_clock_ns(db, clock, getattr(args, "clock_date", None)))

def effect_of(result: Any) -> str:
    if result is None:
        return "success"
    try:
        return "failure" if int(result) < 0 else "success"
    except (TypeError, ValueError):
        return "success"

def label_of(node: Any) -> str:
    labels = set(node.labels)
    for label in ("Process", "File", "Network"):
        if label in labels:
            return label
    return "Unknown"

def node_key(node: Any) -> str:
    props = dict(node)
    label = label_of(node)
    if label == "Process":
        exe = props.get("exe_path") or "<NA>"
        return f"p:{props.get('host_id')}/{props.get('container_id')}:{exe}"
    if label == "File":
        return f"f:{props.get('host_id')}/{props.get('container_id')}:{props.get('path')}"
    if label == "Network":
        return f"n:{props.get('host_id')}:{props.get('endpoints')}"
    return f"?:{props}"

def process_instance_key(node: Any) -> str:
    props = dict(node)
    return (f"p:{props.get('host_id')}/{props.get('container_id')}:"
            f"{props.get('pid')}@{props.get('start_ns')}")

def endpoint_key(node: Any) -> str:
    return process_instance_key(node) if label_of(node) == "Process" else node_key(node)

def exact_node_key(node: Any) -> str:
    return endpoint_key(node)

def node_context(node: Any) -> dict[str, Any]:
    props = dict(node)
    label = label_of(node)
    out: dict[str, Any] = {"label": label}
    if label == "Process":
        for key in ("exe_path", "cmdline", "ppid", "uid", "euid",
                    "container_privileged", "container_host_root_rw"):
            if key in props:
                out[key] = props[key]
    elif label == "File":
        out["path"] = props.get("path")
        out["file_type"] = props.get("file_type")
    elif label == "Network":
        out["endpoints"] = props.get("endpoints")
        out["proto"] = props.get("proto")
    return out

def rule_node_context(node: Any) -> dict[str, Any]:
    """Minimal endpoint context used by rule predicates."""
    props = dict(node)
    label = label_of(node)
    if label == "Process":
        return {"label": label, "exe_path": props.get("exe_path") or "<NA>"}
    if label == "File":
        return {"label": label, "path": props.get("path")}
    if label == "Network":
        return {"label": label, "endpoints": props.get("endpoints")}
    return {"label": label}


def decode_payload(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        raw = base64.b64decode(str(value), validate=False)
    except Exception:
        return {"bytes": None, "text": str(value)[:200]}
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / max(1, len(raw))
    if ratio >= 0.85:
        return {"bytes": len(raw), "text": raw.decode("utf-8", "replace")[:200]}
    return {"bytes": len(raw), "hex": raw[:64].hex()}

def edge_key_of(rel_type: str, edge: Any) -> str:
    props = dict(edge)
    return f"{rel_type}:{props.get('event_id')}:{props.get('action')}"

def edge_row(rec: dict[str, Any], *, include_context: bool = True,
             rule_context: bool = False) -> dict[str, Any]:
    rel_type = str(rec["rel_type"])
    edge = rec["edge"]
    src = rec["src"]
    dst = rec["dst"]
    props = dict(edge)
    action = str(props.get("action") or "")
    result = props.get("result")
    src_key = node_key(src)
    dst_key = node_key(dst)
    fact = {
        "src": src_key,
        "action": action,
        "dst": dst_key,
        "effect": effect_of(result),
        "syscall": props.get("syscall"),
    }
    evidence: dict[str, Any] = {
        "event_id": props.get("event_id"),
        "start_ns": props.get("start_ns"),
        "end_ns": props.get("end_ns"),
        "syscall": props.get("syscall"),
        "result": result,
    }
    for prefix, node in (("src", src), ("dst", dst)):
        label = label_of(node)
        nprops = dict(node)
        if label == "Process":
            evidence[f"{prefix}_pid"] = nprops.get("pid")
            evidence[f"{prefix}_start_ns"] = nprops.get("start_ns")
        elif label == "File":
            evidence[f"{prefix}_path"] = nprops.get("path")
        elif label == "Network":
            evidence[f"{prefix}_endpoints"] = nprops.get("endpoints")
    row: dict[str, Any] = {
        "edge_key": edge_key_of(rel_type, edge),
        "edge_type": rel_type,
        "fact": fact,
        "evidence": evidence,
    }
    ctx: dict[str, Any] = {}
    if include_context:
        if rule_context:
            ctx["src"] = rule_node_context(src)
            ctx["dst"] = rule_node_context(dst)
        else:
            ctx["src"] = node_context(src)
            ctx["dst"] = node_context(dst)
            payload = decode_payload(props.get("payload_b64"))
            if payload:
                ctx["payload"] = payload
            if props.get("to_path"):
                ctx["to_path"] = props.get("to_path")
            if props.get("mode"):
                ctx["mode"] = props.get("mode")
        row["context"] = ctx
    return row

def parse_edge_key(value: str) -> tuple[str, int, str]:
    parts = str(value).split(":", 2)
    if len(parts) != 3:
        fail(f"edge_key 格式应为 关系:event_id:action，收到 {value!r}")
    rel, event, action = parts
    if rel not in REL_TYPES:
        fail(f"未知关系类型 {rel!r}；可选 {REL_TYPES}")
    try:
        event_id = int(event)
    except ValueError:
        fail(f"event_id 不是整数：{event!r}")
    return rel, event_id, action

def try_fetch_edge(db: "DB", edge_key: str) -> dict[str, Any] | None:
    rel, event_id, action = parse_edge_key(edge_key)
    rows = db.run(
        f"MATCH (a)-[r:{rel} {{event_id: $event_id, action: $action}}]->(b) "
        "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst LIMIT 2",
        event_id=event_id, action=action,
    )
    return rows[0] if len(rows) == 1 else None

def fetch_edge(db: "DB", edge_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    rel, event_id, action = parse_edge_key(edge_key)
    rows = db.run(
        f"MATCH (a)-[r:{rel} {{event_id: $event_id, action: $action}}]->(b) "
        "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst LIMIT 2",
        event_id=event_id, action=action,
    )
    if not rows:
        fail(f"图上没有这条边：{edge_key}")
    if len(rows) > 1:
        fail(f"edge_key 不唯一（{len(rows)} 条）：{edge_key}")
    return rows[0], edge_row(rows[0])

def process_summary(node: Any) -> dict[str, Any]:
    props = dict(node)
    return {
        "key": process_instance_key(node),
        "program_key": node_key(node),
        "label": "Process",
        "pid": props.get("pid"),
        "start_ns": props.get("start_ns"),
        "exe_path": props.get("exe_path"),
        "cmdline": props.get("cmdline"),
    }

def rel_summary(rel_type: str, rel: Any, src: Any, dst: Any) -> dict[str, Any]:
    props = dict(rel)
    return {
        "edge_key": edge_key_of(rel_type, rel),
        "action": props.get("action"),
        "start_ns": props.get("start_ns"),
        "src": endpoint_key(src),
        "dst": endpoint_key(dst),
    }

def parse_vertex_key(key: Any) -> dict[str, Any]:
    if not isinstance(key, str) or len(key) < 3:
        fail(f"顶点 key 不合法：{key!r}")
    kind, rest = key.split(":", 1)
    if kind == "p":
        scope, content = rest.split(":", 1)
        host, container = scope.split("/", 1)
        return {"kind": "Process", "host_id": host, "container_id": container,
                "exe_path": None if content == "<NA>" else content}
    if kind == "f":
        scope, path = rest.split(":", 1)
        host, container = scope.split("/", 1)
        return {"kind": "File", "host_id": host, "container_id": container,
                "path": path}
    if kind == "n":
        host, endpoints = rest.split(":", 1)
        return {"kind": "Network", "host_id": host, "endpoints": endpoints}
    fail(f"未知顶点类型 {kind!r}；只支持 p:/f:/n:")

def vertex_match(alias: str, key: str) -> tuple[str, str, dict[str, Any]]:
    vertex = parse_vertex_key(key)
    if vertex["kind"] == "Process":
        pattern = (f"({alias}:Process {{host_id: ${alias}_h, "
                   f"container_id: ${alias}_c}})")
        params = {f"{alias}_h": vertex["host_id"],
                  f"{alias}_c": vertex["container_id"]}
        if vertex["exe_path"] is None:
            where = f"coalesce({alias}.exe_path, '') = ''"
        else:
            params[f"{alias}_e"] = vertex["exe_path"]
            where = f"{alias}.exe_path = ${alias}_e"
        return pattern, where, params
    if vertex["kind"] == "File":
        pattern = (f"({alias}:File {{host_id: ${alias}_h, "
                   f"container_id: ${alias}_c, path: ${alias}_q}})")
        return pattern, "", {f"{alias}_h": vertex["host_id"],
                             f"{alias}_c": vertex["container_id"],
                             f"{alias}_q": vertex["path"]}
    pattern = f"({alias}:Network {{host_id: ${alias}_h, endpoints: ${alias}_q}})"
    return pattern, "", {f"{alias}_h": vertex["host_id"],
                         f"{alias}_q": vertex["endpoints"]}

def node_match(alias: str, node: Any) -> tuple[str, dict[str, Any]]:
    props = dict(node)
    label = label_of(node)
    if label == "Process":
        return (f"({alias}:Process {{host_id: ${alias}_h, container_id: ${alias}_c, "
                f"pid: ${alias}_p, start_ns: ${alias}_s}})",
                {f"{alias}_h": props.get("host_id"), f"{alias}_c": props.get("container_id"),
                 f"{alias}_p": props.get("pid"), f"{alias}_s": props.get("start_ns")})
    if label == "File":
        return (f"({alias}:File {{host_id: ${alias}_h, container_id: ${alias}_c, "
                f"path: ${alias}_q}})",
                {f"{alias}_h": props.get("host_id"), f"{alias}_c": props.get("container_id"),
                 f"{alias}_q": props.get("path")})
    if label == "Network":
        return (f"({alias}:Network {{host_id: ${alias}_h, endpoints: ${alias}_q}})",
                {f"{alias}_h": props.get("host_id"), f"{alias}_q": props.get("endpoints")})
    fail(f"无法识别端点标签：{label}")

def path_nodes(path: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = [process_summary(n) if label_of(n) == "Process" else {
        "key": node_key(n), "label": label_of(n), **node_context(n)
    } for n in path.nodes]
    edges: list[dict[str, Any]] = []
    rels = list(path.relationships)
    pnodes = list(path.nodes)
    for i, rel in enumerate(rels):
        if i + 1 >= len(pnodes):
            break
        true_src = getattr(rel, "start_node", pnodes[i])
        true_dst = getattr(rel, "end_node", pnodes[i + 1])
        ed = rel_summary(rel.type, rel, true_src, true_dst)
        ed["traversal"] = {
            "from": endpoint_key(pnodes[i]),
            "to": endpoint_key(pnodes[i + 1]),
            "direction": "forward" if pnodes[i] == true_src else "reverse",
        }
        edges.append(ed)
    return nodes, edges
