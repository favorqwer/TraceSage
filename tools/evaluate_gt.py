#!/usr/bin/env python
"""GT (ground truth) 召回/查准评估工具。

用法:
    python tools/evaluate_gt.py output/baseline/<dir>/baseline.json [--window SECONDS]

输入:
    - 仓库根目录 1_Multi_Stage_Data_Exfiltration.groundtruth.json（--gt 可指定其他）
    - BaselineRunner 产出的 baseline.json

匹配口径（与 GT 文件 matching_convention 一致）:
    - 顶点内容: Process=coalesce(exepath,name)，File=path，Network=lip:lport->rip:rport
      （与引擎 EntityNode.signature 的内容段一致，签名形如 "355: /etc/resolv.conf"）
    - 边匹配: (src, syscall, dst) 精确三元组；同类边多实例命中任一即算命中
    - 召回 = 命中 attack_path 的三元组数 / attack_path 三元组数
    - 查准 = 命中三元组数 / 最终图去重后的内容三元组数（多出边一律计假阳）

baseline.json 的 final_edges 键是 "host|srcId|dstId|eventId"（数字 id 空间），
不含 syscall/时间。旧产物经 Neo4j 按 event_id + 端点内容反查补全（连接参数取根 .env）；
新产物若 final_edges 已内嵌 syscall/starttime/endtime 则直接使用，不连库。

--window SECONDS 模拟 POI 锚定时间窗过滤（[poiStart-W, poiEnd+W]，区间重叠语义），
按实例过滤、按内容三元组计分，并输出命中/多出边相对 POI 的时间偏移分布。
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_DEFAULT = ROOT / "1_Multi_Stage_Data_Exfiltration.groundtruth.json"


def load_env(path=ROOT / ".env"):
    env = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    return env


def load_gt(path):
    gt = json.loads(Path(path).read_text(encoding="utf-8"))
    triples = []
    for phase in gt["attack_path"]:
        for edge in phase["edges"]:
            triples.append((edge["src"], edge["syscall"], edge["dst"], phase["phase"]))
    return gt, triples


def signature_content(signature):
    """引擎签名 "154: /usr/bin/nc" -> 内容 "/usr/bin/nc"。"""
    idx = signature.find(": ")
    return signature[idx + 2 :] if idx >= 0 else signature


def parse_edge_key(key):
    # host|srcId|dstId|eventId
    parts = key.split("|")
    if len(parts) != 4:
        raise ValueError(f"unexpected canonical key: {key}")
    return parts[0], int(parts[1]), int(parts[2]), parts[3]


def load_final_graph(baseline_path):
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    id2content = {
        v["id"]: signature_content(v["signature"]) for v in data.get("final_vertices", [])
    }
    id2type = {v["id"]: v.get("entity_type") for v in data.get("final_vertices", [])}
    instances = []
    embedded = True
    for entry in data.get("final_edges", []):
        _, src_id, dst_id, event_id = parse_edge_key(entry["key"])
        if "syscall" not in entry:
            embedded = False
        instances.append(
            {
                "src": id2content.get(src_id, f"<id {src_id}>"),
                "dst": id2content.get(dst_id, f"<id {dst_id}>"),
                "event_id": event_id,
                "syscall": entry.get("syscall"),
                "start": entry.get("starttime"),
                "end": entry.get("endtime"),
                "weight": entry.get("weight"),
            }
        )
    poi = data.get("poi", {})
    meta = data.get("meta", {})
    return instances, poi, meta, embedded, id2type


def fetch_edge_facts():
    """从 Neo4j 拉 (event_id, src 内容, dst 内容) -> (syscall, starttime ns, endtime ns)。"""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        sys.exit("需要 neo4j 驱动（requirements.txt 已含），请使用项目 .venv 运行")
    env = load_env()
    uri = env.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (env.get("NEO4J_USER", "neo4j"), env.get("NEO4J_PASSWORD", ""))
    database = env.get("NEO4J_DATABASE", "neo4j")
    content = (
        "CASE labels(a)[0] "
        "WHEN 'Process' THEN coalesce(a.exepath, a.name) "
        "WHEN 'File' THEN a.path "
        "ELSE a.lip + ':' + a.lport + '->' + a.rip + ':' + a.rport END"
    )
    query = (
        "MATCH (a)-[r]->(b) WHERE r.event_id IS NOT NULL "
        "RETURN r.event_id AS eid, r.syscall AS syscall, r.starttime AS st, r.endtime AS et, "
        f"{content} AS sc, "
        "CASE labels(b)[0] "
        "WHEN 'Process' THEN coalesce(b.exepath, b.name) "
        "WHEN 'File' THEN b.path "
        "ELSE b.lip + ':' + b.lport + '->' + b.rip + ':' + b.rport END AS dc"
    )
    facts = defaultdict(list)
    with GraphDatabase.driver(uri, auth=auth) as driver:
        with driver.session(database=database) as session:
            for record in session.run(query):
                facts[str(record["eid"])].append(
                    (record["sc"], record["dc"], record["syscall"], record["st"], record["et"])
                )
    return facts


def enrich(instances):
    """用 Neo4j 反查补全 syscall 与起止时间（纳秒 -> 秒）。"""
    facts = fetch_edge_facts()
    unmatched = 0
    for inst in instances:
        candidates = facts.get(inst["event_id"], [])
        hit = next(
            (c for c in candidates if c[0] == inst["src"] and c[1] == inst["dst"]), None
        )
        if hit is None:
            unmatched += 1
            continue
        inst["syscall"] = hit[2]
        inst["start"] = None if hit[3] is None else hit[3] / 1e9
        inst["end"] = None if hit[4] is None else hit[4] / 1e9
    return unmatched


def to_triples(instances, window=None, poi=None):
    """实例 -> 去重内容三元组集合。window=(W 秒) 时先按 POI 窗口过滤实例。"""
    kept = instances
    if window is not None:
        assert poi is not None, "window 模拟需要 baseline.json 含 poi 时间"
        lo = poi["start_time"] - window
        hi = poi["end_time"] + window
        kept = []
        for inst in instances:
            if inst["start"] is None or inst["end"] is None:
                kept.append(inst)  # 缺时间的边不静默丢弃
                continue
            if inst["start"] <= hi and inst["end"] >= lo:
                kept.append(inst)
    triples = {}
    for inst in kept:
        key = (inst["src"], inst["syscall"], inst["dst"])
        triples.setdefault(key, inst)
    return triples, kept


def fmt_offset(seconds):
    sign = "+" if seconds >= 0 else "-"
    return f"{sign}{abs(seconds):.3f}s"


def report(title, triples, gt_triples, instances=None, poi=None):
    gt_keys = [(t[0], t[1], t[2]) for t in gt_triples]
    hits = [g for g in gt_triples if (g[0], g[1], g[2]) in triples]
    miss = [g for g in gt_triples if (g[0], g[1], g[2]) not in triples]
    extra = sorted(k for k in triples if k not in set(gt_keys))
    print(f"\n== {title} ==")
    print(
        f"召回 {len(hits)}/{len(gt_triples)} = {len(hits)/len(gt_triples):.1%}   "
        f"查准 {len(hits)}/{len(triples)} = {len(hits)/len(triples):.1%}"
    )
    if miss:
        print("未召回:")
        for src, syscall, dst, phase in miss:
            print(f"  [{phase}] {src} --{syscall}--> {dst}")
    if extra:
        print(f"多出边 ({len(extra)}):")
        for src, syscall, dst in extra:
            line = f"  {src} --{syscall}--> {dst}"
            if instances is not None and poi is not None:
                offs = [
                    fmt_offset((i["start"] + i["end"]) / 2 - poi["start_time"])
                    for i in instances
                    if (i["src"], i["syscall"], i["dst"]) == (src, syscall, dst)
                    and i["start"] is not None
                ]
                if offs:
                    line += f"   [相对POI {offs[0]}]"
            print(line)
    return len(hits), len(triples)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="baseline.json 路径")
    parser.add_argument("--gt", default=str(GT_DEFAULT), help="GT 文件路径")
    parser.add_argument(
        "--window",
        type=float,
        nargs="*",
        default=None,
        help="模拟 POI 时间窗（秒），可给多个值做敏感性对比",
    )
    args = parser.parse_args()

    gt, gt_triples = load_gt(args.gt)
    instances, poi, meta, embedded, _ = load_final_graph(args.baseline)
    print(
        f"baseline: {args.baseline}\n"
        f"poi: {poi.get('source_signature')} --{poi.get('event_type')}--> "
        f"{poi.get('sink_signature')}  [{poi.get('start_time')} ~ {poi.get('end_time')}]\n"
        f"final_edges 实例 {len(instances)} 条；syscall 来源: "
        f"{'内嵌' if embedded else 'Neo4j 反查'}"
    )
    if not embedded:
        unmatched = enrich(instances)
        if unmatched:
            print(f"警告: {unmatched} 条实例未能从 Neo4j 反查到 syscall/时间")

    triples_all, _ = to_triples(instances)
    report("最终图（未过滤）", triples_all, gt_triples, instances=instances, poi=poi)

    for window in args.window or []:
        triples_w, kept = to_triples(instances, window=window, poi=poi)
        report(
            f"POI 时间窗 W={window:g}s（保留实例 {len(kept)}/{len(instances)}）",
            triples_w,
            gt_triples,
            instances=instances,
            poi=poi,
        )


if __name__ == "__main__":
    main()
