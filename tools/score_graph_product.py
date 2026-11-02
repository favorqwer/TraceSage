#!/usr/bin/env python
"""GT (ground truth) 召回/查准评估工具（只认 -v2 图模型）。

用法:
    python tools/score_graph_product.py output/engine-runs/new-parser-v2/<场景>/baseline.json \
        --gt groundtruth/<场景>.groundtruth.json [--database <场景库>] [--window SECONDS]

输入:
    - GT 文件：groundtruth/<场景>.groundtruth.json（gt-annotator 产出，用 --gt 指定）
    - BaselineRunner 产出的 baseline.json

图模型口径（与 provenance-parser 写入的 -v2 图一致，没有旧图回退）:
    - Process 内容 = coalesce(exe_path, '<NA>')；File 内容 = path；Network 内容 = endpoints
    - 边属性：event_id / action / syscall / start_ns / end_ns / result / payload_b64 / to_path / mode
    - 顶点主键：Process=(host_id,container_id,pid,start_ns)、File=(host_id,container_id,path)、
      Network=(host_id,endpoints)；评分按内容，不含容器/pid（口径见下）

匹配口径:
    - 必须集合（attack_path 的 edges）: 四元组 (src, syscall, dst, effect)；同类边多实例命中任一即算命中
    - 可能集合（attack_path 的 rules）: 报告里存在至少一条边满足规则的全部条件即算命中，
      该步骤只算一分；满足规则的边全部算正确边
      规则 action 允许写「动作名」（send/recv/create/mmap_exec…）或「syscall 名」两种词表，
      见 rules_match.ACTION_TO_SYSCALLS
    - 成败（effect）判等: 标注与报告两侧都有值时必须相等；任一侧为空按三元命中并披露条数
      （accept/create/clone/mmap_read/exit 这类边不记录返回值，标注 effect 为空时不可判）
    - 召回（按步骤）= (命中条目数 + 命中规则数) / (条目数 + 规则数)
    - 查准（按四元组）= (命中条目边数 + 满足规则的边数) / 报告去重后的内容四元组数
    - 规则条件里的端点种类（process/file/network）从场景库顶点标签判定；连不上库时该条件不判定

baseline.json 的 final_edges 键是 "host|srcId|dstId|eventId"（数字 id 空间），
不含 syscall/时间。产物未内嵌 syscall 时，按库名走 Neo4j 反查补全：
库名取 --database，缺省取 baseline.json 的 meta.database（形如 bolt://host:7687/<库名>）；
反查一条都没命中即阻断退出，不把「查不到」当成 0 分结果。

--window SECONDS 模拟 POI 锚定时间窗过滤（[poiStart-W, poiEnd+W]，区间重叠语义），
按实例过滤、按内容三元组计分，并输出命中/多出边相对 POI 的时间偏移分布。
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "provenance-navigator"))
import rules_match as rm  # noqa: E402
from domain.keys import path_part  # noqa: E402
# GT 文件与场景说明同放 groundtruth/。


def load_env(path=ROOT / ".env"):
    env = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    return env


def strip_endpoint_key(k):
    """顶点键 -> 内容：p:/f: 取第 2 个冒号之后，n: 取端点串。

    容器内文件的内容在图里写成 `容器ID|路径`，标准答案则是纯路径；两侧都过 `path_part`
    才能对上（只按路径比，不看容器）。
    """
    if not isinstance(k, str):
        return k
    if k.startswith(("p:", "f:")) and k.count(":") >= 2:
        return path_part(k.split(":", 2)[2])
    if k.startswith("n:") and k.count(":") >= 2:
        return k.split(":", 2)[2]
    return path_part(k)

def load_gt(path):
    gt = json.loads(Path(path).read_text(encoding="utf-8"))
    triples = []
    for phase in gt.get("attack_path", []):
        phase_name = phase.get("phase") or phase.get("id") or "unnamed"
        for edge in phase.get("edges", []) or []:
            call = edge.get("syscall") or edge.get("action")
            src = strip_endpoint_key(edge.get("src"))
            dst = strip_endpoint_key(edge.get("dst"))
            if src and call and dst:
                triples.append((src, call, dst, edge.get("effect"), phase_name))
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
                "effect": entry.get("effect"),
                "start": entry.get("starttime"),
                "end": entry.get("endtime"),
                "weight": entry.get("weight"),
            }
        )
    poi = data.get("poi", {})
    meta = data.get("meta", {})
    return instances, poi, meta, embedded, id2type


def database_from_meta(meta):
    """baseline.json 的 meta.database（bolt://host:7687/<库名>）-> 库名。"""
    uri = str((meta or {}).get("database") or "").strip().rstrip("/")
    if not uri:
        return None
    name = uri.rsplit("/", 1)[-1]
    return name or None


def _content(alias):
    """顶点内容口径：与 GT 顶点键、rules_match.VertexKinds 完全一致。"""
    return (
        f"CASE labels({alias})[0] "
        f"WHEN 'Process' THEN coalesce({alias}.exe_path, '<NA>') "
        f"WHEN 'File' THEN {alias}.path "
        f"ELSE {alias}.endpoints END"
    )


def fetch_edge_facts(database):
    """从 -v2 库拉 (event_id, src 内容, dst 内容) -> (syscall, start_ns, end_ns)。

    start_ns / end_ns 是纳秒，调用方负责换算成秒。
    """
    try:
        from neo4j import GraphDatabase
    except ImportError:
        sys.exit("需要 neo4j 驱动（requirements.txt 已含），请使用项目 .venv 运行")
    env = load_env()
    uri = env.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (env.get("NEO4J_USER", "neo4j"), env.get("NEO4J_PASSWORD", ""))
    query = (
        "MATCH (a)-[r]->(b) WHERE r.event_id IS NOT NULL "
        "RETURN r.event_id AS eid, r.syscall AS syscall, r.start_ns AS st, r.end_ns AS et, "
        f"{_content('a')} AS sc, {_content('b')} AS dc"
    )
    facts = defaultdict(list)
    with GraphDatabase.driver(uri, auth=auth) as driver:
        with driver.session(database=database) as session:
            for record in session.run(query):
                facts[str(record["eid"])].append(
                    (record["sc"], record["dc"], record["syscall"], record["st"], record["et"])
                )
    return facts


def enrich(instances, database):
    """用 Neo4j 反查补全缺失的 syscall 与起止时间（纳秒 -> 秒）。返回 (未命中数, 命中数)。"""
    todo = [i for i in instances if i["syscall"] is None or i["start"] is None or i["end"] is None]
    if not todo:
        return 0, 0
    facts = fetch_edge_facts(database)
    matched = 0
    for inst in todo:
        candidates = facts.get(inst["event_id"], [])
        hit = next(
            (c for c in candidates if c[0] == inst["src"] and c[1] == inst["dst"]), None
        )
        if hit is None:
            continue
        matched += 1
        inst["syscall"] = hit[2]
        inst["start"] = None if hit[3] is None else hit[3] / 1e9
        inst["end"] = None if hit[4] is None else hit[4] / 1e9
    return len(todo) - matched, matched


def to_triples(instances, window=None, poi=None):
    """实例 -> 去重内容四元组集合（源, 系统调用, 目标, 成败）。window=(W 秒) 时先按 POI 窗口过滤实例。"""
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
        key = (inst["src"], inst["syscall"], inst["dst"], inst.get("effect"))
        triples.setdefault(key, inst)
    return triples, kept


def fmt_offset(seconds):
    sign = "+" if seconds >= 0 else "-"
    return f"{sign}{abs(seconds):.3f}s"


def report(title, triples, gt_triples, rules=(), kinds=None, instances=None, poi=None):
    ordered = sorted(triples, key=lambda k: (k[0], k[1], k[2], k[3] or ""))
    met = rm.evaluate_report(gt_triples, rules, ordered, kinds=kinds)
    print(f"\n== {title} ==")
    print(
        f"召回（按步骤） {met['steps_hit']}/{met['steps_total']} = {met['recall_steps']:.1%}   "
        f"（必须条目 {len(met['must_hits'])}/{met['gt_edges']}，规则 "
        f"{len(met['rule_hits'])}/{met['rules_total']}）"
    )
    print(
        f"查准（按四元组） {met['correct_edges']}/{met['reported_triples']} = "
        f"{met['precision_edges']:.1%}"
    )
    if met["kinds_degraded"]:
        print("提示: 未取到场景库的顶点种类，规则里的 vertex 条件未参与判定")
    if met.get("effect_unchecked"):
        print(f"提示: 规则 {', '.join(met['effect_unchecked'])} 写了 effect 条件，"
              "但报告边不带成败，该条件按「不否决」处理")
    if met.get("effect_unchecked_gt"):
        print(f"提示: {met['effect_unchecked_gt']} 条必须条目的成败未参与判等"
              "（标注 effect 为空，或报告侧无成败证据）")
    if met.get("effect_unchecked_edges"):
        print(f"提示: 查准分子里有 {met['effect_unchecked_edges']} 条正确边没有成败证据，按三元判等算对")
    if met["must_misses"]:
        print("未召回的必须条目:")
        for miss in met["must_misses"]:
            src, syscall, dst, effect, phase = miss
            print(f"  [{phase}] {src} --{syscall}--> {dst}   [{effect or '成败不记'}]")
    if met["rule_misses"]:
        print(f"未命中的规则: {', '.join(met['rule_misses'])}")
    if met["extras"]:
        print(f"多出边 ({len(met['extras'])}):")
        key_to_inst = {}
        if instances is not None and poi is not None:
            for inst in instances:
                if inst.get("start") is not None and inst.get("end") is not None:
                    k = (inst["src"], inst["syscall"], inst["dst"], inst.get("effect"))
                    if k not in key_to_inst:
                        key_to_inst[k] = inst
        for src, syscall, dst, effect in met["extras"]:
            line = f"  {src} --{syscall}--> {dst}" + (f"   [{effect}]" if effect else "")
            inst = key_to_inst.get((src, syscall, dst, effect))
            if inst is not None:
                off = fmt_offset((inst["start"] + inst["end"]) / 2 - poi["start_time"])
                line += f"   [相对POI {off}]"
            print(line)
    return met["steps_hit"], met["steps_total"], met["correct_edges"], met["reported_triples"]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("baseline", help="baseline.json 路径")
    parser.add_argument("--gt", required=True,
                        help="GT 文件路径（groundtruth/<场景>.groundtruth.json）")
    parser.add_argument("--database",
                        help="场景库名（-v2）；缺省取 baseline.json 的 meta.database")
    parser.add_argument(
        "--window",
        type=float,
        nargs="*",
        default=None,
        help="模拟 POI 时间窗（秒），可给多个值做敏感性对比",
    )
    args = parser.parse_args()

    gt, gt_triples = load_gt(args.gt)
    rules = rm.load_rules(gt)
    kinds = rm.VertexKinds.for_gt(gt)
    instances, poi, meta, embedded, _ = load_final_graph(args.baseline)
    print(
        f"baseline: {args.baseline}\n"
        f"poi: {poi.get('source_signature')} --{poi.get('event_type')}--> "
        f"{poi.get('sink_signature')}  [{poi.get('start_time')} ~ {poi.get('end_time')}]\n"
        f"final_edges 实例 {len(instances)} 条"
    )
    if not embedded:
        database = args.database or database_from_meta(meta)
        if not database:
            sys.exit(
                "阻断：baseline.json 未内嵌 syscall/时间，且取不到场景库名。"
                "请用 --database 指定 -v2 库（如 attack-1-web-exploit-ransomware-v2）"
            )
        print(f"syscall 来源: Neo4j 反查（库 {database}）")
        unmatched, matched = enrich(instances, database)
        if instances and matched == 0:
            sys.exit(
                f"阻断：{len(instances)} 条实例在库 {database} 中一条都没反查到 syscall。"
                "库名/图模型不符，拒绝输出 0 分结果"
            )
        if unmatched:
            print(f"警告: {unmatched} 条实例未能从 Neo4j 反查到 syscall/时间")
    else:
        print("syscall 来源: 产物内嵌")

    triples_all, _ = to_triples(instances)
    report("最终图（未过滤）", triples_all, gt_triples, rules=rules, kinds=kinds, instances=instances, poi=poi)

    for window in args.window or []:
        triples_w, kept = to_triples(instances, window=window, poi=poi)
        report(
            f"POI 时间窗 W={window:g}s（保留实例 {len(kept)}/{len(instances)}）",
            triples_w,
            gt_triples,
            rules=rules,
            kinds=kinds,
            instances=instances,
            poi=poi,
        )


if __name__ == "__main__":
    main()
