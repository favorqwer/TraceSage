#!/usr/bin/env python
"""归一化改动的回归面模拟：对六个库的全部 File.path / Process.exepath 应用
   「括号注记有条件剥壳 + posixpath.normpath」，统计会合并多少顶点。

用法: .venv/Scripts/python.exe docs/pathnorm_impact.py
判据：
  merge_group  归一后落到同一个键的多个原键（= 修复后会合并的顶点组）
  rewrite      归一后键发生变化、但目标键原本不存在（= 单纯改名，不合并）
"""
import posixpath
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve()
while not (ROOT / ".env").exists() and ROOT != ROOT.parent:
    ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
from neo4j import GraphDatabase  # noqa: E402

DBS = [
    "tracesage-1-multi-stage-data-exfiltration",
    "tracesage-2-masquerade-data-exfiltration",
    "tracesage-3-ssh-spray",
    "tracesage-4-site-defacement",
    "tracesage-5-user-timer-resource-hijack",
    "tracesage-6-sqlite-pipeline-pollution",
]
# 与 handlers._normalize_exit_path 同一防护：仅当括号内以 / 开头才取括号内
PAREN = re.compile(r"^(?P<raw>[^()]*)\((?P<abs>/[^)]*)\)$")
PSEUDO = re.compile(r"^(pipe:\[|socket:\[|anon_inode:|/memfd:|eventfd:|inotify:|timerfd:)")


def normalize(key: str) -> str:
    if not key or PSEUDO.match(key):
        return key
    m = PAREN.match(key)
    cand = m.group("abs") if m else key
    return posixpath.normpath(cand)


def load_env(path=ROOT / ".env"):
    env = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


env = load_env()
driver = GraphDatabase.driver(
    env["NEO4J_URI"], auth=(env["NEO4J_USER"], env["NEO4J_PASSWORD"])
)
Q = """
MATCH (n) WHERE n:File OR n:Process
OPTIONAL MATCH (n)-[r]-()
WITH n, labels(n)[0] AS lb,
     CASE labels(n)[0] WHEN 'File' THEN n.path ELSE n.exepath END AS key, count(r) AS deg
WHERE key IS NOT NULL
RETURN lb, key, deg
"""
tot_merge = tot_rewrite = 0
for db in DBS:
    groups = defaultdict(list)  # normalized -> [(orig, lb, deg)]
    with driver.session(database=db) as s:
        for rec in s.run(Q):
            if rec["lb"] == "Process" and not PAREN.search(rec["key"] or ""):
                continue  # 进程只关心 execve 注记未剥壳的情形
            groups[normalize(rec["key"])].append((rec["key"], rec["lb"], rec["deg"]))
    merges = {k: v for k, v in groups.items() if len(v) > 1}
    rewrites = {
        k: v for k, v in groups.items()
        if len(v) == 1 and v[0][0] != k
    }
    tot_merge += sum(len(v) for v in merges.values())
    tot_rewrite += len(rewrites)
    print(f"== {db}: 归一后合并顶点组 {len(merges)}（涉及 {sum(len(v) for v in merges.values())} 个原键），"
          f"纯改名 {len(rewrites)}")
    for k, v in sorted(merges.items())[:6]:
        print(f"   MERGE -> {k}\n        原键: {[(x[0], x[1], x[2]) for x in v]}")
    for k, v in sorted(rewrites.items())[:6]:
        print(f"   RENAME {v[0][0]} ({v[0][1]}, deg={v[0][2]})  ->  {k}")
driver.close()
print(f"\n六库合计：参与合并的原键 {tot_merge}，纯改名 {tot_rewrite}")
