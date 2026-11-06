import json
import gzip
import hashlib
from pathlib import Path

ROOT = Path("E:/Work/TraceSage")
base_dir = ROOT / "output/provenance-baseline"
bak_dir = ROOT / "output/provenance-baseline-bak-20261105"

print("[1] 检查备份目录...")
assert bak_dir.is_dir(), "备份目录不存在"
assert (bak_dir / "summary_v2.json").is_file(), "备份 summary_v2.json 缺失"
print("   -> 原基线完整备份至:", bak_dir)

print("[2] 检查 summary_v2.json 与 micro 数字一致性...")
with open(base_dir / "summary_v2.json", "r", encoding="utf-8") as f:
    s = json.load(f)
assert len(s["results"]) == 10, "结果数量不是 10"
m = s["micro"]
assert m["steps_hit"] == 705, f"steps_hit 错误: {m['steps_hit']}"
assert m["steps_total"] == 906, f"steps_total 错误: {m['steps_total']}"
assert m["correct_edges"] == 19544, f"correct_edges 错误: {m['correct_edges']}"
assert m["reported_triples"] == 33062, f"reported_triples 错误: {m['reported_triples']}"
print(f"   -> summary_v2.json 数字完全吻合: 召回 {m['recall']*100:.2f}%, 查准 {m['precision']*100:.2f}%。")

print("[3] 检查 10 份压缩报告与 SHA256 校验...")
for r in s["results"]:
    gz_path = Path(r["gzip"])
    assert gz_path.is_file(), f"压缩文件不存在: {gz_path}"
    h = hashlib.sha256(gz_path.read_bytes()).hexdigest()
    assert h == r["gzip_sha256"], f"SHA256 不一致: {gz_path.name}"
print(f"   -> 10 份 reports_v2/*.json.gz 哈希校验 100% 匹配。")

print("[4] 检查 code-fingerprints.json...")
with open(base_dir / "code-fingerprints.json", "r", encoding="utf-8") as f:
    fp = json.load(f)
assert "git_commit" in fp, "git_commit 缺失"
assert len(fp["files"]) >= 10, "指纹文件数量异常"
print(f"   -> 代码指纹覆盖 {len(fp['files'])} 个模块文件，当前 commit: {fp['git_commit'][:8]}。")

print("[5] 检查 OVERVIEW.md 存在与内容...")
ov = (base_dir / "OVERVIEW.md").read_text(encoding="utf-8")
assert "77.81%" in ov, "OVERVIEW.md 召回率未更新"
assert "59.11%" in ov, "OVERVIEW.md 查准率未更新"
print("   -> OVERVIEW.md 校验通过。")

print("\n全部 5 项基线校验 100% 通过！")
