"""Attack steps state machine and checklist management."""

from __future__ import annotations

import argparse
import datetime
import json
import re
from pathlib import Path
from typing import Any

from common import ROOT, dumps, fail

TMP_DIR = ROOT / "gt-annotator" / "tmp"


def _steps_paths(scenario: str) -> tuple[Path, Path]:
    safe_scenario = scenario.strip().replace("/", "_").replace("\\", "_")
    scen_dir = TMP_DIR / safe_scenario
    scen_dir.mkdir(parents=True, exist_ok=True)
    return scen_dir / "steps.json", scen_dir / "steps.md"


def _recalc_summary(data: dict[str, Any]) -> dict[str, int]:
    steps = data.get("steps", [])
    total = len(steps)
    found = sum(1 for s in steps if s.get("status") == "found")
    context = sum(1 for s in steps if s.get("status") == "context")
    absent = sum(1 for s in steps if s.get("status") == "absent")
    other = total - (found + context + absent)
    summary = {
        "total": total,
        "found": found,
        "context": context,
        "absent": absent,
    }
    if other > 0:
        summary["other"] = other
    data["summary"] = summary
    return summary


def _render_markdown(data: dict[str, Any]) -> str:
    scenario = data.get("scenario", "unknown")
    summary = data.get("summary", {})
    updated = data.get("updated_at", "")
    lines = [
        f"# 攻击步骤清单与销账状态（{scenario}）",
        "",
        f"> 更新时间：{updated}  ",
        f"> **总计**: {summary.get('total', 0)} 步 | "
        f"✅ **Found**: {summary.get('found', 0)} | "
        f"ℹ️ **Context**: {summary.get('context', 0)} | "
        f"❌ **Absent**: {summary.get('absent', 0)}",
        "",
        "| ID | 阶段 | 动作说明 | 状态 | 关联 Edge Key / 4元组 | 判定依据 / 备注 |",
        "|---|---|---|---|---|---|",
    ]
    for step in data.get("steps", []):
        sid = step.get("id", "")
        phase = step.get("phase", "") or "-"
        desc = step.get("description", "").replace("|", "\\|")
        st = step.get("status", "absent")
        badge = "✅ found" if st == "found" else ("ℹ️ context" if st == "context" else "❌ absent")
        keys = ", ".join(step.get("edge_keys", [])) or "-"
        why = step.get("why", "") or "-"
        lines.append(f"| {sid} | {phase} | {desc} | {badge} | {keys} | {why} |")

    absent_steps = [s for s in data.get("steps", []) if s.get("status") == "absent"]
    lines.append("")
    lines.append("## 待办 / 剩余未销账项 (Absent)")
    if not absent_steps:
        lines.append("🎉 全部步骤已销账完毕（无 absent 项）。")
    else:
        for s in absent_steps:
            lines.append(f"- **[{s.get('id')}]** {s.get('description')}")
    lines.append("")
    return "\n".join(lines)


def _save_steps(json_path: Path, md_path: Path, data: dict[str, Any]) -> None:
    data["updated_at"] = datetime.datetime.now().astimezone().isoformat()
    _recalc_summary(data)
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_render_markdown(data), encoding="utf-8")


def _load_steps(json_path: Path) -> dict[str, Any]:
    if not json_path.exists():
        fail(f"步骤状态机文件不存在：{json_path}；请先运行 gt.py steps init --scenario ...")
    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"解析 steps.json 失败：{exc}")


def _parse_attack_markdown(file_path: Path) -> list[dict[str, Any]]:
    if not file_path.exists():
        fail(f"攻击文档不存在：{file_path}")
    text = file_path.read_text(encoding="utf-8")
    steps: list[dict[str, Any]] = []
    current_phase = ""
    idx = 1
    for line in text.splitlines():
        line = line.strip()
        # 捕捉形如 "## 2. 第一部分：..." 或 "### 2.1 装网站..."
        h2 = re.match(r"^##\s+(\d+[\.、].*)$", line)
        if h2:
            current_phase = h2.group(1)
            continue
        h3 = re.match(r"^###\s+(\d+\.\d+[\.、]?\s*.*)$", line)
        if h3:
            desc = h3.group(1)
            steps.append({
                "id": f"S{idx:02d}",
                "phase": current_phase,
                "description": desc,
                "status": "absent",
                "edge_keys": [],
                "why": "",
            })
            idx += 1
            continue
        # 捕捉带有动作意图的有序列表项
        item = re.match(r"^(\d+)\.\s+(\*\*.*?\*\*.*)$", line)
        if item and len(line) > 10 and not current_phase.startswith("0."):
            steps.append({
                "id": f"S{idx:02d}",
                "phase": current_phase,
                "description": item.group(2),
                "status": "absent",
                "edge_keys": [],
                "why": "",
            })
            idx += 1
    return steps


def cmd_steps(args: argparse.Namespace) -> None:
    action = getattr(args, "steps_action", None)
    if not action:
        fail("必须指定 steps 子动作：init, add, update, status")

    json_path, md_path = _steps_paths(args.scenario)

    if action == "init":
        steps: list[dict[str, Any]] = []
        if getattr(args, "from_attack", None):
            attack_file = Path(args.from_attack)
            if not attack_file.is_absolute():
                attack_file = ROOT / attack_file
            steps = _parse_attack_markdown(attack_file)
        data = {
            "scenario": args.scenario,
            "created_at": datetime.datetime.now().astimezone().isoformat(),
            "steps": steps,
        }
        _save_steps(json_path, md_path, data)
        print(dumps({
            "ok": True,
            "scenario": args.scenario,
            "message": f"初始化步骤清单完成，共生成 {len(steps)} 个步骤",
            "json_file": str(json_path),
            "md_file": str(md_path),
            "summary": data["summary"],
        }))
        return

    data = _load_steps(json_path)

    if action == "add":
        if not getattr(args, "id", None) or not getattr(args, "desc", None):
            fail("add 动作必须指定 --id 与 --desc")
        sid = args.id.strip()
        if any(s.get("id") == sid for s in data.get("steps", [])):
            fail(f"Step ID 已存在：{sid}")
        new_step = {
            "id": sid,
            "phase": getattr(args, "phase", "") or "",
            "description": args.desc.strip(),
            "status": getattr(args, "status", "absent"),
            "edge_keys": [args.edge_key] if getattr(args, "edge_key", None) else [],
            "why": getattr(args, "why", "") or "",
        }
        data.setdefault("steps", []).append(new_step)
        _save_steps(json_path, md_path, data)
        print(dumps({
            "ok": True,
            "message": f"添加步骤 {sid} 成功",
            "step": new_step,
            "summary": data["summary"],
        }))
        return

    if action == "update":
        if not getattr(args, "id", None):
            fail("update 动作必须指定 --id")
        sid = args.id.strip()
        target = next((s for s in data.get("steps", []) if s.get("id") == sid), None)
        if not target:
            fail(f"找不到 Step ID：{sid}")
        if getattr(args, "status", None):
            target["status"] = args.status
        if getattr(args, "edge_key", None):
            keys = set(target.get("edge_keys", []))
            keys.add(args.edge_key)
            target["edge_keys"] = sorted(keys)
        if getattr(args, "why", None) is not None:
            target["why"] = args.why
        if getattr(args, "desc", None):
            target["description"] = args.desc
        _save_steps(json_path, md_path, data)
        print(dumps({
            "ok": True,
            "message": f"更新步骤 {sid} 状态成功",
            "step": target,
            "summary": data["summary"],
        }))
        return

    if action == "status":
        _recalc_summary(data)
        summary = data["summary"]
        absent_list = [s for s in data.get("steps", []) if s.get("status") == "absent"]
        print(dumps({
            "scenario": args.scenario,
            "summary": summary,
            "all_resolved": (summary.get("absent", 0) == 0),
            "absent_count": len(absent_list),
            "absent_steps": absent_list,
            "json_file": str(json_path),
            "md_file": str(md_path),
        }))
