"""第一轮判定（判定层内部）：发出调用并解析结论。

要求模型只输出一个 JSON 对象，每条判定原样回抄编号；漏抄、抄错、编号非法的边**不得当作无关**，
由编排器记成未判定（`decide.py`）。提示词在 `pagent/prompts/judge_first_pass.md`（加载器不做任何改写）。
"""

from __future__ import annotations

from typing import Any

from ...contracts import parse_verdicts
from ...core import prompts
from ...core.llm import BudgetCallback, call_json

JUDGE_SYSTEM = prompts.load("judge_first_pass.md")


def judge_first_pass(
    model: Any,
    items: list[dict[str, Any]],
    listing: str,
    *,
    budget: Any,
) -> dict[str, Any]:
    """发出第一轮调用并解析结论。

    返回 `{"ok": True, "verdicts": {id: 判定}, "invalid": n, "calls": 1}`；
    整批调用失败时返回 `{"ok": False, "error": "...", "calls": 1}`（由编排器整批重试）。
    """
    config = {"callbacks": [BudgetCallback(budget, node="judge")]}
    result = call_json(model, JUDGE_SYSTEM, listing, config=config, role="judge")
    if not result.get("_raw_ok", True):
        return {"ok": False, "error": result.get("_error") or "未知错误", "calls": 1}
    verdicts, invalid = parse_verdicts(result, {item["id"] for item in items})
    return {"ok": True, "verdicts": verdicts, "invalid": invalid, "calls": 1}
