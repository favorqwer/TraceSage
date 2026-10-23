"""LLM 接入层：模型工厂 + 结构化 JSON 调用（带自校正）+ token 记账 + 原始输出度量。

不依赖 provider 的 structured-output 能力（中转网关支持情况不一），
统一走「提示里要求只输出 JSON → 宽松解析 → 失败则把错误回灌重试」。

**原始输出度量**：单批判定会吐出 4600~5000 个输出 token，而落库的判定理由
只有 30~50 字符——钱花在看不见的地方。因此每次调用都把「提示词字符数 / 原始输出字符数 /
输出 token / 耗时」写一行 JSONL，并附一小段原始文本样本，供事后归因。

**思考模式默认关闭**：每次请求显式带 DeepSeek 官方字段
`thinking = {"type": "disabled"}`（官方默认是 `enabled`）。开着思考时，上报的输出词里有很大一部分
是网关返回、我们拿不到的推理文字（`reasoning_content`），它们照样占生成时间并能顶到网关超时。
参数文件的 `judge.thinking = true` 恢复官方默认，仅用于对照实验；详见 `cfg.thinking_enabled`。
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from common import config as cfg
from common.graph import short

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


@dataclass
class LlmBudget:
    """token / 调用次数 / **每次调用耗时** 记账。

    `log` 记录每一次尝试（含失败的尝试），是"为什么这么慢"唯一可归因的来源。
    """

    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    failures: int = 0
    by_node: dict[str, int] = field(default_factory=dict)
    by_node_ms: dict[str, float] = field(default_factory=dict)
    by_node_failures: dict[str, int] = field(default_factory=dict)
    by_node_prompt_chars: dict[str, int] = field(default_factory=dict)
    by_node_out_chars: dict[str, int] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)
    run_nodes: dict[Any, str] = field(default_factory=dict)

    def charge(self, node: str, tokens_in: int, tokens_out: int, ms: float = 0.0, ok: bool = True,
               error: str = "", prompt_chars: int = 0, out_chars: int = 0) -> None:
        if ok:
            self.calls += 1
            self.tokens_in += tokens_in
            self.tokens_out += tokens_out
            self.by_node[node] = self.by_node.get(node, 0) + 1
            self.by_node_ms[node] = self.by_node_ms.get(node, 0.0) + ms
            self.by_node_prompt_chars[node] = self.by_node_prompt_chars.get(node, 0) + prompt_chars
            self.by_node_out_chars[node] = self.by_node_out_chars.get(node, 0) + out_chars
        else:
            self.failures += 1
            self.by_node_failures[node] = self.by_node_failures.get(node, 0) + 1
        if len(self.log) < cfg.diagnostic_keep():
            self.log.append({
                "node": node, "ms": round(ms, 1), "ok": ok,
                "tokens_in": tokens_in, "tokens_out": tokens_out,
                "prompt_chars": prompt_chars, "out_chars": out_chars,
                "error": short(error) if error else "",
            })

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_out

    @property
    def total_ms(self) -> float:
        return sum(self.by_node_ms.values())

    def slowest(self, n: Any = None) -> list[dict[str, Any]]:
        """最慢的若干次调用（默认取参数文件里的审计样例条数）。"""
        if n is None:
            n = cfg.audit_sample_n()
        return sorted((r for r in self.log if r["ok"]), key=lambda r: -r["ms"])[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "failures": self.failures,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "tokens_total": self.tokens_total,
            "total_ms": round(self.total_ms, 1),
            "by_node": self.by_node,
            "by_node_ms": {k: round(v, 1) for k, v in self.by_node_ms.items()},
            "by_node_prompt_chars": self.by_node_prompt_chars,
            "by_node_out_chars": self.by_node_out_chars,
            "prompt_chars_total": sum(self.by_node_prompt_chars.values()),
            "out_chars_total": sum(self.by_node_out_chars.values()),
            "by_node_failures": self.by_node_failures,
            "slowest": self.slowest(),
        }


# --------------------------------------------------------------------------- #
# 原始输出度量（写 tmp 日志；失败不影响调用）
# --------------------------------------------------------------------------- #

_RAW_LOG_PATH: Optional[Path] = None
_RAW_LOCK = threading.Lock()


def set_raw_log(path: Optional[Path]) -> None:
    """指定原始输出日志路径（每次运行一个文件；传 None 关闭）。"""
    global _RAW_LOG_PATH
    _RAW_LOG_PATH = Path(path) if path is not None else None


def _log_raw(role: str, prompt_chars: int, text: str, ms: float, usage: tuple[int, int],
             ok: bool = True, error: str = "") -> None:
    if _RAW_LOG_PATH is None:
        return
    record = {
        "ts": time.time(),
        "role": role,
        "prompt_chars": prompt_chars,
        "raw_chars": len(text or ""),
        "tokens_in": usage[0],
        "tokens_out": usage[1],
        "ms": round(ms, 1),
        "ok": ok,
        "error": short(error),
        "text_head": (text or "")[:cfg.diagnostic_keep()],
    }
    try:
        with _RAW_LOCK:
            with _RAW_LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - 度量是旁路，失败绝不能影响调用
        pass


class BudgetCallback(BaseCallbackHandler):
    """把**每一次** LLM 调用（不论走哪个节点、哪个子 agent）记进 LlmBudget。

    用 callback 而不是在每个调用点手写记账，是因为子 agent（如 researcher）内部的
    调用不可见；只有 callback 能统一拦到。
    """

    def __init__(self, budget: "LlmBudget", node: str = "llm") -> None:
        self.budget = budget
        self.default_node = node
        self._t0: dict[Any, float] = {}
        self._chars: dict[Any, int] = {}

    def _node_of(self, run_id: Any) -> str:
        return self.budget.run_nodes.get(run_id, self.default_node)

    def on_chat_model_start(self, serialized: Any, messages: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._t0[run_id] = time.perf_counter()
        # 记 prompt 大小：这是"为什么慢"的第一手指标（不依赖 provider 返回 token 数）
        try:
            chars = 0
            for batch in messages:
                for msg in batch:
                    content = getattr(msg, "content", "")
                    chars += len(content) if isinstance(content, str) else len(str(content))
            self._chars[run_id] = chars
        except Exception:  # noqa: BLE001
            self._chars[run_id] = 0
        name = (serialized or {}).get("name")
        if name:
            self.budget.run_nodes[run_id] = self.default_node or str(name)

    def on_llm_end(self, response: Any, *, run_id: Any, **kwargs: Any) -> None:
        ms = (time.perf_counter() - self._t0.pop(run_id, time.perf_counter())) * 1000.0
        tin, tout = _usage(response)
        self.budget.charge(self._node_of(run_id), tin, tout, ms, ok=True,
                           prompt_chars=self._chars.pop(run_id, 0),
                           out_chars=_output_chars(response))
        self.budget.run_nodes.pop(run_id, None)

    def on_llm_error(self, error: BaseException, *, run_id: Any, **kwargs: Any) -> None:
        ms = (time.perf_counter() - self._t0.pop(run_id, time.perf_counter())) * 1000.0
        self.budget.charge(self._node_of(run_id), 0, 0, ms, ok=False,
                           error=f"{type(error).__name__}: {error}",
                           prompt_chars=self._chars.pop(run_id, 0))
        self.budget.run_nodes.pop(run_id, None)


def make_model(*, temperature: float = 0.0, model_name: Optional[str] = None) -> ChatOpenAI:
    kwargs: dict[str, Any] = {
        "model": model_name or cfg.llm_model(),
        "temperature": temperature,
        "api_key": cfg.llm_api_key(),
        "base_url": cfg.llm_base_url(),
        # 网关（ALB）自己会在 ~60s 返 504，所以客户端超时不需要很长；
        # 重试交给下面的 _invoke_with_retry（带退避），不用 SDK 内置重试。
        "timeout": cfg.llm_timeout_seconds(),
        "max_retries": cfg.llm_sdk_retries(),
    }
    if not cfg.thinking_enabled():
        # 思考模式默认关闭（DeepSeek 官方字段；官方默认是 enabled）。理由与实测见 cfg.thinking_enabled。
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    return ChatOpenAI(**kwargs)


def _usage(response: Any) -> tuple[int, int]:
    meta = getattr(response, "usage_metadata", None) or {}
    if meta:
        return int(meta.get("input_tokens") or 0), int(meta.get("output_tokens") or 0)
    # callback 的 on_llm_end 拿到的是 LLMResult，token 在 generation.message 或 llm_output 里
    for batch in getattr(response, "generations", None) or []:
        for gen in batch:
            msg = getattr(gen, "message", None)
            meta = getattr(msg, "usage_metadata", None) or {}
            if meta:
                return int(meta.get("input_tokens") or 0), int(meta.get("output_tokens") or 0)
    llm_output = getattr(response, "llm_output", None) or {}
    meta = llm_output.get("token_usage") or llm_output.get("usage") or {}
    if meta:
        return (int(meta.get("prompt_tokens") or meta.get("input_tokens") or 0),
                int(meta.get("completion_tokens") or meta.get("output_tokens") or 0))
    meta = (getattr(response, "response_metadata", None) or {}).get("token_usage") or {}
    return int(meta.get("prompt_tokens") or 0), int(meta.get("completion_tokens") or 0)


def _output_chars(response: Any) -> int:
    """本次调用的**原始输出字符数**（含被丢弃的散文/代码块；用于回答"输出花在哪"）。"""
    total = 0
    for batch in getattr(response, "generations", None) or []:
        for gen in batch:
            text = getattr(gen, "text", None)
            if text is None:
                message = getattr(gen, "message", None)
                text = getattr(message, "content", "") if message is not None else ""
            total += len(text if isinstance(text, str) else str(text))
    return total


def _content(response: Any) -> str:
    content = response.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # 多段 content（部分网关返回 list[dict]）
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and "text" in item:
                parts.append(str(item["text"]))
        return "\n".join(parts)
    return str(content)


def extract_json(text: str) -> Optional[dict[str, Any]]:
    """宽松 JSON 提取：优先代码块，其次第一个平衡大括号片段。"""
    candidates: list[str] = []
    for match in _FENCE.finditer(text):
        candidates.append(match.group(1).strip())
    candidates.append(text.strip())
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        start = candidate.find("{")
        if start < 0:
            continue
        depth = 0
        in_str = False
        escape = False
        for idx in range(start, len(candidate)):
            ch = candidate[idx]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start : idx + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break
    return None


_RATE_LIMIT_HINT = re.compile(r"429|rate[ _-]?limit|too many requests|请求过于频繁", re.IGNORECASE)
_RETRY_AFTER = re.compile(r"retryAfterSeconds['\"]?\s*:\s*([0-9.]+)")


def _is_rate_limit(exc: BaseException) -> bool:
    return bool(_RATE_LIMIT_HINT.search(f"{type(exc).__name__}: {exc}"))


def _retry_after_seconds(exc: BaseException) -> Optional[float]:
    """网关给的 `retryAfterSeconds`（有就听它的）。"""
    match = _RETRY_AFTER.search(str(exc))
    return float(match.group(1)) if match else None


def _invoke_with_retry(
    model: ChatOpenAI,
    messages: list[Any],
    *,
    max_retries: Any = None,
    base_delay: Any = None,
    config: Optional[dict[str, Any]] = None,
) -> Any:
    """带退避的调用。**限流（429）单独给更长的等待与更多次重试**，其余错误按指数退避。

    实测教训：网关有限流（`{'limit': 20, 'retryAfterSeconds': 3}`），而 judge 的并行扇出会瞬时打满；
    原先只退避 2/4/8s 就放弃并让节点降级，会把整轮跑测打成“半瘫”。限流不该降级，该等。
    `max_retries` 与 `base_delay` 省略时取参数文件里的值（`llm.plain_retries` / `llm.plain_retry_base_seconds`）。
    记时/记账交给 BudgetCallback（若 config 里带了）。
    """
    max_retries = cfg.llm_plain_retries() if max_retries is None else int(max_retries)
    base_delay = (cfg.llm_plain_retry_base_seconds() if base_delay is None
                  else float(base_delay))
    rate_limit_waits = cfg.llm_rate_limit_waits()
    wait_start = cfg.llm_rate_limit_wait_start_seconds()
    wait_max = cfg.llm_rate_limit_wait_max_seconds()
    last: Optional[Exception] = None
    plain = 0       # 普通传输错误次数
    limited = 0     # 限流次数
    while True:
        try:
            return model.invoke(messages, config=config)
        except Exception as exc:  # noqa: BLE001 - 统一按传输错误处理，交给上层降级
            last = exc
            if _is_rate_limit(exc):
                limited += 1
                if limited > rate_limit_waits:
                    break
                wait = max(_retry_after_seconds(exc) or 0.0, min(wait_max, wait_start * limited))
            else:
                plain += 1
                if plain > max_retries:
                    break
                wait = base_delay * (2 ** (plain - 1))
            time.sleep(wait)
    raise last  # type: ignore[misc]


def call_json(
    model: ChatOpenAI,
    system: str,
    user: str,
    *,
    max_retries: Any = None,
    config: Optional[dict[str, Any]] = None,
    role: str = "judge",
) -> dict[str, Any]:
    """要求模型只输出 JSON；解析失败回灌自校正；**传输失败降级不抛异常**。

    `max_retries` 省略时取参数文件里的值（`llm.format_retries`）。
    token/耗时记账由 `BudgetCallback` 完成（通过 `config` 里的 callbacks 传递）；
    原始输出长度与文本样本写进 `set_raw_log()` 指定的 JSONL（见模块开头）。
    """
    max_retries = cfg.llm_format_retries() if max_retries is None else int(max_retries)
    messages = [SystemMessage(content=system), HumanMessage(content=user)]
    prompt_chars = len(system) + len(user)
    last_error = "未知错误"
    for _attempt in range(max_retries + 1):
        t0 = time.perf_counter()
        try:
            response = _invoke_with_retry(model, messages, config=config)
        except Exception as exc:  # noqa: BLE001 - 降级：返回失败标记，由调用方决定如何退化
            _log_raw(role, prompt_chars, "", (time.perf_counter() - t0) * 1000.0, (0, 0),
                     ok=False, error=f"{type(exc).__name__}: {exc}")
            return {"_raw_ok": False, "_error": f"{type(exc).__name__}: {short(exc)}", "_transport": True}
        text = _content(response)
        _log_raw(role, prompt_chars, text, (time.perf_counter() - t0) * 1000.0, _usage(response))
        parsed = extract_json(text)
        if parsed is not None:
            parsed.setdefault("_raw_ok", True)
            return parsed
        last_error = "输出不是合法 JSON"
        messages = [
            SystemMessage(content=system),
            HumanMessage(content=user),
            HumanMessage(content=f"上一次输出无法解析为 JSON（{last_error}）。只输出一个 JSON 对象，不要任何解释或代码块标记。"),
        ]
    return {"_raw_ok": False, "_error": last_error, "_transport": False}
