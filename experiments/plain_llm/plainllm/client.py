"""最小 OpenAI 兼容聊天客户端：重试、退避、用量与耗时记账。

不引入框架依赖，只做 chat/completions 一种调用；每次调用（含失败）写一行 JSONL，
便于事后核对调用数、token 与失败原因。
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

from .settings import Config

RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class LlmError(RuntimeError):
    """调用最终失败（重试耗尽或不可重试的错误）。"""


@dataclass
class ChatResult:
    text: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    attempts: int
    status: int


def extract_json(text: str) -> Optional[dict[str, Any]]:
    """从模型输出里取出第一个合法 JSON 对象；容忍 ``` 围栏与前后废话。"""
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", s)
        s = re.sub(r"\s*```\s*$", "", s)
    decoder = json.JSONDecoder()
    start = s.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(s[start:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        start = s.find("{", start + 1)
    return None


class LlmClient:
    """线程安全的聊天客户端；多个线程共用一个 httpx.Client。"""

    def __init__(self, cfg: Config, log_path: Path):
        self.cfg = cfg
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._url = _chat_url(cfg.base_url)
        self._http = httpx.Client(
            timeout=httpx.Timeout(cfg.request_timeout, connect=15.0),
            limits=httpx.Limits(max_connections=max(8, cfg.concurrency * 2)),
            headers={
                "Authorization": f"Bearer {cfg.api_key}",
                "Content-Type": "application/json",
                **(cfg.extra_headers or {}),
            },
        )
        self._lock = threading.Lock()
        self._log_fh = self.log_path.open("a", encoding="utf-8")
        self.stats: dict[str, Any] = {
            "calls": 0,
            "failures": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "latency_ms": 0.0,
        }

    def close(self) -> None:
        self._http.close()
        with self._lock:
            self._log_fh.close()

    # ---- 对外接口 -------------------------------------------------------
    def chat(self, system: str, user: str, tag: str = "") -> ChatResult:
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
        }
        if self.cfg.max_tokens:
            body["max_tokens"] = int(self.cfg.max_tokens)
        if self.cfg.response_format_json:
            body["response_format"] = {"type": "json_object"}
        if self.cfg.extra_body:
            body.update(self.cfg.extra_body)

        attempts = 0
        last_error = ""
        while attempts <= self.cfg.max_retries:
            attempts += 1
            started = time.time()
            try:
                resp = self._http.post(self._url, json=body)
                status = resp.status_code
                latency = (time.time() - started) * 1000.0
                if status in RETRY_STATUS:
                    last_error = f"HTTP {status}: {resp.text[:300]}"
                    if attempts > self.cfg.max_retries:
                        self._record(tag, user, system, latency, 0, 0, status, False, last_error, "")
                        raise LlmError(last_error)
                    time.sleep(self._backoff(attempts, resp.headers.get("Retry-After")))
                    continue
                if status >= 400:
                    last_error = f"HTTP {status}: {resp.text[:300]}"
                    self._record(tag, user, system, latency, 0, 0, status, False, last_error, "")
                    raise LlmError(last_error)

                data = resp.json()
                text = _message_text(data)
                if not text:
                    last_error = "响应里没有文本内容"
                    if attempts > self.cfg.max_retries:
                        self._record(tag, user, system, latency, 0, 0, status, False, last_error, "")
                        raise LlmError(last_error)
                    time.sleep(self._backoff(attempts, None))
                    continue
                usage = data.get("usage") or {}
                prompt_tokens = int(usage.get("prompt_tokens") or 0)
                completion_tokens = int(usage.get("completion_tokens") or 0)
                self._record(tag, user, system, latency, prompt_tokens, completion_tokens,
                             status, True, "", text)
                return ChatResult(text, prompt_tokens, completion_tokens, latency, attempts, status)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                latency = (time.time() - started) * 1000.0
                last_error = f"{type(exc).__name__}: {exc}"
                if attempts > self.cfg.max_retries:
                    self._record(tag, user, system, latency, 0, 0, 0, False, last_error, "")
                    raise LlmError(last_error) from exc
                time.sleep(self._backoff(attempts, None))
            except json.JSONDecodeError as exc:
                latency = (time.time() - started) * 1000.0
                last_error = f"响应不是 JSON: {exc}"
                if attempts > self.cfg.max_retries:
                    self._record(tag, user, system, latency, 0, 0, 0, False, last_error, "")
                    raise LlmError(last_error) from exc
                time.sleep(self._backoff(attempts, None))
        raise LlmError(last_error or "调用失败")

    # ---- 内部 -----------------------------------------------------------
    def _backoff(self, attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return min(self.cfg.retry_base_seconds * (2 ** (attempt - 1)), 60.0)

    def _record(self, tag: str, user: str, system: str, latency_ms: float,
                prompt_tokens: int, completion_tokens: int, status: int,
                ok: bool, error: str, text: str) -> None:
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tag": tag,
            "model": self.cfg.model,
            "latency_ms": round(latency_ms, 1),
            "status": status,
            "ok": ok,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "system_chars": len(system),
            "user_chars": len(user),
            "response_chars": len(text),
            "error": error,
            "response": text[:4000],
        }
        if self.cfg.log_prompts:
            row["system"] = system
            row["user"] = user
        with self._lock:
            self.stats["calls"] += 1
            if not ok:
                self.stats["failures"] += 1
            self.stats["prompt_tokens"] += prompt_tokens
            self.stats["completion_tokens"] += completion_tokens
            self.stats["latency_ms"] += latency_ms
            self._log_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._log_fh.flush()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.stats)


def _chat_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    return base if base.endswith("/chat/completions") else base + "/chat/completions"


def _message_text(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        parts = [p.get("text", "") for p in content if isinstance(p, dict)]
        return "".join(parts).strip()
    if isinstance(content, str):
        return content.strip()
    return str(choices[0].get("text") or "").strip()
