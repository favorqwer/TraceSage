"""纯 LLM 溯源基线：配置加载。

只读仓库根目录 .env 与 experiments/plain_llm/config.yaml，不依赖 provenance 包。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Optional

import yaml

MODULE_ROOT = Path(__file__).resolve().parents[1]      # experiments/plain_llm
REPO_ROOT = Path(__file__).resolve().parents[3]        # 仓库根目录


def load_dotenv(path: Path = REPO_ROOT / ".env") -> dict[str, str]:
    """读取 KEY=VALUE 形式的 .env；注释与空行跳过。"""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def _abs(value: str | Path, base: Path = REPO_ROOT) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (base / p)


@dataclass(frozen=True)
class Config:
    model: str
    base_url: str
    api_key: str
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    extra_headers: dict[str, str] = None  # type: ignore[assignment]
    extra_body: dict[str, Any] = None  # type: ignore[assignment]
    response_format_json: bool = False
    chunk_size: int = 200
    assemble_chunk: int = 150
    concurrency: int = 4
    max_retries: int = 3
    retry_base_seconds: float = 2.0
    request_timeout: float = 180.0
    log_prompts: bool = True
    payload_preview_chars: int = 48
    max_line_chars: int = 320
    output_root: Path = MODULE_ROOT / "output"
    prompt_dir: Path = MODULE_ROOT / "prompts"
    scenarios_file: Path = REPO_ROOT / "provenance" / "config" / "scenarios.json"
    neo4j_uri: str = "bolt://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    config_path: Optional[Path] = None

    def describe(self) -> dict[str, Any]:
        """写进 manifest 的配置快照（不含密钥）。"""
        return {
            "model": self.model,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "extra_headers": sorted(self.extra_headers or {}),
            "extra_body": self.extra_body or {},
            "response_format_json": self.response_format_json,
            "chunk_size": self.chunk_size,
            "assemble_chunk": self.assemble_chunk,
            "concurrency": self.concurrency,
            "max_retries": self.max_retries,
            "retry_base_seconds": self.retry_base_seconds,
            "request_timeout": self.request_timeout,
            "log_prompts": self.log_prompts,
            "payload_preview_chars": self.payload_preview_chars,
            "max_line_chars": self.max_line_chars,
            "output_root": str(self.output_root),
            "prompt_dir": str(self.prompt_dir),
            "scenarios_file": str(self.scenarios_file),
            "neo4j_uri": self.neo4j_uri,
            "neo4j_database_user": self.neo4j_user,
        }


def load_config(path: str | Path | None = None, **overrides: Any) -> Config:
    """加载配置：.env 提供端点与模型，YAML 提供运行参数，overrides 最高优先级。"""
    cfg_path = _abs(path) if path else (MODULE_ROOT / "config.yaml")
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    env = {**load_dotenv(), **{k: v for k, v in os.environ.items() if k.startswith(("OPENAI_", "NEO4J_"))}}

    model = str(raw.get("model") or env.get("OPENAI_MODEL") or "").strip()
    base_url = str(raw.get("base_url") or env.get("OPENAI_BASE_URL") or "").strip()
    api_key_env = str(raw.get("api_key_env") or "OPENAI_API_KEY")
    api_key = env.get(api_key_env, "").strip()
    if not model:
        raise ValueError("缺少模型名：config.yaml 的 model 为空，且 .env 没有 OPENAI_MODEL")
    if not base_url:
        raise ValueError("缺少端点：config.yaml 的 base_url 为空，且 .env 没有 OPENAI_BASE_URL")
    if not api_key:
        raise ValueError(f"缺少密钥：环境变量 {api_key_env} 为空")

    values: dict[str, Any] = {
        "model": model,
        "base_url": base_url,
        "api_key": api_key,
        "temperature": float(raw.get("temperature", 0.0)),
        "max_tokens": raw.get("max_tokens"),
        "response_format_json": bool(raw.get("response_format_json", False)),
        "chunk_size": int(raw.get("chunk_size", 200)),
        "assemble_chunk": int(raw.get("assemble_chunk", 150)),
        "concurrency": int(raw.get("concurrency", 4)),
        "max_retries": int(raw.get("max_retries", 3)),
        "retry_base_seconds": float(raw.get("retry_base_seconds", 2.0)),
        "request_timeout": float(raw.get("request_timeout", 180)),
        "log_prompts": bool(raw.get("log_prompts", True)),
        "payload_preview_chars": int(raw.get("payload_preview_chars", 48)),
        "max_line_chars": int(raw.get("max_line_chars", 320)),
        "output_root": _abs(raw.get("output_root", "output/plain-llm-runs")),
        "prompt_dir": _abs(raw.get("prompt_dir", "experiments/plain_llm/prompts")),
        "scenarios_file": _abs(raw.get("scenarios_file", "provenance/config/scenarios.json")),
        "neo4j_uri": str(raw.get("neo4j_uri") or env.get("NEO4J_URI") or "bolt://127.0.0.1:7687"),
        "neo4j_user": str(raw.get("neo4j_user") or env.get("NEO4J_USER") or "neo4j"),
        "neo4j_password": str(raw.get("neo4j_password") or env.get("NEO4J_PASSWORD") or ""),
        "config_path": cfg_path,
    }
    headers = dict(raw.get("extra_headers") or {})
    if "opencode.ai" in base_url:
        headers.setdefault("x-opencode-session",
                           str(raw.get("opencode_session") or "ses_tracesage_plainllm"))
    values["extra_headers"] = headers
    values["extra_body"] = dict(raw.get("extra_body") or {})
    values.update({k: v for k, v in overrides.items() if v is not None})
    return Config(**values)


def with_overrides(cfg: Config, **overrides: Any) -> Config:
    clean = {k: v for k, v in overrides.items() if v is not None}
    return replace(cfg, **clean) if clean else cfg
