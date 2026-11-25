"""Versioned identity of an exact model request."""
import hashlib
import json
from pathlib import Path

PROTOCOL = "triplet-v1"
ENDPOINT_IDENTITY = "typed-endpoints-v1"


def request_identity(cfg, scenario: str, system: str, user: str) -> dict:
    request = [scenario, cfg.model, cfg.base_url, cfg.temperature, cfg.max_tokens,
               cfg.response_format_json, cfg.extra_body, system, user]
    digest = hashlib.sha256(json.dumps(request, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {"input_protocol": PROTOCOL, "endpoint_identity": ENDPOINT_IDENTITY,
            "scenario": scenario, "model": cfg.model, "request_sha256": digest}


def load_checkpoint(path: Path, identity: dict) -> dict | None:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict) or record.get("error"):
        return None
    return record if all(record.get(key) == value for key, value in identity.items()) else None


def write_checkpoint(path: Path, record: dict) -> None:
    staged = path.with_suffix(".tmp")
    staged.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    staged.replace(path)
