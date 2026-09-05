"""Centralized configuration for sysdig-parser.

All environment-variable resolution lives here so parser and storage layers
share one source of truth.  Includes the stdlib-only .env loader (moved out of
the Neo4j writer: configuration is a cross-cutting concern, not a storage
concern) and the PROGQL_* tunables of the parsing pipeline.

Credentials (NEO4J_* / PG_*) are read by the layers that own them, but are
always loaded from the environment / .env — never hardcoded.
"""

import os
import re
from pathlib import Path
from typing import Optional

# --- flush / batching ---
DEFAULT_FLUSH_EDGE_LIMIT = 50000
FLUSH_EDGE_LIMIT_ENV = "PROGQL_SYSDIG_FLUSH_EDGE_LIMIT"

DEFAULT_NEO4J_BATCH_SIZE = 5000
BATCH_SIZE_ENV = "PROGQL_NEO4J_BATCH_SIZE"

# --- progress reporting ---
DEFAULT_PROGRESS_INTERVAL_SECONDS = 15
PROGRESS_INTERVAL_SECONDS_ENV = "PROGQL_SYSDIG_PROGRESS_INTERVAL_SECONDS"

# --- enter/exit pairing ---
DEFAULT_PAIRING_TOLERANCE_NS = 1000
PAIRING_TOLERANCE_NS_ENV = "PROGQL_SYSDIG_PAIRING_TOLERANCE_NS"

# --- run mode ---
DRY_RUN_ENV = "PROGQL_SYSDIG_DRY_RUN"


def load_dotenv(path: Optional[str] = None) -> None:
    """Minimal .env loader (stdlib only): KEY=VALUE lines, # comments, no variable
    expansion, never overrides existing environment variables.  When ``path`` is not
    given, searches the cwd and its parents for the first existing .env."""
    target: Optional[Path] = None
    if path is not None:
        candidate = Path(path)
        if candidate.is_file():
            target = candidate
    else:
        current = Path.cwd()
        for _ in range(6):  # project layout: .env sits at repo root
            candidate = current / ".env"
            if candidate.is_file():
                target = candidate
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
    if target is None:
        return
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                key, value = match.group(1), match.group(2)
                os.environ.setdefault(key, value)


def resolve_int_env(name: str, default: int, minimum: int) -> int:
    """Read an integer env var; invalid or below-minimum values fall back to
    the default (never raise)."""
    raw = os.environ.get(name)
    if raw is not None:
        try:
            value = int(raw.strip())
            if value >= minimum:
                return value
        except ValueError:
            pass
    return default


def resolve_flush_edge_limit() -> int:
    return resolve_int_env(FLUSH_EDGE_LIMIT_ENV, DEFAULT_FLUSH_EDGE_LIMIT, minimum=1)


def resolve_progress_interval_millis() -> int:
    seconds = resolve_int_env(
        PROGRESS_INTERVAL_SECONDS_ENV, DEFAULT_PROGRESS_INTERVAL_SECONDS, minimum=1
    )
    return seconds * 1000


def resolve_pairing_tolerance_ns() -> int:
    return resolve_int_env(PAIRING_TOLERANCE_NS_ENV, DEFAULT_PAIRING_TOLERANCE_NS, minimum=0)


def resolve_batch_size() -> int:
    return resolve_int_env(BATCH_SIZE_ENV, DEFAULT_NEO4J_BATCH_SIZE, minimum=1)


def resolve_dry_run() -> bool:
    raw = os.environ.get(DRY_RUN_ENV)
    return raw is not None and raw.strip().lower() in ("1", "true", "yes")
