"""运行配置：只在这里读环境变量，并拆成各层需要的切片。"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from pathlib import Path

from .core.options import (
    EmitOptions,
    GraphLimits,
    Neo4jOptions,
    ReportOptions,
    RunOptions,
    ScapOptions,
)


def load_dotenv(path: str | None = None) -> None:
    """最小 .env 读取器（stdlib）：KEY=VALUE，不覆盖已存在的环境变量。"""
    target: Path | None = None
    if path:
        candidate = Path(path)
        if candidate.is_file():
            target = candidate
    else:
        current = Path(__file__).resolve().parent
        for _ in range(6):
            candidate = current / ".env"
            if candidate.is_file():
                target = candidate
                break
            current = current.parent
    if target is None:
        return
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if m:
            os.environ.setdefault(m.group(1), m.group(2))


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw:
        try:
            value = int(raw.strip())
            if value >= minimum:
                return value
        except ValueError:
            pass
    return default


@dataclass(frozen=True, slots=True)
class Settings:
    scenario: str
    data_dir: str
    scap: ScapOptions
    run: RunOptions
    graph: GraphLimits
    emit: EmitOptions
    neo4j: Neo4jOptions
    report: ReportOptions

    @property
    def database(self) -> str:
        return self.neo4j.database or f"attack-{self.scenario.lower().replace('_', '-')}"

    @property
    def report_dir(self) -> Path:
        return self.report.report_dir

    def validate(self) -> None:
        # SSH 可以用远端绝对路径，auto 也可能落到 SSH/WSL；文件存在性
        # 交给具体后端检查，避免把合法的远端路径误判为本地文件缺失。
        if self.scap.backend in ("local", "wsl", "docker") and not Path(self.scap.scap).exists():
            raise FileNotFoundError(f"捕获文件不存在：{self.scap.scap}")
        if not self.run.dry_run and not self.neo4j.password:
            raise ValueError("缺少 NEO4J_PASSWORD；或加 --dry-run 只解析不写库")

    @classmethod
    def from_env(cls, scenario: str, scap: str, host_id: str = "") -> "Settings":
        load_dotenv()
        database = f"attack-{scenario.lower().replace('_', '-')}"
        data_dir = str(Path(__file__).resolve().parent.parent / "data")
        return cls(
            scenario=scenario,
            data_dir=data_dir,
            scap=ScapOptions(
                scap=scap,
                backend=os.environ.get("PARSER_BACKEND", "auto"),
                sysdig_bin=os.environ.get("PARSER_SYSDIG_BIN", "sysdig"),
                wsl_distro=os.environ.get("PARSER_WSL_DISTRO", ""),
                ssh_host=os.environ.get("PARSER_SSH_HOST", ""),
                ssh_user=os.environ.get("PARSER_SSH_USER", ""),
                ssh_port=_int_env("PARSER_SSH_PORT", 22, 1),
                ssh_cache_dir=os.environ.get(
                    "PARSER_SSH_CACHE_DIR", "/tmp/scap_cache"
                ),
                ssh_auto_sync=(
                    os.environ.get("PARSER_SSH_AUTO_SYNC", "1").strip().lower()
                    not in ("0", "false", "no", "off")
                ),
            ),
            run=RunOptions(
                scenario=scenario,
                host_id=host_id or scenario,
                pair_pool_max=_int_env("PARSER_PAIR_POOL_MAX", 100_000, 100),
                checkpoint_every=_int_env(
                    "PARSER_CHECKPOINT_EVERY", 1_000_000, 1
                ),
            ),
            graph=GraphLimits(
                fd_table_max=_int_env("PARSER_FD_TABLE_MAX", 4096, 16),
                vertex_batch=_int_env("PARSER_VERTEX_BATCH", 5_000, 1),
                edge_batch=_int_env("PARSER_EDGE_BATCH", 10_000, 1),
            ),
            emit=EmitOptions(),
            neo4j=Neo4jOptions(
                uri=os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687"),
                user=os.environ.get("NEO4J_USER", "neo4j"),
                password=os.environ.get("NEO4J_PASSWORD", ""),
                database=database,
            ),
            report=ReportOptions(
                scenario=scenario,
                host_id=host_id or scenario,
                scap=scap,
                database=database,
                dry_run=False,
            ),
        )

    def with_neo4j_database(self, database: str) -> "Settings":
        return replace(
            self,
            neo4j=replace(self.neo4j, database=database),
            report=replace(self.report, database=database),
        )
