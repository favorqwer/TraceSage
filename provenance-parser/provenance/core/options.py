"""各层配置切片：谁需要什么，就只拿什么。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScapOptions:
    scap: str
    backend: str = "auto"
    sysdig_bin: str = "sysdig"
    wsl_distro: str = ""
    ssh_host: str = ""
    ssh_user: str = ""
    ssh_port: int = 22
    ssh_cache_dir: str = "/tmp/scap_cache"
    ssh_auto_sync: bool = True
    docker_image: str = "sysdig/sysdig:latest"
    max_events: int | None = None
    audit: bool = True


@dataclass(frozen=True, slots=True)
class RunOptions:
    scenario: str
    host_id: str
    dry_run: bool = False
    pair_timeout_ns: int = 5_000_000_000
    pair_pool_max: int = 100_000
    checkpoint_every: int = 1_000_000
    progress_every_s: int = 10


@dataclass(frozen=True, slots=True)
class GraphLimits:
    fd_table_max: int = 4_096
    node_registry_max: int = 3_000_000
    vertex_batch: int = 5_000
    edge_batch: int = 10_000


@dataclass(frozen=True, slots=True)
class EmitOptions:
    keep_payload: bool = True
    payload_max_bytes: int = 80


@dataclass(frozen=True, slots=True)
class Neo4jOptions:
    uri: str = "bolt://127.0.0.1:7687"
    user: str = "neo4j"
    password: str = ""
    database: str = ""
    reset_db: bool = True
    retry_max: int = 5


@dataclass(frozen=True, slots=True)
class ReportOptions:
    scenario: str
    host_id: str
    scap: str
    database: str
    dry_run: bool
    out_dir: str = ""
    node_registry_max: int = 3_000_000

    @property
    def report_dir(self) -> Path:
        base = Path(self.out_dir) if self.out_dir else Path("output/parser-v2") / self.scenario
        return base
