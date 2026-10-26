"""TraceSage-Studio 服务端环境配置。"""

from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings

SERVER_DIR = Path(__file__).resolve().parent
REPO_ROOT = SERVER_DIR.parent
NAVIGATOR_DIR = REPO_ROOT / "provenance-navigator"


class Settings(BaseSettings):
    # 服务主机与端口
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # 跨域设置
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Neo4j 数据库连接
    NEO4J_URI: str = "bolt://127.0.0.1:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str
    NEO4J_DATABASE: str = "neo4j"

    # 人在回路 (HITL) 默认租约时限（秒）
    HITL_LEASE_TIMEOUT_SECONDS: int = 300

    # 路径解析
    REPO_ROOT_PATH: Path = REPO_ROOT
    NAVIGATOR_PATH: Path = NAVIGATOR_DIR
    SCENARIOS_FILE_PATH: Path = NAVIGATOR_DIR / "config" / "scenarios.json"
    OUTPUT_RUNS_DIR: Path = REPO_ROOT / "output" / "navigator-runs"

    model_config = {
        "env_file": str(REPO_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
