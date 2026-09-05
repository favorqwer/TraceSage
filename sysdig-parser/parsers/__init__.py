"""TraceSage sysdig-parser package.

分层结构：
    pipeline/   解析管线（主循环、进出配对、实体注册、边缓冲）
    model/      纯图模型（顶点、EntityNode、EventEdge）
    jsonl/      Sysdig JSONL 行级解析（记录解码、args 字段抽取）
    dispatch/   系统调用分发（Fingerprint/SystemCall、动作注册）
    storage/    Neo4j 批量写入
    config.py   环境变量/.env 配置（横切）
    reporting.py 进度与跳过行上报（横切）
"""

from .config import load_dotenv
from .pipeline.parser import SysdigLogParser
from .storage.neo4j_writer import Neo4jWriter

__all__ = ["SysdigLogParser", "Neo4jWriter", "load_dotenv"]
