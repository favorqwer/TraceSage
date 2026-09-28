"""provenance-agent：基于 sysdig-parser 溯源图的分层架构攻击溯源 agent。

各层在 `pagent/layers/`（各占一个包），编排在 `pagent/orchestration/`，装配在 `pagent/app.py`，
横切基础设施在 `pagent/core/`。
"""

__version__ = "0.1.0"
