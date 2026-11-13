"""流水线运行时上下文 (PipelineContext)。

通过显式上下文对象在流水线各阶段间流转状态，杜绝全局变量与模块级可变状态污染。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from llm.client import LlmBudget


@dataclass
class PipelineConfig:
    """流水线配置参数。"""
    variant: str = "v5_rag_hier"
    use_motif_evidence: bool = False
    real_2hop: bool = True
    content_binding: bool = False
    coverage_min: float = 0.5
    split_evidence: bool = False
    anchor_pair_confirm: bool = False
    subgraph_evidence: bool = False
    structured_output: bool = False
    prompt_file: str = "system_judge.md"


@dataclass
class PipelineContext:
    """单场景调查运行时的完整生命周期上下文。"""
    scenario: str
    fold_lib_path: str
    out_path: str
    config: PipelineConfig = field(default_factory=PipelineConfig)
    budget: LlmBudget = field(default_factory=LlmBudget)
    t0: float = field(default_factory=time.time)

    # 运行期状态
    matcher: Optional[Any] = None
    parent_map: Dict[str, str] = field(default_factory=dict)
    rule_evidence_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = field(default_factory=dict)
    anchor_keys: Set[Tuple[Any, Any, Any]] = field(default_factory=set)
    anchor_triples: List[Tuple[Any, Any, Any]] = field(default_factory=list)
    audit: Dict[str, Any] = field(default_factory=dict)
