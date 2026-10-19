"""三段式调查报告生成器（ReportBuilder）：

构造符合评测脚本与系统标准的三段报告结构。
包含 edges（已确认）、unexcluded（未排除）、excluded（已排除）和 stats 统计信息。
"""
import json
import time


def build_report(
    scenario_name: str,
    confirmed_edges: list,
    unexcluded_edges: list,
    excluded_edges: list = None,
    pruned_count: int = 0,
    promoted_count: int = 0,
    elapsed_seconds: float = 0.0,
    llm_calls: int = 0,
    llm_enabled: bool = False,
    anchor_confirmed_count: int = 0,
    promoted_by_motif: dict = None,
    mode: str = "hybrid",
    matcher_min_conf: float = None,
    conf_filtered_count: int = 0,
) -> dict:
    """
    构造符合评测脚本与系统标准的三段报告结构。
    包含 edges（已确认）、unexcluded（未排除）、excluded（已排除）和 stats 统计信息。

    统计保真：大模型调用次数必须由调用方传入真实记账值；
    运行模式、是否启用慢速通道、锚点强制确认数、规则命中按基模归因一并如实落盘；
    在线放行门槛（matcher_min_conf）及其否决次数（conf_filtered_count）也必须落盘。
    """
    if excluded_edges is None:
        excluded_edges = []

    # 规范化去重
    unique_confirmed = {}
    for e in confirmed_edges:
        key = (e.get("src"), e.get("syscall"), e.get("dst"))
        unique_confirmed[key] = e

    return {
        "scenario": scenario_name,
        "edges": list(unique_confirmed.values()),
        "unexcluded": unexcluded_edges,
        "excluded": excluded_edges,
        "stats": {
            "mode": mode,
            "confirmed_count": len(unique_confirmed),
            "unexcluded_count": len(unexcluded_edges),
            "excluded_count": len(excluded_edges),
            "pruned_noise_count": pruned_count,
            "promoted_count": promoted_count,
            "promoted_by_motif": promoted_by_motif or {},
            "matcher_min_conf": matcher_min_conf,
            "conf_filtered_count": int(conf_filtered_count),
            "anchor_confirmed_count": anchor_confirmed_count,
            "llm_enabled": bool(llm_enabled),
            "llm_calls": int(llm_calls),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    }


def save_report(report_data: dict, output_file: str):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=1, ensure_ascii=False)
