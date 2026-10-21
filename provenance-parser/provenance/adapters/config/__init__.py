"""配置加载适配器：把 TOML 转成 core 可用的内存表。"""

from .tables import load_classifier

__all__ = ["load_classifier"]
