"""单测用的参数文件小工具：把 {段: {键: 值}} 写成一份临时 TOML，并在用例里临时换用它。

生产代码读参数只有一个入口（`common/config.py`），换文件也只有 `settings.use_config`；
测试用它来构造"某一项写成别的值"的场景，退出时自动回到默认那份。
"""

from __future__ import annotations

import contextlib
import pathlib
import tempfile


def write_config(path: pathlib.Path, sections: dict) -> pathlib.Path:
    """写一份最小 TOML（只支持整数、浮点、布尔、字符串）。"""
    lines: list[str] = []
    for section, items in sections.items():
        lines.append(f"[{section}]")
        for key, value in items.items():
            if isinstance(value, bool):
                lines.append(f"{key} = {'true' if value else 'false'}")
            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')
            else:
                lines.append(f"{key} = {value}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@contextlib.contextmanager
def temp_config(sections: dict):
    """临时换一份参数文件跑一段代码，退出时回到默认那份。"""
    import settings as settings

    with tempfile.TemporaryDirectory() as folder:
        path = write_config(pathlib.Path(folder) / "agent.toml", sections)
        settings.use_config(path)
        try:
            yield path
        finally:
            settings.use_config(None)
