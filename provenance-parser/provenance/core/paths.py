"""路径规范化（纯函数）。

只做字符串层面的规整，不访问文件系统、不解析符号链接（§5.4-3/§8-16）。
"""

from __future__ import annotations


def normalize(path: str, cwd: str = "") -> str:
    if not path:
        return ""
    text = path
    if not text.startswith("/") and cwd:
        text = cwd.rstrip("/") + "/" + text
    parts: list[str] = []
    for seg in text.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts)


def path_value(raw: str) -> str:
    """从 `oldpath=Cu1ADxgn(/dir/x)` 这类渲染里取真实路径。

    判定规则：括号前那一段不含 '/' 才算"显示名"，否则括号属于路径本身
    （`/tmp/a(1)` 不能被截成 `1`）。
    """
    text = raw.strip()
    if not text.endswith(")"):
        return text
    idx = text.rfind("(")
    if idx <= 0:
        return text
    prefix = text[:idx]
    if "/" in prefix:
        return text
    return text[idx + 1 : -1]


def is_unresolved(path: str) -> bool:
    text = (path or "").strip()
    if not text or text.startswith("<"):
        return True
    return text.startswith("?")
