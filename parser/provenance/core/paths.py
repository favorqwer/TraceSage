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


def parse_path_arg(raw: str) -> tuple[str, str]:
    """把事件参数里的路径渲染拆成（显示名, 内核解析后的绝对路径）。

    内核/sysdig 对相对名会写成 `shown(resolved)`，两种实测形态：
      - `.(/srv/www/s8-site/uploads)`            shown `.`、resolved `/srv/.../uploads`
      - `base/1(/var/lib/postgresql/14/main/base/1)` shown `base/1`、resolved `/var/.../base/1`

    判定按渲染语法，不按前缀内容猜：整串以 `)` 结尾，且最后一对括号的内容
    **以 `/` 开头且不含 `)`**，才算注记。这样 `/tmp/a(1)`（括号内容是 `1`）、
    `/tmp/a (copy).txt`（不以 `)` 结尾）都不会被误剥——旧实现的
    “括号前含 `/` 就不剥”会把上面第二种形态整串当成路径（实测 10 个库共
    884 个畸形顶点）。

    返回 ``(shown, resolved)``；没有注记时 ``resolved`` 为空串。
    """
    text = (raw or "").strip()
    if not text.endswith(")"):
        return text, ""
    idx = text.rfind("(")
    if idx < 0:
        return text, ""
    inner = text[idx + 1 : -1]
    if inner.startswith("/") and ")" not in inner:
        return text[:idx], inner
    return text, ""


def path_value(raw: str) -> str:
    """参数里的真实路径（有内核注记取注记里的绝对路径，否则取显示名）。"""
    shown, resolved = parse_path_arg(raw)
    return resolved or shown


def is_unresolved(path: str) -> bool:
    text = (path or "").strip()
    if not text or text.startswith("<"):
        return True
    return text.startswith("?")
