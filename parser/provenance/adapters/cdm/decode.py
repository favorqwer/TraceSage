"""CDM18 记录的 Avro-JSON 解码。

CDM18 的 JSON 序列化是 Avro 的「带类型键」形态，字段值不是裸值：

    {"datum": {"com.bbn.tc.schema.avro.cdm18.Event": {...}},
     "CDMVersion": "18", "source": "SOURCE_LINUX_THEIA"}

    "threadId": {"int": 412}                       # union<int>
    "sequence": {"long": 36}                       # union<long>
    "cmdLine":  {"string": "/bin/sh -e /proc/self/fd/9"}
    "subject":  {"com.bbn.tc.schema.avro.cdm18.UUID": "753366C8-..."}
    "properties": {"map": {"rc": "0", "mode": "0644"}}   # map<string,string>

因此裸取 ``record["threadId"]`` 得到的是 dict 而不是数字。本模块只做这一层解包，
不做任何语义判断，也不缓存任何东西（每个函数都是纯函数，输入一条记录，输出一个值）。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

#: CDM 用全零 uuid 表示「没有客体」。实测 EVENT_BOOT 的 subject 与
#: predicateObject 都是这个值。
NULL_UUID = "00000000-0000-0000-0000-000000000000"

#: Avro union 里可能出现的基础类型键；用于 unwrap。
_SCALAR_KEYS = frozenset(
    {"string", "int", "long", "bytes", "boolean", "float", "double", "null"}
)


def datum_of(raw: bytes) -> tuple[str, dict] | None:
    """一行 JSON -> ``(记录类型短名, 记录体)``。

    记录类型取 ``datum`` 唯一键的最后一段（``...cdm18.Event`` -> ``Event``）。
    解析失败、缺 ``datum``、或 ``datum`` 里有多个键时返回 None（由调用方计入
    ABNORMAL 桶）。
    """
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    datum = payload.get("datum")
    if not isinstance(datum, dict) or len(datum) != 1:
        return None
    key, body = next(iter(datum.items()))
    if not isinstance(body, dict):
        return None
    return key.rsplit(".", 1)[-1], body


def unwrap(value):
    """拆掉 Avro 的 union 包装：``{"int": 412}`` -> 412，``{"map": {...}}`` -> {...}。"""
    if isinstance(value, dict) and len(value) == 1:
        key, inner = next(iter(value.items()))
        if key in _SCALAR_KEYS or key == "map":
            return inner
    return value


def text(value) -> str:
    """取字符串字段；缺失/空/非字符串一律空串（不写 ``"None"``）。"""
    if value is None:
        return ""
    if isinstance(value, dict):
        if len(value) == 1:
            key, inner = next(iter(value.items()))
            if key in _SCALAR_KEYS:
                return "" if inner is None else str(inner)
            return ""  # UUID 包装等：调用方应使用 uuid()
        return ""
    return str(value)


def number(value) -> int | None:
    """取整数字段；缺失或不可解析返回 None（``None`` 表示未观测，不是 0）。"""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        inner = unwrap(value)
        if inner is value:
            return None
        return number(inner)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def mapping(value) -> dict[str, str]:
    """取 ``{"map": {k: v}}`` 形态的属性字典；键值统一转字符串。"""
    if not isinstance(value, dict):
        return {}
    inner = value.get("map")
    if not isinstance(inner, dict):
        return {}
    return {str(key): ("" if item is None else str(item)) for key, item in inner.items()}


def uuid(value) -> str:
    """取 UUID 字段；``null`` 与全零 uuid 都返回空串（表示没有此引用）。"""
    if not isinstance(value, dict):
        return ""
    for key, inner in value.items():
        if key.endswith(".UUID"):
            text_value = "" if inner is None else str(inner)
            return "" if text_value == NULL_UUID else text_value
    return ""


def ns_from_iso(value: str) -> int | None:
    """``2018-04-10T17:30:00Z`` / ``+08:00`` -> 纳秒；空串返回 None。"""
    if not value:
        return None
    token = value.strip()
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(token)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1_000_000_000)


def iso_from_ns(value: int | None) -> str:
    """纳秒 -> ``2018-04-10 17:30:00Z``（UTC，秒级）。"""
    if not value:
        return ""
    moment = datetime.fromtimestamp(value / 1_000_000_000, tz=timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S") + "Z"
