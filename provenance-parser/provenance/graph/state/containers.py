"""容器元数据：R5「分次到达、后补全」。

实测（场景 9）：每个容器两条 container 事件，先占位（挂载表空、privileged=false），
后完整。占位值不得当结论，所以这里只在"有名字或有挂载表"时才接受 privileged。

host_root_rw 判据：挂载表里存在 source="/" 且 rw=true。这是启发式，不是权限证明，
报告里必须与 privileged 一起标注为容器元数据结论（§8-19：缺失即未知，不得当 false）。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ContainerInfo:
    id: str
    name: str = ""
    image: str = ""
    privileged: bool | None = None
    host_root_rw: bool | None = None
    mounts_raw: str = ""
    observations: int = 0
    backfills: int = 0

    def props(self) -> dict[str, object]:
        return {
            "privileged": self.privileged,
            "host_root_rw": self.host_root_rw,
        }


class ContainerState:
    def __init__(self) -> None:
        self._items: dict[str, ContainerInfo] = {}
        self.counts = {
            "observed": 0,
            "backfilled": 0,
            "placeholder_ignored": 0,
            "mounts_parse_failed": 0,
        }

    # -- 解析 ----------------------------------------------------------
    @staticmethod
    def _parse_privileged(raw: str) -> bool | None:
        text = (raw or "").strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
        return None

    def _parse_mounts(self, raw: str) -> tuple[bool | None, bool]:
        """返回 (host_root_rw, 是否解析失败)。"""
        text = (raw or "").strip()
        if not text:
            return None, False
        failed = False
        host_root = False
        for item in text.split(","):
            parts = item.split(":")
            if len(parts) < 5:
                failed = True
                continue
            src, _dst, _mode, rw = parts[0], parts[1], parts[2], parts[3]
            if src == "/" and rw.strip().lower() == "true":
                host_root = True
        return host_root, failed

    # -- 观测 ----------------------------------------------------------
    def observe(self, meta: dict[str, str]) -> ContainerInfo:
        cid = (meta.get("id") or "").strip()
        info = self._items.get(cid)
        if info is None:
            info = ContainerInfo(id=cid)
            self._items[cid] = info
        info.observations += 1
        self.counts["observed"] += 1

        name = (meta.get("name") or "").strip()
        image = (meta.get("image") or "").strip()
        mounts = (meta.get("mounts") or "").strip()
        privileged = self._parse_privileged(meta.get("privileged", ""))
        host_root, failed = self._parse_mounts(mounts)
        if failed:
            self.counts["mounts_parse_failed"] += 1

        complete = bool(name or mounts)
        changed = False
        if name and name != info.name:
            info.name = name
            changed = True
        if image and image != info.image:
            info.image = image
            changed = True
        if complete:
            if privileged is not None and privileged != info.privileged:
                info.privileged = privileged
                changed = True
            if host_root is not None and host_root != info.host_root_rw:
                info.host_root_rw = host_root
                changed = True
            if mounts:
                info.mounts_raw = mounts
        elif privileged is not None:
            # 占位行：privileged=false 没有信息量（R5）
            self.counts["placeholder_ignored"] += 1
        if changed and info.observations > 1:
            info.backfills += 1
            self.counts["backfilled"] += 1
        return info

    def get(self, cid: str) -> ContainerInfo | None:
        return self._items.get(cid)

    def props_for(self, cid: str) -> dict[str, object]:
        info = self._items.get(cid)
        if info is None:
            return {"privileged": None, "host_root_rw": None}
        return info.props()

    def listing(self) -> list[ContainerInfo]:
        return list(self._items.values())

    def stats(self) -> dict[str, int]:
        return dict(self.counts)
