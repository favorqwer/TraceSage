"""SCAP 采集适配器：后端选择、模板解码、审计与容器元数据。"""

from __future__ import annotations

from typing import Iterator

from ...core.events import BadRow, EventRow
from ...core.options import ScapOptions
from .backends import choose_backend, create_scap_source, detect_available_backends
from .template import (
    CONTAINER_MOUNT_START,
    CONTAINER_MOUNT_STRIDE,
    CONTAINER_MOUNTS_INDEX,
    CONTAINER_TEMPLATE,
    MOUNT_SLOTS,
    STAR_TEMPLATE,
    as_bytes,
    container_na,
    decode_one,
    is_record_start,
)


class ScapCapture:
    def __init__(self, options: ScapOptions) -> None:
        self.options = options
        self._backend: str | None = None
        self._star_checked: bool | None = None

    @property
    def backend(self) -> str:
        if self._backend is None:
            self._backend = self._resolve_backend()
        return self._backend

    def _resolve_backend(self) -> str:
        if self.options.backend != "auto":
            return self.options.backend
        readiness = detect_available_backends(
            ssh_host=self.options.ssh_host,
            ssh_user=self.options.ssh_user,
            ssh_port=self.options.ssh_port,
            sysdig_bin=self.options.sysdig_bin,
            wsl_distribution=self.options.wsl_distro,
        )
        return choose_backend(readiness)

    def _make_source(self, template: str, expression: str | None = None,
                     max_events: int | None = None, base64_buffer: bool = False):
        return create_scap_source(
            scap_path=self.options.scap,
            backend=self.backend,
            format_string=template,
            max_events=self.options.max_events if max_events is None else max_events,
            json_output=False,
            expression=expression,
            sysdig_bin=self.options.sysdig_bin,
            ssh_host=self.options.ssh_host,
            ssh_user=self.options.ssh_user,
            ssh_port=self.options.ssh_port,
            ssh_cache_dir=self.options.ssh_cache_dir,
            ssh_auto_sync=self.options.ssh_auto_sync,
            wsl_distribution=self.options.wsl_distro,
            docker_image=self.options.docker_image,
            base64_buffer=base64_buffer,
        )

    def _source(self, template: str, expression: str | None = None,
                base64_buffer: bool = False):
        return self._make_source(
            template, expression, self.options.max_events, base64_buffer
        )

    def _ensure_star(self) -> None:
        """探测 sysdig 是否支持格式串最前面的 *；不支持就明确阻断。"""
        if self._star_checked is not None:
            return
        source = self._make_source("*%evt.num", max_events=1)
        with source:
            first = next(source.stream_lines(), None)
        if first is None:
            self._star_checked = True
            return
        text = as_bytes(first).strip()
        self._star_checked = bool(text) and not text.startswith(b"*") and text.split(b"	")[0].isdigit()
        if not self._star_checked:
            raise RuntimeError(
                "当前 sysdig 不支持格式串最前面的 *（无法在条件字段缺失时保留整行）；"
                "请升级 sysdig 或回退到旧的多趟审计模式。"
            )

    def containers(self) -> list[dict[str, object]]:
        self._ensure_star()
        out: list[dict[str, object]] = []
        with self._source(CONTAINER_TEMPLATE, "evt.type=container") as source:
            for raw in source.stream_lines():
                parts = as_bytes(raw).rstrip(b"\r\n").split(b"\t")
                if len(parts) <= CONTAINER_MOUNTS_INDEX:
                    continue
                vals = [
                    container_na(p.decode("utf-8", "replace"))
                    for p in parts
                ]
                indexed: list[dict[str, str]] = []
                for i in range(MOUNT_SLOTS):
                    base = CONTAINER_MOUNT_START + i * CONTAINER_MOUNT_STRIDE
                    source_path = vals[base]
                    dest_path = vals[base + 1]
                    if not source_path and not dest_path:
                        continue
                    indexed.append(
                        {
                            "source": source_path,
                            "dest": dest_path,
                            "rdwr": vals[base + 2],
                            "mode": vals[base + 3],
                            "propagation": vals[base + 4],
                        }
                    )
                out.append(
                    {
                        "id": vals[1],
                        "name": vals[2],
                        "image": vals[3],
                        "privileged": vals[4],
                        "mounts": vals[CONTAINER_MOUNTS_INDEX],
                        "mounts_indexed": indexed,
                    }
                )
        return out

    def events(self) -> Iterator[EventRow | BadRow]:
        self._ensure_star()
        line_no = 0
        pending: bytes | None = None
        with self._source(STAR_TEMPLATE, base64_buffer=True) as source:
            for chunk in source.stream_chunks():
                for raw in chunk:
                    if not raw:
                        continue
                    line_no += 1
                    line = raw[:-1] if raw.endswith(b"\r") else raw
                    if is_record_start(line):
                        if pending is not None:
                            yield decode_one(pending)
                        pending = line
                    elif pending is not None:
                        pending = pending + b"\n" + line
                    else:
                        yield BadRow(
                            line_no,
                            "OrphanContinuation",
                            line[:200].decode("utf-8", "replace"),
                        )
            if pending is not None:
                yield decode_one(pending)
