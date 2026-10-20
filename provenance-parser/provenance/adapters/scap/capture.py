"""SCAP 采集适配器：后端选择、模板解码、审计与容器元数据。"""

from __future__ import annotations

from typing import Iterator

from ...core.audit import Audit
from ...core.events import BadRow, EventRow
from ...core.options import ScapOptions
from .audit import run_audit
from .backends import choose_backend, create_scap_source, detect_available_backends
from .template import (
    CONTAINER_TEMPLATE,
    TEMPLATE,
    as_bytes,
    decode_one,
    is_record_start,
)


class ScapCapture:
    def __init__(self, options: ScapOptions) -> None:
        self.options = options
        self._backend: str | None = None

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

    def _source(self, template: str, expression: str | None = None):
        return create_scap_source(
            scap_path=self.options.scap,
            backend=self.backend,
            format_string=template,
            max_events=self.options.max_events,
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
        )

    def containers(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        with self._source(CONTAINER_TEMPLATE, "evt.type=container") as source:
            for raw in source.stream_lines():
                parts = as_bytes(raw).rstrip(b"\r\n").split(b"\t")
                if len(parts) < 5:
                    continue
                vals = [p.decode("utf-8", "replace") for p in parts[:5]]
                out.append(
                    {
                        "id": vals[0],
                        "name": vals[1],
                        "image": vals[2],
                        "privileged": vals[3],
                        "mounts": vals[4],
                    }
                )
        return out

    def audit(self) -> Audit:
        return run_audit(lambda template: self._source(template))

    def events(self) -> Iterator[EventRow | BadRow]:
        line_no = 0
        pending: bytearray | None = None
        with self._source(TEMPLATE) as source:
            for raw in source.stream_lines():
                if not raw:
                    continue
                line_no += 1
                line = as_bytes(raw).rstrip(b"\r\n")
                if is_record_start(line):
                    if pending is not None:
                        yield decode_one(bytes(pending))
                    pending = bytearray(line)
                elif pending is not None:
                    pending += b"\n" + line
                else:
                    yield BadRow(
                        line_no,
                        "OrphanContinuation",
                        line[:200].decode("utf-8", "replace"),
                    )
            if pending is not None:
                yield decode_one(bytes(pending))
