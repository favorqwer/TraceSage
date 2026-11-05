"""客体 -> 边方向的路由（与对象解析解耦）。

``ObjectResolver`` 只回答“这个 fd/路径是哪个节点”；
本模块回答“这条边是 FileToProcess / ProcessToFile / ProcessToNetwork / NetworkToProcess，
方向是什么”。
"""

from __future__ import annotations

from ..core.events import Call
from ..core.graph import Outcome
from ..core.kinds import Bucket, EdgeClass
from .objects import ResolvedObject


class FlowRouter:
    def flow(
        self,
        ctx,
        out: Outcome,
        call: Call,
        obj: ResolvedObject,
        action: str,
        payload: bool,
        result: int | None,
    ) -> Bucket:
        if obj.kind == "none":
            return obj.bucket

        if obj.kind == "network":
            node = ctx.graph.net_node(obj.key.endpoints, obj.proto)
            if node is None:
                return Bucket.OTHER
            ctx.graph.attach(out, node)
            if action in ("read", "recv"):
                ctx.graph.add(out, ctx.graph.edge(
                    EdgeClass.N2P, "recv", node.key, ctx.key(call),
                    call, result=result, payload=payload,
                ))
            else:
                ctx.graph.add(out, ctx.graph.edge(
                    EdgeClass.P2N, "send", ctx.key(call), node.key,
                    call, result=result, payload=payload,
                ))
            return Bucket.COVERED

        node = ctx.graph.file_node(
            call.container_id, obj.key.path, obj.node_kind
        )
        if node is None:
            return Bucket.OTHER
        ctx.graph.attach(out, node)
        if action in ("read", "stat", "mmap_read", "mmap_exec", "exec", "recv"):
            ctx.graph.add(out, ctx.graph.edge(
                EdgeClass.F2P, action, node.key, ctx.key(call),
                call, result=result, payload=payload,
            ))
        else:
            ctx.graph.add(out, ctx.graph.edge(
                EdgeClass.P2F, action, ctx.key(call), node.key,
                call, result=result, payload=payload,
            ))
        # 只对 /proc/<pid>/mem 派生 ProcessToProcess；普通文件/元数据路径由 policy 直接返回。
        ctx.derive_proc(out, call, node.key, action, ctx.key(call))
        return Bucket.COVERED
