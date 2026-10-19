"""因果拓扑枢纽路由器与包管理原子性剪枝器 (CausalPivotRouter)

职责：
1. 识别并阻断包管理器（apt-get, dpkg 等）产生的伴生系统临时碎片（如 .dpkg-new, 帮助手册, /var/cache/ 等）；
2. 保护具备前向因果传递性的有效攻击实体（如场景 4 中的恶意 postinst 脚本）；
3. 结合调查目标（POI 锚点）亲和度，保证受害客体（如场景 1 中的勒索加密文件）绝对保全；
4. 将判为死端碎片的边安全转移至未排除（unexcluded）候选池，绝不静默丢弃。
"""

from typing import Any, Dict, List, Optional, Set, Tuple

PKG_MANAGERS = frozenset({
    "dpkg", "dpkg-deb", "dpkg-split", "dpkg-preconfigure", "mandb", "ldconfig", "ldconfig.real"
})

PKG_INTERNAL_SINKS = (
    ".dpkg-new", ".dpkg-tmp", ".triggers",
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/",
    "/var/cache/man/", "/var/cache/apt/", "/var/lib/apt/lists/"
)


class CausalPivotRouter:
    """因果枢纽路由器：消除死端汇流与包管理伴生碎片。"""

    def __init__(self, poi_anchors: Optional[List[Tuple[Any, Any, Any]]] = None):
        self.poi_dirs: Set[str] = set()
        if poi_anchors:
            for s, _, d in poi_anchors:
                for node in (str(s), str(d)):
                    if "/" in node and not node.startswith("unix:"):
                        self.poi_dirs.add("/".join(node.split("/")[:-1]))

    def is_operational_debris(self, edge: Dict[str, Any]) -> bool:
        """判定一条边是否属于包管理器内部的死端伴生碎片。"""
        s = str(edge.get("src", ""))
        d = str(edge.get("dst", ""))
        sc = str(edge.get("syscall", ""))
        prog_s = s.split("/")[-1]

        # 1. 保护具有命令执行或后门安装属性的实体（如场景 4 中的 postinst）
        if "postinst" in s or "postinst" in d or sc == "execve":
            return False

        # 2. 保护与调查起点（POI）同目录的受害客体（如场景 1 勒索受害文件）
        if any(d.startswith(p_dir) for p_dir in self.poi_dirs if len(p_dir) > 4):
            return False

        # 3. 识别包管理内部辅助进程向系统缓存/文档/临时包文件的读写
        if prog_s in PKG_MANAGERS:
            if any(sink in d for sink in PKG_INTERNAL_SINKS) or d.startswith("pipe:"):
                return True
            if any(sink in d for sink in (".dpkg-new", ".dpkg-tmp", "/usr/share/doc/", "/var/cache/man/")):
                return True

        # 4. 识别 apt-get 自身的包列表索引与缓存读写
        if prog_s == "apt-get" and sc in ("read", "write"):
            if any(d.startswith(p) for p in ("/var/lib/apt/", "/var/cache/apt/", "pipe:")):
                return True

        return False

    def route_confirmed(
        self,
        confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]]
    ) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
        """对已确认边进行因果收敛过滤。

        返回:
            (filtered_confirmed_map, pruned_debris_edges)
        """
        filtered_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        pruned_debris: List[Dict[str, Any]] = []

        for key, edge in confirmed_map.items():
            # 告警事实锚点强制确认，不参与过滤
            if edge.get("class") == "anchor":
                filtered_confirmed[key] = edge
                continue

            if self.is_operational_debris(edge):
                e_pruned = dict(edge)
                e_pruned["origin"] = "kept"
                e_pruned["reason"] = "因果路由器：包管理内部死端伴生碎片，归入未排除"
                pruned_debris.append(e_pruned)
            else:
                filtered_confirmed[key] = edge

        return filtered_confirmed, pruned_debris
