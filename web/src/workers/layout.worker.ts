import dagre from "dagre";

interface LayoutMessage {
  nodes: Array<{ id: string; type?: string; [key: string]: any }>;
  edges: Array<{ id: string; source: string; target: string; [key: string]: any }>;
}

self.onmessage = (e: MessageEvent<LayoutMessage>) => {
  const { nodes, edges } = e.data;
  if (!nodes || nodes.length === 0) {
    self.postMessage({ nodes: [], edges: [] });
    return;
  }

  const g = new dagre.graphlib.Graph();
  g.setGraph({
    rankdir: "LR",
    nodesep: 35,
    ranksep: 90,
    marginx: 30,
    marginy: 30,
  });
  g.setDefaultEdgeLabel(() => ({}));

  // 登记所有顶点尺寸
  nodes.forEach((node) => {
    const isNetwork = node.data?.label === "Network" || node.type === "network";
    const width = 240;
    const height = isNetwork ? 70 : 44;
    g.setNode(node.id, { width, height });
  });

  // 登记所有有向关系边（过滤完全自环）
  const validEdges = edges.filter(
    (edge) => edge.source && edge.target && edge.source !== edge.target
  );

  validEdges.forEach((edge) => {
    g.setEdge(edge.source, edge.target);
  });

  try {
    dagre.layout(g);

    let unplacedIdx = 0;
    const layoutedNodes = nodes.map((node) => {
      const nodeWithPos = g.node(node.id);
      if (!nodeWithPos || isNaN(nodeWithPos.x) || isNaN(nodeWithPos.y)) {
        // 孤立未连边节点按整齐矩阵排布在下方
        const x = (unplacedIdx % 3) * 280 + 50;
        const y = Math.floor(unplacedIdx / 3) * 100 + 400;
        unplacedIdx++;
        return {
          ...node,
          position: { x, y },
        };
      }
      return {
        ...node,
        position: {
          x: nodeWithPos.x - nodeWithPos.width / 2,
          y: nodeWithPos.y - nodeWithPos.height / 2,
        },
      };
    });

    self.postMessage({ nodes: layoutedNodes, edges });
  } catch (err) {
    console.error("Layout calculation error in worker:", err);
    // 降级使用规则网格布局
    const fallbackNodes = nodes.map((n, idx) => ({
      ...n,
      position: { x: (idx % 4) * 280 + 50, y: Math.floor(idx / 4) * 110 + 50 },
    }));
    self.postMessage({ nodes: fallbackNodes, edges });
  }
};
