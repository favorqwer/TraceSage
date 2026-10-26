import React, { useEffect, useRef, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  BackgroundVariant,
} from "@xyflow/react";
import { ProcessNode } from "./ProcessNode";
import { FileNode } from "./FileNode";
import { NetworkNode } from "./NetworkNode";
import { useInvestigationStore } from "../../store/useInvestigationStore";

const nodeTypes = {
  process: ProcessNode,
  file: FileNode,
  network: NetworkNode,
};

const proOptions = { hideAttribution: true };

export const GraphCanvas: React.FC = () => {
  const { nodesMap, edgesMap } = useInvestigationStore();
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([]);
  const workerRef = useRef<Worker | null>(null);
  const flowInstanceRef = useRef<any>(null);

  // 初始化 Web Worker 进行离屏 Dagre 拓扑布局计算
  useEffect(() => {
    workerRef.current = new Worker(
      new URL("../../workers/layout.worker.ts", import.meta.url),
      { type: "module" }
    );

    workerRef.current.onmessage = (e: MessageEvent) => {
      const { nodes: layoutedNodes, edges: layoutedEdges } = e.data;
      setNodes(layoutedNodes);
      setEdges(layoutedEdges);

      // 拓扑更新后自动执行视口自适应居中
      setTimeout(() => {
        flowInstanceRef.current?.fitView({ padding: 0.18, duration: 300 });
      }, 50);
    };

    return () => {
      workerRef.current?.terminate();
    };
  }, [setNodes, setEdges]);

  // 当图数据变化时，通知 Worker 重排
  useEffect(() => {
    if (nodesMap.size === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const rawNodes = Array.from(nodesMap.values()).map((n) => {
      let type = "process";
      if (n.label === "File") type = "file";
      if (n.label === "Network") type = "network";

      return {
        id: n.id,
        type,
        data: n,
        position: { x: 0, y: 0 },
      };
    });

    const rawEdges = Array.from(edgesMap.values()).map((e) => {
      const isConfirmed = e.status === "confirmed";
      const strokeColor = isConfirmed ? "#f43f5e" : "#64748b";
      // 边上仅展示 action 属性
      const labelText = e.action || e.syscall || "unknown";

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "smoothstep",
        label: labelText,
        animated: false, // 消除流动动画，提升拖拽与缩放性能
        style: {
          stroke: strokeColor,
          strokeWidth: isConfirmed ? 2.0 : 1.2,
          strokeDasharray: isConfirmed ? undefined : "4 4",
        },
        labelStyle: {
          fill: isConfirmed ? "#fecdd3" : "#cbd5e1",
          fontSize: 10,
          fontWeight: 600,
          fontFamily: "ui-monospace, monospace",
        },
        labelBgStyle: {
          fill: "#090d16",
          fillOpacity: 0.9,
        },
        labelBgPadding: [6, 3] as [number, number],
        labelBgBorderRadius: 4,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 14,
          height: 14,
          color: strokeColor,
        },
      };
    });

    workerRef.current?.postMessage({ nodes: rawNodes, edges: rawEdges });
  }, [nodesMap, edgesMap, setNodes, setEdges]);

  const onInit = useCallback((instance: any) => {
    flowInstanceRef.current = instance;
    instance.fitView({ padding: 0.18 });
  }, []);

  return (
    <div className="w-full h-full bg-[#030712] relative select-none">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        onInit={onInit}
        fitView
        fitViewOptions={{ padding: 0.18, minZoom: 0.25, maxZoom: 1.0 }}
        minZoom={0.08}
        maxZoom={2.5}
        onlyRenderVisibleElements={false}
        proOptions={proOptions}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1.2}
          color="#1e293b"
        />

        <Controls
          position="bottom-left"
          className="!bg-slate-900/90 !backdrop-blur-md !border !border-slate-800 !text-slate-300 !rounded-xl !shadow-2xl overflow-hidden !m-4"
        />

        <MiniMap
          position="bottom-right"
          style={{
            width: 190,
            height: 110,
            backgroundColor: "#090d16",
            border: "1px solid #1e293b",
            borderRadius: "10px",
            boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.7)",
          }}
          nodeColor={(node) => {
            if (node.type === "process") return "#38bdf8";
            if (node.type === "file") return "#34d399";
            return "#c084fc";
          }}
          nodeStrokeWidth={2}
          maskColor="rgba(3, 7, 18, 0.75)"
          className="!m-4"
        />
      </ReactFlow>
    </div>
  );
};
