import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";

export const NetworkNode = memo(({ data }: { data: any }) => {
  const props = data.properties || {};
  const endpoints =
    props.endpoints || props.full_identifier || props.name || "0.0.0.0:0";

  return (
    <div className="relative w-[240px] h-[70px] flex items-center justify-center select-none group">
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2.5 !h-2.5 !bg-purple-400 !border-2 !border-slate-950 !-left-1 z-20"
      />

      {/* 网络：菱形 (SVG 矢量多边形) */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none"
        viewBox="0 0 240 70"
      >
        <polygon
          points="120,3 237,35 120,67 3,35"
          className="fill-slate-900/95 stroke-purple-500 group-hover:stroke-purple-300 transition-colors"
          strokeWidth="2"
        />
      </svg>

      {/* 网络：仅展示 IP 和端口四元组 */}
      <div
        className="relative z-10 px-8 text-center max-w-[180px] text-xs font-mono font-bold truncate text-purple-200 tracking-tight"
        title={endpoints}
      >
        {endpoints}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!w-2.5 !h-2.5 !bg-purple-400 !border-2 !border-slate-950 !-right-1 z-20"
      />
    </div>
  );
});
