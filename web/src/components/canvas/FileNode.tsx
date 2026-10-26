import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";

export const FileNode = memo(({ data }: { data: any }) => {
  const props = data.properties || {};
  const path = props.path || props.full_identifier || props.name || "文件";

  return (
    <div className="px-6 py-2.5 border-2 border-emerald-500 bg-slate-900/95 text-slate-100 rounded-full shadow-lg min-w-[200px] max-w-[300px] text-center select-none relative transition-all hover:border-emerald-300">
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2.5 !h-2.5 !bg-emerald-400 !border-2 !border-slate-950 !-left-1"
      />

      {/* 文件：仅展示路径 */}
      <div
        className="text-xs font-mono font-bold truncate text-emerald-200 tracking-tight"
        title={path}
      >
        {path}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!w-2.5 !h-2.5 !bg-emerald-400 !border-2 !border-slate-950 !-right-1"
      />
    </div>
  );
});
