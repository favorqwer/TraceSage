import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";

export const ProcessNode = memo(({ data }: { data: any }) => {
  const props = data.properties || {};
  const exePath =
    props.exe_path ||
    (props.full_identifier && props.full_identifier.startsWith("/") ? props.full_identifier : "") ||
    props.name ||
    "进程";

  return (
    <div className="px-4 py-2 border-2 border-sky-500 bg-slate-900/95 text-slate-100 rounded-none shadow-lg min-w-[180px] max-w-[270px] text-center select-none relative transition-all hover:border-sky-300">
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2.5 !h-2.5 !bg-sky-400 !border-2 !border-slate-950 !-left-1.5"
      />

      {/* 进程：仅展示执行路径 */}
      <div
        className="text-xs font-mono font-bold truncate text-sky-200 tracking-tight"
        title={exePath}
      >
        {exePath}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!w-2.5 !h-2.5 !bg-sky-400 !border-2 !border-slate-950 !-right-1.5"
      />
    </div>
  );
});
