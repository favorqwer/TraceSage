import React, { useEffect, useRef, useState } from "react";
import {
  Zap,
  Activity,
  Terminal,
  BrainCircuit,
  CheckCircle2,
} from "lucide-react";
import { useInvestigationStore } from "../../store/useInvestigationStore";

export const ReasoningPanel: React.FC = () => {
  const { stage, matchedRules, stats, edgesMap, nodesMap, logs, progress } =
    useInvestigationStore();
  const [activeTab, setActiveTab] = useState<"terminal" | "motifs" | "llm">("terminal");
  const logEndRef = useRef<HTMLDivElement | null>(null);

  // 自动滚动到最新控制台日志
  useEffect(() => {
    if (activeTab === "terminal") {
      logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, activeTab]);

  const stages = [
    { key: "EXTRACTING_CLOSURE", label: "因果闭包" },
    { key: "MATCHING_RULES", label: "符号基模" },
    { key: "LLM_ARBITRATING", label: "意图仲裁" },
    { key: "COMPLETED", label: "调查收敛" },
  ];

  const confirmedCount = Array.from(edgesMap.values()).filter(
    (e) => e.status === "confirmed"
  ).length;

  const formatLogTime = (ns: number) => {
    if (!ns) return "";
    const ms = ns / 1_000_000;
    const date = new Date(ms);
    return date.toLocaleTimeString("zh-CN", { hour12: false });
  };

  return (
    <div className="w-[380px] min-w-[380px] max-w-[380px] h-full bg-[#0b0f19] border-l border-slate-800 flex flex-col text-slate-100 select-none shadow-2xl shrink-0 overflow-hidden">
      {/* 顶部标题与阶段步进器 */}
      <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/50 shrink-0">
        <div className="flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h2 className="text-xs font-bold text-slate-200 tracking-wide uppercase">
              调查推理遥测中枢
            </h2>
          </div>
          {progress && progress.percent < 100 && (
            <span className="text-[11px] font-mono text-sky-400 font-bold animate-pulse">
              {progress.percent}%
            </span>
          )}
        </div>

        {/* 细粒度阶段进度指示 */}
        <div className="grid grid-cols-4 gap-1 mb-2">
          {stages.map((s, idx) => {
            const isCurrent = stage === s.key;
            const isDone =
              stage === "COMPLETED" ||
              (idx === 0 &&
                [
                  "MATCHING_RULES",
                  "LLM_ARBITRATING",
                  "AWAITING_HITL",
                  "COMPLETED",
                ].includes(stage)) ||
              (idx === 1 &&
                ["LLM_ARBITRATING", "AWAITING_HITL", "COMPLETED"].includes(
                  stage
                )) ||
              (idx === 2 && ["COMPLETED"].includes(stage));

            return (
              <div
                key={s.key}
                className={`py-1 text-center rounded text-[9px] font-semibold transition ${
                  isCurrent
                    ? "bg-sky-600 text-white shadow-md shadow-sky-500/40 ring-1 ring-sky-400"
                    : isDone
                    ? "bg-emerald-950/70 text-emerald-300 border border-emerald-800/50"
                    : "bg-slate-950/60 text-slate-500 border border-slate-800/40"
                }`}
              >
                {s.label}
              </div>
            );
          })}
        </div>

        {/* 进度百分比条 */}
        {progress && progress.percent < 100 && (
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
            <div
              className="bg-sky-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${progress.percent}%` }}
            />
          </div>
        )}
      </div>

      {/* 核心指标微调卡片 */}
      <div className="p-3 grid grid-cols-3 gap-2 border-b border-slate-800/80 bg-slate-950/40 text-center shrink-0">
        <div className="bg-slate-900/80 p-1.5 rounded-lg border border-slate-800">
          <div className="text-[9px] text-slate-400 font-medium">拓扑节点</div>
          <div className="text-sm font-bold text-sky-300 font-mono">
            {nodesMap.size}
          </div>
        </div>
        <div className="bg-slate-900/80 p-1.5 rounded-lg border border-slate-800">
          <div className="text-[9px] text-slate-400 font-medium">候选边数</div>
          <div className="text-sm font-bold text-slate-200 font-mono">
            {stats.raw_candidate_edges ?? edgesMap.size}
          </div>
        </div>
        <div className="bg-rose-950/20 p-1.5 rounded-lg border border-rose-500/40">
          <div className="text-[9px] text-rose-300 font-bold">确诊攻击边</div>
          <div className="text-sm font-bold text-rose-400 font-mono">
            {confirmedCount}
          </div>
        </div>
      </div>

      {/* 选项卡导航 */}
      <div className="flex border-b border-slate-800 bg-slate-950/60 px-2 pt-1.5 text-xs shrink-0">
        <button
          onClick={() => setActiveTab("terminal")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t-lg font-bold text-[11px] transition shrink-0 ${
            activeTab === "terminal"
              ? "bg-[#060a12] text-emerald-400 border-t border-x border-slate-800"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>控制台终端</span>
          <span className="text-[9px] px-1 rounded bg-slate-800 text-slate-300 ml-0.5 font-mono">
            {logs.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("motifs")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t-lg font-bold text-[11px] transition shrink-0 ${
            activeTab === "motifs"
              ? "bg-[#060a12] text-amber-400 border-t border-x border-slate-800"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>检出基模</span>
          <span className="text-[9px] px-1 rounded bg-slate-800 text-slate-300 ml-0.5 font-mono">
            {matchedRules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("llm")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t-lg font-bold text-[11px] transition shrink-0 ${
            activeTab === "llm"
              ? "bg-[#060a12] text-sky-400 border-t border-x border-slate-800"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <BrainCircuit className="w-3.5 h-3.5" />
          <span>慢速仲裁</span>
        </button>
      </div>

      {/* 选项卡内容区（宽度绝对锁定 380px，杜绝任何跳动和挤压） */}
      <div className="flex-1 overflow-hidden bg-[#060a12] flex flex-col min-w-0 w-full">
        {activeTab === "terminal" && (
          <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed space-y-1.5 w-full overflow-x-hidden">
            {logs.length === 0 ? (
              <div className="text-slate-600 text-center py-10 italic">
                待调查任务启动后建立推演日志流...
              </div>
            ) : (
              logs.map((log, idx) => {
                const color =
                  log.level === "error"
                    ? "text-rose-400 bg-rose-950/20"
                    : log.level === "warn"
                    ? "text-amber-300"
                    : log.level === "success"
                    ? "text-emerald-400"
                    : "text-slate-300";

                return (
                  <div key={idx} className={`p-1 rounded break-words break-all ${color} border border-transparent hover:border-slate-800/60`}>
                    <span className="text-slate-500 mr-1.5 select-none text-[10px]">
                      [{formatLogTime(log.timestamp_ns)}]
                    </span>
                    <span>{log.message}</span>
                  </div>
                );
              })
            )}
            <div ref={logEndRef} />
          </div>
        )}

        {activeTab === "motifs" && (
          <div className="flex-1 overflow-y-auto p-3 space-y-2 w-full overflow-x-hidden">
            {matchedRules.length === 0 ? (
              <div className="text-[11px] text-slate-600 text-center py-10 italic">
                等待因果基模检出...
              </div>
            ) : (
              matchedRules.map((rule, idx) => (
                <div
                  key={`${rule.edge_id}_${idx}`}
                  className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 text-xs flex items-start justify-between gap-2 w-full min-w-0"
                >
                  <div className="min-w-0 flex-1 overflow-hidden">
                    <div className="text-slate-200 font-mono text-[11px] font-bold break-words break-all">
                      {rule.motif_name || rule.motif_id}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono break-all mt-0.5">
                      {rule.motif_id}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono font-bold text-emerald-400 bg-emerald-950/80 border border-emerald-800/60 px-1.5 py-0.5 rounded shrink-0 self-start">
                    {Math.round((rule.confidence || 1.0) * 100)}%
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "llm" && (
          <div className="flex-1 overflow-y-auto p-4 text-[11px] text-slate-300 font-mono leading-relaxed space-y-3 w-full overflow-x-hidden">
            <div className="flex items-center justify-between text-xs text-sky-400 border-b border-slate-800 pb-2">
              <span>大模型意图仲裁通道</span>
              <span>调用: {stats.llm_calls ?? 0} 次</span>
            </div>
            {stage === "LLM_ARBITRATING" ? (
              <div className="flex items-center gap-2 text-sky-400">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-500"></span>
                </span>
                正在分析微观系统调用歧义上下文...
              </div>
            ) : stage === "COMPLETED" ? (
              <div className="text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                多轮因果拓扑仲裁已收敛，取证完成。
              </div>
            ) : (
              <div className="text-slate-500 italic">
                待出现高歧义候选边时自动激活 LLM 慢速图通道...
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
