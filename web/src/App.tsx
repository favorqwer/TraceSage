import React, { useEffect, useState, useRef } from "react";
import { Play, RotateCw, Sparkles, Sliders } from "lucide-react";
import { GraphCanvas } from "./components/canvas/GraphCanvas";
import { ReasoningPanel } from "./components/inspector/ReasoningPanel";
import { HitlModal } from "./components/inspector/HitlModal";
import {
  EngineSettingsModal,
  DEFAULT_ENGINE_PARAMETERS,
} from "./components/inspector/EngineSettingsModal";
import { useInvestigationStore } from "./store/useInvestigationStore";
import { ScenarioInfo, InvestigationParameters } from "./types";

export const App: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>("");
  const [mode, setMode] = useState<"hybrid" | "rules" | "llm-only">("rules");
  const [engineParams, setEngineParams] = useState<InvestigationParameters>(
    DEFAULT_ENGINE_PARAMETERS
  );
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const {
    taskId,
    stage,
    initInvestigation,
    setStage,
    applyGraphDelta,
    addRuleMatch,
    addLog,
    setProgress,
    setHitlRequest,
    setError,
    reset,
  } = useInvestigationStore();

  const eventSourceRef = useRef<EventSource | null>(null);

  // 加载可用场景列表
  useEffect(() => {
    fetch("/api/v1/scenarios")
      .then((res) => res.json())
      .then((data: ScenarioInfo[]) => {
        setScenarios(data);
        if (data.length > 0) {
          setSelectedScenario(data[0].name);
        }
      })
      .catch((err) => {
        console.error("Failed to load scenarios:", err);
      });
  }, []);

  // 监听后端 SSE 事件流
  useEffect(() => {
    if (!taskId) return;

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const sse = new EventSource(`/api/v1/investigations/${taskId}/events`);
    eventSourceRef.current = sse;

    sse.addEventListener("stage_changed", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      setStage(data.data.stage, data.data);
    });

    sse.addEventListener("graph_delta", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      const { nodes = [], edges = [] } = data.data;
      applyGraphDelta(nodes, edges);
    });

    sse.addEventListener("rule_matched", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      addRuleMatch(data.data);
    });

    sse.addEventListener("console_log", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      addLog(data.data);
    });

    sse.addEventListener("investigation_progress", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      setProgress(data.data);
    });

    sse.addEventListener("hitl_pause", (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      setHitlRequest(data.data);
    });

    sse.onerror = (err) => {
      console.error("SSE connection error:", err);
      sse.close();
    };

    return () => {
      sse.close();
    };
  }, [
    taskId,
    setStage,
    applyGraphDelta,
    addRuleMatch,
    addLog,
    setProgress,
    setHitlRequest,
  ]);

  // 发起调查
  const handleStartInvestigation = async () => {
    if (!selectedScenario || loading) return;
    setLoading(true);
    reset();

    try {
      const res = await fetch("/api/v1/investigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_name: selectedScenario,
          mode,
          rules_from: "frozen",
          params: engineParams,
        }),
      });
      const data = await res.json();
      initInvestigation(data.task_id, selectedScenario);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const isRunning = Boolean(
    taskId &&
      [
        "PENDING",
        "EXTRACTING_CLOSURE",
        "MATCHING_RULES",
        "LLM_ARBITRATING",
        "AWAITING_HITL",
      ].includes(stage)
  );

  return (
    <div className="w-screen h-screen flex flex-col bg-[#030712] font-sans overflow-hidden">
      {/* 顶部全局控制栏 */}
      <header className="h-14 bg-slate-900 border-b border-slate-800 px-4 flex items-center justify-between shrink-0 select-none z-20 shadow-xl gap-3">
        <div className="flex items-center gap-2.5 shrink-0">
          <div className="p-1.5 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-400 shadow-inner shrink-0">
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold text-slate-100 tracking-tight whitespace-nowrap">
              TraceSage
            </h1>
            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-slate-800 text-sky-300 border border-slate-700 whitespace-nowrap">
              Studio v2.0
            </span>
          </div>
        </div>

        {/* 场景与模式控制组（严格防折行） */}
        <div className="flex items-center gap-3 shrink-0 flex-nowrap">
          <div className="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
            <span className="text-slate-400 font-medium">调查场景:</span>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              disabled={isRunning}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-sky-500 disabled:opacity-50 transition shadow-sm max-w-[210px] truncate"
            >
              {scenarios.map((sc) => (
                <option key={sc.name} value={sc.name}>
                  {sc.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs whitespace-nowrap shrink-0">
            <span className="text-slate-400 font-medium">运行模式:</span>
            <select
              value={mode}
              onChange={(e: any) => setMode(e.target.value)}
              disabled={isRunning}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-sky-500 disabled:opacity-50 transition shadow-sm max-w-[190px] truncate"
            >
              <option value="rules">快速符号 (Fisher-FDR 基模)</option>
              <option value="hybrid">神经符号混合通道 (Hybrid)</option>
              <option value="llm-only">纯大语言模型通道 (LLM)</option>
            </select>
          </div>

          <button
            onClick={() => setIsSettingsOpen(true)}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-300 hover:text-white hover:border-slate-700 text-xs transition shadow-sm disabled:opacity-50 shrink-0"
            title="调节后端因果推理超参数"
          >
            <Sliders className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span>引擎参数</span>
          </button>

          <button
            onClick={handleStartInvestigation}
            disabled={loading || isRunning || !selectedScenario}
            className="flex items-center gap-2 bg-gradient-to-r from-sky-600 to-blue-600 hover:from-sky-500 hover:to-blue-500 disabled:opacity-50 text-white text-xs font-bold px-4 py-1.5 rounded-lg transition shadow-lg shadow-sky-600/25 active:scale-95 whitespace-nowrap shrink-0 min-w-[125px] justify-center"
          >
            {isRunning ? (
              <>
                <RotateCw className="w-3.5 h-3.5 animate-spin shrink-0" />
                <span>分析推进中...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current shrink-0" />
                <span>启动全链调查</span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* 主工作区 */}
      <main className="flex-1 flex overflow-hidden relative">
        {/* 左侧拓扑画布 */}
        <div className="flex-1 min-w-0 h-full relative">
          <GraphCanvas />
        </div>

        {/* 右侧推理遥测抽屉 */}
        <ReasoningPanel />
      </main>

      {/* 人机在环审查模态弹窗 */}
      <HitlModal />

      {/* 引擎推理参数调节弹窗 */}
      <EngineSettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        parameters={engineParams}
        onSave={setEngineParams}
      />
    </div>
  );
};

export default App;
