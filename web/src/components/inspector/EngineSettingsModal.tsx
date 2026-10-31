import React, { useState } from "react";
import { Sliders, X, RotateCcw, Check, ShieldAlert, Cpu, Sparkles } from "lucide-react";
import { InvestigationParameters } from "../../types";

export const DEFAULT_ENGINE_PARAMETERS: InvestigationParameters = {
  max_closure_rounds: null,
  hitl_enabled: false,
  hitl_lease_timeout_sec: 120,
  llm_budget_calls: 10,
  llm_temperature: 0.0,
};

interface EngineSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  parameters: InvestigationParameters;
  onSave: (params: InvestigationParameters) => void;
}

export const EngineSettingsModal: React.FC<EngineSettingsModalProps> = ({
  isOpen,
  onClose,
  parameters,
  onSave,
}) => {
  const [formParams, setFormParams] = useState<InvestigationParameters>(parameters);

  if (!isOpen) return null;

  const handleReset = () => {
    setFormParams({ ...DEFAULT_ENGINE_PARAMETERS });
  };

  const handleSave = () => {
    onSave(formParams);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm select-none animate-in fade-in duration-150">
      <div className="w-[580px] max-w-[95vw] max-h-[90vh] bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        {/* 顶部标题栏 */}
        <div className="h-12 px-5 bg-slate-800/80 border-b border-slate-700 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-slate-100 font-bold text-sm">
            <Sliders className="w-4 h-4 text-sky-400" />
            <span>因果图谱推理引擎参数控制</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-700 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* 参数表单主体 */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs text-slate-300">
          {/* 1. 快速符号通道准入（由规则库 selected 名单决定，无数值阈值） */}
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/90 space-y-2">
            <div className="flex items-center gap-2 text-sky-300 font-semibold text-xs">
              <Cpu className="w-3.5 h-3.5" />
              <span>快速符号通道：因果形态准入</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              准入由规则库冻结的 <span className="font-mono text-sky-300">selected</span> 名单决定：
              形态按「边际查准率」排序，选到不再有新攻击边可覆盖为止，全过程不含任何数值阈值。
              具体放行了哪些形态、第几步入选、边际收益与成本，见调查报告的
              <span className="font-mono text-sky-300"> rules_library </span>字段与规则库的
              <span className="font-mono text-sky-300"> greedy_trace</span>。
            </p>
          </div>

          {/* 2. 反向闭包拓扑展开 */}
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/90 space-y-3">
            <div className="flex items-center gap-2 text-indigo-300 font-semibold text-xs">
              <Sparkles className="w-3.5 h-3.5" />
              <span>反向因果闭包：展开轮次与拓扑步长</span>
            </div>

            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-200">展开轮数上限:</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setFormParams({
                      ...formParams,
                      max_closure_rounds: formParams.max_closure_rounds === null ? 15 : null,
                    })
                  }
                  className={`px-2.5 py-1 rounded text-xs border transition ${
                    formParams.max_closure_rounds === null
                      ? "bg-indigo-600/30 border-indigo-500 text-indigo-200 font-bold"
                      : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  自动因果收敛
                </button>
                {formParams.max_closure_rounds !== null && (
                  <div className="flex items-center gap-1.5">
                    <input
                      type="number"
                      min={1}
                      max={30}
                      value={formParams.max_closure_rounds}
                      onChange={(e) =>
                        setFormParams({
                          ...formParams,
                          max_closure_rounds: Math.max(1, Math.min(30, parseInt(e.target.value) || 1)),
                        })
                      }
                      className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-100 font-mono text-center text-xs"
                    />
                    <span className="text-slate-400">轮</span>
                  </div>
                )}
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              默认执行自动因果收敛，直至依赖图没有未探索父节点；指定轮数可硬截断遍历深度。
            </p>
          </div>

          {/* 3. 慢速通道大语言模型配额与温度 */}
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/90 space-y-3">
            <div className="flex items-center gap-2 text-purple-300 font-semibold text-xs">
              <Cpu className="w-3.5 h-3.5" />
              <span>慢速意图仲裁通道 (LLM) 配额与超参数</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-200">大模型单次调查调用配额:</span>
              <div className="flex items-center gap-1.5">
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={formParams.llm_budget_calls}
                  onChange={(e) =>
                    setFormParams({
                      ...formParams,
                      llm_budget_calls: Math.max(1, Math.min(50, parseInt(e.target.value) || 1)),
                    })
                  }
                  className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-100 font-mono text-center text-xs"
                />
                <span className="text-slate-400">次</span>
              </div>
            </div>

            <div className="space-y-1.5 pt-2 border-t border-slate-800/70">
              <div className="flex justify-between items-center">
                <span className="font-mono text-slate-200">采样温度 (Temperature):</span>
                <span className="font-mono font-bold text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/60">
                  {formParams.llm_temperature.toFixed(1)}
                </span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.1"
                value={formParams.llm_temperature}
                onChange={(e) =>
                  setFormParams({
                    ...formParams,
                    llm_temperature: parseFloat(e.target.value),
                  })
                }
                className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-purple-500"
              />
              <p className="text-[11px] text-slate-400">
                0.0 为确定性输出（符合可验证性法则）；非 0 采样增加语义推断发散度。
              </p>
            </div>
          </div>

          {/* 4. 人在回路 (HITL) 审查机制 */}
          <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/90 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-amber-300 font-semibold text-xs">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>人在回路 (HITL) 审查机制</span>
              </div>
              <button
                type="button"
                onClick={() =>
                  setFormParams({
                    ...formParams,
                    hitl_enabled: !formParams.hitl_enabled,
                  })
                }
                className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  formParams.hitl_enabled ? "bg-amber-500" : "bg-slate-800"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
                    formParams.hitl_enabled ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </button>
            </div>

            {formParams.hitl_enabled && (
              <div className="space-y-1.5 pt-2 border-t border-slate-800/70">
                <div className="flex justify-between items-center">
                  <span className="text-slate-200">租约超时等待时限:</span>
                  <div className="flex items-center gap-1.5">
                    <input
                      type="number"
                      min={30}
                      max={600}
                      value={formParams.hitl_lease_timeout_sec}
                      onChange={(e) =>
                        setFormParams({
                          ...formParams,
                          hitl_lease_timeout_sec: Math.max(30, Math.min(600, parseInt(e.target.value) || 30)),
                        })
                      }
                      className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-100 font-mono text-center text-xs"
                    />
                    <span className="text-slate-400">秒</span>
                  </div>
                </div>
                <p className="text-[11px] text-slate-400">
                  开启后，若遇到临界争议边将挂起流程，等待安全分析师手动确认或超时降级。
                </p>
              </div>
            )}
          </div>
        </div>

        {/* 底部按钮栏 */}
        <div className="h-14 px-5 bg-slate-800/80 border-t border-slate-700 flex items-center justify-between shrink-0">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-200 text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/60 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>重置默认参数</span>
          </button>

          <div className="flex items-center gap-2.5">
            <button
              onClick={onClose}
              className="text-slate-300 hover:text-white text-xs px-3.5 py-1.5 rounded-lg border border-slate-700 transition"
            >
              取消
            </button>
            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs px-4 py-1.5 rounded-lg transition shadow-md shadow-sky-600/30"
            >
              <Check className="w-3.5 h-3.5" />
              <span>确认并应用</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
