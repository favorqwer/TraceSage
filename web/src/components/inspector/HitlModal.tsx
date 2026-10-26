import React, { useEffect, useState } from "react";
import { AlertTriangle, Clock, ShieldAlert, Check, X } from "lucide-react";
import { useInvestigationStore } from "../../store/useInvestigationStore";

export const HitlModal: React.FC = () => {
  const { activeHitlRequest, setHitlRequest, taskId } = useInvestigationStore();
  const [timeLeft, setTimeLeft] = useState(300);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!activeHitlRequest) return;
    setTimeLeft(activeHitlRequest.timeout_seconds || 300);

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          setHitlRequest(null);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [activeHitlRequest, setHitlRequest]);

  if (!activeHitlRequest) return null;

  const edge = activeHitlRequest.edge || {};

  const handleDecision = async (decision: "confirm_attack" | "exclude_benign") => {
    if (!taskId || submitting) return;
    setSubmitting(true);
    try {
      await fetch(`/api/v1/investigations/${taskId}/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: activeHitlRequest.request_id,
          edge_id: activeHitlRequest.edge_id,
          decision,
          analyst_notes: `人工在环控制台审查确认: ${decision}`,
        }),
      });
      setHitlRequest(null);
    } catch (err) {
      console.error("Failed to submit HITL decision:", err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 select-none">
      <div className="bg-slate-900 border border-amber-500/60 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden text-slate-100">
        {/* 顶部标题栏 */}
        <div className="px-5 py-4 bg-amber-500/10 border-b border-amber-500/20 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h3 className="font-bold text-slate-100 text-sm">
              人机在环 (HITL) 调查中断审查
            </h3>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 border border-amber-500/40 text-amber-300 font-mono text-xs">
            <Clock className="w-3.5 h-3.5" />
            <span>租约倒计时: {timeLeft}s</span>
          </div>
        </div>

        {/* 审查内容 */}
        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-300 leading-relaxed">
            {activeHitlRequest.reason}
          </p>

          <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 text-[11px] font-mono space-y-1.5">
            <div className="flex justify-between">
              <span className="text-slate-500">事件标识:</span>
              <span className="text-slate-200">{activeHitlRequest.edge_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">底层系统调用:</span>
              <span className="text-sky-300 font-bold">{edge.syscall || "unknown"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">动作行为:</span>
              <span className="text-amber-300">{edge.action || "-"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">客体路径 / 端点:</span>
              <span className="text-emerald-300 truncate max-w-[280px]">
                {edge.path || edge.to_path || edge.dst || "-"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">返回值 (Result):</span>
              <span className="text-slate-300">{edge.result ?? "-"}</span>
            </div>
          </div>
        </div>

        {/* 决策操作栏 */}
        <div className="px-5 py-4 bg-slate-950/60 border-t border-slate-800 flex gap-3">
          <button
            onClick={() => handleDecision("confirm_attack")}
            disabled={submitting}
            className="flex-1 py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition shadow-lg shadow-rose-600/20"
          >
            <Check className="w-4 h-4" />
            确认属于攻击链路 (纳入因果图)
          </button>
          <button
            onClick={() => handleDecision("exclude_benign")}
            disabled={submitting}
            className="flex-1 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition"
          >
            <X className="w-4 h-4" />
            判定为良性操作 (作为噪音剔除)
          </button>
        </div>
      </div>
    </div>
  );
};
