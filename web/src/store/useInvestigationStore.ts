import { create } from "zustand";
import {
  ConsoleLogEntry,
  GraphEdge,
  GraphNode,
  HitlRequestPayload,
  InvestigationProgress,
  InvestigationStage,
  RuleMatchEvent,
} from "../types";

interface InvestigationState {
  // 任务上下文
  taskId: string | null;
  scenarioName: string | null;
  stage: InvestigationStage;
  error: string | null;

  // 图拓扑数据
  nodesMap: Map<string, GraphNode>;
  edgesMap: Map<string, GraphEdge>;

  // 遥测与决策
  matchedRules: RuleMatchEvent[];
  activeHitlRequest: HitlRequestPayload | null;
  stats: Record<string, any>;

  // 实时推演与控制台日志
  logs: ConsoleLogEntry[];
  progress: InvestigationProgress | null;

  // Actions
  initInvestigation: (taskId: string, scenarioName: string) => void;
  setStage: (stage: InvestigationStage, metadata?: Record<string, any>) => void;
  applyGraphDelta: (nodes: GraphNode[], edges: GraphEdge[]) => void;
  addRuleMatch: (rule: RuleMatchEvent) => void;
  addLog: (log: ConsoleLogEntry) => void;
  setProgress: (prog: InvestigationProgress) => void;
  setHitlRequest: (req: HitlRequestPayload | null) => void;
  setError: (err: string | null) => void;
  reset: () => void;
}

export const useInvestigationStore = create<InvestigationState>((set) => ({
  taskId: null,
  scenarioName: null,
  stage: "IDLE",
  error: null,

  nodesMap: new Map(),
  edgesMap: new Map(),

  matchedRules: [],
  activeHitlRequest: null,
  stats: {},

  logs: [],
  progress: null,

  initInvestigation: (taskId, scenarioName) => {
    set({
      taskId,
      scenarioName,
      stage: "PENDING",
      error: null,
      nodesMap: new Map(),
      edgesMap: new Map(),
      matchedRules: [],
      activeHitlRequest: null,
      stats: {},
      logs: [],
      progress: null,
    });
  },

  setStage: (stage, metadata) => {
    set((state) => ({
      stage,
      stats: metadata ? { ...state.stats, ...metadata } : state.stats,
    }));
  },

  applyGraphDelta: (newNodes, newEdges) => {
    set((state) => {
      const nextNodes = new Map(state.nodesMap);
      const nextEdges = new Map(state.edgesMap);

      newNodes.forEach((node) => {
        nextNodes.set(node.id, node);
      });

      newEdges.forEach((edge) => {
        nextEdges.set(edge.id, edge);
      });

      return {
        nodesMap: nextNodes,
        edgesMap: nextEdges,
      };
    });
  },

  addRuleMatch: (rule) => {
    set((state) => ({
      matchedRules: [rule, ...state.matchedRules].slice(0, 100),
    }));
  },

  addLog: (log) => {
    set((state) => ({
      logs: [...state.logs, log].slice(-300), // 保留最近 300 条实时日志
    }));
  },

  setProgress: (prog) => {
    set({ progress: prog });
  },

  setHitlRequest: (req) => set({ activeHitlRequest: req }),

  setError: (err) => set({ error: err }),

  reset: () => {
    set({
      taskId: null,
      scenarioName: null,
      stage: "IDLE",
      error: null,
      nodesMap: new Map(),
      edgesMap: new Map(),
      matchedRules: [],
      activeHitlRequest: null,
      stats: {},
      logs: [],
      progress: null,
    });
  },
}));
