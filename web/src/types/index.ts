export type InvestigationStage =
  | "IDLE"
  | "PENDING"
  | "EXTRACTING_CLOSURE"
  | "MATCHING_RULES"
  | "LLM_ARBITRATING"
  | "AWAITING_HITL"
  | "COMPLETED"
  | "FAILED";

export interface NodeProperties {
  name?: string;
  full_identifier?: string;
  pid?: number;
  exe_path?: string;
  cmdline?: string;
  path?: string;
  file_type?: string;
  endpoints?: string;
  container_privileged?: boolean;
  [key: string]: any;
}

export interface GraphNode {
  id: string;
  label: "Process" | "File" | "Network";
  host_id: string;
  properties: NodeProperties;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  action: string;
  syscall: string;
  start_ns: number;
  end_ns?: number;
  result?: number;
  status: "confirmed" | "unexcluded" | "excluded";
  confirmed_by?: string;
  properties?: Record<string, any>;
}

export interface RuleMatchEvent {
  edge_id: string;
  motif_id: string;
  motif_name?: string;
  confidence: number;
}

export interface HitlRequestPayload {
  request_id: string;
  task_id: string;
  edge_id: string;
  reason: string;
  edge: Record<string, any>;
  expire_at_ns: number;
  timeout_seconds: number;
}

export interface ScenarioInfo {
  name: string;
  database: string;
  description: string;
  poi: Record<string, any>;
}

export interface ConsoleLogEntry {
  level: "info" | "warn" | "error" | "success";
  source: string;
  message: string;
  timestamp_ns: number;
}

export interface InvestigationProgress {
  stage: string;
  percent: number;
  description: string;
  current_round?: number;
  processed_count?: number;
}

export interface InvestigationParameters {
  matcher_min_lor: number;
  matcher_min_conf: number;
  max_closure_rounds: number | null;
  hitl_enabled: boolean;
  hitl_lease_timeout_sec: number;
  llm_budget_calls: number;
  llm_temperature: number;
}
