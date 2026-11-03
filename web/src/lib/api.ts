export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export type QueryValue = string | number | boolean | null | undefined;

export function queryString(params?: Record<string, QueryValue>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* keep the status text */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export interface Source {
  id: string;
  name: string;
  description: string | null;
  hostname: string | null;
  source_year: number | null;
  kind: string;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: string;
  source_id: string;
  kind: string;
  filename: string;
  status: string;
  lines_total: number;
  lines_parsed: number;
  lines_errored: number;
  duplicates_skipped: number;
  conflicts: number;
  error_message: string | null;
  created_at: string;
}

export interface ParseError {
  line_number: number | null;
  error_kind: string;
  message: string;
  raw_line: string | null;
}

export interface LogEvent {
  id: string;
  source_id: string;
  job_id: string;
  line_number: number;
  raw_line: string;
  event_timestamp: string | null;
  hostname: string;
  component: string;
  pid: number | null;
  content: string;
  event_id: string | null;
  event_template: string | null;
  source_ip: string | null;
  username: string | null;
  month: string;
  day: number;
  time_of_day: string;
  origin: string;
}

export interface EventPage {
  total: number;
  limit: number;
  offset: number;
  items: LogEvent[];
}

export interface Facet {
  value: string;
  count: number;
}

export interface Facets {
  total: number;
  components: Facet[];
  event_ids: Facet[];
  hostnames: Facet[];
}

export interface RecentAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  source_address: string | null;
  rule_id: string;
  first_event_at: string | null;
  last_event_at: string | null;
  line_numbers: number[];
}

export interface Overview {
  events: number;
  alerts: number;
  investigations: number;
  templates: number;
  auth_failures: number;
  time_min: string | null;
  time_max: string | null;
  daily: { day: string; events: number; auth_failures: number }[];
  severity: { severity: string; count: number }[];
  recent_alerts: RecentAlert[];
  sources: {
    id: string;
    name: string;
    hostname: string | null;
    source_year: number | null;
    kind: string;
    events: number;
    alerts: number;
  }[];
  anomaly: {
    model_id: string | null;
    model_version: number | null;
    windows: number;
    flagged_isolation: number;
    flagged_baseline: number;
    flagged_either: number;
  };
  ingestion: {
    jobs: number;
    jobs_completed: number;
    jobs_failed: number;
    parse_errors: number;
    lines_errored: number;
    last_job: {
      id: string;
      filename: string;
      kind: string;
      status: string;
      lines_parsed: number;
      lines_errored: number;
      created_at: string;
    } | null;
  };
}

export interface AlertNote {
  id: string;
  actor: string;
  note: string;
  from_status: string;
  to_status: string;
  created_at: string;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_version: number;
  source_id: string;
  title: string;
  severity: string;
  status: string;
  source_address: string | null;
  explanation: string;
  threshold: number;
  window_seconds: number;
  window_type: string;
  window_start: string;
  window_end: string;
  first_event_at: string;
  last_event_at: string;
  event_ids: string[];
  line_numbers: number[];
  group_value: string;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  notes: AlertNote[];
}

export interface AlertPage {
  total: number;
  limit: number;
  offset: number;
  items: Alert[];
}

export interface Rule {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  severity: string | null;
  version: number;
  logic: {
    threshold?: number;
    window_seconds?: number;
    window_type?: string;
  };
  updated_at: string;
}

export interface DetectionRun {
  created: number;
  updated: number;
  skipped: number;
  by_rule: Record<string, number>;
  disabled: string[];
}

export interface InvestigationSummary {
  id: string;
  title: string;
  status: string;
  summary: string | null;
  alerts: number;
  events: number;
  created_at: string;
  updated_at: string;
}

export interface InvestigationEvent {
  id: string;
  line_number: number;
  event_timestamp: string | null;
  hostname: string;
  component: string;
  event_id: string | null;
  content: string;
  raw_line: string;
  source_ip: string | null;
  username: string | null;
}

export interface InvestigationAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  rule_id: string;
  rule_name: string | null;
  rule_version: number;
  threshold: number;
  window_seconds: number;
  window_type: string;
  source_address: string | null;
  explanation: string;
  event_ids: string[];
  line_numbers: number[];
  first_event_at: string | null;
  last_event_at: string | null;
  confirmed_compromise: boolean;
  label: string;
}

export interface AnomalyWindow {
  id: string;
  model_id: string;
  model_version: number;
  window_start: string;
  window_end: string;
  event_count: number;
  isolation_score: number;
  baseline_score: number;
  flagged_isolation: boolean;
  flagged_baseline: boolean;
  confirmed_compromise: boolean;
  label: string;
  disclaimer: string;
}

export interface InvestigationNote {
  id: string;
  actor: string;
  body: string;
  created_at: string;
}

export interface InvestigationDetail {
  id: string;
  title: string;
  status: string;
  summary: string | null;
  created_at: string;
  updated_at: string;
  alerts: InvestigationAlert[];
  anomaly_windows: AnomalyWindow[];
  events: InvestigationEvent[];
  notes: InvestigationNote[];
}

export interface EvidenceBundle {
  kind: string;
  pdf: boolean;
  label: string;
  investigation: { id: string; title: string; status: string; summary: string | null };
  observations: {
    section: string;
    label: string;
    description: string;
    timeline: InvestigationEvent[];
  };
  automated_hypotheses: {
    section: string;
    label: string;
    description: string;
    rule_alerts: InvestigationAlert[];
    anomaly_windows: AnomalyWindow[];
  };
  analyst_confirmed_findings: {
    section: string;
    label: string;
    description: string;
    notes: InvestigationNote[];
  };
}

export interface GraphPayload {
  investigation_id: string;
  event_limit: number;
  linked_events: number;
  shown_events: number;
  nodes: { id: string; kind: string; label: string; severity?: string; count?: number }[];
  edges: { id: string; source: string; target: string; kind: string }[];
}

export interface ModelDetail {
  id: string;
  version: number;
  algorithm: string;
  window_seconds: number;
  window_type: string;
  train_fraction: number;
  n_train: number;
  n_validation: number;
  n_features: number;
  baseline_z_threshold: number;
  isolation_score_threshold: number;
  sklearn_version: string;
  dropped_features: unknown[];
  created_at: string;
  ground_truth: boolean;
  metrics: null;
  metrics_note: string;
  disclaimer: string;
  hyperparameters: Record<string, unknown>;
  validation_summary: Record<string, unknown>;
}

export interface Score {
  id: string;
  model_id: string;
  model_version: number;
  source_id: string;
  window_start: string;
  window_end: string;
  event_count: number;
  split_role: string;
  features: Record<string, number>;
  isolation_score: number;
  baseline_score: number;
  flagged_isolation: boolean;
  flagged_baseline: boolean;
  explanation: {
    summary?: string;
    metrics_note?: string;
    isolation_contributions?: { feature: string; score_delta: number }[];
    baseline?: { feature: string; robust_z: number }[];
  };
  ground_truth: boolean;
  metrics: null;
  metrics_note: string;
}

export interface ScorePage {
  total: number;
  limit: number;
  offset: number;
  model_id: string | null;
  model_version: number | null;
  items: Score[];
  ground_truth: boolean;
  metrics: null;
  metrics_note: string;
}

export interface SettingsPayload {
  version: string;
  log_level: string;
  max_upload_bytes: number;
  source_year: number | null;
  anomaly_artifact_dir: string;
  live_collection: boolean;
  pdf_export: boolean;
  database: { driver: string; host: string | null; port: number | null; name: string | null };
}

export interface AuditPage {
  total: number;
  limit: number;
  offset: number;
  items: {
    id: string;
    actor: string;
    action: string;
    entity_type: string;
    entity_id: string | null;
    details: Record<string, unknown>;
    created_at: string;
  }[];
}

export const api = {
  health: () => request<{ status: string }>("/health"),
  settings: () => request<SettingsPayload>("/api/v1/settings"),
  audit: (limit = 50, offset = 0) =>
    request<AuditPage>(`/api/v1/audit${queryString({ limit, offset })}`),
  sources: () => request<Source[]>("/api/v1/sources"),
  createSource: (body: { name: string; description?: string; source_year?: number | null }) =>
    request<Source>("/api/v1/sources", { method: "POST", body: JSON.stringify(body) }),
  overview: (sourceId?: string | null) =>
    request<Overview>(`/api/v1/overview${queryString({ source_id: sourceId })}`),
  events: (params: Record<string, QueryValue>) =>
    request<EventPage>(`/api/v1/events${queryString(params)}`),
  event: (id: string) => request<LogEvent>(`/api/v1/events/${id}`),
  facets: (params: Record<string, QueryValue>) =>
    request<Facets>(`/api/v1/events/facets${queryString(params)}`),
  jobs: (sourceId?: string | null) =>
    request<Job[]>(`/api/v1/jobs${queryString({ source_id: sourceId })}`),
  jobErrors: (jobId: string) => request<ParseError[]>(`/api/v1/jobs/${jobId}/errors?limit=100`),
  upload: (sourceId: string, kind: "raw" | "templates" | "structured", file: File) => {
    const body = new FormData();
    body.append("file", file);
    return request<Job>(`/api/v1/sources/${sourceId}/ingest/${kind}`, { method: "POST", body });
  },
  alerts: (params: Record<string, QueryValue>) =>
    request<AlertPage>(`/api/v1/alerts${queryString(params)}`),
  alert: (id: string) => request<Alert>(`/api/v1/alerts/${id}`),
  setAlertStatus: (id: string, status: string, note: string) =>
    request<Alert>(`/api/v1/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status, note }),
    }),
  rules: () => request<Rule[]>("/api/v1/rules"),
  patchRule: (
    id: string,
    body: { enabled?: boolean; threshold?: number; window_seconds?: number; window_type?: string },
  ) => request<Rule>(`/api/v1/rules/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  runDetection: (sourceId?: string | null) =>
    request<DetectionRun>(`/api/v1/detection/run${queryString({ source_id: sourceId })}`, {
      method: "POST",
    }),
  investigations: () => request<InvestigationSummary[]>("/api/v1/investigations"),
  investigation: (id: string) => request<InvestigationDetail>(`/api/v1/investigations/${id}`),
  createInvestigation: (body: {
    title: string;
    summary?: string | null;
    alert_ids: string[];
    event_ids: string[];
    note?: string | null;
  }) =>
    request<InvestigationDetail>("/api/v1/investigations", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  linkInvestigation: (id: string, body: { alert_ids: string[]; event_ids: string[] }) =>
    request<InvestigationDetail>(`/api/v1/investigations/${id}/links`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  setInvestigationStatus: (id: string, status: string, note: string) =>
    request<InvestigationDetail>(`/api/v1/investigations/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status, note }),
    }),
  addInvestigationNote: (id: string, body: string) =>
    request<InvestigationDetail>(`/api/v1/investigations/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),
  graph: (id: string) => request<GraphPayload>(`/api/v1/investigations/${id}/graph`),
  evidence: (id: string) => request<EvidenceBundle>(`/api/v1/investigations/${id}/evidence`),
  downloadInvestigationPdf: async (id: string) => {
    const response = await fetch(`/api/v1/investigations/${id}/report.pdf`);
    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = (await response.json()) as { detail?: unknown };
        if (typeof body.detail === "string") detail = body.detail;
      } catch {
        /* keep the status text */
      }
      throw new ApiError(response.status, detail);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `investigation-${id}.pdf`;
    link.click();
    URL.revokeObjectURL(url);
  },
  mlStatus: () =>
    request<{ ground_truth: boolean; metrics: null; metrics_note: string; detail: string }>(
      "/api/v1/ml/status",
    ),
  latestModel: () => request<ModelDetail>("/api/v1/ml/models/latest"),
  scores: (params: Record<string, QueryValue>) =>
    request<ScorePage>(`/api/v1/ml/scores${queryString(params)}`),
  liveStatus: () =>
    request<LiveStatus>("/api/v1/live/status"),
  liveCollectors: () => request<LiveCollector[]>("/api/v1/live/collectors"),
  authorizeFile: (body: { name: string; path: string; source_year?: number | null }) =>
    request<LiveCollector>("/api/v1/live/files", { method: "POST", body: JSON.stringify(body) }),
  startCollector: (id: string) =>
    request<LiveCollector>(`/api/v1/live/collectors/${id}/start`, { method: "POST" }),
  stopCollector: (id: string) =>
    request<LiveCollector>(`/api/v1/live/collectors/${id}/stop`, { method: "POST" }),
};

export interface LiveStatus {
  implemented: boolean;
  journald_available: boolean;
  journald_detail: string;
  allow_roots: string[];
  detail: string;
}

export interface LiveCollector {
  id: string;
  source_id: string;
  source_name: string;
  source_kind: string;
  kind: string;
  path: string;
  enabled: boolean;
  status: string;
  byte_offset: number;
  lines_read: number;
  lines_imported: number;
  duplicates_skipped: number;
  lines_errored: number;
  last_error: string | null;
  last_event_at: string | null;
}
