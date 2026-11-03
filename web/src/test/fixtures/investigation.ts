/** Test-only investigation payload. Production pages do not import this file. */
export const investigationListFixture = [
  {
    id: "investigation-fixture",
    title: "fixture investigation",
    status: "open",
    summary: "fixture summary",
    alerts: 1,
    events: 1,
    created_at: "2005-06-14T15:16:01Z",
    updated_at: "2005-06-14T15:20:01Z",
  },
];

export const investigationDetailFixture = {
  id: "investigation-fixture",
  title: "fixture investigation",
  status: "open",
  summary: "fixture summary",
  created_at: "2005-06-14T15:16:01Z",
  updated_at: "2005-06-14T15:20:01Z",
  alerts: [
    {
      id: "alert-fixture",
      title: "fixture alert",
      severity: "medium",
      status: "open",
      rule_id: "rule-fixture",
      rule_name: "fixture-rule",
      rule_version: 2,
      threshold: 5,
      window_seconds: 60,
      window_type: "sliding",
      source_address: null,
      explanation: "A rule finding on unlabeled logs.",
      event_ids: ["event-fixture"],
      line_numbers: [1],
      first_event_at: "2005-06-14T15:16:01Z",
      last_event_at: "2005-06-14T15:16:01Z",
      confirmed_compromise: false,
      label: "not a confirmed compromise",
    },
  ],
  anomaly_windows: [
    {
      id: "window-fixture",
      model_id: "model-fixture",
      model_version: 1,
      window_start: "2005-06-14T15:00:00Z",
      window_end: "2005-06-14T16:00:00Z",
      event_count: 4,
      isolation_score: 0.2,
      baseline_score: 1.5,
      flagged_isolation: false,
      flagged_baseline: false,
      confirmed_compromise: false,
      label: "not a confirmed compromise",
      disclaimer: "Scores are experimental anomaly rankings, not confirmed compromise.",
    },
  ],
  events: [
    {
      id: "event-fixture",
      line_number: 12,
      event_timestamp: "2005-06-14T15:16:01Z",
      hostname: "combo",
      component: "sshd(pam_unix)",
      event_id: "E16",
      content: "authentication failure",
      raw_line: "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure",
      source_ip: null,
      username: null,
    },
  ],
  notes: [
    {
      id: "note-fixture",
      actor: "analyst",
      body: "Analyst wrote this note.",
      created_at: "2005-06-14T16:00:00Z",
    },
  ],
};

export const graphFixture = {
  investigation_id: "investigation-fixture",
  event_limit: 40,
  linked_events: 1,
  shown_events: 1,
  nodes: [],
  edges: [],
};
