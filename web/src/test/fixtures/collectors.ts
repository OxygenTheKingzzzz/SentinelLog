/** Test-only collector payload. Production pages do not import this file. */
export const collectorFixture = [
  {
    id: "collector-fixture",
    source_id: "source-live-fixture",
    source_name: "fixture-live",
    source_kind: "live_file",
    kind: "file",
    path: "/tmp/allowed/app.log",
    enabled: true,
    status: "running",
    byte_offset: 128,
    lines_read: 5,
    lines_imported: 4,
    duplicates_skipped: 1,
    lines_errored: 0,
    last_error: null,
    last_event_at: null,
  },
];

export const liveStatusFixture = {
  implemented: true,
  journald_available: false,
  journald_detail: "journalctl is installed but this VM has no journal files.",
  allow_roots: ["/tmp/allowed"],
  detail: "fixture",
};
