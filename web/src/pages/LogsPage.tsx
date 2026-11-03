import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type LogEvent } from "@/lib/api";
import { csvEscape, downloadText, formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const PAGE = 50;

export function LogsPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const toggleEvent = useSelection((state) => state.toggleEvent);
  const picked = useSelection((state) => state.eventIds);
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [component, setComponent] = useState(params.get("component") ?? "");
  const [eventId, setEventId] = useState(params.get("event_id") ?? "");
  const [hostname, setHostname] = useState(params.get("hostname") ?? "");
  const [occurredFrom, setOccurredFrom] = useState(params.get("from") ?? "");
  const [occurredTo, setOccurredTo] = useState(params.get("to") ?? "");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Record<string, LogEvent>>({});
  const lineNumber = params.get("line");
  const focusId = params.get("event");

  const filters = {
    source_id: sourceId,
    q,
    component,
    event_id: eventId,
    hostname,
    occurred_from: occurredFrom || undefined,
    occurred_to: occurredTo || undefined,
    line_number: lineNumber || undefined,
  };
  const facets = useQuery({
    queryKey: ["facets", sourceId],
    queryFn: () => api.facets({ source_id: sourceId }),
  });
  const events = useQuery({
    queryKey: ["events", filters, page],
    queryFn: () => api.events({ ...filters, limit: PAGE, offset: page * PAGE }),
  });
  const focused = useQuery({
    queryKey: ["event", focusId],
    queryFn: () => api.event(focusId ?? ""),
    enabled: Boolean(focusId),
  });

  const rows = events.data?.items ?? [];
  const open = focused.data ?? rows.find((row) => row.id === focusId) ?? null;
  const selectedRows = useMemo(() => Object.values(selected), [selected]);

  function apply(next: { q?: string; component?: string; eventId?: string; hostname?: string }) {
    const query = next.q ?? q;
    const comp = next.component ?? component;
    const template = next.eventId ?? eventId;
    const host = next.hostname ?? hostname;
    setQ(query);
    setComponent(comp);
    setEventId(template);
    setHostname(host);
    setPage(0);
    const url = new URLSearchParams();
    if (query) url.set("q", query);
    if (comp) url.set("component", comp);
    if (template) url.set("event_id", template);
    if (host) url.set("hostname", host);
    if (occurredFrom) url.set("from", occurredFrom);
    if (occurredTo) url.set("to", occurredTo);
    setParams(url);
  }

  function exportSelected() {
    const header = ["line_number", "event_timestamp", "hostname", "component", "event_id", "content", "raw_line"];
    const lines = [
      header.join(","),
      ...selectedRows.map((row) =>
        [row.line_number, row.event_timestamp, row.hostname, row.component, row.event_id, row.content, row.raw_line]
          .map(csvEscape)
          .join(","),
      ),
    ];
    downloadText("events.csv", lines.join("\n"), "text/csv");
  }

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="space-y-2">
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-[11px] text-mute">
            Search
            <Input value={q} onChange={(event) => setQ(event.target.value)} className="w-48" />
          </label>
          <label className="text-[11px] text-mute">
            From (UTC)
            <Input
              type="datetime-local"
              value={occurredFrom.slice(0, 16)}
              onChange={(event) => setOccurredFrom(event.target.value ? `${event.target.value}:00Z` : "")}
            />
          </label>
          <label className="text-[11px] text-mute">
            To (UTC)
            <Input
              type="datetime-local"
              value={occurredTo.slice(0, 16)}
              onChange={(event) => setOccurredTo(event.target.value ? `${event.target.value}:00Z` : "")}
            />
          </label>
          <Button type="button" onClick={() => apply({})}>
            Search
          </Button>
          <Button type="button" variant="outline" disabled={selectedRows.length === 0} onClick={exportSelected}>
            Export selected ({selectedRows.length})
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          <Select value={component} onChange={(event) => apply({ component: event.target.value })}>
            <option value="">Component</option>
            {(facets.data?.components ?? []).map((row) => (
              <option key={row.value} value={row.value}>
                {row.value} ({row.count})
              </option>
            ))}
          </Select>
          <Select value={eventId} onChange={(event) => apply({ eventId: event.target.value })}>
            <option value="">Event id</option>
            {(facets.data?.event_ids ?? []).map((row) => (
              <option key={row.value} value={row.value}>
                {row.value} ({row.count})
              </option>
            ))}
          </Select>
          <Select value={hostname} onChange={(event) => apply({ hostname: event.target.value })}>
            <option value="">Host</option>
            {(facets.data?.hostnames ?? []).map((row) => (
              <option key={row.value} value={row.value}>
                {row.value} ({row.count})
              </option>
            ))}
          </Select>
          {lineNumber ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                params.delete("line");
                setParams(params);
              }}
            >
              Line {lineNumber} · clear
            </Button>
          ) : null}
        </div>
        {events.isLoading ? <Loading label="Loading events" /> : null}
        {events.isError ? <ErrorNote error={events.error} /> : null}
        {events.data && events.data.total === 0 ? <Empty>No events match these filters.</Empty> : null}
        {events.data && events.data.total > 0 ? (
          <>
            <p className="text-[11px] text-mute">{events.data.total} events</p>
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full text-left text-xs">
                <thead className="bg-panel text-mute">
                  <tr>
                    <th className="px-2 py-1.5" />
                    <th className="px-2 py-1.5 font-medium">Line</th>
                    <th className="px-2 py-1.5 font-medium">Time (UTC)</th>
                    <th className="px-2 py-1.5 font-medium">Host</th>
                    <th className="px-2 py-1.5 font-medium">Component</th>
                    <th className="px-2 py-1.5 font-medium">Event</th>
                    <th className="px-2 py-1.5 font-medium">Content</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.id} className="border-t border-line hover:bg-white/5">
                      <td className="px-2 py-1">
                        <input
                          type="checkbox"
                          checked={Boolean(selected[row.id])}
                          onChange={() => {
                            setSelected((current) => {
                              const next = { ...current };
                              if (next[row.id]) delete next[row.id];
                              else next[row.id] = row;
                              return next;
                            });
                            toggleEvent(row.id);
                          }}
                          aria-label={`Select line ${row.line_number}`}
                        />
                      </td>
                      <td className="px-2 py-1 font-mono">
                        <Link className="text-cyan" to={`/logs?line=${row.line_number}`}>
                          {row.line_number}
                        </Link>
                      </td>
                      <td className="px-2 py-1 whitespace-nowrap">{formatWhen(row.event_timestamp)}</td>
                      <td className="px-2 py-1">{row.hostname}</td>
                      <td className="px-2 py-1">{row.component}</td>
                      <td className="px-2 py-1 font-mono text-mute">{row.event_id ?? "—"}</td>
                      <td className="max-w-[420px] truncate px-2 py-1">
                        <button
                          type="button"
                          className="text-left hover:text-cyan"
                          onClick={() => {
                            params.set("event", row.id);
                            setParams(params);
                          }}
                        >
                          {row.content}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <Button type="button" variant="outline" disabled={page === 0} onClick={() => setPage((n) => n - 1)}>
                Previous
              </Button>
              <span className="text-mute">
                {page * PAGE + 1}–{Math.min(events.data.total, (page + 1) * PAGE)} of {events.data.total}
              </span>
              <Button
                type="button"
                variant="outline"
                disabled={(page + 1) * PAGE >= events.data.total}
                onClick={() => setPage((n) => n + 1)}
              >
                Next
              </Button>
              {picked.length > 0 ? (
                <Link className="text-amber" to="/investigations">
                  Investigate {picked.length} events
                </Link>
              ) : null}
            </div>
          </>
        ) : null}
      </div>
      <aside className="rounded-lg border border-line bg-panel">
        <div className="border-b border-line px-3 py-2 text-[11px] uppercase tracking-wider text-mute">
          Event detail
        </div>
        {!open ? <Empty>Select a row to compare the raw line and the parsed fields.</Empty> : null}
        {open ? (
          <div className="space-y-2 p-3 text-xs">
            <div className="font-mono text-cyan">Line {open.line_number}</div>
            <Link className="text-mute underline" to={`/logs?line=${open.line_number}`}>
              Open this source line
            </Link>
            <Tabs defaultValue="parsed">
              <TabsList>
                <TabsTrigger value="parsed">Parsed</TabsTrigger>
                <TabsTrigger value="raw">Raw</TabsTrigger>
              </TabsList>
              <TabsContent value="parsed" className="mt-2 space-y-1">
                <Field label="Time" value={formatWhen(open.event_timestamp)} />
                <Field label="Host" value={open.hostname} />
                <Field label="Component" value={open.component} />
                <Field label="PID" value={open.pid == null ? "—" : String(open.pid)} />
                <Field label="Event id" value={open.event_id ?? "—"} />
                <Field label="Template" value={open.event_template ?? "—"} />
                <Field label="IP" value={open.source_ip ?? "—"} />
                <Field label="User" value={open.username ?? "—"} />
                <Field label="Content" value={open.content} />
              </TabsContent>
              <TabsContent value="raw" className="mt-2">
                <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-ink">{open.raw_line}</pre>
              </TabsContent>
            </Tabs>
          </div>
        ) : null}
      </aside>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-mute">{label}</div>
      <div className="break-words">{value}</div>
    </div>
  );
}
