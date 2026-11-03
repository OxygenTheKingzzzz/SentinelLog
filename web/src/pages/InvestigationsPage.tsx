import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { useEffect, useMemo, useState } from "react";
import { api, type GraphPayload } from "@/lib/api";
import { downloadText, formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select, TextArea } from "@/components/ui/input";
import "@xyflow/react/dist/style.css";

const columns: Record<string, number> = {
  investigation: 0,
  rule: 1,
  alert: 2,
  address: 3,
  event: 4,
  more_events: 4,
};

function toFlow(graph: GraphPayload): { nodes: Node[]; edges: Edge[] } {
  const row: Record<number, number> = {};
  const nodes = graph.nodes.map((node) => {
    const column = columns[node.kind] ?? 2;
    const index = row[column] ?? 0;
    row[column] = index + 1;
    return {
      id: node.id,
      position: { x: column * 230, y: index * 74 },
      data: { label: node.label },
      style: {
        background: "#172232",
        color: "#d7e0ea",
        border: "1px solid #243246",
        fontSize: 11,
        width: 200,
      },
    };
  });
  const edges = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.kind,
    style: { stroke: "#5ec8d8" },
    labelStyle: { fill: "#8ea0b5", fontSize: 10 },
  }));
  return { nodes, edges };
}

export function InvestigationsPage() {
  const alertIds = useSelection((state) => state.alertIds);
  const eventIds = useSelection((state) => state.eventIds);
  const clearPicks = useSelection((state) => state.clearPicks);
  const [active, setActive] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [openingNote, setOpeningNote] = useState("");
  const [note, setNote] = useState("");
  const [statusNote, setStatusNote] = useState("");
  const [nextStatus, setNextStatus] = useState("closed");
  const client = useQueryClient();

  const list = useQuery({ queryKey: ["investigations"], queryFn: api.investigations });
  const detail = useQuery({
    queryKey: ["investigation", active],
    queryFn: () => api.investigation(active ?? ""),
    enabled: Boolean(active),
  });
  const graph = useQuery({
    queryKey: ["graph", active],
    queryFn: () => api.graph(active ?? ""),
    enabled: Boolean(active),
  });
  const flow = useMemo(() => (graph.data ? toFlow(graph.data) : null), [graph.data]);

  useEffect(() => {
    if (!active && list.data && list.data.length > 0) setActive(list.data[0].id);
  }, [active, list.data]);

  const create = useMutation({
    mutationFn: () =>
      api.createInvestigation({
        title,
        summary: summary || null,
        alert_ids: alertIds,
        event_ids: eventIds,
        note: openingNote || null,
      }),
    onSuccess: async (created) => {
      setTitle("");
      setSummary("");
      setOpeningNote("");
      clearPicks();
      setActive(created.id);
      await client.invalidateQueries({ queryKey: ["investigations"] });
    },
  });
  const saveNote = useMutation({
    mutationFn: () => api.addInvestigationNote(active ?? "", note),
    onSuccess: async () => {
      setNote("");
      await client.invalidateQueries({ queryKey: ["investigation", active] });
    },
  });
  const saveStatus = useMutation({
    mutationFn: () => api.setInvestigationStatus(active ?? "", nextStatus, statusNote),
    onSuccess: async () => {
      setStatusNote("");
      await client.invalidateQueries({ queryKey: ["investigation", active] });
      await client.invalidateQueries({ queryKey: ["investigations"] });
    },
  });

  async function downloadEvidence() {
    if (!active) return;
    const bundle = await api.evidence(active);
    downloadText(
      `investigation-${active}.json`,
      JSON.stringify(bundle, null, 2),
      "application/json",
    );
  }

  return (
    <div className="grid gap-3 lg:grid-cols-[260px_minmax(0,1fr)]">
      <div className="space-y-2">
        <h1 className="text-sm font-medium">Investigations</h1>
        {list.isLoading ? <Loading /> : null}
        {list.isError ? <ErrorNote error={list.error} /> : null}
        <ul className="space-y-1">
          {(list.data ?? []).map((item) => (
            <li key={item.id}>
              <button
                type="button"
                className="w-full rounded border border-line bg-panel px-2 py-1.5 text-left hover:border-cyan"
                onClick={() => setActive(item.id)}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate">{item.title}</span>
                  <Badge value={item.status} />
                </div>
                <div className="text-[11px] text-mute">
                  {item.alerts} alerts · {item.events} events
                </div>
              </button>
            </li>
          ))}
        </ul>
        <form
          className="space-y-2 rounded-lg border border-line bg-panel p-2"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <div className="text-[11px] uppercase tracking-wider text-mute">New investigation</div>
          <p className="text-[11px] text-mute">
            Attaches {alertIds.length} selected alerts and {eventIds.length} selected events.
          </p>
          <Input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Title" required />
          <TextArea value={summary} onChange={(event) => setSummary(event.target.value)} placeholder="Summary" />
          <TextArea
            value={openingNote}
            onChange={(event) => setOpeningNote(event.target.value)}
            placeholder="Opening note"
          />
          <Button type="submit" disabled={!title.trim() || create.isPending}>
            Create
          </Button>
          {create.isError ? <ErrorNote error={create.error} /> : null}
        </form>
      </div>
      <div className="space-y-3">
        {!detail.data ? <Empty>Create an investigation or open one from the list.</Empty> : null}
        {detail.data ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm">{detail.data.title}</h2>
              <Badge value={detail.data.status} />
              <Button type="button" variant="outline" onClick={() => void downloadEvidence()}>
                JSON evidence bundle
              </Button>
            </div>
            <p className="text-[11px] text-mute">
              The bundle separates observations, rule hypotheses, and analyst notes. PDF export is not in this build.
            </p>
            {detail.data.summary ? <p>{detail.data.summary}</p> : null}
            <div className="grid gap-2 lg:grid-cols-3">
              <section className="rounded-lg border border-line bg-panel p-2">
                <h3 className="text-[11px] uppercase tracking-wider text-mute">Observations</h3>
                <ol className="mt-2 space-y-2">
                  {detail.data.events.map((event) => (
                    <li key={event.id} className="border-t border-line pt-1 text-xs">
                      <div className="font-mono text-cyan">
                        L{event.line_number} · {formatWhen(event.event_timestamp)} UTC
                      </div>
                      <div className="text-mute">
                        {event.component} {event.event_id ?? ""}
                      </div>
                      <div>{event.content}</div>
                    </li>
                  ))}
                  {detail.data.events.length === 0 ? <Empty>No linked events.</Empty> : null}
                </ol>
              </section>
              <section className="rounded-lg border border-line bg-panel p-2">
                <h3 className="text-[11px] uppercase tracking-wider text-mute">Rule hypotheses</h3>
                <ul className="mt-2 space-y-2 text-xs">
                  {detail.data.alerts.map((alert) => (
                    <li key={alert.id} className="border-t border-line pt-1">
                      <Badge value={alert.severity} /> {alert.title}
                      <div className="text-mute">{alert.explanation}</div>
                    </li>
                  ))}
                  {detail.data.alerts.length === 0 ? <Empty>No linked alerts.</Empty> : null}
                </ul>
              </section>
              <section className="rounded-lg border border-line bg-panel p-2">
                <h3 className="text-[11px] uppercase tracking-wider text-mute">Analyst notes</h3>
                <ul className="mt-2 space-y-2 text-xs">
                  {detail.data.notes.map((item) => (
                    <li key={item.id} className="border-t border-line pt-1">
                      <div className="text-mute">
                        {item.actor} · {formatWhen(item.created_at)} UTC
                      </div>
                      <div>{item.body}</div>
                    </li>
                  ))}
                </ul>
                <TextArea
                  className="mt-2"
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="Add an analyst note"
                />
                <Button
                  className="mt-2"
                  type="button"
                  variant="outline"
                  disabled={!note.trim() || saveNote.isPending}
                  onClick={() => saveNote.mutate()}
                >
                  Add note
                </Button>
                <div className="mt-3 flex gap-2">
                  <Select value={nextStatus} onChange={(event) => setNextStatus(event.target.value)}>
                    <option value="open">open</option>
                    <option value="closed">closed</option>
                  </Select>
                </div>
                <TextArea
                  className="mt-2"
                  value={statusNote}
                  onChange={(event) => setStatusNote(event.target.value)}
                  placeholder="Note required to change status"
                />
                <Button
                  className="mt-2"
                  type="button"
                  disabled={!statusNote.trim() || saveStatus.isPending}
                  onClick={() => saveStatus.mutate()}
                >
                  Update status
                </Button>
                {saveStatus.isError ? <ErrorNote error={saveStatus.error} /> : null}
              </section>
            </div>
            <section className="h-[440px] rounded-lg border border-line bg-navy">
              <div className="border-b border-line px-2 py-1 text-[11px] text-mute">
                Correlation graph · {graph.data?.shown_events ?? 0} of {graph.data?.linked_events ?? 0} events shown
              </div>
              {flow ? (
                <div className="h-[400px]">
                <ReactFlow
                  nodes={flow.nodes}
                  edges={flow.edges}
                  fitView
                  colorMode="dark"
                  proOptions={{ hideAttribution: true }}
                >
                  <Background />
                  <Controls />
                </ReactFlow>
                </div>
              ) : (
                <Loading label="Loading graph" />
              )}
            </section>
          </>
        ) : null}
      </div>
    </div>
  );
}
