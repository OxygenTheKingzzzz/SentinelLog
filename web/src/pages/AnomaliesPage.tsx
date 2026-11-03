import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ApiError, api } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { ChartSkeleton, PanelSkeleton, TableSkeleton } from "@/components/PageSkeleton";
import { Empty, ErrorNote } from "@/components/States";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";

export function AnomaliesPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const [flagged, setFlagged] = useState("");
  const [picked, setPicked] = useState<string | null>(null);
  const status = useQuery({ queryKey: ["ml-status"], queryFn: api.mlStatus });
  const model = useQuery({ queryKey: ["ml-latest"], queryFn: api.latestModel, retry: false });
  const scores = useQuery({
    queryKey: ["scores", sourceId, model.data?.id, flagged],
    queryFn: () =>
      api.scores({
        source_id: sourceId,
        model_id: model.data?.id,
        flagged: flagged || undefined,
        limit: 1000,
      }),
    enabled: Boolean(model.data?.id),
  });
  const rows = scores.data?.items ?? [];
  const selected = rows.find((row) => row.id === picked) ?? rows.find((row) => row.flagged_isolation || row.flagged_baseline) ?? rows[0];
  const chart = rows.map((row) => ({
    window: formatWhen(row.window_start),
    isolation: row.isolation_score,
    baseline: row.baseline_score,
  }));

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber/40 bg-amber/10 px-3 py-2">
        <div className="text-xs font-medium text-amber">No ground truth / not a confirmed incident</div>
        <p className="mt-1 text-xs text-mute">{status.data?.metrics_note ?? "Loading the model disclaimer…"}</p>
      </div>
      {model.isLoading ? (
        <div className="space-y-3">
          <div className="grid gap-2 md:grid-cols-4">
            {["Model", "Window", "Train / validation", "Thresholds"].map((label) => (
              <div key={label} className="rounded-lg border border-line bg-panel px-3 py-2">
                <div className="text-[11px] uppercase tracking-wider text-mute">{label}</div>
                <div className="mt-2 h-4 w-24 animate-pulse rounded bg-panel-2" />
              </div>
            ))}
          </div>
          <ChartSkeleton label="Loading model" />
          <TableSkeleton
            label="Loading scores"
            headers={["Window (UTC)", "Split", "Events", "Isolation", "Baseline", "Flags"]}
          />
        </div>
      ) : null}
      {model.error instanceof ApiError && model.error.status === 404 ? (
        <Empty>No anomaly model is stored. Train one with the CLI before this page has scores.</Empty>
      ) : null}
      {model.isError && !(model.error instanceof ApiError && model.error.status === 404) ? (
        <ErrorNote error={model.error} />
      ) : null}
      {model.data ? (
        <>
          <div className="grid gap-2 md:grid-cols-4">
            <Meta label="Model" value={`v${model.data.version} · ${model.data.algorithm}`} />
            <Meta label="Window" value={`${model.data.window_seconds}s ${model.data.window_type}`} />
            <Meta
              label="Train / validation"
              value={`${model.data.n_train} / ${model.data.n_validation}`}
            />
            <Meta
              label="Thresholds"
              value={`IF > ${model.data.isolation_score_threshold} · |z| ≥ ${model.data.baseline_z_threshold}`}
            />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Model metadata</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1 text-xs text-mute">
              <p>
                sklearn {model.data.sklearn_version} · features {model.data.n_features} · dropped{" "}
                {model.data.dropped_features.length === 0
                  ? "none"
                  : model.data.dropped_features
                      .map((item) =>
                        item && typeof item === "object" && "feature" in item
                          ? String((item as { feature: unknown }).feature)
                          : String(item),
                      )
                      .join(", ")}
              </p>
              <p>Ground truth flag from the API: {String(model.data.ground_truth)}. Metrics: null.</p>
              <p>{model.data.disclaimer}</p>
            </CardContent>
          </Card>
          <div className="flex items-center gap-2">
            <Select className="w-48" value={flagged} onChange={(event) => setFlagged(event.target.value)}>
              <option value="">All windows</option>
              <option value="either">Flagged by either</option>
              <option value="isolation">Isolation forest only</option>
              <option value="baseline">Baseline only</option>
            </Select>
            <span className="text-[11px] text-mute">
              {scores.data ? `${scores.data.items.length} of ${scores.data.total} windows` : ""}
            </span>
          </div>
          {scores.isError ? <ErrorNote error={scores.error} /> : null}
          {scores.isLoading ? (
            <div className="space-y-3">
              <ChartSkeleton label="Loading scores" />
              <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_320px]">
                <TableSkeleton
                  label="Loading score windows"
                  headers={["Window (UTC)", "Split", "Events", "Isolation", "Baseline", "Flags"]}
                />
                <PanelSkeleton label="Loading window" rows={6} />
              </div>
            </div>
          ) : (
            <>
          <Card>
            <CardHeader>
              <CardTitle>Forest vs baseline</CardTitle>
            </CardHeader>
            <CardContent className="h-64">
              {chart.length === 0 ? (
                <p className="text-mute">No scores for this filter.</p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chart}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="window" hide />
                    <YAxis tick={{ fill: "#8ea0b5", fontSize: 11 }} width={48} />
                    <Tooltip
                      contentStyle={{ background: "#111924", border: "1px solid #243246", fontSize: 12 }}
                    />
                    <Legend />
                    <Line type="monotone" dataKey="isolation" name="Isolation score" stroke="#5ec8d8" dot={false} />
                    <Line type="monotone" dataKey="baseline" name="Baseline |z|" stroke="#e39a45" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
          <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_320px]">
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full text-left text-xs">
                <thead className="bg-panel text-mute">
                  <tr>
                    <th className="px-2 py-1.5 font-medium">Window (UTC)</th>
                    <th className="px-2 py-1.5 font-medium">Split</th>
                    <th className="px-2 py-1.5 font-medium">Events</th>
                    <th className="px-2 py-1.5 font-medium">Isolation</th>
                    <th className="px-2 py-1.5 font-medium">Baseline</th>
                    <th className="px-2 py-1.5 font-medium">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {rows
                    .filter((row) => flagged || row.flagged_isolation || row.flagged_baseline || rows.length <= 40)
                    .slice(0, 80)
                    .map((row) => (
                      <tr
                        key={row.id}
                        className="cursor-pointer border-t border-line hover:bg-white/5"
                        onClick={() => setPicked(row.id)}
                      >
                        <td className="px-2 py-1 whitespace-nowrap">{formatWhen(row.window_start)}</td>
                        <td className="px-2 py-1">{row.split_role}</td>
                        <td className="px-2 py-1 font-mono">{row.event_count}</td>
                        <td className="px-2 py-1 font-mono text-cyan">{row.isolation_score.toFixed(4)}</td>
                        <td className="px-2 py-1 font-mono text-amber">{row.baseline_score.toFixed(4)}</td>
                        <td className="px-2 py-1">
                          {row.flagged_isolation ? <span className="text-cyan">forest</span> : null}{" "}
                          {row.flagged_baseline ? <span className="text-amber">baseline</span> : null}
                          {!row.flagged_isolation && !row.flagged_baseline ? (
                            <span className="text-mute">—</span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
            <aside className="rounded-lg border border-line bg-panel p-3 text-xs">
              <h2 className="text-[11px] uppercase tracking-wider text-mute">Feature context</h2>
              {selected ? (
                <div className="mt-2 space-y-2">
                  <p>{selected.explanation.summary}</p>
                  <p className="text-mute">{selected.metrics_note}</p>
                  <div>
                    <div className="text-mute">Isolation contributions</div>
                    <ul>
                      {(selected.explanation.isolation_contributions ?? []).map((item) => (
                        <li key={item.feature} className="flex justify-between gap-2 font-mono">
                          <span>{item.feature}</span>
                          <span>{Number(item.score_delta).toFixed(3)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <div className="text-mute">Baseline robust z</div>
                    <ul>
                      {(selected.explanation.baseline ?? []).slice(0, 8).map((item) => (
                        <li key={item.feature} className="flex justify-between gap-2 font-mono">
                          <span>{item.feature}</span>
                          <span>{Number(item.robust_z).toFixed(3)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <Empty>Select a window.</Empty>
              )}
            </aside>
          </div>
            </>
          )}
        </>
      ) : null}
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <div className="text-[11px] uppercase tracking-wider text-mute">{label}</div>
      <div className="mt-1 text-xs">{value}</div>
    </div>
  );
}
