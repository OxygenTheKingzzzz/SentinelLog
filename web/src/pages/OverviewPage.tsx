import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { OverviewSkeleton } from "@/components/PageSkeleton";
import { ErrorNote, Stat } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const chartTip = {
  contentStyle: { background: "#111924", border: "1px solid #243246", fontSize: 12 },
  labelStyle: { color: "#8ea0b5" },
};

export function OverviewPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const query = useQuery({
    queryKey: ["overview", sourceId],
    queryFn: () => api.overview(sourceId),
  });

  if (query.isPending) return <OverviewSkeleton />;
  if (query.isError) return <ErrorNote error={query.error} />;
  const data = query.data;
  if (!data) return <OverviewSkeleton />;

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-sm font-medium">Overview</h1>
        <p className="text-[11px] text-mute">
          Counts are queried from stored rows
          {data.time_min ? ` · ${formatWhen(data.time_min)} – ${formatWhen(data.time_max)} UTC` : ""}.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Stat label="Events" value={data.events} testId="event-total" />
        <Stat label="Rule alerts" value={data.alerts} testId="alert-total" />
        <Stat label="Investigations" value={data.investigations} testId="investigation-total" />
        <Stat label="Auth failures" value={data.auth_failures} testId="auth-total" />
      </div>
      <div className="grid gap-2 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Event frequency</CardTitle>
          </CardHeader>
          <CardContent className="h-56">
            {data.daily.length === 0 ? (
              <p className="text-mute">No timestamped events.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.daily}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: "#8ea0b5", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#8ea0b5", fontSize: 11 }} width={36} />
                  <Tooltip {...chartTip} />
                  <Bar dataKey="events" fill="#5ec8d8" radius={2} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Severity mix</CardTitle>
          </CardHeader>
          <CardContent className="h-56">
            {data.severity.length === 0 ? (
              <p className="text-mute">No rule alerts.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.severity} layout="vertical">
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#8ea0b5", fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="severity"
                    tick={{ fill: "#8ea0b5", fontSize: 11 }}
                    width={72}
                  />
                  <Tooltip {...chartTip} />
                  <Bar dataKey="count" fill="#e39a45" radius={2} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Auth-failure trend</CardTitle>
        </CardHeader>
        <CardContent className="h-48">
          {data.daily.length === 0 ? (
            <p className="text-mute">No timestamped events.</p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.daily}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="day" tick={{ fill: "#8ea0b5", fontSize: 11 }} />
                <YAxis tick={{ fill: "#8ea0b5", fontSize: 11 }} width={36} />
                <Tooltip {...chartTip} />
                <Line type="monotone" dataKey="auth_failures" stroke="#e06a6a" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>
      <div className="grid gap-2 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent alerts</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full text-left text-xs">
              <thead className="text-mute">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Title</th>
                  <th className="px-3 py-1.5 font-medium">Severity</th>
                  <th className="px-3 py-1.5 font-medium">Status</th>
                  <th className="px-3 py-1.5 font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_alerts.map((alert) => (
                  <tr key={alert.id} className="border-t border-line">
                    <td className="px-3 py-1.5">
                      <Link className="text-cyan hover:underline" to={`/alerts?id=${alert.id}`}>
                        {alert.title}
                      </Link>
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge value={alert.severity} />
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge value={alert.status} />
                    </td>
                    <td className="px-3 py-1.5 font-mono text-mute">{alert.source_address ?? "—"}</td>
                  </tr>
                ))}
                {data.recent_alerts.length === 0 ? (
                  <tr>
                    <td className="px-3 py-3 text-mute" colSpan={4}>
                      No alerts stored.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Ingestion health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            <div className="grid grid-cols-3 gap-2">
              <Stat label="Jobs" value={data.ingestion.jobs} />
              <Stat label="Completed" value={data.ingestion.jobs_completed} />
              <Stat label="Failed" value={data.ingestion.jobs_failed} />
            </div>
            <p className="text-mute">
              Parse errors {data.ingestion.parse_errors} · lines errored {data.ingestion.lines_errored}
            </p>
            {data.ingestion.last_job ? (
              <p>
                Last job <span className="text-cyan">{data.ingestion.last_job.filename}</span>{" "}
                <Badge value={data.ingestion.last_job.status} /> · parsed{" "}
                {data.ingestion.last_job.lines_parsed}
              </p>
            ) : (
              <p className="text-mute">No ingestion jobs.</p>
            )}
            <p className="text-mute">
              Templates in catalog {data.templates}. Anomaly windows {data.anomaly.windows}, flagged{" "}
              {data.anomaly.flagged_either}
              {data.anomaly.model_version != null ? ` (model v${data.anomaly.model_version})` : ""}.
            </p>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Sources</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-left text-xs">
            <thead className="text-mute">
              <tr>
                <th className="px-3 py-1.5 font-medium">Name</th>
                <th className="px-3 py-1.5 font-medium">Host</th>
                <th className="px-3 py-1.5 font-medium">Year</th>
                <th className="px-3 py-1.5 font-medium">Events</th>
                <th className="px-3 py-1.5 font-medium">Alerts</th>
              </tr>
            </thead>
            <tbody>
              {data.sources.map((source) => (
                <tr key={source.id} className="border-t border-line">
                  <td className="px-3 py-1.5">
                    {source.name}{" "}
                    {source.kind === "live_file" ? <Badge value="live" /> : null}
                  </td>
                  <td className="px-3 py-1.5">{source.hostname ?? "—"}</td>
                  <td className="px-3 py-1.5">{source.source_year ?? "—"}</td>
                  <td className="px-3 py-1.5 font-mono text-cyan">{source.events}</td>
                  <td className="px-3 py-1.5 font-mono">{source.alerts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
