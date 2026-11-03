import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Select, TextArea } from "@/components/ui/input";

const STATUSES = ["open", "investigating", "resolved", "false_positive"] as const;

export function AlertsPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const alertIds = useSelection((state) => state.alertIds);
  const toggleAlert = useSelection((state) => state.toggleAlert);
  const [params] = useSearchParams();
  const focus = params.get("id");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("window_start");
  const [page, setPage] = useState(0);
  const [note, setNote] = useState("");
  const [nextStatus, setNextStatus] = useState<string>("investigating");
  const [dialog, setDialog] = useState(false);
  const client = useQueryClient();
  const limit = 50;

  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const ruleName = new Map((rules.data ?? []).map((rule) => [rule.id, rule.name]));
  const alerts = useQuery({
    queryKey: ["alerts", sourceId, severity, status, sort, page],
    queryFn: () =>
      api.alerts({
        source_id: sourceId,
        severity: severity || undefined,
        status: status || undefined,
        sort,
        limit,
        offset: page * limit,
      }),
  });
  const detailId = focus || alerts.data?.items[0]?.id || null;
  const detail = useQuery({
    queryKey: ["alert", detailId],
    queryFn: () => api.alert(detailId ?? ""),
    enabled: Boolean(detailId),
  });
  const update = useMutation({
    mutationFn: () => api.setAlertStatus(detail.data?.id ?? "", nextStatus, note),
    onSuccess: async () => {
      setNote("");
      setDialog(false);
      await client.invalidateQueries({ queryKey: ["alerts"] });
      await client.invalidateQueries({ queryKey: ["alert"] });
    },
  });

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-sm font-medium">Security alerts</h1>
          <Select
            className="w-36"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setPage(0);
            }}
          >
            <option value="">Severity</option>
            {["critical", "high", "medium", "low"].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </Select>
          <Select
            className="w-40"
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setPage(0);
            }}
          >
            <option value="">Status</option>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </Select>
          <Select className="w-40" value={sort} onChange={(event) => setSort(event.target.value)}>
            <option value="window_start">Sort by window</option>
            <option value="created_at">Sort by created</option>
            <option value="severity">Sort by severity</option>
          </Select>
          {alertIds.length > 0 ? (
            <Link className="text-xs text-amber" to="/investigations">
              Investigate {alertIds.length} alerts
            </Link>
          ) : null}
        </div>
        {alerts.isLoading ? <Loading label="Loading alerts" /> : null}
        {alerts.isError ? <ErrorNote error={alerts.error} /> : null}
        {alerts.data && alerts.data.total === 0 ? <Empty>No rule alerts match these filters.</Empty> : null}
        {alerts.data && alerts.data.total > 0 ? (
          <>
            <p className="text-[11px] text-mute">{alerts.data.total} alerts. Findings are not confirmed incidents.</p>
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full text-left text-xs">
                <thead className="bg-panel text-mute">
                  <tr>
                    <th className="px-2 py-1.5" />
                    <th className="px-2 py-1.5 font-medium">Severity</th>
                    <th className="px-2 py-1.5 font-medium">Status</th>
                    <th className="px-2 py-1.5 font-medium">Rule</th>
                    <th className="px-2 py-1.5 font-medium">Title</th>
                    <th className="px-2 py-1.5 font-medium">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.items.map((alert) => (
                    <tr key={alert.id} className="border-t border-line hover:bg-white/5">
                      <td className="px-2 py-1">
                        <input
                          type="checkbox"
                          checked={alertIds.includes(alert.id)}
                          onChange={() => toggleAlert(alert.id)}
                          aria-label={`Select ${alert.title}`}
                        />
                      </td>
                      <td className="px-2 py-1">
                        <Badge value={alert.severity} />
                      </td>
                      <td className="px-2 py-1">
                        <Badge value={alert.status} />
                      </td>
                      <td className="px-2 py-1 text-mute">{ruleName.get(alert.rule_id) ?? alert.rule_id}</td>
                      <td className="px-2 py-1">
                        <Link className="hover:text-cyan" to={`/alerts?id=${alert.id}`}>
                          {alert.title}
                        </Link>
                      </td>
                      <td className="px-2 py-1 font-mono text-mute">
                        {alert.line_numbers.length} {alert.line_numbers.length === 1 ? "line" : "lines"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex gap-2 text-xs">
              <Button type="button" variant="outline" disabled={page === 0} onClick={() => setPage((n) => n - 1)}>
                Previous
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={(page + 1) * limit >= alerts.data.total}
                onClick={() => setPage((n) => n + 1)}
              >
                Next
              </Button>
            </div>
          </>
        ) : null}
      </div>
      <aside className="rounded-lg border border-line bg-panel p-3 text-xs">
        {detail.isLoading ? <Loading /> : null}
        {detail.isError ? <ErrorNote error={detail.error} /> : null}
        {detail.data ? (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              <Badge value={detail.data.severity} />
              <Badge value={detail.data.status} />
            </div>
            <h2 className="text-sm">{detail.data.title}</h2>
            <p className="text-mute">{ruleName.get(detail.data.rule_id) ?? "Rule"} · v{detail.data.rule_version}</p>
            <p>{detail.data.explanation}</p>
            <p className="text-mute">
              {formatWhen(detail.data.window_start)} – {formatWhen(detail.data.window_end)} UTC
            </p>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-mute">Evidence events</div>
              <ul className="mt-1 space-y-1">
                {detail.data.line_numbers.map((line, index) => (
                  <li key={`${line}-${index}`}>
                    <Link className="text-cyan" to={`/logs?line=${line}&event=${detail.data?.event_ids[index] ?? ""}`}>
                      Line {line}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-mute">Analyst notes</div>
              {detail.data.notes.length === 0 ? <p className="text-mute">No notes yet.</p> : null}
              <ul className="mt-1 space-y-1">
                {detail.data.notes.map((item) => (
                  <li key={item.id} className="border-t border-line pt-1">
                    <span className="text-mute">
                      {item.actor} · {item.from_status} → {item.to_status} · {formatWhen(item.created_at)} UTC
                    </span>
                    <div>{item.note}</div>
                  </li>
                ))}
              </ul>
            </div>
            <Button type="button" onClick={() => setDialog(true)}>
              Change status
            </Button>
            {update.isError ? <ErrorNote error={update.error} /> : null}
          </div>
        ) : null}
      </aside>
      <Dialog open={dialog} onOpenChange={setDialog} title="Update alert status">
        <div className="space-y-2">
          <Select value={nextStatus} onChange={(event) => setNextStatus(event.target.value)}>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </Select>
          <TextArea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Analyst note" />
          <Button type="button" disabled={!note.trim() || update.isPending} onClick={() => update.mutate()}>
            Save note and status
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
