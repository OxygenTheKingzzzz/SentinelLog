import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { ErrorNote, Loading } from "@/components/States";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function SettingsPage() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api.audit(50, 0) });

  return (
    <div className="space-y-3">
      <h1 className="text-sm font-medium">Settings</h1>
      <div className="grid gap-2 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Database health</CardTitle>
          </CardHeader>
          <CardContent className="text-xs">
            {health.isLoading ? <Loading /> : null}
            {health.isError ? <ErrorNote error={health.error} /> : null}
            {health.data ? (
              <p>
                API health: <span className="text-ok">{health.data.status}</span>
              </p>
            ) : null}
            {settings.data ? (
              <p className="mt-2 text-mute">
                {settings.data.database.driver} · {settings.data.database.host}:
                {settings.data.database.port} · {settings.data.database.name}
              </p>
            ) : null}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-xs">
            {settings.isLoading ? <Loading /> : null}
            {settings.isError ? <ErrorNote error={settings.error} /> : null}
            {settings.data ? (
              <>
                <Row label="Version" value={settings.data.version} />
                <Row label="Log level" value={settings.data.log_level} />
                <Row label="Max upload" value={String(settings.data.max_upload_bytes)} />
                <Row label="Default source year" value={settings.data.source_year == null ? "unset" : String(settings.data.source_year)} />
                <Row label="Anomaly artifacts" value={settings.data.anomaly_artifact_dir} />
                <Row label="Live collection" value={String(settings.data.live_collection)} />
                <Row label="PDF export" value={String(settings.data.pdf_export)} />
              </>
            ) : null}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          {audit.isLoading ? <Loading /> : null}
          {audit.isError ? <ErrorNote error={audit.error} /> : null}
          {audit.data ? <p className="px-3 py-1 text-[11px] text-mute">{audit.data.total} entries</p> : null}
          <table className="w-full text-left text-xs">
            <thead className="text-mute">
              <tr>
                <th className="px-3 py-1.5 font-medium">When (UTC)</th>
                <th className="px-3 py-1.5 font-medium">Actor</th>
                <th className="px-3 py-1.5 font-medium">Action</th>
                <th className="px-3 py-1.5 font-medium">Entity</th>
              </tr>
            </thead>
            <tbody>
              {(audit.data?.items ?? []).map((row) => (
                <tr key={row.id} className="border-t border-line">
                  <td className="px-3 py-1.5 whitespace-nowrap">{formatWhen(row.created_at)}</td>
                  <td className="px-3 py-1.5">{row.actor}</td>
                  <td className="px-3 py-1.5">{row.action}</td>
                  <td className="px-3 py-1.5 text-mute">
                    {row.entity_type}
                    {row.entity_id ? ` ${row.entity_id}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <span className="text-mute">{label}</span>
      <span className="text-right">{value}</span>
    </div>
  );
}
