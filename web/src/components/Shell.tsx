import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api, apiUrl } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useSelection } from "@/store/selection";
import { Select } from "@/components/ui/input";

const links = [
  ["/", "Overview"],
  ["/logs", "Log explorer"],
  ["/alerts", "Alerts"],
  ["/investigations", "Investigations"],
  ["/anomalies", "Anomalies"],
  ["/risk", "Risk"],
  ["/sources", "Sources"],
  ["/rules", "Rules"],
  ["/settings", "Settings"],
] as const;

export function Shell() {
  const client = useQueryClient();
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  useEffect(() => {
    const stream = new EventSource(apiUrl("/api/v1/live/stream"));
    stream.onmessage = () => {
      void client.invalidateQueries({ queryKey: ["overview"] });
      void client.invalidateQueries({ queryKey: ["events"] });
      void client.invalidateQueries({ queryKey: ["live-collectors"] });
      void client.invalidateQueries({ queryKey: ["jobs"] });
    };
    return () => stream.close();
  }, [client]);
  const sourceId = useSelection((state) => state.sourceId);
  const setSourceId = useSelection((state) => state.setSourceId);
  const picks = useSelection((state) => state.alertIds.length + state.eventIds.length);

  return (
    <div className="flex min-h-full flex-col">
      <header className="sticky top-0 z-20 border-b border-line bg-panel/95 backdrop-blur">
        <div className="flex h-12 items-center gap-4 px-3">
          <div className="shrink-0 leading-tight">
            <div className="text-xs font-semibold tracking-[0.18em] text-cyan">SENTINELLOG</div>
            <div className="text-[10px] uppercase tracking-wider text-mute">Stored logs only</div>
          </div>
          <nav className="flex min-w-0 flex-1 gap-1 overflow-x-auto">
            {links.map(([to, label]) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                className={({ isActive }) =>
                  cn(
                    "shrink-0 rounded px-2 py-1 text-xs text-mute hover:text-ink",
                    isActive && "bg-navy text-cyan",
                  )
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
          <label className="flex items-center gap-2 text-[11px] text-mute">
            Source
            <Select
              className="w-44"
              value={sourceId ?? ""}
              onChange={(event) => setSourceId(event.target.value || null)}
            >
              <option value="">{sources.isLoading ? "Loading sources…" : "All sources"}</option>
              {(sources.data ?? []).map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name}
                  {source.source_year ? ` · ${source.source_year}` : ""}
                </option>
              ))}
            </Select>
          </label>
          {picks > 0 ? (
            <span className="text-[11px] text-amber">{picks} selected</span>
          ) : null}
        </div>
      </header>
      <main className="mx-auto w-full max-w-[1440px] flex-1 px-3 py-3">
        <Outlet />
      </main>
    </div>
  );
}
