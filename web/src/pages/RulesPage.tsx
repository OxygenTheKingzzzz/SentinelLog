import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type DetectionRun, type Rule } from "@/lib/api";
import { useSelection } from "@/store/selection";
import { RuleListSkeleton } from "@/components/PageSkeleton";
import { ErrorNote } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";

export function RulesPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const [result, setResult] = useState<DetectionRun | null>(null);
  const client = useQueryClient();
  const run = useMutation({
    mutationFn: () => api.runDetection(sourceId),
    onSuccess: async (body) => {
      setResult(body);
      await client.invalidateQueries({ queryKey: ["alerts"] });
      await client.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-sm font-medium">Rules</h1>
        <Button type="button" disabled={run.isPending} onClick={() => run.mutate()}>
          Run detection
        </Button>
        {result ? (
          <span className="text-xs text-cyan">
            Created {result.created} alerts · updated {result.updated} · skipped {result.skipped}
          </span>
        ) : null}
      </div>
      {run.isError ? <ErrorNote error={run.error} /> : null}
      {result ? (
        <ul className="text-xs text-mute">
          {Object.entries(result.by_rule).map(([name, count]) => (
            <li key={name}>
              {name}: {count}
            </li>
          ))}
        </ul>
      ) : null}
      {rules.isLoading ? <RuleListSkeleton /> : null}
      {rules.isError ? <ErrorNote error={rules.error} /> : null}
      <div className="space-y-2">
        {(rules.data ?? []).map((rule) => (
          <RuleRow key={`${rule.id}:${rule.version}:${rule.enabled}`} rule={rule} />
        ))}
      </div>
    </div>
  );
}

function RuleRow({ rule }: { rule: Rule }) {
  const client = useQueryClient();
  const [threshold, setThreshold] = useState(String(rule.logic.threshold ?? ""));
  const [windowSeconds, setWindowSeconds] = useState(String(rule.logic.window_seconds ?? ""));
  const [windowType, setWindowType] = useState(rule.logic.window_type ?? "tumbling");
  const save = useMutation({
    mutationFn: (body: { enabled?: boolean; threshold?: number; window_seconds?: number; window_type?: string }) =>
      api.patchRule(rule.id, body),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  return (
    <form
      className="grid gap-2 rounded-lg border border-line bg-panel p-3 md:grid-cols-[minmax(0,1fr)_auto]"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate({
          threshold: Number(threshold),
          window_seconds: Number(windowSeconds),
          window_type: windowType,
        });
      }}
    >
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{rule.name}</span>
          <span className={rule.enabled ? "text-ok" : "text-mute"}>
            {rule.enabled ? "enabled" : "disabled"}
          </span>
          {rule.severity ? <Badge value={rule.severity} /> : null}
          <span className="text-[11px] text-mute">v{rule.version}</span>
        </div>
        <p className="mt-1 text-xs text-mute">{rule.description}</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <label className="text-[11px] text-mute">
            Threshold
            <Input className="w-24" value={threshold} onChange={(event) => setThreshold(event.target.value)} />
          </label>
          <label className="text-[11px] text-mute">
            Window seconds
            <Input
              className="w-28"
              value={windowSeconds}
              onChange={(event) => setWindowSeconds(event.target.value)}
            />
          </label>
          <label className="text-[11px] text-mute">
            Window
            <Select value={windowType} onChange={(event) => setWindowType(event.target.value)}>
              <option value="tumbling">tumbling</option>
              <option value="sliding">sliding</option>
            </Select>
          </label>
        </div>
        {save.isError ? <ErrorNote error={save.error} /> : null}
      </div>
      <div className="flex items-start gap-2">
        <Button type="submit" variant="outline" disabled={save.isPending}>
          Save
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={save.isPending}
          onClick={() => save.mutate({ enabled: !rule.enabled })}
        >
          {rule.enabled ? "Disable" : "Enable"}
        </Button>
      </div>
    </form>
  );
}
