import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";

export function SourcesPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const setSourceId = useSelection((state) => state.setSourceId);
  const [name, setName] = useState("");
  const [year, setYear] = useState("");
  const [liveName, setLiveName] = useState("");
  const [livePath, setLivePath] = useState("");
  const [liveYear, setLiveYear] = useState("");
  const [kind, setKind] = useState<"raw" | "templates" | "structured">("raw");
  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const client = useQueryClient();
  const jobs = useQuery({
    queryKey: ["jobs", sourceId],
    queryFn: () => api.jobs(sourceId),
  });
  const liveStatus = useQuery({ queryKey: ["live-status"], queryFn: api.liveStatus });
  const collectors = useQuery({ queryKey: ["live-collectors"], queryFn: api.liveCollectors });
  const errors = useQuery({
    queryKey: ["job-errors", jobId],
    queryFn: () => api.jobErrors(jobId ?? ""),
    enabled: Boolean(jobId),
  });
  const create = useMutation({
    mutationFn: () =>
      api.createSource({
        name,
        source_year: year ? Number(year) : null,
      }),
    onSuccess: async (source) => {
      setName("");
      setSourceId(source.id);
      await client.invalidateQueries({ queryKey: ["sources"] });
    },
  });
  const authorize = useMutation({
    mutationFn: () =>
      api.authorizeFile({
        name: liveName,
        path: livePath,
        source_year: liveYear ? Number(liveYear) : null,
      }),
    onSuccess: async (collector) => {
      setLiveName("");
      setLivePath("");
      setSourceId(collector.source_id);
      await client.invalidateQueries({ queryKey: ["live-collectors"] });
      await client.invalidateQueries({ queryKey: ["sources"] });
    },
  });
  const toggleCollector = useMutation({
    mutationFn: (collector: { id: string; enabled: boolean }) =>
      collector.enabled ? api.stopCollector(collector.id) : api.startCollector(collector.id),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["live-collectors"] });
    },
  });
  const upload = useMutation({
    mutationFn: () => api.upload(sourceId ?? "", kind, file as File),
    onSuccess: async (job) => {
      setJobId(job.id);
      setFile(null);
      await client.invalidateQueries({ queryKey: ["jobs"] });
      await client.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return (
    <div className="space-y-3">
      <h1 className="text-sm font-medium">Data sources</h1>
      <section className="space-y-2 rounded-lg border border-line bg-panel px-3 py-2 text-xs">
        <h2 className="text-[11px] uppercase tracking-wider text-mute">Live collectors</h2>
        <p className="text-mute">
          {liveStatus.data?.journald_detail ?? "Checking journald…"} File tails read as this user, not as root,
          and log text is not sent to a shell.
        </p>
        {liveStatus.data ? (
          <p className="text-mute">
            Allowlist: {liveStatus.data.allow_roots.length ? liveStatus.data.allow_roots.join(", ") : "empty"}
          </p>
        ) : null}
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            authorize.mutate();
          }}
        >
          <label className="text-[11px] text-mute">
            Live source name
            <Input value={liveName} onChange={(event) => setLiveName(event.target.value)} required />
          </label>
          <label className="text-[11px] text-mute">
            Authorized file
            <Input
              value={livePath}
              onChange={(event) => setLivePath(event.target.value)}
              placeholder="/var/log/sentinellog/app.log"
              required
              className="w-72"
            />
          </label>
          <label className="text-[11px] text-mute">
            Year
            <Input
              value={liveYear}
              onChange={(event) => setLiveYear(event.target.value)}
              className="w-24"
            />
          </label>
          <Button type="submit" disabled={authorize.isPending}>
            Authorize file
          </Button>
        </form>
        {authorize.isError ? <ErrorNote error={authorize.error} /> : null}
        {collectors.isLoading ? <Loading label="Loading collectors" /> : null}
        {collectors.isError ? <ErrorNote error={collectors.error} /> : null}
        {collectors.data && collectors.data.length === 0 ? (
          <Empty>No authorized live files.</Empty>
        ) : null}
        {collectors.data && collectors.data.length > 0 ? (
          <table className="w-full text-left">
            <thead className="text-mute">
              <tr>
                <th className="py-1 font-medium">Source</th>
                <th className="py-1 font-medium">Status</th>
                <th className="py-1 font-medium">Imported</th>
                <th className="py-1 font-medium">Duplicates</th>
                <th className="py-1 font-medium">Offset</th>
                <th className="py-1 font-medium">Path</th>
                <th className="py-1 font-medium" />
              </tr>
            </thead>
            <tbody>
              {collectors.data.map((collector) => (
                <tr key={collector.id} className="border-t border-line">
                  <td className="py-1">
                    {collector.source_name} <Badge value="live" />
                  </td>
                  <td className="py-1">
                    <Badge value={collector.status} />
                  </td>
                  <td className="py-1 font-mono" data-testid="collector-imported">
                    {collector.lines_imported}
                  </td>
                  <td className="py-1 font-mono">{collector.duplicates_skipped}</td>
                  <td className="py-1 font-mono">{collector.byte_offset}</td>
                  <td className="max-w-[280px] truncate py-1 text-mute">{collector.path}</td>
                  <td className="py-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => toggleCollector.mutate(collector)}
                    >
                      {collector.enabled ? "Stop" : "Start"}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        {collectors.data?.some((collector) => collector.last_error) ? (
          <ul className="text-danger">
            {collectors.data
              .filter((collector) => collector.last_error)
              .map((collector) => (
                <li key={collector.id}>
                  {collector.source_name}: {collector.last_error}
                </li>
              ))}
          </ul>
        ) : null}
      </section>
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate();
        }}
      >
        <label className="text-[11px] text-mute">
          New source
          <Input value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <label className="text-[11px] text-mute">
          Year (optional)
          <Input
            value={year}
            onChange={(event) => setYear(event.target.value)}
            inputMode="numeric"
            className="w-28"
          />
        </label>
        <Button type="submit" disabled={create.isPending}>
          Create source
        </Button>
      </form>
      {create.isError ? <ErrorNote error={create.error} /> : null}
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (file && sourceId) upload.mutate();
        }}
      >
        <label className="text-[11px] text-mute">
          Upload into the selected source
          <Select
            value={kind}
            onChange={(event) => setKind(event.target.value as "raw" | "templates" | "structured")}
          >
            <option value="raw">Raw log</option>
            <option value="templates">Template CSV</option>
            <option value="structured">Structured CSV</option>
          </Select>
        </label>
        <Input
          type="file"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <Button type="submit" disabled={!sourceId || !file || upload.isPending}>
          Upload
        </Button>
      </form>
      {!sourceId ? <p className="text-xs text-mute">Choose a source in the header before uploading.</p> : null}
      {upload.isError ? <ErrorNote error={upload.error} /> : null}
      {upload.data ? (
        <p className="text-xs">
          Job {upload.data.status}: parsed {upload.data.lines_parsed}, errored {upload.data.lines_errored},
          duplicates {upload.data.duplicates_skipped}.
        </p>
      ) : null}
      {jobs.isLoading ? <Loading label="Loading jobs" /> : null}
      {jobs.isError ? <ErrorNote error={jobs.error} /> : null}
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-xs">
          <thead className="bg-panel text-mute">
            <tr>
              <th className="px-2 py-1.5 font-medium">When (UTC)</th>
              <th className="px-2 py-1.5 font-medium">File</th>
              <th className="px-2 py-1.5 font-medium">Kind</th>
              <th className="px-2 py-1.5 font-medium">Status</th>
              <th className="px-2 py-1.5 font-medium">Parsed</th>
              <th className="px-2 py-1.5 font-medium">Errors</th>
            </tr>
          </thead>
          <tbody>
            {(jobs.data ?? []).map((job) => (
              <tr key={job.id} className="border-t border-line">
                <td className="px-2 py-1 whitespace-nowrap">{formatWhen(job.created_at)}</td>
                <td className="px-2 py-1">
                  <button type="button" className="text-cyan" onClick={() => setJobId(job.id)}>
                    {job.filename}
                  </button>
                </td>
                <td className="px-2 py-1">{job.kind}</td>
                <td className="px-2 py-1">
                  <Badge value={job.status} />
                </td>
                <td className="px-2 py-1 font-mono">{job.lines_parsed}</td>
                <td className="px-2 py-1 font-mono">{job.lines_errored}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {jobs.data && jobs.data.length === 0 ? <Empty>No ingestion jobs for this selection.</Empty> : null}
      </div>
      {jobId ? (
        <section className="rounded-lg border border-line bg-panel p-3 text-xs">
          <h2 className="text-[11px] uppercase tracking-wider text-mute">Parse errors</h2>
          {errors.isLoading ? <Loading /> : null}
          {errors.isError ? <ErrorNote error={errors.error} /> : null}
          {errors.data && errors.data.length === 0 ? <Empty>This job recorded no per-line errors.</Empty> : null}
          <ul className="mt-2 space-y-2">
            {(errors.data ?? []).map((error, index) => (
              <li key={`${error.line_number}-${index}`} className="border-t border-line pt-1">
                <span className="text-mute">
                  line {error.line_number ?? "—"} · {error.error_kind}
                </span>
                <div>{error.message}</div>
                {error.raw_line ? <pre className="whitespace-pre-wrap text-mute">{error.raw_line}</pre> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
