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
  const [kind, setKind] = useState<"raw" | "templates" | "structured">("raw");
  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const client = useQueryClient();
  const jobs = useQuery({
    queryKey: ["jobs", sourceId],
    queryFn: () => api.jobs(sourceId),
  });
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
      <div className="rounded-lg border border-line bg-panel px-3 py-2 text-xs text-mute">
        <Button type="button" variant="outline" disabled>
          Start live collector
        </Button>
        <p className="mt-2">Live collectors are not in this build.</p>
      </div>
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
