import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ApiError, api, type RealisticModel, type RiskModelResult } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useSelection } from "@/store/selection";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";

const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const NOT_EVALUATED = "Not evaluated — ground-truth labels required";

function metricText(model: RiskModelResult, key: "accuracy" | "precision" | "recall" | "f1" | "roc_auc" | "pr_auc") {
  if (!model.real_world || model.metrics == null) return NOT_EVALUATED;
  const value = model.metrics[key];
  if (value == null) return model.metrics[`${key}_note` as "roc_auc_note"] ?? "undefined";
  return value.toFixed(3);
}

export function RiskPage() {
  const sourceId = useSelection((state) => state.sourceId);
  const client = useQueryClient();
  const experiments = useQuery({ queryKey: ["risk-experiments"], queryFn: api.riskExperiments });
  const realistic = useQuery({ queryKey: ["risk-realistic"], queryFn: api.riskRealistic });
  const distribution = useQuery({
    queryKey: ["risk-distribution", sourceId],
    queryFn: () => api.riskDistribution(sourceId),
  });
  const stored = useQuery({ queryKey: ["risk-models"], queryFn: api.riskModels });
  const predictions = useQuery({
    queryKey: ["risk-predictions", sourceId],
    queryFn: () => api.riskPredictions({ source_id: sourceId, limit: 100 }),
  });
  const [picked, setPicked] = useState<string | null>(null);
  const [level, setLevel] = useState<(typeof LEVELS)[number]>("HIGH");
  const [note, setNote] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const label = useMutation({
    mutationFn: (eventId: string) =>
      api.saveRiskLabel({ log_event_id: eventId, risk_level: level, note: note || undefined }),
    onSuccess: async () => {
      setMessage("Verified manual label saved. It is not a model prediction.");
      await client.invalidateQueries({ queryKey: ["risk-predictions"] });
    },
    onError: (error: Error) => setMessage(error.message),
  });
  const upload = useMutation({
    mutationFn: (file: File) => {
      if (!sourceId) throw new Error("Choose a source before importing labels.");
      return api.importRiskLabels(sourceId, file);
    },
    onSuccess: (result) => setMessage(`Imported ${result.labels} verified labels.`),
    onError: (error: Error) => setMessage(error.message),
  });
  const bands = useMutation({
    mutationFn: () => {
      if (!sourceId) throw new Error("Choose a source before fitting score bands.");
      return api.trainRiskBands(sourceId);
    },
    onSuccess: async () => {
      setMessage("Score bands fitted. Accuracy stays unevaluated without verified labels.");
      await client.invalidateQueries({ queryKey: ["risk-predictions"] });
      await client.invalidateQueries({ queryKey: ["risk-distribution"] });
      await client.invalidateQueries({ queryKey: ["risk-models"] });
    },
    onError: (error: Error) => setMessage(error.message),
  });

  const rows = predictions.data?.items ?? [];
  const selected = rows.find((row) => row.id === picked) ?? rows[0];
  const published = experiments.data?.experiments ?? [];
  const evaluated = published.flatMap((experiment) =>
    experiment.models
      .filter((model) => model.real_world && model.metrics?.confusion_matrix)
      .map((model) => ({ experiment, model })),
  );

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber/40 bg-amber/10 px-3 py-2">
        <div className="text-xs font-medium text-amber">Linux risk accuracy</div>
        <p className="mt-1 text-xs text-mute">{NOT_EVALUATED}</p>
        <p className="mt-1 text-xs text-mute">
          Loghub Linux has no verified risk labels. Score bands, rule alerts, and weak labels stay
          separate from held-out accuracy.
        </p>
      </div>
      {message ? <p className="text-xs text-cyan">{message}</p> : null}
      {experiments.isLoading ? <Loading label="Loading evaluations" /> : null}
      {experiments.isError ? <ErrorNote error={experiments.error} /> : null}

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_280px]">
        <Card>
          <CardHeader>
            <CardTitle>Risk distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {(distribution.data?.counts.length ?? 0) === 0 ? (
              <Empty>No risk predictions for this source yet.</Empty>
            ) : (
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={distribution.data?.counts ?? []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="risk" />
                    <YAxis allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#5ec8d8" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
            <p className="mt-2 text-[11px] text-mute">
              {distribution.data?.metrics_note ?? "Counts are model predictions, not verified labels."}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Label a stored log</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            <p className="text-mute">Manual labels are verified_manual. They are not copied from the model.</p>
            <Select className="w-full" value={level} onChange={(event) => setLevel(event.target.value as (typeof LEVELS)[number])}>
              {LEVELS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </Select>
            <input
              className="w-full rounded border border-line bg-navy px-2 py-1"
              placeholder="Reviewer note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
            <Button
              type="button"
              disabled={!selected || label.isPending}
              onClick={() => selected && label.mutate(selected.log_event_id)}
            >
              Save verified label
            </Button>
            <label className="block text-mute">
              Import verified CSV
              <input
                className="mt-1 block w-full text-ink"
                type="file"
                accept=".csv,text/csv"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) upload.mutate(file);
                }}
              />
            </label>
            <Button type="button" variant="outline" disabled={!sourceId || bands.isPending} onClick={() => bands.mutate()}>
              Fit unsupervised bands
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Benchmark comparison (rebalanced sample)</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-mute">
              <tr>
                <th className="px-2 py-1">Dataset</th>
                <th className="px-2 py-1">Model</th>
                <th className="px-2 py-1">Labels</th>
                <th className="px-2 py-1">Train / test</th>
                <th className="px-2 py-1">Accuracy</th>
                <th className="px-2 py-1">Precision</th>
                <th className="px-2 py-1">Recall</th>
                <th className="px-2 py-1">F1</th>
                <th className="px-2 py-1">ROC-AUC</th>
                <th className="px-2 py-1">PR-AUC</th>
              </tr>
            </thead>
            <tbody>
              {published.flatMap((experiment) =>
                experiment.models.map((model) => (
                  <tr key={`${experiment.dataset}-${model.algorithm}`} className="border-t border-line">
                    <td className="px-2 py-1">{experiment.dataset}</td>
                    <td className="px-2 py-1">{model.algorithm}</td>
                    <td className="px-2 py-1">{experiment.label_provenance}</td>
                    <td className="px-2 py-1">
                      {model.n_train ?? "—"} / {model.n_test ?? "—"}
                    </td>
                    <td className="px-2 py-1">{metricText(model, "accuracy")}</td>
                    <td className="px-2 py-1">{metricText(model, "precision")}</td>
                    <td className="px-2 py-1">{metricText(model, "recall")}</td>
                    <td className="px-2 py-1">{metricText(model, "f1")}</td>
                    <td className="px-2 py-1">{metricText(model, "roc_auc")}</td>
                    <td className="px-2 py-1">{metricText(model, "pr_auc")}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
          <p className="mt-3 text-[11px] text-mute">
            This table keeps the original benchmark. BGL and HDFS were drawn round-robin by class
            before the split, so their anomaly rate is much higher than the corpus. It is not the
            realistic-prevalence result.
          </p>
          <div className="mt-3 space-y-2 text-[11px] text-mute">
            {published.map((experiment) => (
              <p key={experiment.dataset}>
                <span className="text-ink">{experiment.dataset}</span> · {experiment.label_unit} ·{" "}
                {populationText(experiment.population)}
                {experiment.label_definition}{" "}
                {typeof experiment.sample.method === "string" ? experiment.sample.method : ""}
              </p>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Realistic prevalence and chronological holdout</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {realistic.isLoading ? <Loading label="Loading realistic evaluations" /> : null}
          {realistic.data && realistic.data.experiments.length === 0 ? (
            <Empty>{realistic.data.detail ?? "Realistic prevalence results have not been generated."}</Empty>
          ) : null}
          <p className="mb-2 text-[11px] text-mute">
            Groups were assigned before sampling. Validation chose the threshold. Test rows keep the
            holdout's own anomaly rate. These binary scores do not validate four-class severity.
          </p>
          <table className="w-full text-left text-xs">
            <thead className="text-mute">
              <tr>
                <th className="px-2 py-1">Dataset</th>
                <th className="px-2 py-1">Protocol</th>
                <th className="px-2 py-1">Model</th>
                <th className="px-2 py-1">Test prevalence</th>
                <th className="px-2 py-1">Accuracy</th>
                <th className="px-2 py-1">Precision</th>
                <th className="px-2 py-1">Recall</th>
                <th className="px-2 py-1">F1</th>
                <th className="px-2 py-1">ROC-AUC</th>
                <th className="px-2 py-1">PR-AUC</th>
                <th className="px-2 py-1">FP / 1,000 normal</th>
              </tr>
            </thead>
            <tbody>
              {(realistic.data?.experiments ?? []).flatMap((experiment) => {
                if (experiment.protocols.length === 0) {
                  return [
                    <tr key={`${experiment.dataset}-empty`} className="border-t border-line">
                      <td className="px-2 py-1">{experiment.dataset}</td>
                      <td className="px-2 py-1" colSpan={10}>
                        {experiment.metrics_note ?? experiment.detail}
                      </td>
                    </tr>,
                  ];
                }
                return experiment.protocols.flatMap((protocol) => {
                  if (!protocol.meaningful || protocol.models.length === 0) {
                    return [
                      <tr key={`${experiment.dataset}-${protocol.name}-skipped`} className="border-t border-line">
                        <td className="px-2 py-1">{experiment.dataset}</td>
                        <td className="px-2 py-1">{protocol.name}</td>
                        <td className="px-2 py-1" colSpan={9}>
                          {protocol.reason}
                        </td>
                      </tr>,
                    ];
                  }
                  return protocol.models.map((model) => {
                    if (!model.real_world || model.operating_point == null) {
                      const reason = [model.metrics_note ?? NOT_EVALUATED, model.detail]
                        .filter((part): part is string => Boolean(part))
                        .filter((part, index, all) => all.indexOf(part) === index)
                        .join(" ");
                      return (
                        <tr
                          key={`${experiment.dataset}-${protocol.name}-${model.algorithm}`}
                          className="border-t border-line"
                        >
                          <td className="px-2 py-1">{experiment.dataset}</td>
                          <td className="px-2 py-1">{protocol.name}</td>
                          <td className="px-2 py-1">{model.algorithm}</td>
                          <td className="px-2 py-1" colSpan={8}>
                            {reason}
                          </td>
                        </tr>
                      );
                    }
                    return (
                      <tr
                        key={`${experiment.dataset}-${protocol.name}-${model.algorithm}`}
                        className="border-t border-line"
                      >
                        <td className="px-2 py-1">{experiment.dataset}</td>
                        <td className="px-2 py-1">{protocol.name}</td>
                        <td className="px-2 py-1">{model.algorithm}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "prevalence")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "accuracy")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "precision")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "recall")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "f1")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "roc_auc")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "pr_auc")}</td>
                        <td className="px-2 py-1">{realisticMetric(model, "fp_per_1000_normal")}</td>
                      </tr>
                    );
                  });
                });
              })}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {evaluated.map(({ experiment, model }) => (
        <Card key={`${experiment.dataset}-${model.algorithm}`}>
          <CardHeader>
            <CardTitle>
              Confusion matrix · {experiment.dataset} · {model.algorithm}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ConfusionTable
              labels={model.metrics?.confusion_matrix?.labels ?? []}
              matrix={model.metrics?.confusion_matrix?.matrix ?? []}
            />
            <ul className="mt-2 space-y-1 text-[11px] text-mute">
              {(model.metrics?.per_class ?? []).map((row) => (
                <li key={row.label}>
                  {row.label}: precision {row.precision.toFixed(3)} · recall {row.recall.toFixed(3)} · F1{" "}
                  {row.f1.toFixed(3)} · support {row.support}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px] text-mute">
              Macro F1 {model.metrics?.f1_macro?.toFixed(3) ?? "—"} · weighted F1{" "}
              {model.metrics?.f1_weighted?.toFixed(3) ?? "—"} · train positives{" "}
              {model.metrics?.n_train_positive ?? "—"} · test positives {model.metrics?.n_test_positive ?? "—"}
              . Precision, recall, and F1 in the table are the anomaly class for binary datasets. These
              counts are the held-out split of the sampled groups, not a second full-corpus pass.
            </p>
          </CardContent>
        </Card>
      ))}

      <Card>
        <CardHeader>
          <CardTitle>Stored model runs</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          {(stored.data ?? []).length === 0 ? <Empty>No risk model is stored for this database.</Empty> : null}
          {(stored.data ?? []).map((model) => (
            <div key={model.id} className="rounded border border-line px-2 py-1">
              <div>
                v{model.version} · {model.algorithm} · {model.label_provenance} · {model.metrics_status}
              </div>
              <div className="text-mute">{model.metrics_note}</div>
              {model.label_provenance === "weak_rule" && model.config.weak_label_agreement ? (
                <div className="text-amber">
                  Agreement with weak rule labels is {model.config.weak_label_agreement.accuracy?.toFixed(3)}.
                  This is not real-world accuracy.
                </div>
              ) : null}
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Predicted risk</CardTitle>
        </CardHeader>
        <CardContent>
          {predictions.isLoading ? <Loading label="Loading predictions" /> : null}
          {predictions.isError && predictions.error instanceof ApiError && predictions.error.status !== 404 ? (
            <ErrorNote error={predictions.error} />
          ) : null}
          {rows.length === 0 ? <Empty>Fit score bands or train on verified labels to see predictions.</Empty> : null}
          {rows.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-mute">
                  <tr>
                    <th className="px-2 py-1">Line</th>
                    <th className="px-2 py-1">Time (UTC)</th>
                    <th className="px-2 py-1">Prediction</th>
                    <th className="px-2 py-1">Class probability</th>
                    <th className="px-2 py-1">Anomaly score</th>
                    <th className="px-2 py-1">Verified label</th>
                    <th className="px-2 py-1">Content</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr
                      key={row.id}
                      className="cursor-pointer border-t border-line hover:bg-white/5"
                      onClick={() => setPicked(row.id)}
                    >
                      <td className="px-2 py-1 font-mono">{row.line_number}</td>
                      <td className="px-2 py-1 whitespace-nowrap">{formatWhen(row.event_timestamp)}</td>
                      <td className="px-2 py-1">
                        <Badge value={row.predicted_risk.toLowerCase()} />
                      </td>
                      <td className="px-2 py-1">
                        {row.class_confidence == null ? "—" : row.class_confidence.toFixed(3)}
                      </td>
                      <td className="px-2 py-1">
                        {row.anomaly_score == null ? "—" : row.anomaly_score.toFixed(3)}
                      </td>
                      <td className="px-2 py-1">
                        {row.verified_label ? (
                          <Badge value={row.verified_label.toLowerCase()} />
                        ) : row.attached_provenance === "weak_rule" ? (
                          <span className="text-amber">weak {row.attached_label}</span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="max-w-[360px] truncate px-2 py-1">{row.content}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {selected ? (
                <p className="mt-2 text-[11px] text-mute">
                  {selected.explanation.summary} Model {selected.algorithm}. Split {selected.split_role}.
                </p>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

function realisticMetric(
  model: RealisticModel,
  key: "accuracy" | "precision" | "recall" | "f1" | "roc_auc" | "pr_auc" | "fp_per_1000_normal" | "prevalence",
) {
  if (!model.real_world || model.operating_point == null) return NOT_EVALUATED;
  const value = model.operating_point[key];
  if (value == null) return "—";
  return value.toFixed(3);
}

function populationText(population: Record<string, number | string>) {
  const parts = ["normal", "anomaly", "sampled", "lines", "instances"]
    .filter((key) => typeof population[key] === "number")
    .map((key) => `${key} ${population[key]}`);
  return parts.length > 0 ? `${parts.join(", ")}. ` : "";
}

function ConfusionTable({ labels, matrix }: { labels: string[]; matrix: number[][] }) {
  return (
    <table className="text-xs">
      <thead>
        <tr>
          <th className="px-2 py-1 text-mute">Actual \ predicted</th>
          {labels.map((label) => (
            <th key={label} className="px-2 py-1">
              {label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {matrix.map((row, index) => (
          <tr key={labels[index] ?? index}>
            <th className="px-2 py-1 text-left">{labels[index]}</th>
            {row.map((value, column) => (
              <td key={`${labels[index]}-${labels[column]}`} className="px-2 py-1 font-mono">
                {value}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
