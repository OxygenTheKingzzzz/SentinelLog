import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RiskPage } from "@/pages/RiskPage";

vi.mock("recharts", () => {
  const Pass = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
  return {
    ResponsiveContainer: Pass,
    BarChart: Pass,
    Bar: () => null,
    XAxis: () => null,
    YAxis: () => null,
    Tooltip: () => null,
    CartesianGrid: () => null,
  };
});

vi.mock("@/lib/api", () => ({
  api: {
    riskRealistic: () =>
      Promise.resolve({
        generated_at: "2026-11-03T12:00:00Z",
        experiments: [
          {
            dataset: "bgl",
            protocols: [
              {
                name: "realistic_group",
                meaningful: true,
                models: [
                  {
                    algorithm: "random_forest",
                    metrics_status: "evaluated",
                    metrics_note: null,
                    detail: "binary",
                    real_world: true,
                    n_train: 100,
                    n_validation: 40,
                    n_test: 80,
                    operating_point: {
                      accuracy: 0.91,
                      precision: 0.4,
                      recall: 0.5,
                      f1: 0.44,
                      roc_auc: 0.88,
                      pr_auc: 0.42,
                      fp_per_1000_normal: 12.5,
                      prevalence: 0.074,
                    },
                  },
                ],
              },
            ],
          },
          {
            dataset: "openstack",
            protocols: [
              {
                name: "realistic_group",
                meaningful: true,
                models: [
                  {
                    algorithm: "random_forest",
                    metrics_status: "not_evaluated",
                    metrics_note: "Not evaluated — ground-truth labels required",
                    detail:
                      "Fewer than two template groups contain any anomaly. A supervised model cannot be trained on that template and tested on a different one.",
                    real_world: false,
                    n_train: 10,
                    n_validation: 4,
                    n_test: 4,
                    operating_point: null,
                  },
                ],
              },
            ],
          },
          {
            dataset: "linux",
            metrics_note: "Not evaluated — ground-truth labels required",
            detail: "Estimated bands are not validated four-class severity.",
            protocols: [],
          },
        ],
      }),
    riskExperiments: () =>
      Promise.resolve({
        generated_at: "2026-11-03T11:00:00Z",
        experiments: [
          {
            dataset: "linux",
            dataset_version: "loghub-Linux_2k",
            source_url: null,
            label_unit: "line",
            label_provenance: "none",
            label_definition: "Loghub's dataset table leaves Linux unlabeled.",
            population: {},
            sample: {},
            task: "multiclass_risk",
            random_seed: 42,
            models: [
              {
                algorithm: "isolation_forest",
                task: "unsupervised_band",
                fit_protocol: "group_holdout",
                n_train: null,
                n_test: null,
                metrics_status: "not_evaluated",
                metrics_note: "Not evaluated — ground-truth labels required",
                detail: "unlabeled",
                metrics: null,
                cv: { folds: 0 },
                real_world: false,
              },
            ],
          },
          {
            dataset: "bgl",
            dataset_version: "fixture",
            source_url: null,
            label_unit: "line",
            label_provenance: "dataset_native",
            label_definition: "First token is the alert label.",
            population: { lines: 100 },
            sample: {},
            task: "binary_anomaly",
            random_seed: 42,
            models: [
              {
                algorithm: "tfidf_logreg",
                task: "binary_anomaly",
                fit_protocol: "stratified_group",
                n_train: 70,
                n_test: 30,
                metrics_status: "evaluated",
                metrics_note: null,
                detail: "held out",
                real_world: true,
                cv: { folds: 3, note: "not the held-out test score" },
                metrics: {
                  accuracy: 0.8,
                  precision: 0.7,
                  recall: 0.6,
                  f1: 0.65,
                  f1_macro: 0.64,
                  f1_weighted: 0.78,
                  roc_auc: 0.9,
                  pr_auc: 0.75,
                  n_train_positive: 10,
                  n_test_positive: 4,
                  per_class: [
                    { label: "normal", precision: 0.9, recall: 0.8, f1: 0.85, support: 26 },
                    { label: "anomaly", precision: 0.7, recall: 0.6, f1: 0.65, support: 4 },
                  ],
                  confusion_matrix: {
                    labels: ["normal", "anomaly"],
                    matrix: [
                      [20, 6],
                      [2, 2],
                    ],
                  },
                },
              },
            ],
          },
        ],
      }),
    riskDistribution: () =>
      Promise.resolve({
        model_id: "m1",
        metrics_note: "Not evaluated — ground-truth labels required",
        counts: [{ risk: "LOW", count: 3 }],
      }),
    riskModels: () => Promise.resolve([]),
    riskPredictions: () =>
      Promise.resolve({
        total: 1,
        metrics_status: "not_evaluated",
        metrics_note: "Not evaluated — ground-truth labels required",
        items: [
          {
            id: "p1",
            model_id: "m1",
            algorithm: "isolation_forest",
            log_event_id: "e1",
            line_number: 4,
            event_timestamp: "2005-06-14T15:16:01Z",
            content: "authentication failure",
            split_role: "test",
            predicted_risk: "HIGH",
            class_confidence: null,
            anomaly_score: 0.42,
            score_kind: "anomaly_score",
            explanation: { summary: "Isolation Forest anomaly score 0.420." },
            attached_label: null,
            attached_provenance: null,
            verified_label: null,
          },
        ],
      }),
  },
}));

describe("RiskPage", () => {
  it("shows the unevaluated Linux note and a real confusion matrix", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <RiskPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Linux risk accuracy")).toBeInTheDocument();
    expect(await screen.findByText("0.800")).toBeInTheDocument();
    expect(screen.getAllByText("Not evaluated — ground-truth labels required").length).toBeGreaterThan(0);
    expect(screen.getAllByText("bgl").length).toBeGreaterThan(0);
    expect(screen.getByText("Confusion matrix · bgl · tfidf_logreg")).toBeInTheDocument();
    expect(screen.getByText("Realistic prevalence and chronological holdout")).toBeInTheDocument();
    expect(screen.getAllByText("realistic_group").length).toBeGreaterThan(0);
    expect(screen.getByText("12.500")).toBeInTheDocument();
    expect(screen.getByText(/Fewer than two template groups contain any anomaly/)).toBeInTheDocument();
    expect(screen.getByText("20")).toBeInTheDocument();
    expect(screen.getByText("authentication failure")).toBeInTheDocument();
  });
});
