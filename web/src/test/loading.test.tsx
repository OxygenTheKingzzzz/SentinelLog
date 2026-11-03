import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AlertsPage } from "@/pages/AlertsPage";
import { AnomaliesPage } from "@/pages/AnomaliesPage";
import { InvestigationsPage } from "@/pages/InvestigationsPage";
import { LogsPage } from "@/pages/LogsPage";
import { RiskPage } from "@/pages/RiskPage";
import { RulesPage } from "@/pages/RulesPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { SourcesPage } from "@/pages/SourcesPage";

vi.mock("recharts", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  return {
    ResponsiveContainer: Pass,
    BarChart: Pass,
    Bar: () => null,
    LineChart: Pass,
    Line: () => null,
    XAxis: () => null,
    YAxis: () => null,
    Tooltip: () => null,
    CartesianGrid: () => null,
    Legend: () => null,
  };
});

vi.mock("@xyflow/react", () => ({
  ReactFlow: () => null,
  Background: () => null,
  Controls: () => null,
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status = 0;
  },
  api: new Proxy(
    {},
    {
      get: () => () => new Promise(() => {}),
    },
  ),
}));

function renderPage(page: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("page loading structure", () => {
  it("keeps the log table while events are pending", () => {
    renderPage(<LogsPage />);
    expect(screen.getByRole("status", { name: "Loading events" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Content" })).toBeInTheDocument();
  });

  it("keeps the alert table and detail pane while alerts are pending", () => {
    renderPage(<AlertsPage />);
    expect(screen.getByRole("status", { name: "Loading alerts" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Title" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading alert" })).toBeInTheDocument();
  });

  it("keeps anomaly cards while the model is pending", () => {
    renderPage(<AnomaliesPage />);
    expect(screen.getByText("No ground truth / not a confirmed incident")).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading model" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Isolation" })).toBeInTheDocument();
  });

  it("keeps risk charts and tables instead of empty copy", () => {
    renderPage(<RiskPage />);
    expect(screen.getByRole("status", { name: "Loading risk distribution" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading evaluations" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading realistic evaluations" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading predictions" })).toBeInTheDocument();
    expect(screen.queryByText("No risk predictions for this source yet.")).not.toBeInTheDocument();
    expect(screen.queryByText("Fit score bands or train on verified labels to see predictions.")).not.toBeInTheDocument();
  });

  it("keeps rule cards while rules are pending", () => {
    renderPage(<RulesPage />);
    expect(screen.getByRole("heading", { name: "Rules" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading rules" })).toBeInTheDocument();
  });

  it("keeps settings sections while health and audit are pending", () => {
    renderPage(<SettingsPage />);
    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading database health" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading configuration" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading audit log" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Actor" })).toBeInTheDocument();
  });

  it("keeps source tables while collectors and jobs are pending", () => {
    renderPage(<SourcesPage />);
    expect(screen.getByRole("heading", { name: "Data sources" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading collectors" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading jobs" })).toBeInTheDocument();
    expect(screen.queryByText("No ingestion jobs for this selection.")).not.toBeInTheDocument();
  });

  it("keeps the investigation list and detail while they are pending", () => {
    renderPage(<InvestigationsPage />);
    expect(screen.getByRole("heading", { name: "Investigations" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading investigations" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading investigation" })).toBeInTheDocument();
    expect(screen.getByText("Observations")).toBeInTheDocument();
    expect(screen.queryByText("Create an investigation or open one from the list.")).not.toBeInTheDocument();
  });
});
