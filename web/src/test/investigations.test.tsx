import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { InvestigationsPage } from "@/pages/InvestigationsPage";
import {
  graphFixture,
  investigationDetailFixture,
  investigationListFixture,
} from "@/test/fixtures/investigation";

vi.mock("@xyflow/react", () => ({
  ReactFlow: () => <div>graph</div>,
  Background: () => null,
  Controls: () => null,
}));

vi.mock("@/lib/api", () => ({
  api: {
    investigations: () => Promise.resolve(investigationListFixture),
    investigation: () => Promise.resolve(investigationDetailFixture),
    graph: () => Promise.resolve(graphFixture),
    evidence: () => Promise.resolve({}),
    downloadInvestigationPdf: () => Promise.resolve(),
  },
}));

describe("InvestigationsPage", () => {
  it("renders the three report sections and export actions", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <InvestigationsPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Observations" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Automated hypotheses" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Analyst-confirmed findings" })).toBeInTheDocument();
    expect(screen.getByTestId("export-json")).toBeInTheDocument();
    expect(screen.getByTestId("export-pdf")).toBeInTheDocument();
    expect(screen.getByText("rule rule-fixture version 2 threshold 5")).toBeInTheDocument();
    expect(screen.getByText("Analyst wrote this note.")).toBeInTheDocument();
    expect(screen.getAllByText("not a confirmed compromise").length).toBeGreaterThan(0);
  });
});