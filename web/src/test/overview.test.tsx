import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OverviewPage } from "@/pages/OverviewPage";
import { overviewFixture } from "@/test/fixtures/overview";

const { overviewMock } = vi.hoisted(() => ({ overviewMock: vi.fn() }));

vi.mock("recharts", () => {
  const Pass = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
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
  };
});

vi.mock("@/lib/api", () => ({
  api: {
    overview: (...args: unknown[]) => overviewMock(...args),
  },
}));

describe("OverviewPage", () => {
  beforeEach(() => {
    overviewMock.mockReset();
    overviewMock.mockResolvedValue(overviewFixture);
  });

  it("keeps the overview layout while the request is pending", () => {
    overviewMock.mockImplementation(() => new Promise(() => {}));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByRole("status", { name: "Loading overview" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByText("Events")).toBeInTheDocument();
    expect(screen.getByText("Event frequency")).toBeInTheDocument();
    expect(screen.queryByTestId("event-total")).not.toBeInTheDocument();
  });

  it("renders counts from the fixture response", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByTestId("event-total")).toHaveTextContent("42");
    expect(screen.getByTestId("alert-total")).toHaveTextContent("7");
    expect(screen.getByTestId("investigation-total")).toHaveTextContent("3");
    expect(screen.getByTestId("auth-total")).toHaveTextContent("11");
    expect(screen.getByText("fixture alert")).toBeInTheDocument();
    expect(screen.getByText("fixture-source")).toBeInTheDocument();
  });
});
