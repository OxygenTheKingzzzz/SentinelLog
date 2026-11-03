import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SourcesPage } from "@/pages/SourcesPage";
import { collectorFixture, liveStatusFixture } from "@/test/fixtures/collectors";

vi.mock("@/lib/api", () => ({
  api: {
    jobs: () => Promise.resolve([]),
    liveStatus: () => Promise.resolve(liveStatusFixture),
    liveCollectors: () => Promise.resolve(collectorFixture),
  },
}));

describe("SourcesPage", () => {
  it("renders collector health from the fixture", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <SourcesPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("fixture-live")).toBeInTheDocument();
    expect(screen.getByTestId("collector-imported")).toHaveTextContent("4");
    expect(screen.getByText("/tmp/allowed/app.log")).toBeInTheDocument();
    expect(screen.getByText(liveStatusFixture.journald_detail, { exact: false })).toBeInTheDocument();
  });
});
