import { describe, expect, it, vi } from "vitest";
import { api, apiBase, apiUrl, queryString } from "@/lib/api";

describe("api client", () => {
  it("drops empty query values", () => {
    expect(queryString({ source_id: "abc", q: "", limit: 50, offset: 0 })).toBe(
      "source_id=abc&limit=50&offset=0".replace(/^/, "?"),
    );
  });

  it("reads overview JSON from the response body", async () => {
    const payload = { events: 7, alerts: 1 };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(payload), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.overview("src-1")).resolves.toMatchObject({ events: 7, alerts: 1 });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/overview?source_id=src-1",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    vi.unstubAllGlobals();
  });

  it("keeps same-origin paths when no API origin is configured", () => {
    vi.stubEnv("VITE_API_BASE_URL", "");
    expect(apiBase()).toBe("");
    expect(apiUrl("/health")).toBe("/health");
    vi.unstubAllEnvs();
  });

  it("uses a public API origin without credentials", () => {
    vi.stubEnv("VITE_API_BASE_URL", "https://api.example.test/");
    expect(apiUrl("/api/v1/overview")).toBe("https://api.example.test/api/v1/overview");
    vi.stubEnv("VITE_API_BASE_URL", "https://user:secret@api.example.test");
    expect(() => apiBase()).toThrow(/credentials/);
    vi.unstubAllEnvs();
  });

  it("surfaces API error detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ detail: "source not found" }), { status: 404 })),
    );
    await expect(api.overview("missing")).rejects.toThrow("source not found");
    vi.unstubAllGlobals();
  });
});
