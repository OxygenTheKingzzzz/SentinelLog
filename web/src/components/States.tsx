import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";

export function Loading({ label = "Loading", rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div role="status" aria-busy="true" aria-label={label} className="space-y-2 px-1 py-2">
      <p className="text-[11px] text-mute">{label}…</p>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="h-8 animate-pulse rounded border border-line bg-panel-2" />
      ))}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  const message = error instanceof ApiError ? error.message : "The request failed.";
  return <p className="px-1 py-4 text-danger">{message}</p>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="px-1 py-6 text-mute">{children}</p>;
}

export function Stat({
  label,
  value,
  testId,
  hint,
}: {
  label: string;
  value: number | string;
  testId?: string;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <div className="text-[11px] uppercase tracking-wider text-mute">{label}</div>
      <div className="mt-1 font-mono text-2xl text-cyan" data-testid={testId}>
        {value}
      </div>
      {hint ? <div className="mt-1 text-[11px] text-mute">{hint}</div> : null}
    </div>
  );
}
