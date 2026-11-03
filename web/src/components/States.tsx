import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";

export function Loading({ label = "Loading" }: { label?: string }) {
  return <p className="px-1 py-6 text-mute">{label}…</p>;
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
