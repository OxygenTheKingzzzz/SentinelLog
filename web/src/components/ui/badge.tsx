import { cn } from "@/lib/utils";

const tones: Record<string, string> = {
  critical: "bg-danger/15 text-danger",
  high: "bg-high/15 text-high",
  medium: "bg-amber/15 text-amber",
  low: "bg-cyan/15 text-cyan",
  open: "bg-cyan/15 text-cyan",
  investigating: "bg-amber/15 text-amber",
  resolved: "bg-ok/15 text-ok",
  false_positive: "bg-mute/15 text-mute",
  closed: "bg-mute/15 text-mute",
  completed: "bg-ok/15 text-ok",
  failed: "bg-danger/15 text-danger",
  running: "bg-amber/15 text-amber",
  live: "bg-cyan/15 text-cyan",
  waiting: "bg-amber/15 text-amber",
  stopped: "bg-mute/15 text-mute",
  error: "bg-danger/15 text-danger",
};

export function Badge({ value }: { value: string }) {
  return (
    <span
      className={cn(
        "inline-flex rounded px-1.5 py-0.5 text-[11px] uppercase tracking-wide",
        tones[value] ?? "bg-white/5 text-mute",
      )}
    >
      {value.replaceAll("_", " ")}
    </span>
  );
}
