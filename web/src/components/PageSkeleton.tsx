import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function Bone({ className = "h-3 w-full" }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-panel-2 ${className}`} />;
}

export function LoadingRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="status" aria-busy="true" aria-label={label} className="space-y-2">
      <p className="text-[11px] text-mute">{label}</p>
      {children}
    </div>
  );
}

export function TableSkeleton({
  label,
  headers,
  rows = 8,
}: {
  label: string;
  headers: string[];
  rows?: number;
}) {
  return (
    <LoadingRegion label={label}>
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-xs">
          <thead className="bg-panel text-mute">
            <tr>
              {headers.map((header) => (
                <th key={header || "mark"} className="px-2 py-1.5 font-medium">
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }, (_, row) => (
              <tr key={row} className="border-t border-line">
                {headers.map((_, column) => (
                  <td key={`${row}-${column}`} className="px-2 py-2">
                    <Bone className={column === headers.length - 1 ? "h-3 w-4/5" : "h-3 w-16"} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </LoadingRegion>
  );
}

export function OverviewSkeleton() {
  return (
    <LoadingRegion label="Loading overview">
      <div>
        <h1 className="text-sm font-medium">Overview</h1>
        <Bone className="mt-2 h-3 w-64" />
      </div>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {["Events", "Rule alerts", "Investigations", "Auth failures"].map((label) => (
          <div key={label} className="rounded-lg border border-line bg-panel px-3 py-2">
            <div className="text-[11px] uppercase tracking-wider text-mute">{label}</div>
            <Bone className="mt-2 h-7 w-16" />
          </div>
        ))}
      </div>
      <div className="grid gap-2 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Event frequency</CardTitle>
          </CardHeader>
          <CardContent>
            <Bone className="h-52 w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Severity mix</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Bone className="h-8 w-full" />
            <Bone className="h-8 w-4/5" />
            <Bone className="h-8 w-3/5" />
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Auth-failure trend</CardTitle>
        </CardHeader>
        <CardContent>
          <Bone className="h-40 w-full" />
        </CardContent>
      </Card>
      <div className="grid gap-2 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent alerts</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Bone className="h-6 w-full" />
            <Bone className="h-6 w-full" />
            <Bone className="h-6 w-5/6" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Ingestion health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-3 gap-2">
              <Bone className="h-12" />
              <Bone className="h-12" />
              <Bone className="h-12" />
            </div>
            <Bone className="h-3 w-48" />
          </CardContent>
        </Card>
      </div>
    </LoadingRegion>
  );
}

export function PanelSkeleton({ label, rows = 4 }: { label: string; rows?: number }) {
  return (
    <LoadingRegion label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <Bone key={index} className="h-10 w-full" />
      ))}
    </LoadingRegion>
  );
}

export function ChartSkeleton({ label }: { label: string }) {
  return (
    <LoadingRegion label={label}>
      <Bone className="h-52 w-full" />
    </LoadingRegion>
  );
}

export function RowsSkeleton({ label, rows = 4 }: { label: string; rows?: number }) {
  return (
    <LoadingRegion label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="flex justify-between gap-3">
          <Bone className="h-3 w-24" />
          <Bone className="h-3 w-36" />
        </div>
      ))}
    </LoadingRegion>
  );
}

export function RuleListSkeleton() {
  return (
    <LoadingRegion label="Loading rules">
      {Array.from({ length: 6 }, (_, index) => (
        <div key={index} className="rounded-lg border border-line bg-panel p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Bone className="h-4 w-48" />
            <Bone className="h-3 w-16" />
            <Bone className="h-4 w-14" />
          </div>
          <Bone className="mt-2 h-3 w-full" />
          <div className="mt-3 flex flex-wrap gap-2">
            <Bone className="h-8 w-24" />
            <Bone className="h-8 w-28" />
            <Bone className="h-8 w-24" />
          </div>
        </div>
      ))}
    </LoadingRegion>
  );
}

export function InvestigationSkeleton() {
  return (
    <div className="space-y-3">
      <LoadingRegion label="Loading investigation">
        <Bone className="h-5 w-56" />
        <div className="grid gap-2 lg:grid-cols-3">
          {["Observations", "Automated hypotheses", "Analyst-confirmed findings"].map((title) => (
            <div key={title} className="space-y-2 rounded-lg border border-line bg-panel p-2">
              <div className="text-[11px] uppercase tracking-wider text-mute">{title}</div>
              <Bone className="h-12 w-full" />
              <Bone className="h-12 w-full" />
              <Bone className="h-12 w-4/5" />
            </div>
          ))}
        </div>
      </LoadingRegion>
      <div className="h-[440px] rounded-lg border border-line bg-navy p-3">
        <ChartSkeleton label="Loading graph" />
      </div>
    </div>
  );
}
