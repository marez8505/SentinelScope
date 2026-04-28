import { cn } from "@/lib/utils";

const sev = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof sev)[number];

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const s = (sev.includes(severity as Severity) ? severity : "info") as Severity;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-mono uppercase tracking-wide",
        `sev-${s}`,
        className,
      )}
      data-testid={`badge-severity-${s}`}
    >
      {s}
    </span>
  );
}
