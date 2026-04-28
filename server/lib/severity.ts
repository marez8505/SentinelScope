import type { Finding } from "@shared/schema";

export const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
} as const;

export type Severity = keyof typeof SEVERITY_RANK;

/** Map a CVSS v3 base score to a coarse severity bucket. */
export function severityFromCvss(score: number | null | undefined): Severity {
  if (score == null || isNaN(score)) return "info";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Effective severity for a finding considering KEV (always critical) + EPSS bumps. */
export function effectiveSeverity(opts: {
  base: Severity;
  isKev?: boolean;
  epss?: number | null;
}): Severity {
  if (opts.isKev) return "critical";
  if (opts.epss != null) {
    if (opts.epss >= 0.5 && SEVERITY_RANK[opts.base] < SEVERITY_RANK.high) return "high";
    if (opts.epss >= 0.1 && SEVERITY_RANK[opts.base] < SEVERITY_RANK.medium) return "medium";
  }
  return opts.base;
}

/** Sort findings most-urgent-first. KEV before non-KEV, then severity, then CVSS. */
export function prioritizeFindings<T extends Pick<Finding, "severity" | "cvssScore">>(
  rows: T[],
  kevSet?: Set<string>,
  cveAccessor?: (row: T) => string[],
): T[] {
  return [...rows].sort((a, b) => {
    const aKev = kevSet && cveAccessor ? cveAccessor(a).some((c) => kevSet.has(c)) : false;
    const bKev = kevSet && cveAccessor ? cveAccessor(b).some((c) => kevSet.has(c)) : false;
    if (aKev !== bKev) return aKev ? -1 : 1;
    const sa = SEVERITY_RANK[(a.severity as Severity) ?? "info"] ?? 0;
    const sb = SEVERITY_RANK[(b.severity as Severity) ?? "info"] ?? 0;
    if (sa !== sb) return sb - sa;
    const ca = a.cvssScore ?? 0;
    const cb = b.cvssScore ?? 0;
    return cb - ca;
  });
}

export function severityCounts(rows: Pick<Finding, "severity">[]): Record<Severity, number> {
  const out: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const r of rows) {
    const s = (r.severity as Severity) || "info";
    out[s] = (out[s] ?? 0) + 1;
  }
  return out;
}
