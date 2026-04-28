/**
 * Report rendering helpers — produces JSON and Markdown reports for a scan.
 */
import type { Finding, Scan, Kev, Epss } from "@shared/schema";
import { prioritizeFindings } from "./severity";

export interface ReportInput {
  scan: Scan;
  findings: Finding[];
  kev: Kev[];
  epss: Epss[];
}

export interface ReportJson {
  generated: string;
  tool: string;
  scan: {
    id: number;
    target: string;
    resolvedIp: string | null;
    profile: string;
    ports: number[];
    status: string;
    startedAt: number;
    finishedAt: number | null;
    summary: Record<string, number>;
  };
  findings: Array<
    Omit<Finding, "cveIds" | "references" | "evidence"> & {
      cveIds: string[];
      references: string[];
      evidence: unknown;
      kev?: Kev | null;
      epss?: Epss | null;
    }
  >;
}

function safeParse<T>(s: string | null | undefined, fallback: T): T {
  if (!s) return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

export function renderJson(input: ReportInput): ReportJson {
  const kevIndex = new Map(input.kev.map((k) => [k.cveId, k]));
  const epssIndex = new Map(input.epss.map((e) => [e.cveId, e]));

  const ranked = prioritizeFindings(
    input.findings,
    new Set(kevIndex.keys()),
    (f) => safeParse<string[]>(f.cveIds, []),
  );

  const summary: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of ranked) summary[f.severity] = (summary[f.severity] ?? 0) + 1;

  return {
    generated: new Date().toISOString(),
    tool: "SentinelScope",
    scan: {
      id: input.scan.id,
      target: input.scan.target,
      resolvedIp: input.scan.resolvedIp ?? null,
      profile: input.scan.profile,
      ports: safeParse<number[]>(input.scan.ports, []),
      status: input.scan.status,
      startedAt: input.scan.startedAt,
      finishedAt: input.scan.finishedAt ?? null,
      summary,
    },
    findings: ranked.map((f) => {
      const cves = safeParse<string[]>(f.cveIds, []);
      const firstKev = cves.find((c) => kevIndex.has(c));
      const firstEpss = cves.find((c) => epssIndex.has(c));
      return {
        ...f,
        cveIds: cves,
        references: safeParse<string[]>(f.references, []),
        evidence: safeParse<unknown>(f.evidence, null),
        kev: firstKev ? kevIndex.get(firstKev) ?? null : null,
        epss: firstEpss ? epssIndex.get(firstEpss) ?? null : null,
      };
    }),
  };
}

const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Markdown report. Plain text — no HTML — so it cannot host XSS even when rendered. */
export function renderMarkdown(input: ReportInput): string {
  const j = renderJson(input);
  const lines: string[] = [];
  lines.push(`# SentinelScope Report — Scan #${j.scan.id}`);
  lines.push("");
  lines.push(`Generated: ${j.generated}`);
  lines.push("");
  lines.push("## Authorization Notice");
  lines.push("");
  lines.push(
    "This report covers a scan of a target the operator declared they are authorized to assess. Do not use SentinelScope against systems you do not own or have written permission to test.",
  );
  lines.push("");
  lines.push("## Scope");
  lines.push("");
  lines.push(`- Target: \`${escapeMd(j.scan.target)}\``);
  lines.push(`- Resolved IP: \`${escapeMd(j.scan.resolvedIp ?? "n/a")}\``);
  lines.push(`- Profile: ${escapeMd(j.scan.profile)}`);
  lines.push(`- Ports: ${j.scan.ports.join(", ") || "(none)"}`);
  lines.push(`- Status: ${escapeMd(j.scan.status)}`);
  lines.push(
    `- Duration: ${j.scan.finishedAt ? Math.max(0, j.scan.finishedAt - j.scan.startedAt) + "ms" : "in progress"}`,
  );
  lines.push("");
  lines.push("## Severity Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    lines.push(`| ${SEV_LABEL[sev]} | ${j.scan.summary[sev] ?? 0} |`);
  }
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  if (!j.findings.length) {
    lines.push("_No findings recorded._");
  } else {
    lines.push("| # | Severity | Host | Port | Service | Title | CVSS | KEV | EPSS |");
    lines.push("|---|---|---|---|---|---|---|---|---|");
    j.findings.forEach((f, i) => {
      const epssScore = f.epss?.epss != null ? f.epss.epss.toFixed(2) : "—";
      lines.push(
        `| ${i + 1} | ${SEV_LABEL[f.severity] ?? f.severity} | ${escapeMd(f.host)} | ${f.port ?? "—"} | ${escapeMd(
          f.service ?? "—",
        )} | ${escapeMd(f.title)} | ${f.cvssScore != null ? f.cvssScore.toFixed(1) : "—"} | ${
          f.kev ? "Yes" : "—"
        } | ${epssScore} |`,
      );
    });
  }
  lines.push("");

  // Detailed sections
  for (const f of j.findings) {
    lines.push(`### Finding #${f.id} — ${SEV_LABEL[f.severity] ?? f.severity}: ${escapeMd(f.title)}`);
    lines.push("");
    if (f.host) lines.push(`- Host: \`${escapeMd(f.host)}\``);
    if (f.port != null) lines.push(`- Port: ${f.port}`);
    if (f.service) lines.push(`- Service: ${escapeMd(f.service)}`);
    if (f.product || f.version)
      lines.push(`- Product: ${escapeMd(f.product ?? "—")}${f.version ? " " + escapeMd(f.version) : ""}`);
    if (f.cvssScore != null) lines.push(`- CVSS: ${f.cvssScore.toFixed(1)}`);
    if (f.matchBasis) lines.push(`- Match basis: ${escapeMd(f.matchBasis)} (confidence: ${escapeMd(f.confidence ?? "")})`);
    if (f.cveIds.length) lines.push(`- CVEs: ${f.cveIds.map((c) => "`" + escapeMd(c) + "`").join(", ")}`);
    if (f.kev) lines.push(`- KEV: ${escapeMd(f.kev.vulnerabilityName ?? "listed")} (added ${f.kev.dateAdded ?? "?"})`);
    if (f.epss) lines.push(`- EPSS: ${f.epss.epss?.toFixed(3)} (percentile ${f.epss.percentile?.toFixed(3)})`);
    lines.push("");
    lines.push("**Description**");
    lines.push("");
    lines.push(escapeMd(f.description));
    lines.push("");
    if (f.evidence != null) {
      lines.push("**Evidence**");
      lines.push("");
      lines.push("```json");
      lines.push(JSON.stringify(f.evidence, null, 2));
      lines.push("```");
      lines.push("");
    }
    if (f.remediation) {
      lines.push("**Remediation**");
      lines.push("");
      lines.push(escapeMd(f.remediation));
      lines.push("");
    }
    if (f.references.length) {
      lines.push("**References**");
      lines.push("");
      for (const r of f.references) lines.push(`- ${escapeMd(r)}`);
      lines.push("");
    }
  }
  lines.push("## Data Sources");
  lines.push("");
  lines.push(
    "- NVD CVE API — https://nvd.nist.gov/developers/vulnerabilities  ",
  );
  lines.push(
    "- CISA KEV — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json  ",
  );
  lines.push("- FIRST EPSS — https://api.first.org/epss/");
  lines.push("");
  return lines.join("\n");
}

/** Defensive Markdown escaping for fields that came from network responses or user input. */
function escapeMd(s: string | null | undefined): string {
  if (s == null) return "";
  return String(s)
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/`/g, "\\`")
    .replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;"));
}

export const __test__ = { escapeMd };
