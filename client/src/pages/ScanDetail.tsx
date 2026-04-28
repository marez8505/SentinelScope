import { useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useRoute } from "wouter";
import { PageHeader } from "@/components/AppLayout";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Download, FileJson, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { safeHref } from "@shared/url";

const API_BASE = "__PORT_5000__".startsWith("__") ? "" : "__PORT_5000__";

interface ScanDetail {
  scan: any;
  findings: any[];
}

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const id = params?.id;
  const { data, isLoading, refetch } = useQuery<ScanDetail>({
    queryKey: ["/api/scans", id],
    enabled: !!id,
    refetchInterval: (q) => {
      const d = q.state.data as ScanDetail | undefined;
      return d?.scan?.status === "running" ? 1500 : false;
    },
  });
  const { toast } = useToast();

  const updateStatus = useMutation({
    mutationFn: async ({ findingId, status }: { findingId: number; status: string }) => {
      await apiRequest("PATCH", `/api/findings/${findingId}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans", id] });
      toast({ title: "Finding updated" });
    },
  });

  useEffect(() => {
    if (data?.scan?.status === "complete") {
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard"] });
    }
  }, [data?.scan?.status]);

  if (isLoading || !data) {
    return (
      <>
        <PageHeader eyebrow="Scan" title="Loading…" />
        <Skeleton className="h-32 w-full" />
      </>
    );
  }

  const ports: number[] = (() => {
    try {
      return JSON.parse(data.scan.ports);
    } catch {
      return [];
    }
  })();

  const summary = (() => {
    try {
      return data.scan.summary ? JSON.parse(data.scan.summary) : {};
    } catch {
      return {};
    }
  })();

  const findings = data.findings.slice().sort((a, b) => {
    const order = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(a.severity) - order.indexOf(b.severity);
  });

  return (
    <>
      <PageHeader
        eyebrow={`Scan #${data.scan.id}`}
        title={data.scan.target}
        description={`Profile: ${data.scan.profile} • Resolved: ${data.scan.resolvedIp ?? "—"} • ${ports.length} port(s) scanned`}
        actions={
          <>
            <a href={`${API_BASE}/api/scans/${data.scan.id}/report.md`} download>
              <Button variant="outline" size="sm" data-testid="button-export-md">
                <FileText className="h-3.5 w-3.5 mr-1.5" /> Markdown
              </Button>
            </a>
            <a href={`${API_BASE}/api/scans/${data.scan.id}/report.json`} download>
              <Button variant="outline" size="sm" data-testid="button-export-json">
                <FileJson className="h-3.5 w-3.5 mr-1.5" /> JSON
              </Button>
            </a>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-6">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <Card key={s} className="border-card-border p-3 flex items-center justify-between">
            <SeverityBadge severity={s} />
            <span className="font-mono tabular-nums text-lg" data-testid={`text-summary-${s}`}>
              {summary[s] ?? 0}
            </span>
          </Card>
        ))}
      </div>

      {data.scan.status === "running" && (
        <Card className="border-card-border p-4 mb-6 bg-primary/5">
          <div className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
            <p className="text-sm">Scan is running… results refresh automatically.</p>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              Refresh
            </Button>
          </div>
        </Card>
      )}

      {data.scan.status === "failed" && (
        <Card className="border-destructive/40 bg-destructive/5 p-4 mb-6">
          <p className="text-sm">
            <strong>Scan failed:</strong> {data.scan.error || "unknown error"}
          </p>
        </Card>
      )}

      <Card className="border-card-border overflow-hidden">
        <div className="px-5 py-3 border-b border-card-border flex items-center justify-between">
          <h2 className="text-sm font-semibold">Findings ({findings.length})</h2>
        </div>
        {findings.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground text-sm">No findings yet.</div>
        ) : (
          <ul className="divide-y divide-card-border">
            {findings.map((f) => (
              <FindingItem
                key={f.id}
                finding={f}
                onUpdate={(status) => updateStatus.mutate({ findingId: f.id, status })}
              />
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function FindingItem({ finding, onUpdate }: { finding: any; onUpdate: (s: string) => void }) {
  const cves: string[] = safeArr(finding.cveIds);
  const refs: string[] = safeArr(finding.references);
  const evidence = safeJson(finding.evidence);

  return (
    <li className="p-5 hover:bg-accent/30 transition-colors" data-testid={`finding-${finding.id}`}>
      <div className="flex items-start gap-4">
        <SeverityBadge severity={finding.severity} className="mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <h3 className="text-sm font-semibold leading-snug">{finding.title}</h3>
            <div className="flex items-center gap-1.5 shrink-0">
              {finding.cvssScore != null && (
                <span className="text-xs font-mono text-muted-foreground">
                  CVSS {finding.cvssScore.toFixed(1)}
                </span>
              )}
              <StatusPill status={finding.status} />
            </div>
          </div>
          <div className="mt-1 text-xs text-muted-foreground font-mono">
            {finding.host}
            {finding.port != null ? `:${finding.port}` : ""}
            {finding.service ? ` · ${finding.service}` : ""}
            {finding.product ? ` · ${finding.product}${finding.version ? " " + finding.version : ""}` : ""}
            {finding.matchBasis ? ` · basis: ${finding.matchBasis}` : ""}
            {finding.confidence ? ` · ${finding.confidence}` : ""}
          </div>
          <p className="mt-2 text-sm leading-relaxed">{finding.description}</p>

          {cves.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {cves.map((c) => (
                <span
                  key={c}
                  className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground"
                >
                  {c}
                </span>
              ))}
            </div>
          )}

          {evidence && (
            <details className="mt-3">
              <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                Evidence
              </summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted/50 p-3 text-[11px] font-mono">
                {JSON.stringify(evidence, null, 2)}
              </pre>
            </details>
          )}

          {finding.remediation && (
            <div className="mt-3 text-xs">
              <span className="font-semibold">Remediation:</span>{" "}
              <span className="text-muted-foreground">{finding.remediation}</span>
            </div>
          )}

          {refs.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs">
              {refs.map((r) => {
                // Reference URLs come from third-party CVE / NVD records and
                // are treated as untrusted. Only render http(s) URLs as
                // clickable links; other schemes (javascript:, data:, file:,
                // mailto:, relative paths, embedded credentials, ...) are
                // shown as plain text via React's default escaping.
                const safe = safeHref(r);
                return (
                  <li key={r} data-testid={`ref-${finding.id}`}>
                    {safe ? (
                      <a
                        href={safe}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-primary hover:underline break-all"
                        data-testid={`link-ref-${finding.id}`}
                      >
                        {safe}
                      </a>
                    ) : (
                      <span
                        className="text-muted-foreground break-all"
                        title="Reference omitted: not an http(s) URL"
                        data-testid={`text-ref-unsafe-${finding.id}`}
                      >
                        {r}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          <div className="mt-3 flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              data-testid={`button-resolve-${finding.id}`}
              onClick={() => onUpdate("resolved")}
              disabled={finding.status === "resolved"}
            >
              Mark resolved
            </Button>
            <Button
              size="sm"
              variant="outline"
              data-testid={`button-accept-${finding.id}`}
              onClick={() => onUpdate("accepted_risk")}
              disabled={finding.status === "accepted_risk"}
            >
              Accept risk
            </Button>
            <Button
              size="sm"
              variant="ghost"
              data-testid={`button-reopen-${finding.id}`}
              onClick={() => onUpdate("open")}
              disabled={finding.status === "open"}
            >
              Reopen
            </Button>
          </div>
        </div>
      </div>
    </li>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    open: "border-amber-500/40 text-amber-300 bg-amber-500/10",
    accepted_risk: "border-muted-foreground/30 text-muted-foreground bg-muted/40",
    resolved: "border-success/30 text-success bg-success/10",
  };
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${map[status] || map.open}`}
    >
      {status.replace("_", " ")}
    </span>
  );
}

function safeArr(s: any): string[] {
  if (Array.isArray(s)) return s;
  if (typeof s !== "string") return [];
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
function safeJson(s: any): any {
  if (s == null) return null;
  if (typeof s !== "string") return s;
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
