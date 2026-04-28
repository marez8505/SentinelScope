import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { PageHeader } from "@/components/AppLayout";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowRight, Database as DatabaseIcon, ShieldAlert, Activity } from "lucide-react";

interface DashboardData {
  scans: any[];
  totalScans: number;
  findings: any[];
  summary: Record<string, number>;
  feeds: { cveCount: number; kevCount: number; epssCount: number; meta: any[] };
}

export default function Dashboard() {
  const { data, isLoading } = useQuery<DashboardData>({ queryKey: ["/api/dashboard"] });

  return (
    <>
      <PageHeader
        eyebrow="Console"
        title="Dashboard"
        description="Operational overview of recent scans, finding severity, and local vulnerability feed status."
        actions={
          <Link href="/scan">
            <Button data-testid="button-start-scan">Start a scan</Button>
          </Link>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3 mb-8">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <Card
            key={s}
            className="border-card-border p-4"
            data-testid={`card-kpi-${s}`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase tracking-wider text-muted-foreground">{s}</span>
              <SeverityBadge severity={s} />
            </div>
            <div className="text-2xl font-semibold font-mono tabular-nums" data-testid={`text-count-${s}`}>
              {isLoading ? <Skeleton className="h-7 w-16" /> : (data?.summary?.[s] ?? 0)}
            </div>
            <div className="text-xs text-muted-foreground mt-1">findings across all scans</div>
          </Card>
        ))}
      </div>

      {/* Two-column: recent scans / feed status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 border-card-border">
          <div className="flex items-center justify-between p-5 border-b border-card-border">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold">Recent scans</h2>
            </div>
            <Link href="/scans" className="text-xs text-muted-foreground hover:text-foreground">
              View all <ArrowRight className="inline h-3 w-3 ml-1" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b border-card-border">
                  <th className="text-left font-medium px-5 py-2.5">Target</th>
                  <th className="text-left font-medium px-5 py-2.5">Profile</th>
                  <th className="text-left font-medium px-5 py-2.5">Status</th>
                  <th className="text-right font-medium px-5 py-2.5">Started</th>
                  <th className="text-right font-medium px-5 py-2.5">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-card-border">
                {isLoading ? (
                  Array.from({ length: 3 }).map((_, i) => (
                    <tr key={i}>
                      <td className="px-5 py-3" colSpan={5}>
                        <Skeleton className="h-4 w-full" />
                      </td>
                    </tr>
                  ))
                ) : !data?.scans?.length ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-12 text-center">
                      <div className="text-muted-foreground text-sm">No scans yet.</div>
                      <Link href="/scan">
                        <Button variant="outline" size="sm" className="mt-3" data-testid="button-empty-scan">
                          Run your first scan
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ) : (
                  data.scans.slice(0, 6).map((s) => (
                    <tr key={s.id} data-testid={`row-scan-${s.id}`}>
                      <td className="px-5 py-3 font-mono text-xs">{s.target}</td>
                      <td className="px-5 py-3">{s.profile}</td>
                      <td className="px-5 py-3">
                        <StatusPill status={s.status} />
                      </td>
                      <td className="px-5 py-3 text-right text-xs text-muted-foreground tabular-nums">
                        {new Date(s.startedAt).toLocaleString()}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <Link href={`/scans/${s.id}`} className="text-xs text-primary hover:underline">
                          Open
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="space-y-6">
          <Card className="border-card-border p-5">
            <div className="flex items-center gap-2 mb-4">
              <DatabaseIcon className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold">Vulnerability feed</h2>
            </div>
            <dl className="space-y-3 text-sm">
              <FeedRow label="NVD CVEs" value={data?.feeds.cveCount} />
              <FeedRow label="CISA KEV" value={data?.feeds.kevCount} />
              <FeedRow label="FIRST EPSS" value={data?.feeds.epssCount} />
            </dl>
            <Link href="/feed">
              <Button variant="outline" size="sm" className="w-full mt-4" data-testid="button-feed-link">
                Manage feeds
              </Button>
            </Link>
          </Card>

          <Card className="border-card-border p-5">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold">Recent findings</h2>
            </div>
            <ul className="space-y-2.5 text-sm">
              {(data?.findings || []).slice(0, 5).map((f: any) => (
                <li key={f.id} className="flex items-start gap-2.5">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs">{f.title}</div>
                    <div className="font-mono text-[10px] text-muted-foreground truncate">{f.host}</div>
                  </div>
                </li>
              ))}
              {!data?.findings?.length && (
                <li className="text-xs text-muted-foreground">No findings yet.</li>
              )}
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    running: "bg-primary/15 text-primary border-primary/30",
    complete: "bg-success/15 text-success border-success/30",
    failed: "bg-destructive/15 text-destructive border-destructive/30",
    queued: "bg-muted text-muted-foreground border-border",
  };
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${map[status] || map.queued}`}
    >
      {status}
    </span>
  );
}

function FeedRow({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="flex items-center justify-between border-b border-card-border last:border-0 pb-2 last:pb-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono tabular-nums">{value ?? "—"}</span>
    </div>
  );
}
