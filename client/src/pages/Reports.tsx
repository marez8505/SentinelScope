import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { FileJson, FileText } from "lucide-react";

const API_BASE = "__PORT_5000__".startsWith("__") ? "" : "__PORT_5000__";

export default function Reports() {
  const { data, isLoading } = useQuery<any[]>({ queryKey: ["/api/scans"] });
  return (
    <>
      <PageHeader
        eyebrow="Export"
        title="Reports"
        description="Download a Markdown or JSON report for any completed scan. Reports include findings, evidence, severity, KEV/EPSS prioritization, and remediation."
      />
      <Card className="border-card-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wider text-muted-foreground bg-muted/30">
            <tr>
              <th className="text-left font-medium px-5 py-2.5">ID</th>
              <th className="text-left font-medium px-5 py-2.5">Target</th>
              <th className="text-left font-medium px-5 py-2.5">Profile</th>
              <th className="text-left font-medium px-5 py-2.5">Status</th>
              <th className="text-right font-medium px-5 py-2.5">Started</th>
              <th className="text-right font-medium px-5 py-2.5">Export</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-card-border">
            {isLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={i}>
                  <td className="px-5 py-3" colSpan={6}>
                    <Skeleton className="h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : !data?.length ? (
              <tr>
                <td colSpan={6} className="px-5 py-12 text-center text-muted-foreground text-sm">
                  No scans to report on yet. <Link href="/scan" className="text-primary hover:underline">Run a scan</Link>.
                </td>
              </tr>
            ) : (
              data.map((s) => (
                <tr key={s.id} data-testid={`row-report-${s.id}`}>
                  <td className="px-5 py-2.5 font-mono text-xs">#{s.id}</td>
                  <td className="px-5 py-2.5 font-mono text-xs">{s.target}</td>
                  <td className="px-5 py-2.5">{s.profile}</td>
                  <td className="px-5 py-2.5 text-xs uppercase tracking-wider text-muted-foreground">
                    {s.status}
                  </td>
                  <td className="px-5 py-2.5 text-right text-xs text-muted-foreground tabular-nums">
                    {new Date(s.startedAt).toLocaleString()}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <div className="inline-flex items-center gap-1.5">
                      <a href={`${API_BASE}/api/scans/${s.id}/report.md`} download>
                        <Button variant="outline" size="sm" data-testid={`button-md-${s.id}`}>
                          <FileText className="h-3 w-3 mr-1" /> MD
                        </Button>
                      </a>
                      <a href={`${API_BASE}/api/scans/${s.id}/report.json`} download>
                        <Button variant="outline" size="sm" data-testid={`button-json-${s.id}`}>
                          <FileJson className="h-3 w-3 mr-1" /> JSON
                        </Button>
                      </a>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Card>
    </>
  );
}
