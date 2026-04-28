import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";

export default function Scans() {
  const { data, isLoading } = useQuery<any[]>({ queryKey: ["/api/scans"] });

  return (
    <>
      <PageHeader
        eyebrow="History"
        title="Scan results"
        description="Every scan ever run on this instance, newest first."
        actions={
          <Link href="/scan">
            <Button data-testid="button-new-scan">New scan</Button>
          </Link>
        }
      />
      <Card className="border-card-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wider text-muted-foreground bg-muted/30">
            <tr>
              <th className="text-left font-medium px-5 py-2.5">ID</th>
              <th className="text-left font-medium px-5 py-2.5">Target</th>
              <th className="text-left font-medium px-5 py-2.5">Resolved</th>
              <th className="text-left font-medium px-5 py-2.5">Profile</th>
              <th className="text-left font-medium px-5 py-2.5">Status</th>
              <th className="text-right font-medium px-5 py-2.5">Started</th>
              <th className="text-right font-medium px-5 py-2.5"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-card-border">
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  <td className="px-5 py-3" colSpan={7}>
                    <Skeleton className="h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : !data?.length ? (
              <tr>
                <td colSpan={7} className="px-5 py-12 text-center text-muted-foreground text-sm">
                  No scans yet. <Link href="/scan" className="text-primary hover:underline">Run one</Link>.
                </td>
              </tr>
            ) : (
              data.map((s) => (
                <tr key={s.id} data-testid={`row-scan-${s.id}`} className="hover:bg-accent/40 transition-colors">
                  <td className="px-5 py-2.5 font-mono text-xs">#{s.id}</td>
                  <td className="px-5 py-2.5 font-mono text-xs">{s.target}</td>
                  <td className="px-5 py-2.5 font-mono text-xs text-muted-foreground">{s.resolvedIp || "—"}</td>
                  <td className="px-5 py-2.5">{s.profile}</td>
                  <td className="px-5 py-2.5">
                    <span
                      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${
                        s.status === "complete"
                          ? "bg-success/15 text-success border-success/30"
                          : s.status === "failed"
                            ? "bg-destructive/15 text-destructive border-destructive/30"
                            : "bg-primary/15 text-primary border-primary/30"
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td className="px-5 py-2.5 text-right text-xs text-muted-foreground tabular-nums">
                    {new Date(s.startedAt).toLocaleString()}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <Link href={`/scans/${s.id}`} className="text-xs text-primary hover:underline">
                      Open →
                    </Link>
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
