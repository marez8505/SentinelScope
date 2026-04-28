import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Database, RefreshCw } from "lucide-react";

interface FeedsResp {
  meta: { source: string; lastSync: number | null; lastStatus: string | null; recordCount: number | null; message: string | null }[];
  cveCount: number;
  kevCount: number;
  epssCount: number;
}

export default function Feed() {
  const { data: feeds, isLoading } = useQuery<FeedsResp>({ queryKey: ["/api/feeds"] });
  const { toast } = useToast();
  const [q, setQ] = useState("");
  const { data: cves, isFetching: searching } = useQuery<any[]>({
    queryKey: ["/api/cves", { q }],
    queryFn: async () => {
      const u = new URL(window.location.origin + "/api/cves");
      if (q) u.searchParams.set("q", q);
      u.searchParams.set("limit", "30");
      const r = await fetch(u.pathname + u.search);
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },
  });

  const refresh = useMutation({
    mutationFn: async (source: "all" | "nvd" | "kev" | "epss") => {
      const r = await apiRequest("POST", "/api/feeds/refresh", { source });
      return r.json();
    },
    onSuccess: (d) => {
      queryClient.invalidateQueries({ queryKey: ["/api/feeds"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard"] });
      const lines = (d.results || []).map((r: any) => `${r.source}: ${r.message}`).join(" — ");
      toast({ title: "Feed refresh complete", description: lines || "Done." });
    },
    onError: (e: any) =>
      toast({ title: "Refresh failed", description: e.message, variant: "destructive" }),
  });

  return (
    <>
      <PageHeader
        eyebrow="Data"
        title="Vulnerability feed"
        description="Local snapshot of NVD CVE, CISA KEV, and FIRST EPSS data. Manually refresh from upstream — failures fall back to seed data."
        actions={
          <Button
            data-testid="button-refresh-all"
            onClick={() => refresh.mutate("all")}
            disabled={refresh.isPending}
          >
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${refresh.isPending ? "animate-spin" : ""}`} />
            Refresh all
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <FeedCard
          title="NVD CVE"
          description="National Vulnerability Database — CVE metadata, CVSS, CPE, references."
          source="https://nvd.nist.gov/developers/vulnerabilities"
          count={feeds?.cveCount}
          meta={feeds?.meta.find((m) => m.source === "nvd")}
          onRefresh={() => refresh.mutate("nvd")}
          loading={refresh.isPending}
        />
        <FeedCard
          title="CISA KEV"
          description="Known Exploited Vulnerabilities — actively exploited issues with required action dates."
          source="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
          count={feeds?.kevCount}
          meta={feeds?.meta.find((m) => m.source === "kev")}
          onRefresh={() => refresh.mutate("kev")}
          loading={refresh.isPending}
        />
        <FeedCard
          title="FIRST EPSS"
          description="Exploit Prediction Scoring System — probability a CVE will be exploited in the next 30 days."
          source="https://api.first.org/epss/"
          count={feeds?.epssCount}
          meta={feeds?.meta.find((m) => m.source === "epss")}
          onRefresh={() => refresh.mutate("epss")}
          loading={refresh.isPending}
        />
      </div>

      <Card className="border-card-border">
        <div className="px-5 py-3 border-b border-card-border flex items-center gap-3">
          <Database className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold flex-1">CVE explorer</h2>
          <Input
            data-testid="input-cve-search"
            placeholder="Search by CVE id, keyword, or product…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="max-w-sm font-mono"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-xs uppercase tracking-wider text-muted-foreground">
              <tr className="border-b border-card-border">
                <th className="text-left font-medium px-5 py-2.5">CVE</th>
                <th className="text-left font-medium px-5 py-2.5">CVSS</th>
                <th className="text-left font-medium px-5 py-2.5">Severity</th>
                <th className="text-left font-medium px-5 py-2.5">Published</th>
                <th className="text-left font-medium px-5 py-2.5">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-card-border">
              {(isLoading || searching) && !cves ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td className="px-5 py-3" colSpan={5}>
                      <Skeleton className="h-4 w-full" />
                    </td>
                  </tr>
                ))
              ) : !cves?.length ? (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center text-muted-foreground text-sm">
                    No CVEs match.
                  </td>
                </tr>
              ) : (
                cves.map((c: any) => (
                  <tr key={c.cveId} data-testid={`row-cve-${c.cveId}`}>
                    <td className="px-5 py-3 font-mono text-xs">{c.cveId}</td>
                    <td className="px-5 py-3 font-mono text-xs">
                      {c.cvssV3Score != null ? c.cvssV3Score.toFixed(1) : "—"}
                    </td>
                    <td className="px-5 py-3 text-xs">{c.cvssV3Severity ?? "—"}</td>
                    <td className="px-5 py-3 text-xs text-muted-foreground tabular-nums">{c.publishedDate ?? "—"}</td>
                    <td className="px-5 py-3 text-xs max-w-md truncate">{c.description}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

function FeedCard({
  title,
  description,
  source,
  count,
  meta,
  onRefresh,
  loading,
}: {
  title: string;
  description: string;
  source: string;
  count?: number;
  meta?: { lastSync: number | null; lastStatus: string | null; message: string | null };
  onRefresh: () => void;
  loading: boolean;
}) {
  const status = meta?.lastStatus ?? "never";
  const ok = status === "ok";
  return (
    <Card className="border-card-border p-5">
      <div className="flex items-start justify-between mb-2">
        <div>
          <h3 className="text-sm font-semibold">{title}</h3>
          <a
            href={source}
            target="_blank"
            rel="noreferrer noopener"
            className="text-[11px] text-primary hover:underline break-all"
          >
            {source}
          </a>
        </div>
        <span
          className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${
            ok
              ? "bg-success/10 text-success border-success/30"
              : status === "error"
                ? "bg-destructive/10 text-destructive border-destructive/30"
                : "bg-muted text-muted-foreground border-border"
          }`}
        >
          {status}
        </span>
      </div>
      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{description}</p>
      <div className="mt-4 flex items-center justify-between text-sm">
        <div>
          <div className="font-mono text-2xl tabular-nums" data-testid={`text-count-${title.toLowerCase().replace(/[^a-z]/g, "-")}`}>
            {count ?? "—"}
          </div>
          <div className="text-[11px] text-muted-foreground">
            Last sync: {meta?.lastSync ? new Date(meta.lastSync).toLocaleString() : "never"}
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={loading}>
          <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>
      {meta?.message && (
        <p className="mt-3 text-[11px] text-muted-foreground italic">{meta.message}</p>
      )}
    </Card>
  );
}
