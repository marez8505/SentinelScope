import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest, queryClient as qc } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { AlertTriangle } from "lucide-react";

const PROFILES = [
  { id: "quick", title: "Quick", desc: "22, 80, 443 — under 5 seconds typical." },
  { id: "standard", title: "Standard", desc: "Common service ports (21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, 8443…)." },
  { id: "web", title: "Web", desc: "HTTP/S ports only — 80, 443, 8080, 8443, 8000, 8888." },
  { id: "custom", title: "Custom", desc: "Comma list and ranges, e.g. 22, 80-90, 443. Max 200 ports." },
] as const;

export default function NewScan() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"quick" | "standard" | "web" | "custom">("quick");
  const [customPorts, setCustomPorts] = useState("");
  const [authorizedAck, setAuthorizedAck] = useState(false);
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/scans", {
        target,
        profile,
        customPorts: profile === "custom" ? customPorts : undefined,
        authorizedAck: true,
      });
      return res.json();
    },
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["/api/scans"] });
      qc.invalidateQueries({ queryKey: ["/api/dashboard"] });
      toast({ title: "Scan started", description: `Scan #${d.id} is running.` });
      navigate(`/scans/${d.id}`);
    },
    onError: (e: any) => {
      toast({ title: "Could not start scan", description: e.message, variant: "destructive" });
    },
  });

  const disabled = !authorizedAck || !target || (profile === "custom" && !customPorts) || create.isPending;

  return (
    <>
      <PageHeader
        eyebrow="Scan"
        title="New scan"
        description="Run a non-intrusive TCP discovery and metadata scan against a target you own or are authorized to assess."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 border-card-border p-6 space-y-6">
          <div className="space-y-2">
            <Label htmlFor="target">Target hostname or IP</Label>
            <Input
              id="target"
              data-testid="input-target"
              placeholder="example.com, 192.168.1.10, or [::1]"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Hostname (RFC 1123), IPv4, or IPv6 only. Do not include scheme, paths, or credentials.
            </p>
          </div>

          <div className="space-y-2">
            <Label>Scan profile</Label>
            <RadioGroup
              value={profile}
              onValueChange={(v) => setProfile(v as any)}
              className="grid grid-cols-1 sm:grid-cols-2 gap-2"
            >
              {PROFILES.map((p) => (
                <Label
                  key={p.id}
                  htmlFor={`profile-${p.id}`}
                  data-testid={`radio-profile-${p.id}`}
                  className="flex cursor-pointer items-start gap-3 rounded-md border border-border bg-card p-3 hover:border-primary/50 has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5"
                >
                  <RadioGroupItem id={`profile-${p.id}`} value={p.id} className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium">{p.title}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{p.desc}</div>
                  </div>
                </Label>
              ))}
            </RadioGroup>
          </div>

          {profile === "custom" && (
            <div className="space-y-2">
              <Label htmlFor="ports">Custom ports</Label>
              <Input
                id="ports"
                data-testid="input-ports"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
                placeholder="e.g. 22, 80, 443, 8000-8090"
                spellCheck={false}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Digits, commas, spaces, and `-` ranges only. Maximum 200 ports per scan.
              </p>
            </div>
          )}

          <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
              <div className="text-sm">
                <p className="font-medium mb-2">Authorization required</p>
                <p className="text-muted-foreground mb-3">
                  Unauthorized scanning may violate computer-misuse laws (e.g. CFAA in the United States,
                  the UK Computer Misuse Act, and similar laws elsewhere) and the terms of service of
                  hosting providers. Run scans only against hosts you operate or have written permission
                  to test.
                </p>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    data-testid="checkbox-authorized"
                    checked={authorizedAck}
                    onCheckedChange={(v) => setAuthorizedAck(Boolean(v))}
                  />
                  <span className="text-sm">
                    I am the owner of <span className="font-mono">{target || "this target"}</span> or have
                    explicit written authorization to assess it.
                  </span>
                </label>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2">
            <Button
              data-testid="button-submit-scan"
              disabled={disabled}
              onClick={() => create.mutate()}
            >
              {create.isPending ? "Starting…" : "Start scan"}
            </Button>
          </div>
        </Card>

        <Card className="border-card-border p-6 h-fit">
          <h2 className="text-sm font-semibold mb-3">What this scan does</h2>
          <ul className="text-sm text-muted-foreground space-y-2">
            <li>• Resolves the hostname to a single IP via DNS lookup.</li>
            <li>• Performs TCP connect tests on the chosen ports — no SYN scanning.</li>
            <li>• Reads short banners on SSH/FTP/SMTP, sends a HEAD request to web ports.</li>
            <li>• Captures TLS protocol, cipher, and certificate metadata for HTTPS.</li>
            <li>• Correlates discovered services with the local CVE/KEV/EPSS snapshot.</li>
          </ul>
          <h2 className="text-sm font-semibold mt-5 mb-3">What it never does</h2>
          <ul className="text-sm text-muted-foreground space-y-2">
            <li>• No exploit execution or payload delivery.</li>
            <li>• No brute force or credential testing.</li>
            <li>• No stealth/evasion or scan-rate manipulation.</li>
            <li>• No remote system modification.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}
