import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { ShieldCheck, Wrench, Lock, Server, RotateCcw } from "lucide-react";

interface Playbook {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  scope: string;
  steps: string[];
  refs: { label: string; href: string }[];
}

const PLAYBOOKS: Playbook[] = [
  {
    icon: Wrench,
    title: "Patch / upgrade affected software",
    scope: "Use when a finding identifies a specific product/version with a CVE match.",
    steps: [
      "Confirm the affected version on the host (do not rely on banners alone).",
      "Read the vendor advisory linked from the finding's References section.",
      "Schedule a maintenance window. Take a backup or snapshot first.",
      "Apply the vendor-supplied patch or upgrade to a fixed release.",
      "Re-run the scan to verify the version no longer matches the CVE range.",
    ],
    refs: [
      { label: "NVD vulnerability search", href: "https://nvd.nist.gov/vuln/search" },
      { label: "CISA KEV catalog", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
    ],
  },
  {
    icon: Lock,
    title: "Enforce TLS hygiene",
    scope: "Use for findings about deprecated TLS protocols, expired certs, or weak ciphers.",
    steps: [
      "Reconfigure the server to require TLS 1.2 (and prefer TLS 1.3) only.",
      "Disable SSLv3, TLS 1.0, and TLS 1.1 explicitly in the server config.",
      "Replace expired or self-signed certificates with a CA-issued cert; consider ACME (Let's Encrypt) for renewal automation.",
      "Restrict to modern AEAD ciphers (e.g. TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256).",
      "Verify externally with a TLS analyser; re-run the SentinelScope scan to confirm.",
    ],
    refs: [
      { label: "Mozilla Server Side TLS guide", href: "https://wiki.mozilla.org/Security/Server_Side_TLS" },
      { label: "RFC 8996 — Deprecating TLS 1.0/1.1", href: "https://www.rfc-editor.org/rfc/rfc8996" },
    ],
  },
  {
    icon: ShieldCheck,
    title: "Set HTTP security headers",
    scope: "Use when a finding lists missing security headers on a web service.",
    steps: [
      "Add Strict-Transport-Security with a long max-age once HTTPS is verified.",
      "Author a Content-Security-Policy that allows only required script/style sources.",
      "Set X-Content-Type-Options: nosniff to prevent MIME confusion.",
      "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
      "Set Permissions-Policy to disable unused browser features.",
      "Re-scan to confirm the headers are present on the path tested.",
    ],
    refs: [
      { label: "OWASP Secure Headers Project", href: "https://owasp.org/www-project-secure-headers/" },
      { label: "MDN — HTTP headers", href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" },
    ],
  },
  {
    icon: Server,
    title: "Restrict exposure / firewall",
    scope: "Use when a service is reachable but should not be public.",
    steps: [
      "Identify the legitimate consumers of the service (internal app tier, admin VPN, etc.).",
      "Move the service behind a firewall, security group, or zero-trust proxy.",
      "Bind the listener to a non-public interface where possible.",
      "Enable network logging at the perimeter and review for prior exposure.",
      "Re-scan from outside the boundary to confirm the port is unreachable.",
    ],
    refs: [
      { label: "NIST SP 800-41 — Firewalls", href: "https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final" },
    ],
  },
  {
    icon: RotateCcw,
    title: "Disable / replace EOL software",
    scope: "Use when the detected product/version is past end-of-life.",
    steps: [
      "Confirm the EOL date with the vendor.",
      "Identify a supported replacement; plan a migration with rollback steps.",
      "If migration is not yet possible, isolate the service via firewall and add monitoring.",
      "Document the temporary risk acceptance (use the 'Accept risk' control on the finding).",
      "After replacement, re-scan to verify the EOL banner no longer appears.",
    ],
    refs: [
      { label: "endoflife.date", href: "https://endoflife.date/" },
    ],
  },
];

export default function Remediation() {
  return (
    <>
      <PageHeader
        eyebrow="Playbooks"
        title="Remediation"
        description="Instruction-only remediation guidance. SentinelScope never modifies remote systems on your behalf — review and apply changes manually."
      />
      <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-4 mb-6 text-sm">
        <strong className="font-medium">Local helpers only.</strong>{" "}
        <span className="text-muted-foreground">
          Optional helper commands shown below are intended for local execution by an operator who
          understands their effect. Nothing here is auto-executed by SentinelScope.
        </span>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {PLAYBOOKS.map((p) => (
          <Card key={p.title} className="border-card-border p-5" data-testid={`playbook-${p.title.toLowerCase().replace(/[^a-z]+/g, "-")}`}>
            <div className="flex items-start gap-3 mb-3">
              <div className="rounded-md bg-primary/15 text-primary p-2 shrink-0">
                <p.icon className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">{p.title}</h3>
                <p className="text-xs text-muted-foreground mt-0.5">{p.scope}</p>
              </div>
            </div>
            <ol className="text-sm space-y-2 list-decimal list-inside marker:text-muted-foreground">
              {p.steps.map((s, i) => (
                <li key={i} className="leading-relaxed pl-1">{s}</li>
              ))}
            </ol>
            <div className="mt-4 pt-4 border-t border-card-border">
              <h4 className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">References</h4>
              <ul className="space-y-1 text-xs">
                {p.refs.map((r) => (
                  <li key={r.href}>
                    <a
                      href={r.href}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-primary hover:underline"
                    >
                      {r.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </Card>
        ))}
      </div>
    </>
  );
}
