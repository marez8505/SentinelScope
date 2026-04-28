import { PageHeader } from "@/components/AppLayout";
import { Card } from "@/components/ui/card";
import { ExternalLink } from "lucide-react";

export default function Settings() {
  return (
    <>
      <PageHeader
        eyebrow="Settings & Docs"
        title="Configuration & documentation"
        description="In-app reference for setup, safe scanning practices, and data sources. Full docs ship with the project under /docs."
      />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-card-border p-6">
          <h2 className="text-sm font-semibold mb-3">Authorized use</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            SentinelScope is designed for security professionals and developers assessing systems
            they own or are explicitly authorized to test. Unauthorized scanning of third-party
            systems may violate computer-misuse statutes such as the U.S. Computer Fraud and Abuse
            Act, the U.K. Computer Misuse Act, and equivalent laws in other jurisdictions, as well
            as the terms of service of cloud providers and ISPs.
          </p>
          <p className="text-sm text-muted-foreground leading-relaxed mt-3">
            By default, every scan requires an explicit authorization checkbox before it will run.
          </p>
        </Card>

        <Card className="border-card-border p-6">
          <h2 className="text-sm font-semibold mb-3">Safety boundaries</h2>
          <ul className="text-sm text-muted-foreground space-y-2">
            <li>• TCP-connect only — no SYN/ACK/FIN scanning, no raw sockets.</li>
            <li>• Banner reads are passive (or send a single QUIT for SMTP).</li>
            <li>• HTTP probes use HEAD; redirects are not followed.</li>
            <li>• TLS handshake captures protocol &amp; cert metadata; no data is sent post-handshake.</li>
            <li>• Per-scan ports are capped at 200; concurrency at 8.</li>
            <li>• Per-IP scan creation is rate-limited (10/minute).</li>
            <li>• No exploit, brute-force, credential, or evasion functionality is implemented.</li>
          </ul>
        </Card>

        <Card className="border-card-border p-6">
          <h2 className="text-sm font-semibold mb-3">Environment variables</h2>
          <dl className="text-sm space-y-2">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="font-mono text-xs">NVD_API_KEY</dt>
              <dd className="text-muted-foreground text-xs">
                Optional. Supplies a higher rate limit when refreshing the NVD CVE feed.
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="font-mono text-xs">PORT</dt>
              <dd className="text-muted-foreground text-xs">Bind port (default 5000).</dd>
            </div>
          </dl>
          <p className="text-xs text-muted-foreground mt-3">
            See <code className="font-mono">.env.example</code> at the project root.
          </p>
        </Card>

        <Card className="border-card-border p-6">
          <h2 className="text-sm font-semibold mb-3">Data sources</h2>
          <ul className="text-sm space-y-2">
            <Doc href="https://nvd.nist.gov/developers/vulnerabilities" label="NVD CVE API documentation" />
            <Doc href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" label="CISA KEV catalog" />
            <Doc
              href="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
              label="CISA KEV JSON feed"
            />
            <Doc href="https://api.first.org/epss/" label="FIRST EPSS API" />
          </ul>
        </Card>

        <Card className="border-card-border p-6 lg:col-span-2">
          <h2 className="text-sm font-semibold mb-3">Documentation</h2>
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
            <li className="font-mono text-xs">README.md — project overview &amp; quick start</li>
            <li className="font-mono text-xs">docs/INSTALL-WSL.md — Linux/WSL setup</li>
            <li className="font-mono text-xs">docs/INSTALL-POWERSHELL.md — Windows PowerShell setup</li>
            <li className="font-mono text-xs">docs/USAGE.md — scan workflow walkthrough</li>
            <li className="font-mono text-xs">docs/SAFE-SCANNING.md — what is and isn't allowed</li>
            <li className="font-mono text-xs">docs/SECURITY.md — security policy &amp; threat model</li>
            <li className="font-mono text-xs">docs/ARCHITECTURE.md — technical design notes</li>
            <li className="font-mono text-xs">SECURITY_REVIEW.md — pre-publication self-review</li>
          </ul>
        </Card>
      </div>
    </>
  );
}

function Doc({ href, label }: { href: string; label: string }) {
  return (
    <li>
      <a
        href={href}
        target="_blank"
        rel="noreferrer noopener"
        className="text-primary hover:underline inline-flex items-center gap-1.5"
      >
        {label}
        <ExternalLink className="h-3 w-3" />
      </a>
    </li>
  );
}
