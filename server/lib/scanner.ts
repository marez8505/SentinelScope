/**
 * SentinelScope safe scanner.
 *
 * Performs only:
 *   - DNS resolution (lookup)
 *   - TCP connect tests with a short timeout
 *   - Polite banner grab on common service ports (read-only or minimal probe)
 *   - HTTP/HTTPS header & TLS metadata collection
 *   - Local CVE correlation by service/product/version keyword match
 *
 * Performs NONE of the following (out of scope by design):
 *   - SYN/ACK/FIN scanning, raw sockets, or anything privileged
 *   - Brute force, credential testing, exploit payload delivery
 *   - Stealth/evasion or scan-rate manipulation beyond the local concurrency cap
 *   - Modifying remote systems
 */
import { lookup } from "node:dns/promises";
import { Socket, isIP } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { storage } from "./../storage";
import type { Cve, InsertFinding } from "@shared/schema";
import { severityFromCvss, effectiveSeverity, type Severity } from "./severity";

const CONNECT_TIMEOUT_MS = 1500;
const BANNER_TIMEOUT_MS = 2000;
const HTTP_TIMEOUT_MS = 4000;
const TLS_TIMEOUT_MS = 4500;
const MAX_BANNER_BYTES = 1024;
const MAX_CONCURRENCY = 8;

// Conservative service map by port — used as a hint, banner overrides.
const PORT_SERVICE_HINT: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  465: "smtps",
  587: "smtp-submission",
  993: "imaps",
  995: "pop3s",
  3306: "mysql",
  3389: "rdp",
  5432: "postgresql",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
};

export interface OpenPortResult {
  port: number;
  service: string;
  product?: string;
  version?: string;
  banner?: string;
  http?: HttpProbe;
  tls?: TlsProbe;
}

export interface HttpProbe {
  status: number;
  server?: string;
  poweredBy?: string;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
}

export interface TlsProbe {
  protocol?: string;
  cipher?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysToExpiry?: number;
  selfSigned?: boolean;
  weakProtocol?: boolean;
}

export interface ScanContext {
  scanId: number;
  target: string;
  ports: number[];
  cveSnapshot: Cve[];
  kevSet: Set<string>;
  epssMap: Map<string, number>;
}

/** Resolve DNS A/AAAA record; IP literals (v4 or v6, optionally bracketed)
 *  pass through unchanged. We strip surrounding brackets so the rest of the
 *  pipeline always sees a bare IP. */
export async function resolveTarget(target: string): Promise<string> {
  const stripped = target.startsWith("[") && target.endsWith("]")
    ? target.slice(1, -1)
    : target;
  if (isIP(stripped) !== 0) return stripped;
  const r = await lookup(target);
  return r.address;
}

/** TCP connect test. Resolves true if SYN/ACK arrives within timeout. */
export function tcpConnect(host: string, port: number, timeoutMs = CONNECT_TIMEOUT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new Socket();
    let done = false;
    const finish = (v: boolean) => {
      if (done) return;
      done = true;
      try {
        sock.destroy();
      } catch {}
      resolve(v);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
    try {
      sock.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

/** Read up to N bytes from a socket. Used for SSH/SMTP/FTP banner. */
function readSomeBytes(sock: Socket, ms: number, max = MAX_BANNER_BYTES): Promise<string> {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    const finish = () => {
      try {
        sock.destroy();
      } catch {}
      resolve(buf.toString("utf8").trim());
    };
    sock.setTimeout(ms);
    sock.once("data", (d) => {
      buf = Buffer.concat([buf, d]).slice(0, max);
      // give a tiny window for the rest of the line
      setTimeout(finish, 100);
    });
    sock.once("timeout", finish);
    sock.once("error", finish);
    sock.once("close", finish);
  });
}

/** Capture a passive banner for SSH/FTP/SMTP-style services. Sends nothing for SSH/FTP.
 *  For SMTP we briefly read the greeting then QUIT cleanly. */
export async function grabBanner(host: string, port: number, service: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    const sock = new Socket();
    sock.setTimeout(BANNER_TIMEOUT_MS);
    let resolved = false;
    const out = (v?: string) => {
      if (resolved) return;
      resolved = true;
      try {
        if (service === "smtp" || service === "smtp-submission") {
          sock.write("QUIT\r\n");
        }
        sock.destroy();
      } catch {}
      resolve(v);
    };
    sock.once("error", () => out(undefined));
    sock.once("timeout", () => out(undefined));
    sock.once("connect", async () => {
      const data = await readSomeBytes(sock, BANNER_TIMEOUT_MS);
      out(data || undefined);
    });
    try {
      sock.connect(port, host);
    } catch {
      out(undefined);
    }
  });
}

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

/**
 * Passive probe option: accept any server cert so we can record TLS findings
 * (expiry, self-signed, weak protocol). Probe traffic is read-only metadata
 * collection against operator-supplied targets; results are never used to
 * authenticate outbound requests from this app.
 */
const PROBE_TLS_REJECT_UNAUTHORIZED = false;

/** Issue a simple HTTP/HTTPS HEAD request and collect headers + missing security headers. */
export function probeHttp(host: string, port: number, useTls: boolean): Promise<HttpProbe | undefined> {
  return new Promise((resolve) => {
    const reqFn = useTls ? httpsRequest : httpRequest;
    // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
    const opts = {
      host,
      port,
      method: "HEAD",
      path: "/",
      timeout: HTTP_TIMEOUT_MS,
      // Local research tool: do not send any auth, do not follow redirects
      headers: { "User-Agent": "SentinelScope/0.1" },
      rejectUnauthorized: PROBE_TLS_REJECT_UNAUTHORIZED,
    };
    let settled = false;
    const finish = (v: HttpProbe | undefined) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    try {
      const req = reqFn(opts as any, (res) => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers || {})) {
          if (Array.isArray(v)) headers[k] = v.join(", ");
          else if (v != null) headers[k] = String(v);
        }
        const have = new Set(Object.keys(headers).map((k) => k.toLowerCase()));
        const missing = SECURITY_HEADERS.filter((h) => !have.has(h));
        finish({
          status: res.statusCode || 0,
          server: headers["server"],
          poweredBy: headers["x-powered-by"],
          headers,
          missingSecurityHeaders: missing,
        });
        res.resume();
      });
      req.on("error", () => finish(undefined));
      req.on("timeout", () => {
        req.destroy();
        finish(undefined);
      });
      req.end();
    } catch {
      finish(undefined);
    }
  });
}

/** Initiate a TLS handshake to inspect cert + protocol. No data is sent post-handshake. */
export function probeTls(host: string, port: number): Promise<TlsProbe | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: TlsProbe | undefined) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    let sock: TLSSocket | null = null;
    try {
      sock = tlsConnect(
        { // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
          host,
          port,
          servername: host,
          rejectUnauthorized: PROBE_TLS_REJECT_UNAUTHORIZED,
          timeout: TLS_TIMEOUT_MS,
        },
        () => {
          try {
            const cert = sock!.getPeerCertificate(false);
            const cipher = sock!.getCipher();
            const protocol = sock!.getProtocol() ?? undefined;
            const validFrom = cert?.valid_from;
            const validTo = cert?.valid_to;
            const daysToExpiry = validTo ? Math.round((Date.parse(validTo) - Date.now()) / 86_400_000) : undefined;
            const subject = cert?.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(", ") : undefined;
            const issuer = cert?.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(", ") : undefined;
            const selfSigned = cert?.issuer && cert?.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
            const weakProtocol = protocol === "TLSv1" || protocol === "TLSv1.1" || protocol === "SSLv3";
            finish({
              protocol,
              cipher: cipher?.name,
              subject,
              issuer,
              validFrom,
              validTo,
              daysToExpiry,
              selfSigned: !!selfSigned,
              weakProtocol,
            });
          } finally {
            try {
              sock!.destroy();
            } catch {}
          }
        },
      );
      sock.on("error", () => finish(undefined));
      sock.on("timeout", () => {
        try {
          sock?.destroy();
        } catch {}
        finish(undefined);
      });
    } catch {
      finish(undefined);
    }
  });
}

/** Identify product+version from a banner. Conservative parsers — return `undefined` when uncertain. */
export function parseBanner(service: string, banner: string): { product?: string; version?: string } {
  if (!banner) return {};
  if (service === "ssh") {
    const m = /^SSH-\S+\s*-?(\S+)/.exec(banner) || /^(SSH-\S+)/.exec(banner);
    if (m) {
      const verPart = m[1] || "";
      const inner = /(OpenSSH|libssh|dropbear)[_\-\/]?([0-9][\w\.\-p]*)/i.exec(banner);
      if (inner) return { product: inner[1], version: inner[2] };
      return { product: "ssh", version: verPart };
    }
  }
  if (service === "ftp") {
    const m = /^220[ -](.*)/.exec(banner);
    if (m) {
      const inner = /(vsftpd|ProFTPD|Pure-FTPd|FileZilla)\s*([\w\.\-]+)?/i.exec(m[1]);
      if (inner) return { product: inner[1], version: inner[2] };
      return { product: "ftp", version: m[1].slice(0, 80) };
    }
  }
  if (service === "smtp" || service === "smtp-submission") {
    const m = /^220[ -](.*)/.exec(banner);
    if (m) {
      const inner = /(Postfix|Sendmail|Exim|Microsoft ESMTP|smtpd)\s*([\w\.\-]+)?/i.exec(m[1]);
      if (inner) return { product: inner[1], version: inner[2] };
      return { product: "smtp", version: m[1].slice(0, 80) };
    }
  }
  return {};
}

/** Identify a product/version from an HTTP Server header. */
export function parseHttpServer(server?: string): { product?: string; version?: string } {
  if (!server) return {};
  const m = /([A-Za-z][A-Za-z0-9_\-]+)(?:\/([\w\.\-]+))?/.exec(server);
  if (m) return { product: m[1], version: m[2] };
  return {};
}

/** Naive but transparent CVE correlation by keyword. Returns matches with confidence. */
export function correlateCves(opts: {
  cves: Cve[];
  service?: string;
  product?: string;
  version?: string;
}): { cveId: string; confidence: "low" | "medium" | "high"; basis: string }[] {
  const out: { cveId: string; confidence: "low" | "medium" | "high"; basis: string }[] = [];
  const haystackTokens = [opts.service, opts.product, opts.version]
    .filter(Boolean)
    .map((s) => String(s).toLowerCase());
  if (!haystackTokens.length) return out;

  for (const cve of opts.cves) {
    let kw: string[] = [];
    try {
      kw = cve.keywords ? JSON.parse(cve.keywords) : [];
    } catch {}
    let cpes: string[] = [];
    try {
      cpes = cve.cpes ? JSON.parse(cve.cpes) : [];
    } catch {}
    const desc = (cve.description || "").toLowerCase();

    let confidence: "low" | "medium" | "high" | undefined;
    const matched: string[] = [];

    // CPE match against product+version
    if (opts.product) {
      const prod = opts.product.toLowerCase();
      const cpeHit = cpes.some((c) => c.toLowerCase().includes(`:${prod}:`));
      if (cpeHit) {
        matched.push(`cpe:${prod}`);
        confidence = "high";
      }
    }

    // keyword token match
    const kwHit = kw.some((k) => haystackTokens.some((t) => t.includes(k.toLowerCase())));
    if (kwHit) {
      matched.push("keyword");
      confidence = confidence ?? "medium";
    }

    // description match (least confident)
    const descHit = haystackTokens.some((t) => t.length >= 4 && desc.includes(t));
    if (descHit) {
      matched.push("description");
      confidence = confidence ?? "low";
    }

    if (confidence) {
      out.push({ cveId: cve.cveId, confidence, basis: matched.join("+") });
    }
  }
  // Cap matches per service to keep findings readable
  return out.slice(0, 10);
}

async function withConcurrency<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = idx++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export interface ScanResult {
  resolvedIp: string;
  open: OpenPortResult[];
  findings: InsertFinding[];
}

/** Run a complete scan: resolve, connect-check ports, banner-grab, HTTP/TLS probes, correlate. */
export async function runScan(ctx: ScanContext): Promise<ScanResult> {
  const resolvedIp = await resolveTarget(ctx.target);
  const targetForConn = ctx.target;

  // 1. TCP connect across all ports with concurrency cap.
  const openPorts = (
    await withConcurrency(ctx.ports, MAX_CONCURRENCY, async (p) => {
      const ok = await tcpConnect(targetForConn, p);
      return ok ? p : null;
    })
  ).filter((p): p is number => p !== null);

  const open: OpenPortResult[] = [];
  const findings: InsertFinding[] = [];
  const now = () => Date.now();

  // 2. Per-port banner / HTTP / TLS probes.
  for (const port of openPorts) {
    const service = PORT_SERVICE_HINT[port] || "unknown";
    let product: string | undefined;
    let version: string | undefined;
    let banner: string | undefined;
    let http: HttpProbe | undefined;
    let tls: TlsProbe | undefined;

    if (service === "ssh" || service === "ftp" || service === "smtp" || service === "smtp-submission") {
      banner = await grabBanner(targetForConn, port, service);
      const parsed = parseBanner(service, banner || "");
      product = parsed.product;
      version = parsed.version;
    }

    const isHttps = service === "https" || service === "https-alt" || port === 443 || port === 8443;
    const isHttp = service === "http" || service === "http-alt" || port === 80 || port === 8080 || port === 8000 || port === 8888;

    if (isHttps) {
      tls = await probeTls(targetForConn, port);
      http = await probeHttp(targetForConn, port, true);
    } else if (isHttp) {
      http = await probeHttp(targetForConn, port, false);
    }

    if (http?.server) {
      const p = parseHttpServer(http.server);
      product = product || p.product;
      version = version || p.version;
    }

    open.push({ port, service, product, version, banner, http, tls });

    // 3. Build findings.
    findings.push({
      scanId: ctx.scanId,
      host: ctx.target,
      port,
      service,
      product: product ?? null,
      version: version ?? null,
      title: `Open port ${port}/${service}`,
      description: `Port ${port} (${service}) is reachable on ${ctx.target}.${
        banner ? " Banner: " + truncate(banner, 200) : ""
      }`,
      severity: "info",
      cvssScore: null,
      cveIds: JSON.stringify([]),
      evidence: JSON.stringify({ banner: banner || null, server: http?.server || null }),
      matchBasis: banner ? "banner" : "tcp-connect",
      confidence: banner ? "medium" : "low",
      references: JSON.stringify([]),
      remediation: "If this service is unintentionally exposed, restrict it via firewall or unbind the listener.",
      status: "open",
    });

    if (tls) {
      const refs = ["https://wiki.mozilla.org/Security/Server_Side_TLS"];
      if (tls.weakProtocol) {
        findings.push({
          scanId: ctx.scanId,
          host: ctx.target,
          port,
          service,
          product: "TLS",
          version: tls.protocol ?? null,
          title: `Weak TLS protocol: ${tls.protocol}`,
          description: `Server negotiated ${tls.protocol}, which is deprecated. Disable SSLv3, TLS 1.0, and TLS 1.1.`,
          severity: "high",
          cvssScore: 7.0,
          cveIds: JSON.stringify([]),
          evidence: JSON.stringify(tls),
          matchBasis: "tls",
          confidence: "high",
          references: JSON.stringify(refs),
          remediation: "Configure the server to require TLS 1.2 or 1.3 and disable older protocols.",
          status: "open",
        });
      }
      if (tls.daysToExpiry != null && tls.daysToExpiry < 14) {
        findings.push({
          scanId: ctx.scanId,
          host: ctx.target,
          port,
          service,
          product: "TLS",
          version: null,
          title: tls.daysToExpiry < 0 ? "Expired TLS certificate" : "TLS certificate expires soon",
          description: `Certificate validity ends ${tls.validTo}. ${tls.daysToExpiry} day(s) remaining.`,
          severity: tls.daysToExpiry < 0 ? "high" : "medium",
          cvssScore: tls.daysToExpiry < 0 ? 7.0 : 5.0,
          cveIds: JSON.stringify([]),
          evidence: JSON.stringify({ validFrom: tls.validFrom, validTo: tls.validTo }),
          matchBasis: "tls",
          confidence: "high",
          references: JSON.stringify(refs),
          remediation: "Renew the TLS certificate. Consider automation (ACME / Let's Encrypt) for short-lived certs.",
          status: "open",
        });
      }
      if (tls.selfSigned) {
        findings.push({
          scanId: ctx.scanId,
          host: ctx.target,
          port,
          service,
          product: "TLS",
          version: null,
          title: "Self-signed TLS certificate",
          description: "Server presented a self-signed certificate; clients cannot validate authenticity by default.",
          severity: "low",
          cvssScore: 3.7,
          cveIds: JSON.stringify([]),
          evidence: JSON.stringify({ subject: tls.subject, issuer: tls.issuer }),
          matchBasis: "tls",
          confidence: "high",
          references: JSON.stringify(refs),
          remediation: "Issue a certificate from a trusted CA or use an internal PKI consistently across clients.",
          status: "open",
        });
      }
    }

    if (http) {
      if (http.missingSecurityHeaders.length) {
        findings.push({
          scanId: ctx.scanId,
          host: ctx.target,
          port,
          service,
          product: parseHttpServer(http.server).product ?? null,
          version: parseHttpServer(http.server).version ?? null,
          title: `Missing HTTP security headers: ${http.missingSecurityHeaders.join(", ")}`,
          description:
            "The HTTP response is missing one or more recommended security headers. Adding them reduces a class of client-side and transport-layer attacks.",
          severity: "low",
          cvssScore: 3.1,
          cveIds: JSON.stringify([]),
          evidence: JSON.stringify({ headers: http.headers, missing: http.missingSecurityHeaders }),
          matchBasis: "header",
          confidence: "high",
          references: JSON.stringify([
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
          ]),
          remediation:
            "Configure the web server / reverse proxy to set the missing headers. Start with strict-transport-security, content-security-policy, x-content-type-options, and referrer-policy.",
          status: "open",
        });
      }
      if (http.poweredBy || http.server) {
        findings.push({
          scanId: ctx.scanId,
          host: ctx.target,
          port,
          service,
          product: parseHttpServer(http.server).product ?? null,
          version: parseHttpServer(http.server).version ?? null,
          title: "Server / X-Powered-By disclosure",
          description: `Response advertises: ${[http.server, http.poweredBy].filter(Boolean).join(" / ")}.`,
          severity: "info",
          cvssScore: null,
          cveIds: JSON.stringify([]),
          evidence: JSON.stringify({ server: http.server, poweredBy: http.poweredBy }),
          matchBasis: "header",
          confidence: "high",
          references: JSON.stringify([]),
          remediation: "Suppress or generalize Server/X-Powered-By headers if not needed for diagnostics.",
          status: "open",
        });
      }
    }

    // 4. CVE correlation against the local snapshot.
    const matches = correlateCves({ cves: ctx.cveSnapshot, service, product, version });
    if (matches.length) {
      const cveIds = matches.map((m) => m.cveId);
      // pick the highest-scoring CVE for severity
      let best = matches[0];
      let bestScore: number | null = null;
      let bestRefs: string[] = [];
      let bestDesc = "";
      for (const m of matches) {
        const c = ctx.cveSnapshot.find((x) => x.cveId === m.cveId);
        if (!c) continue;
        if ((c.cvssV3Score ?? -1) > (bestScore ?? -1)) {
          bestScore = c.cvssV3Score ?? null;
          best = m;
          try {
            bestRefs = c.references ? JSON.parse(c.references) : [];
          } catch {}
          bestDesc = c.description || "";
        }
      }
      const isKev = cveIds.some((id) => ctx.kevSet.has(id));
      const epssScore = Math.max(0, ...cveIds.map((id) => ctx.epssMap.get(id) ?? 0));
      const baseSev = severityFromCvss(bestScore);
      const sev: Severity = effectiveSeverity({ base: baseSev, isKev, epss: epssScore });

      findings.push({
        scanId: ctx.scanId,
        host: ctx.target,
        port,
        service,
        product: product ?? null,
        version: version ?? null,
        title: `Possible CVE match for ${product ?? service}${version ? " " + version : ""}: ${best.cveId}${
          isKev ? " (KEV)" : ""
        }`,
        description: bestDesc || `Local CVE feed matched ${product ?? service}.`,
        severity: sev,
        cvssScore: bestScore,
        cveIds: JSON.stringify(cveIds),
        evidence: JSON.stringify({
          banner: banner ?? null,
          server: http?.server ?? null,
          basis: best.basis,
          confidence: best.confidence,
          isKev,
          epss: epssScore,
        }),
        matchBasis: best.basis,
        confidence: best.confidence,
        references: JSON.stringify(bestRefs),
        remediation:
          "Verify the affected version, then upgrade per vendor guidance. Match basis is heuristic — confirm with authoritative advisories before action.",
        status: "open",
      });
    }
  }

  // No-open-ports finding so the report shows something.
  if (!openPorts.length) {
    findings.push({
      scanId: ctx.scanId,
      host: ctx.target,
      port: null,
      service: null,
      product: null,
      version: null,
      title: "No reachable ports detected",
      description: `No ports in the selected profile responded to TCP connect on ${ctx.target}. Network ACLs, firewall rules, or host-down state may explain this.`,
      severity: "info",
      cvssScore: null,
      cveIds: JSON.stringify([]),
      evidence: null,
      matchBasis: "tcp-connect",
      confidence: "low",
      references: JSON.stringify([]),
      remediation: "If you expected a port to be open, verify your network path and target.",
      status: "open",
    });
  }

  return { resolvedIp, open, findings };
}

function truncate(s: string, n: number) {
  return s.length <= n ? s : s.slice(0, n) + "…";
}
