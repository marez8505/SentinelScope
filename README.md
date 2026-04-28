# SentinelScope

A safe, authorized-use, local vulnerability assessment tool with a web GUI.
Inspired by tools like Nessus, but intentionally narrow in scope: SentinelScope
performs **non-intrusive** TCP service discovery and benign metadata collection,
correlates discovered services against locally stored CVE / CISA KEV / FIRST EPSS
data, and produces human-readable Markdown and JSON reports.

> **Authorized-use only.** Run scans only against hosts you own or have explicit
> written permission to assess. Unauthorized scanning may violate the
> Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act
> in the United Kingdom, and similar laws elsewhere, plus the terms of service
> of most hosting providers.

## What it does

- **DNS resolution + TCP connect tests** against a small, capped port set
  (default profiles: Quick, Standard, Web, or a custom comma-separated list).
- **Banner grabbing** for SSH/FTP/SMTP — short reads with a tight timeout, plus
  a polite `QUIT` for SMTP so it does not wedge.
- **HTTP/HTTPS metadata** — a single `HEAD` request capturing status, server
  banner, and response headers (`Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Frame-Options`, etc.). Redirects are not followed.
- **TLS metadata** — protocol version, negotiated cipher, and certificate
  subject / issuer / validity for HTTPS ports.
- **CVE correlation** against a local snapshot of the
  [NVD CVE 2.0 API](https://services.nvd.nist.gov/rest/json/cves/2.0),
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  and [FIRST EPSS](https://www.first.org/epss/), with a transparent confidence
  level (low / medium / high) and a human-readable match basis.
- **Markdown and JSON reports** per scan, downloadable from the GUI or via API.

## What it does **not** do

SentinelScope is a discovery-and-correlation tool. It deliberately omits any
capability that turns reconnaissance into intrusion:

- **No exploit execution or payload delivery.**
- **No credential attacks, brute forcing, or password spraying.**
- **No stealth, evasion, or scan-rate manipulation.**
- **No destructive remediation or remote system modification** — remediation is
  always presented as instructions you read and run yourself.
- **No raw-socket / privileged scanning.** All probes use the OS-level TCP
  connect path (`node:net`).

See [`docs/SAFE-SCANNING.md`](docs/SAFE-SCANNING.md) and
[`docs/SECURITY.md`](docs/SECURITY.md) for the full safety model.

## Quick start

```bash
npm install
cp .env.example .env        # optional — only for NVD_API_KEY / PORT
npm run build
npm start                   # http://localhost:5000
```

For development:

```bash
npm run dev                 # vite + express on :5000
npm run typecheck           # strict TypeScript
npm test                    # vitest unit tests (target validation, ports, severity, reports)
```

Platform-specific install guides:

- [docs/INSTALL-WSL.md](docs/INSTALL-WSL.md) — Windows users running under WSL
- [docs/INSTALL-POWERSHELL.md](docs/INSTALL-POWERSHELL.md) — native Windows PowerShell

## Key documentation

| Document                                                  | What it covers                                                                  |
| --------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [docs/USAGE.md](docs/USAGE.md)                             | Walkthrough of the GUI: dashboard, new scan, results, feed, remediation, reports |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)               | Stack, request flow, data model, and feed refresh design                        |
| [docs/SAFE-SCANNING.md](docs/SAFE-SCANNING.md)             | The scanning safety model and what is and is not implemented                    |
| [docs/SECURITY.md](docs/SECURITY.md)                       | Application security posture, threat model, and reporting issues                |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md)                   | Pre-publication security review checklist                                       |

## Tech stack

- **Frontend:** React 18 + TypeScript, Vite, Tailwind CSS, shadcn/ui, wouter (hash routing), TanStack Query
- **Backend:** Express 4, TypeScript, better-sqlite3 + Drizzle ORM, Zod validation
- **Tests:** Vitest

## License

This project is provided for educational and defensive use within authorized
environments. You are responsible for complying with all applicable laws and
the terms of service of any system you target.
