# Usage

This walkthrough covers each page of the SentinelScope GUI.

> **Authorized use only.** Every page surfaces this notice and a scan cannot
> start until you tick the explicit authorization checkbox.

## 1. Dashboard

The landing page summarizes recent activity:

- **KPI cards** — total scans, total findings, KEV-tagged findings, and the
  freshness of the local CVE / KEV / EPSS snapshot.
- **Recent scans** — the last few scans with profile, target, and status.
- **Recent findings** — the highest-severity findings across all scans, with
  a click-through to the originating scan.

## 2. New Scan

Start a non-intrusive scan against a single target you are authorized to test.

1. Enter a **hostname** (RFC 1123) or an **IPv4 / IPv6** address. URLs, paths,
   credentials, whitespace, and shell metacharacters are rejected by the
   target validator. See [`shared/schema.ts`](../shared/schema.ts) for the
   exact rules.
2. Pick a **scan profile**:
   - **Quick** — `22, 80, 443`. Typically completes in under five seconds.
   - **Standard** — common service ports (`21, 22, 25, 80, 443, 3306, 3389,
     5432, 8080, 8443, ...`).
   - **Web** — HTTP/S only (`80, 443, 8080, 8443, 8000, 8888`).
   - **Custom** — comma list and ranges, e.g. `22, 80-90, 443`. Capped at
     **200 ports** per scan.
3. Tick **"I am the owner of this target or have explicit written authorization
   to assess it."** The **Start scan** button is disabled until this is checked.
4. Click **Start scan**. The browser navigates to the scan detail page, which
   refreshes automatically while the scan runs (1.5s interval).

Concurrency is capped at **8 in-flight TCP probes per scan** and the server
allows at most **2 active scans** at once. The `/api/scans` POST endpoint is
rate-limited to **10 requests per minute per IP**.

## 3. Scan Detail

Once the scan completes you'll see:

- **Severity counts** (Critical / High / Medium / Low / Info).
- **Findings** sorted by effective severity, each with:
  - The **match basis** — `banner`, `cpe:<vendor>+<keyword>+description`,
    `header`, `tls`, etc. — and a **confidence** (low / medium / high). This
    is the transparency layer: you can always see *why* a finding fired.
  - **Evidence** (collapsible) showing the raw banner / header / cert subject
    that drove the match.
  - **Remediation guidance** — instructional only.
  - State controls: **Mark resolved**, **Accept risk**, **Reopen**.
- **Markdown** and **JSON** download buttons in the header. The same content
  is available at:
  - `GET /api/scans/:id/report.md`
  - `GET /api/scans/:id/report.json`

CVE matches are intentionally conservative. A match with low confidence
(e.g. a CPE keyword hit with no version pinning) is still surfaced, but it
will be labeled as such — confirm against the upstream advisory before acting.

## 4. Vulnerability Feed

Three cards, one per upstream feed:

- **NVD** — [services.nvd.nist.gov/rest/json/cves/2.0](https://services.nvd.nist.gov/rest/json/cves/2.0).
- **CISA KEV** — [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **FIRST EPSS** — [api.first.org/data/v1/epss](https://api.first.org/data/v1/epss).

Each card shows the last refresh time, the count of items in the local
snapshot, and a **Refresh** button. Refresh requests run on the server with a
20 s timeout; failures are reported in-line and the existing snapshot is kept.

The **CVE explorer** below the cards lets you search the local CVE table by
CVE ID or keyword.

## 5. Remediation

Five general playbooks, instruction-only:

1. **Patch the affected service** — pinned-version verification, vendor advisory
   links, change-window guidance.
2. **Harden TLS** — Mozilla intermediate / modern profiles, HSTS, OCSP stapling.
   See [Mozilla Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS).
3. **Add security headers** — `Strict-Transport-Security`,
   `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
   `Referrer-Policy`. See [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).
4. **Restrict exposure** — review whether the service must be reachable from
   the network you scanned at all (firewall, VPN, bind-address).
5. **Replace end-of-life components** — upgrade paths, supported branches,
   migration plans.

These playbooks are deliberately advisory. SentinelScope **never** runs a
remediation step on a remote system on your behalf.

## 6. Reports

A flat table of every scan with **Markdown** and **JSON** download buttons.
Both formats embed:

- The target, profile, and resolved IP.
- All findings with severity, basis, confidence, evidence, and references.
- A timestamp and the local feed snapshot version used for correlation.

Markdown is escaped server-side: pipe (`|`), backtick, and `<`/`>` are
neutralized to prevent table breakout or HTML injection in any downstream
viewer.

## 7. Settings & Docs

- The full authorized-use notice and safety boundaries.
- Environment variables (`PORT`, `NVD_API_KEY`).
- An index of all docs files in `docs/`.

## API quick reference

| Method | Path                              | Purpose                              |
| ------ | --------------------------------- | ------------------------------------ |
| GET    | `/api/health`                     | Liveness                             |
| GET    | `/api/dashboard`                  | KPI summary                          |
| GET    | `/api/scans`                      | List scans                           |
| POST   | `/api/scans`                      | Start a scan (requires `authorizedAck: true`) |
| GET    | `/api/scans/:id`                  | Scan detail (with findings)          |
| GET    | `/api/scans/:id/report.md`        | Markdown report                      |
| GET    | `/api/scans/:id/report.json`      | JSON report                          |
| PATCH  | `/api/findings/:id`               | Update finding state                 |
| GET    | `/api/feeds`                      | Feed snapshot status                 |
| POST   | `/api/feeds/:name/refresh`        | Refresh `nvd` / `kev` / `epss`       |
| GET    | `/api/cves`                       | Search local CVE table               |

All POST/PATCH bodies are validated with Zod. Invalid input returns a `400`
with the issue list.
