# Architecture

SentinelScope is a single-process Node.js application that serves both an
Express JSON API and a Vite-built React SPA from one port. All persistent
state lives in a local SQLite file.

## Layout

```
sentinelscope/
├── client/                   # Vite + React frontend
│   └── src/
│       ├── App.tsx           # wouter hash router + ThemeProvider + AppLayout
│       ├── components/       # Logo, AppLayout, SeverityBadge, ThemeProvider, ui/
│       └── pages/            # Dashboard, NewScan, Scans, ScanDetail, Feed,
│                             # Remediation, Reports, Settings
├── server/                   # Express + scanner + feeds
│   ├── index.ts              # entrypoint (template-provided)
│   ├── routes.ts             # all /api/* endpoints + rate limiting
│   ├── storage.ts            # DatabaseStorage (Drizzle) + inline migrations
│   ├── seed.ts               # bundled CVE/KEV/EPSS snapshot for first run
│   ├── feeds.ts              # NVD / KEV / EPSS refreshers (timeout-bounded)
│   └── lib/
│       ├── ports.ts          # parsePortList, profilePorts, port profiles
│       ├── severity.ts       # CVSS bucketing, KEV/EPSS bumps, prioritization
│       ├── scanner.ts        # runScan: TCP connect, banner, HEAD, TLS
│       └── report.ts         # renderJson, renderMarkdown (with escaping)
├── shared/
│   └── schema.ts             # drizzle tables + Zod validators
├── docs/                     # USAGE / ARCHITECTURE / SECURITY / SAFE-SCANNING / installs
├── tests in *.test.ts        # vitest suite (42 tests)
└── data.db                   # SQLite (created on first run)
```

## Tech stack

| Layer    | Choice                                                                     |
| -------- | -------------------------------------------------------------------------- |
| Frontend | React 18 + TypeScript + Tailwind v3 + shadcn/ui + wouter + TanStack Query  |
| Backend  | Express 4 + TypeScript + better-sqlite3 + Drizzle ORM                       |
| Validation | Zod (shared between server and client via `shared/schema.ts`)             |
| Tests    | Vitest                                                                      |
| Build    | Vite (frontend) + esbuild via `script/build.ts` (server bundle)             |

## Request flow — starting a scan

1. The user fills the **New Scan** form and ticks the authorization checkbox.
2. The browser POSTs to `/api/scans` with `{ target, profile, ports?, authorizedAck: true }`.
3. The IP-based rate limiter (10 req / min) and active-scan limiter (max 2)
   guard the route.
4. `newScanRequestSchema` (Zod) validates the body. The schema includes
   `authorizedAck: z.literal(true)` — anything else is a 400.
5. The route inserts a `scans` row in `running` state and kicks off
   `runScan(scanId)` asynchronously. The HTTP response returns immediately
   with the scan ID.
6. `runScan`:
   - Resolves the target via DNS (`dns.lookup`).
   - Resolves the port list via `profilePorts(profile, ports)` (capped at 200).
   - For each port, with `concurrency = 8`:
     - Opens a TCP connection (`node:net.Socket`) with a 1.5 s timeout.
     - If the port answers, attempts a service-appropriate banner read
       (2 s; SMTP gets a `QUIT`).
     - For HTTP/S ports, issues a single `HEAD /` request with `node:http` /
       `node:https` (no redirects, `rejectUnauthorized: false` so we can
       observe broken-cert hosts diagnostically).
     - For TLS ports, captures protocol, cipher, and certificate metadata via
       `tls.connect`.
   - Correlates findings against the local CVE / KEV / EPSS tables and writes
     a `findings` row per match plus an `Open port` info-level finding per
     answering port.
   - Updates the `scans` row to `complete` (or `error` with a message).

Front-end polling (`useQuery` with `refetchInterval` while status === running)
picks up progress in the GUI.

## Data model

Tables in `shared/schema.ts`:

| Table       | Purpose                                                                |
| ----------- | ---------------------------------------------------------------------- |
| `scans`     | One row per scan. Columns: target, profile, ports JSON, status, timestamps. |
| `findings`  | One row per finding. FK → scans. Severity, basis, confidence, evidence, references JSON, state. |
| `cves`      | Local CVE snapshot. CVE ID, description, CVSS, CPEs, references.        |
| `kev`       | Local CISA KEV catalog snapshot.                                       |
| `epss`      | Local FIRST EPSS snapshot (CVE → epss/percentile).                     |
| `feed_meta` | Last refresh timestamp / count / status per feed.                      |
| `settings`  | Future-proofing for user preferences.                                  |

> **Note:** SQL `references` is a reserved word. The DDL and DML quote the
> column as `"references"`. Search for that exact string when extending the
> schema.

## Severity model

`server/lib/severity.ts`:

- `severityFromCvss(score)` buckets CVSS into Info / Low / Medium / High /
  Critical.
- `effectiveSeverity(finding, kev?, epss?)` is the dashboard-facing severity:
  - **KEV-listed** CVEs are bumped to **critical**.
  - **EPSS ≥ 0.7** bumps Medium → High (and High → Critical when paired with
    KEV).
- `prioritizeFindings` sorts by effective severity, then by confidence, then
  by basis specificity (CPE > banner > header).

This bumping logic is also why the dashboard's "KEV findings" KPI is a useful
risk indicator independent of raw CVSS.

## Feed refresh

`server/feeds.ts` exposes three async refresh functions. All of them:

- Use `fetch` with an `AbortController` and a 20-second timeout.
- Treat any non-2xx response as a soft failure — the existing snapshot is
  kept and `feed_meta.status` is set to `error` with a short message.
- Run in a single transaction at the storage layer, so partial failures do
  not corrupt the table.

Sources:

- NVD: <https://services.nvd.nist.gov/rest/json/cves/2.0>
- CISA KEV: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- FIRST EPSS: <https://api.first.org/data/v1/epss>

## Frontend conventions

- **Hash routing.** `<Router hook={useHashLocation}>` wraps `<Switch>` so the
  app works inside iframes and static hosts. URLs look like `#/scans/1`.
- **No browser storage.** No `localStorage` / `sessionStorage` / `cookies`.
  Theme is derived from `prefers-color-scheme`. Persistent state goes to the
  backend SQLite.
- **TanStack Query everywhere.** All HTTP goes through `apiRequest` from
  `@/lib/queryClient`, which respects the `__PORT_5000__` substitution used by
  the deploy pipeline.
- **`data-testid`** on every interactive element and meaningful display
  element, following `{action}-{target}` / `{type}-{content}` conventions.

## Build and run

- `npm run dev` — Vite + Express on port 5000 (hot reload).
- `npm run build` — produces `dist/public` (static SPA) and `dist/index.cjs`
  (server bundle).
- `npm start` — runs `dist/index.cjs` in `production`.
- `npm run typecheck` — strict TS.
- `npm test` — Vitest, currently 42 unit tests.
