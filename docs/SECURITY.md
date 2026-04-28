# Security Posture

This document covers the security of the **SentinelScope application itself**
— how it validates input, isolates work, and avoids becoming a vector. For
the *scanning* safety model, see [SAFE-SCANNING.md](SAFE-SCANNING.md).

## Threat model

**In scope.** A local operator runs SentinelScope on their workstation or a
trusted host and uses the GUI / API to scan systems they own. The threats we
defend against are:

- A **malformed or hostile target string** trying to coerce the server into
  shell injection, path traversal, or SSRF-style behavior.
- A **malformed or hostile port list** trying to pivot to denial-of-service
  via giant ranges, integer overflow, or shell metacharacter injection.
- A **hostile finding payload** (e.g., a banner from a target containing
  Markdown / HTML) trying to break out of a generated report into XSS or
  table breakout.
- **Resource exhaustion** from a runaway scan or burst of API calls.

**Out of scope.** SentinelScope is a single-tenant local tool. It does not
implement authentication, multi-user RBAC, or hardened transport. The server
defaults to binding `127.0.0.1` (loopback only). If you need to reach it from
another host, set `HOST=0.0.0.0` *only* behind a trusted reverse proxy that
adds authentication, or restrict access with a firewall / VPN. Exposing the
raw Express server to a network without one of those in front of it is
unsupported.

## Input validation

All inputs cross the trust boundary through Zod schemas in `shared/schema.ts`:

- `targetSchema` — RFC 1123 hostname, IPv4, or IPv6 only. URLs, paths,
  whitespace, and shell metacharacters are rejected (see
  [SAFE-SCANNING.md](SAFE-SCANNING.md#target-validation)).
- `portsArraySchema` — integers `1..65535`, deduplicated, capped at 200.
- `parsePortList` (`server/lib/ports.ts`) — accepts the GUI's comma /
  range syntax, rejects anything else. Tested against shell-injection
  inputs in `server/lib/ports.test.ts`.
- `newScanRequestSchema` — requires `authorizedAck: z.literal(true)`.
- Finding state updates use a Zod enum.

Validation failures return `400` with the issue list — they do not throw
500s.

## No shell execution

The codebase does not call `child_process.exec`, `exec`, `execSync`, or any
shell-string variant. Scanning is implemented entirely with Node's built-in
`net`, `tls`, `http`, `https`, and `dns` modules. There is therefore no
attack surface for command injection through targets, port lists, or
banners.

If a future feature ever needs to invoke a local binary, the rule is
`spawn` / `execFile` with a fixed command and a fixed argument array — never
a shell string, never user input concatenated into a command.

## SSRF avoidance

The HTTP/HTTPS probe is restricted to:

- The **host** the operator entered and validated through `targetSchema`
  (no `Host:` rewrites, no upstream URL composition from user input).
- A single `HEAD /` request.
- Redirect following **disabled** (`maxRedirects: 0` in the request
  options) — a hostile target cannot redirect us into the local metadata
  service or the operator's intranet.

Combined with target validation, this means the scanner cannot be
weaponized to fetch arbitrary URLs.

## Report rendering

`server/lib/report.ts → renderMarkdown` runs every finding field through
`escapeMd`, which:

- Escapes `|` to prevent breakout from Markdown tables.
- Escapes backticks to prevent code-fence breakout.
- Escapes `<` and `>` to HTML entities to prevent injected `<script>` tags
  from rendering when a third-party Markdown viewer is permissive.

These escapes are unit-tested in `server/lib/report.test.ts` against typical
XSS / table-breakout payloads.

JSON reports are produced with `JSON.stringify`, which already handles
embedded quotes and control characters safely.

## Rate limits and resource caps

- **API rate limit.** `/api/scans` POST is limited to 10 requests / minute
  per IP. Other state-mutating routes are bounded by the same limiter.
- **Active scans.** The server tracks running scans and rejects new requests
  past the cap (default 2). This prevents one client from launching dozens
  of concurrent probes by automating the API.
- **Per-scan caps.** Max 200 ports per scan, max 8 concurrent in-flight
  probes per scan. Each TCP probe has a 1.5 s timeout.
- **Feed refresh.** 20 s `AbortController` timeout per upstream call.

## Database and on-disk data

- The SQLite database (`data.db`) is created in the project directory. On
  POSIX hosts, the server `chmod`s `data.db`, `data.db-wal`, and
  `data.db-shm` to `0600` at startup so only the running user can read or
  write them. On Windows hosts the equivalent NTFS ACL is the operator's
  responsibility — store the project under a per-user profile directory and
  avoid sharing the parent folder.
- The DB and its WAL/SHM sidecars are listed in `.gitignore` and must never
  be committed.
- Runtime DB files (`*.db`, `*.db-wal`, `*.db-shm`) must be excluded from
  any backup or artifact bundle that crosses a trust boundary.
- Findings, evidence, and references are stored as JSON columns. The
  `references` column is quoted (`"references"`) because it is a SQL
  reserved word — keep that quoting if you extend the DDL.
- No secrets, credentials, or personal data are written. The optional
  `NVD_API_KEY` lives in `.env` (gitignored); it is sent only to NVD.

## Dependencies

The project pins major versions of all dependencies in `package.json`. Run
`npm audit` periodically and treat **high** or **critical** advisories as
release blockers. Native modules (`better-sqlite3`) compile from source on
install — make sure `npm install` runs cleanly before running tests.

## Browser-side isolation

- The frontend never reads or writes `localStorage`, `sessionStorage`,
  `indexedDB`, or cookies. Theme is derived from `prefers-color-scheme`.
- The frontend uses TanStack Query for all HTTP. There is no `dangerouslySet
  InnerHTML` against scan output anywhere in the UI.

## Network exposure

- The Express server binds to `127.0.0.1` by default. Set `HOST` in `.env`
  (or as an environment variable) to override; the server logs a clear
  warning at startup whenever the bind address is anything other than
  loopback.
- The scan-creation endpoint resolves the requested target via DNS and
  rejects any address that classifies as loopback, link-local, IPv4 private
  (RFC 1918), CGNAT (`100.64.0.0/10`), multicast/reserved, IPv6 unique-local
  (`fc00::/7`), IPv6 link-local (`fe80::/10`), or IPv4-mapped IPv6, unless
  the request body sets `allowPrivate: true`. The GUI surfaces this opt-in
  as an explicit “Allow private/LAN target” checkbox that only appears once
  the entered target looks private — lab operators must consciously confirm
  each in-network scan.
- Reference URLs are treated as untrusted everywhere they are rendered.
  Both the server (Markdown reports in `server/lib/report.ts`) and the
  client (Scan Detail page in `client/src/pages/ScanDetail.tsx`) call the
  shared `safeHref` helper in `shared/url.ts`, which only accepts
  syntactically valid `http:` / `https:` URLs without embedded credentials,
  whitespace, or control characters and caps the length at 2 KB. Any other
  scheme (`javascript:`, `data:`, `file:`, `mailto:`, `ftp:`, relative
  paths, garbage, etc.) is rendered as escaped plain text — never as a
  clickable `<a href>` and never as a Markdown `[link](url)`. The server
  also re-exports the helper as `sanitizeHref` for backwards compatibility.
  Both surfaces are unit-tested in `shared/url.test.ts` and
  `server/lib/report.test.ts`.

## Reporting a vulnerability

If you find a security issue in SentinelScope, please open a private
disclosure with the project owner (do not file a public issue with exploit
details). Include the affected file path, a minimal reproduction, and any
suggested mitigation.

See [SECURITY_REVIEW.md](../SECURITY_REVIEW.md) for the pre-publication
checklist used during development.
