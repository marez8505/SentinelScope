# Security Review — Pre-publication Checklist

Use this checklist before sharing or deploying SentinelScope. It enumerates
the categories of issues that have a track record of going wrong in
"vulnerability scanner with a web GUI" projects, with the relevant code
paths in this repository.

Last reviewed: SentinelScope v1.0.0.

---

## 1. Command / shell injection

- [x] No `child_process.exec`, `execSync`, `spawnSync(..., { shell: true })`,
      or template-stringed shells anywhere in `server/`.
- [x] Scanning uses `node:net`, `node:tls`, `node:http`, `node:https`,
      `node:dns` only.
- [x] `parsePortList` (`server/lib/ports.ts`) rejects any character outside
      `[0-9, -]`. Unit-tested in `server/lib/ports.test.ts` against payloads
      like `22; rm -rf /`, `22 && ls`, and `$(whoami)`.

## 2. SSRF / scheme confusion / metadata service

- [x] `targetSchema` (`shared/schema.ts`) rejects URLs, schemes, paths, and
      userinfo.
- [x] HTTP probe issues a single `HEAD /` against the validated host. No
      `Host:` overrides, no upstream URL composition from user input.
- [x] HTTP redirects are disabled (`maxRedirects: 0`) so hostile targets
      cannot redirect probes into intranet ranges or `169.254.169.254`.
- [x] `tls.connect` is called with the validated host and a known port
      number; `servername` is set to the same hostname.

## 3. Path traversal / file system writes

- [x] Server does not accept file paths from the API. The only on-disk write
      is the SQLite database (`data.db`) in the project directory.
- [x] No `fs.readFile` / `fs.writeFile` calls keyed off user input.
- [x] Reports are streamed as response bodies (Markdown / JSON), not written
      to disk.

## 4. Scan abuse / DoS amplification

- [x] **Authorization gate.** `/api/scans` requires `authorizedAck: true`
      (Zod `z.literal(true)`). Enforced server-side, not just in the GUI.
- [x] **Single-target only.** `targetSchema` admits one host per scan.
- [x] **Port cap = 200** per scan (`HARD_PORT_LIMIT` in `server/lib/ports.ts`).
- [x] **Concurrency cap = 8** in-flight probes per scan (`server/lib/scanner.ts`).
- [x] **Active-scan cap = 2** server-wide (`server/routes.ts`).
- [x] **Rate limit = 10/min/IP** on `/api/scans` POST.
- [x] **Per-port timeout = 1.5 s**, banner read = 2 s. No long-lived sockets.

## 5. Report rendering / output XSS

- [x] `renderMarkdown` (`server/lib/report.ts`) escapes `|`, `` ` ``, `<`,
      `>` in every dynamic field via `escapeMd`.
- [x] Unit tests in `server/lib/report.test.ts` cover table-breakout (`|`)
      and HTML/script payloads in banners.
- [x] JSON reports use `JSON.stringify` (which escapes control characters
      and quotes).
- [x] The frontend renders findings through React components — no
      `dangerouslySetInnerHTML` against scan output.

## 6. Frontend storage / sandbox

- [x] No `localStorage`, `sessionStorage`, `indexedDB`, or cookie use anywhere
      in `client/`.
- [x] Theme derived from `window.matchMedia("(prefers-color-scheme: dark)")`.
- [x] All HTTP goes through `apiRequest` from `@/lib/queryClient` (no raw
      `fetch` calls that bypass `__PORT_5000__` substitution).

## 7. Dependency risk

- [x] `package.json` pins major versions for runtime deps.
- [x] `npm audit` checked at build time; no high/critical advisories at
      release.
- [x] Native deps: `better-sqlite3` only. Documented build prerequisites in
      `docs/INSTALL-WSL.md` and `docs/INSTALL-POWERSHELL.md`.
- [ ] *Re-run* `npm audit` before each release.

## 8. Sensitive data handling

- [x] No credentials, tokens, or personal data are logged or persisted by
      design.
- [x] `.env` is gitignored. `NVD_API_KEY` is read from `process.env` and
      only sent to NVD.
- [x] No telemetry or third-party analytics.

## 9. Unsafe remediation

- [x] Remediation pages render text and links only.
- [x] No GUI or API path that executes a remediation step on a remote host.
- [x] No "auto-fix" buttons. Every action is described, not performed.

## 10. CVE correlation transparency

- [x] Every finding records a `basis` (e.g., `banner`, `cpe:openssh+keyword+description`)
      and a `confidence` (low / medium / high). The user can always see
      *why* a finding fired and how speculative the match is.
- [x] CVSS-only severity is bumped only via documented rules (KEV → critical;
      EPSS ≥ 0.7 bumps Medium → High). Implemented and unit-tested in
      `server/lib/severity.ts` / `severity.test.ts`.

## 11. Build and tests

- [x] `npm run typecheck` — clean.
- [x] `npm test` — 42 tests passing across 4 files
      (`server/lib/ports.test.ts`, `server/lib/severity.test.ts`,
      `server/lib/report.test.ts`, `shared/schema.test.ts`).
- [x] `npm run build` — produces `dist/public` and `dist/index.cjs` without
      warnings related to source code.

## 12. Documentation completeness

- [x] `README.md` — purpose, safety, quick start, doc index.
- [x] `docs/USAGE.md` — page-by-page walkthrough.
- [x] `docs/ARCHITECTURE.md` — stack, request flow, data model, severity.
- [x] `docs/SAFE-SCANNING.md` — what is and isn't implemented, and why.
- [x] `docs/SECURITY.md` — application security posture and threat model.
- [x] `docs/INSTALL-WSL.md` and `docs/INSTALL-POWERSHELL.md` — install paths.
- [x] `.env.example` — `PORT`, `NVD_API_KEY` keys.

---

## Sign-off

If every box above is checked at release time, SentinelScope is considered
ready to share with authorized operators. This file is meant to be re-run
on every release — copy it into a release notes section and re-tick.
