# Safe Scanning Model

SentinelScope is intentionally narrow. This document is the source of truth
for what the scanner *will* do and what it *will not* do, and why.

## Authorization is required

Every scan request must include `authorizedAck: true` in the JSON body. The
Zod validator uses `z.literal(true)` — any other value (including `false`,
`"true"`, or omission) is rejected with a 400. The GUI's **Start scan**
button is disabled until the explicit authorization checkbox is ticked.

This is enforced server-side, not just in the GUI.

## What is implemented

- **DNS resolution** of the target via `dns.lookup`.
- **TCP connect probes** (`node:net.Socket.connect`) with a 1.5 s timeout
  per port. This uses the OS's normal TCP three-way handshake — no SYN
  scanning, no spoofing, no raw sockets, no privileged operations.
- **Service banners**:
  - SSH: short read on connect.
  - FTP: short read on connect.
  - SMTP: short read, then a `QUIT\r\n` so we don't hold the connection.
- **HTTP / HTTPS**: a single `HEAD /` request with redirects disabled. We
  capture the status line and headers we care about
  (`Server`, `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
  `rejectUnauthorized` is `false` so we can *observe* misconfigured certs
  for reporting; we do not validate or trust them for any other purpose.
- **TLS handshake metadata**: protocol version, cipher suite, certificate
  subject / issuer / validity from `tls.connect`.
- **CVE / KEV / EPSS correlation** against the local snapshot, with a
  conservative basis label and a confidence rating.

## What is **not** implemented (and won't be)

The following capabilities are out of scope for this project:

- **Exploit execution or payload delivery.** No CVE PoCs, no shellcode, no
  fuzzing of the target.
- **Credential attacks.** No brute force, no password spraying, no default-
  credential checks that submit credentials.
- **Stealth or evasion.** No fragmentation, no source-port games, no
  rate-shaping designed to evade IDS.
- **Active service manipulation.** We never write, post, or modify state on
  the target. All probes are read-only.
- **Destructive remediation.** Remediation guidance is text only. There is
  no "fix it for me" button that reaches a remote host.
- **Privileged scanning.** No raw sockets, no `setcap CAP_NET_RAW`, no SYN /
  ACK / FIN / Xmas / null scans. Everything is a normal TCP connect.

## Scope and rate limits

These are baked into the code and tests:

| Limit                          | Value                                |
| ------------------------------ | ------------------------------------ |
| Targets per scan               | **1** (single host or IP)            |
| Per-scan port cap              | **200**                              |
| Default Quick profile          | `[22, 80, 443]`                      |
| Per-port TCP timeout           | **1.5 s**                            |
| Per-port banner read timeout   | **2 s**                              |
| In-flight TCP probes per scan  | **8**                                |
| Concurrent scans (server-wide) | **2**                                |
| `/api/scans` POST rate limit   | **10 / minute / IP**                 |
| Feed refresh timeout           | **20 s** (then soft-fail, keep prev) |

## Target validation

`shared/schema.ts → targetSchema` is the only way a target enters the system.
It is also unit-tested (see `shared/schema.test.ts`). The validator:

- Trims input and rejects empty strings.
- Rejects URLs (`http://`, `https://`, `ftp://`, ...), schemes in general,
  paths, query strings, and fragments.
- Rejects userinfo (`user:pass@host`).
- Rejects whitespace and shell metacharacters (`; & | \` $ ( ) < > \n` etc.).
- Accepts:
  - **RFC 1123 hostnames** — labels of `[A-Za-z0-9]` and `-`, no leading or
    trailing hyphen, total length ≤ 253.
  - **IPv4** addresses.
  - **IPv6** addresses, optionally bracketed (`[::1]`).

This rules out SSRF-style abuse via crafted URLs, command injection via
shell metacharacters, and accidental scanning of multi-target inputs.

## Why TCP connect (not SYN)?

A TCP connect probe completes the handshake the way any normal client
would, then closes politely. It:

- Does **not** require root / `CAP_NET_RAW`.
- Is recorded in target logs as a normal connection — there is no attempt
  to hide. This is a feature, not a bug, for an authorized-use tool.
- Cannot be confused with a flood, fragmentation attack, or stealth scan.

If you want SYN-level visibility, use a dedicated tool like `nmap` outside
of SentinelScope. The install docs note this as an optional, fully-external
dependency — SentinelScope itself does not invoke it.

## Optional local helpers

If a remediation playbook ever ships with helper commands, those commands
are:

- Local-only (e.g., a `systemctl` line for the operator's own host),
- Clearly labeled as instructions, and
- **Never executed automatically** — the GUI does not have a "run command on
  remote host" path, and the server never spawns shells against external
  systems.

The current implementation contains no such helpers. Remediation is plain
text guidance with vendor / standards links.

## Logging

Scans, findings, and feed refresh attempts are logged to the SQLite database
on the local machine. Nothing is sent to any third party. There is no
telemetry, analytics, or crash reporting.
