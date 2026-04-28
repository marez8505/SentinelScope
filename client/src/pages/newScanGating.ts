/**
 * Pure helpers powering the "New scan" form's UI gating.
 *
 * These live in their own module (no React imports) so they can be unit
 * tested in a Node test environment without dragging in JSX, the query
 * client, shadcn/ui components, etc.
 *
 * The server is the authoritative gate for both the authorized-use and
 * the private/LAN acknowledgements (see `newScanRequestSchema` and
 * `RESTRICTED_TARGET_CLASSES` in `shared/schema.ts`). These helpers
 * exist to mirror that policy in the client so operators get immediate
 * feedback instead of a 400 round-trip.
 */

/**
 * Quick textual heuristic for hostnames that obviously refer to private,
 * loopback or link-local space. We deliberately do NOT resolve DNS here —
 * the server does that after the request lands. This is a UX hint only:
 * when it returns true we surface the additional "I understand this is a
 * private/LAN target" checkbox.
 *
 * Covered cases:
 *  - `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.lan`
 *  - IPv6 loopback (`::1`, expanded form), link-local `fe80::/10`,
 *    unique-local `fc00::/7` (`fc..`/`fd..`)
 *  - IPv4 loopback `127.0.0.0/8`, RFC1918 (`10/8`, `192.168/16`,
 *    `172.16/12`), link-local `169.254/16`, CGNAT `100.64/10`,
 *    and the unspecified `0.0.0.0`
 */
export function isPrivateLikeText(t: string): boolean {
  const v = t.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!v) return false;
  if (
    v === "localhost" ||
    v.endsWith(".localhost") ||
    v.endsWith(".local") ||
    v.endsWith(".internal") ||
    v.endsWith(".lan")
  )
    return true;
  if (v === "::1" || v === "0:0:0:0:0:0:0:1") return true;
  if (/^fe80:/i.test(v) || /^fc[0-9a-f]{2}:/i.test(v) || /^fd[0-9a-f]{2}:/i.test(v)) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  if (m) {
    const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  return false;
}

export interface DisableStartArgs {
  /** Primary "I am authorized to scan this target" checkbox state. */
  authorizedAck: boolean;
  /** Current target string from the input. */
  target: string;
  /** Selected scan profile id. */
  profile: string;
  /** Comma/range port list — only meaningful when `profile === "custom"`. */
  customPorts: string;
  /** Secondary "Allow private/LAN target" checkbox state. */
  allowPrivate: boolean;
  /** Whether a scan-create mutation is currently in flight. */
  isPending: boolean;
}

/**
 * Decide whether the Start-scan submit button should be disabled.
 *
 * The button is disabled when ANY of the following are true:
 *  - the operator has not checked the primary authorized-use box;
 *  - no target is entered;
 *  - the custom profile is selected without a port list;
 *  - the typed target looks private/loopback/LAN and the second
 *    "Allow private/LAN target" checkbox has not been ticked
 *    (mirrors the server's `allowPrivate: z.literal(true)` rule);
 *  - a scan request is already in flight.
 */
export function shouldDisableStart(args: DisableStartArgs): boolean {
  const { authorizedAck, target, profile, customPorts, allowPrivate, isPending } = args;
  if (!authorizedAck) return true;
  if (!target) return true;
  if (profile === "custom" && !customPorts) return true;
  if (isPrivateLikeText(target) && !allowPrivate) return true;
  if (isPending) return true;
  return false;
}
