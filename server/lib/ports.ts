/**
 * Port list parsing and predefined safe profiles.
 *
 * SAFE-DEFAULTS: Only TCP connect to a small, well-known set. No SYN scanning,
 * no UDP, no privileged operations. The hard cap of 200 ports keeps any single
 * scan from spamming a remote target.
 */

export const QUICK_PORTS = [22, 80, 443];
export const STANDARD_PORTS = [
  21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443,
];
export const WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888];

export const HARD_PORT_LIMIT = 200;

const PORT_LIST_RE = /^[0-9,\s\-]+$/;

/**
 * Parse a user-supplied port list into a sorted, deduped, validated number[].
 * Accepts comma-separated values and inclusive ranges with `-`.
 *   "22, 80, 443"       -> [22, 80, 443]
 *   "1-10"              -> [1..10]
 *   "22, 80-82, 443"    -> [22, 80, 81, 82, 443]
 *
 * Rejects shell metacharacters, scientific notation, or anything outside 1-65535.
 * Throws Error with a helpful message on invalid input.
 */
export function parsePortList(input: string): number[] {
  if (typeof input !== "string") throw new Error("Port list must be a string");
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Port list is empty");
  if (!PORT_LIST_RE.test(trimmed)) {
    throw new Error("Only digits, commas, spaces, and ranges (e.g. 80-90) allowed");
  }
  const out = new Set<number>();
  const parts = trimmed.split(",").map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    if (part.includes("-")) {
      const [lo, hi] = part.split("-").map((s) => s.trim());
      const a = Number(lo);
      const b = Number(hi);
      if (!Number.isInteger(a) || !Number.isInteger(b)) {
        throw new Error(`Invalid range: ${part}`);
      }
      if (a < 1 || b > 65535 || a > b) {
        throw new Error(`Range out of bounds: ${part}`);
      }
      if (b - a > HARD_PORT_LIMIT) {
        throw new Error(`Range too wide (max ${HARD_PORT_LIMIT} ports): ${part}`);
      }
      for (let i = a; i <= b; i++) out.add(i);
    } else {
      const n = Number(part);
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        throw new Error(`Invalid port: ${part}`);
      }
      out.add(n);
    }
    if (out.size > HARD_PORT_LIMIT) {
      throw new Error(`Too many ports (max ${HARD_PORT_LIMIT})`);
    }
  }
  return Array.from(out).sort((a, b) => a - b);
}

export function profilePorts(profile: string, custom?: string): number[] {
  switch (profile) {
    case "quick":
      return [...QUICK_PORTS];
    case "standard":
      return [...STANDARD_PORTS];
    case "web":
      return [...WEB_PORTS];
    case "custom":
      if (!custom) throw new Error("Custom profile requires customPorts");
      return parsePortList(custom);
    default:
      throw new Error(`Unknown profile: ${profile}`);
  }
}
