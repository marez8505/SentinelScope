/**
 * URL safety helpers used by both the server (Markdown report rendering) and
 * the client (rendering reference links in the Scan Detail UI).
 *
 * Reference URLs in CVE / KEV / NVD records are user-influenceable data: NVD
 * pulls them from third-party sources, so we treat them as untrusted input.
 * Both surfaces (Markdown reports, React UI) must only render clickable links
 * for `http:` / `https:` URLs and fall back to escaped/plain text for anything
 * else (`javascript:`, `data:`, `mailto:`, `file:`, `ftp:`, relative paths,
 * embedded credentials, whitespace, control characters, ...).
 *
 * Returns the canonicalized URL string when safe; returns null otherwise.
 */
export function safeHref(input: string | null | undefined): string | null {
  if (!input) return null;
  const trimmed = String(input).trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return null;
  // Disallow whitespace, NUL, and other control characters anywhere in the
  // raw input. The URL constructor would otherwise normalize away tab / CR
  // / LF inside the path, which can be used to hide a `javascript:` payload
  // from a permissive renderer.
  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) return null;
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  // Disallow embedded userinfo (e.g. `https://user:pass@evil/`).
  if (u.username || u.password) return null;
  return u.toString();
}
