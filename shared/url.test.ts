import { describe, it, expect } from "vitest";
import { safeHref } from "./url";

describe("safeHref", () => {
  it("accepts http and https URLs", () => {
    expect(safeHref("http://example.com")).toBe("http://example.com/");
    expect(safeHref("https://nvd.nist.gov/vuln/detail/CVE-2024-1")).toBe(
      "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
    );
    expect(safeHref("https://example.com:8443/path?q=1#frag")).toBe(
      "https://example.com:8443/path?q=1#frag",
    );
  });

  it("rejects non-http(s) schemes", () => {
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("JavaScript:alert(1)")).toBeNull();
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(safeHref("mailto:victim@example.com")).toBeNull();
    expect(safeHref("ftp://example.com/")).toBeNull();
    expect(safeHref("file:///etc/passwd")).toBeNull();
    expect(safeHref("vbscript:msgbox")).toBeNull();
  });

  it("rejects relative paths and bare strings", () => {
    expect(safeHref("/admin")).toBeNull();
    expect(safeHref("./foo")).toBeNull();
    expect(safeHref("example.com")).toBeNull();
    expect(safeHref("not a url")).toBeNull();
  });

  it("rejects URLs with embedded credentials", () => {
    expect(safeHref("https://user:pass@example.com")).toBeNull();
    expect(safeHref("http://admin@example.com/")).toBeNull();
  });

  it("rejects URLs with whitespace or control characters", () => {
    expect(safeHref("https://example.com/ a")).toBeNull();
    expect(safeHref("https://example.com/\nb")).toBeNull();
    expect(safeHref("https://example.com/\tb")).toBeNull();
    expect(safeHref("https://example.com/\u0000b")).toBeNull();
    expect(safeHref(" https://example.com/")).toBe("https://example.com/"); // leading/trailing whitespace trimmed
  });

  it("rejects empty / null / oversized input", () => {
    expect(safeHref(null)).toBeNull();
    expect(safeHref(undefined)).toBeNull();
    expect(safeHref("")).toBeNull();
    expect(safeHref("   ")).toBeNull();
    expect(safeHref("https://example.com/" + "a".repeat(2050))).toBeNull();
  });

  it("rejects scheme-confusion payloads", () => {
    // Common payload: trailing colon or unusual whitespace tricks
    expect(safeHref("javascript\t:alert(1)")).toBeNull();
    expect(safeHref("java\nscript:alert(1)")).toBeNull();
  });
});
