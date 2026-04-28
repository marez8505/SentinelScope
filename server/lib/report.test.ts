import { describe, it, expect } from "vitest";
import { renderJson, renderMarkdown, __test__ } from "./report";

const baseScan = {
  id: 42,
  target: "example.com",
  resolvedIp: "93.184.216.34",
  profile: "quick",
  ports: JSON.stringify([22, 80, 443]),
  status: "complete",
  startedAt: 1_700_000_000_000,
  finishedAt: 1_700_000_001_000,
  error: null,
  summary: null,
  authorizedAck: 1,
};

const findings = [
  {
    id: 1,
    scanId: 42,
    host: "example.com",
    port: 443,
    service: "https",
    product: "nginx",
    version: "1.18.0",
    title: "Possible CVE match: CVE-2021-44228",
    description: "Log4j is bundled with this stack…",
    severity: "critical",
    cvssScore: 10.0,
    cveIds: JSON.stringify(["CVE-2021-44228"]),
    evidence: JSON.stringify({ banner: null, server: "nginx/1.18.0" }),
    matchBasis: "cpe+keyword",
    confidence: "high",
    references: JSON.stringify(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]),
    remediation: "Upgrade Log4j to 2.17.1+.",
    status: "open",
    createdAt: 1_700_000_000_500,
  },
  {
    id: 2,
    scanId: 42,
    host: "example.com",
    port: 80,
    service: "http",
    product: null,
    version: null,
    title: "Missing HTTP security headers",
    description: "Several headers are missing.",
    severity: "low",
    cvssScore: 3.1,
    cveIds: JSON.stringify([]),
    evidence: JSON.stringify({ headers: { server: "nginx" }, missing: ["strict-transport-security"] }),
    matchBasis: "header",
    confidence: "high",
    references: JSON.stringify([]),
    remediation: "Set the missing headers.",
    status: "open",
    createdAt: 1_700_000_000_600,
  },
];

const kev = [
  {
    cveId: "CVE-2021-44228",
    vendorProject: "Apache",
    product: "Log4j2",
    vulnerabilityName: "Log4Shell",
    dateAdded: "2021-12-10",
    shortDescription: "Apache Log4j2 RCE",
    requiredAction: "Patch.",
    dueDate: "2021-12-24",
    knownRansomware: "Known",
    notes: "",
    cwes: "[]",
  },
];
const epss = [{ cveId: "CVE-2021-44228", epss: 0.97, percentile: 0.99, date: "2025-01-01" }];

describe("renderJson", () => {
  it("returns a structured report ranked KEV-first", () => {
    const r = renderJson({ scan: baseScan as any, findings: findings as any, kev: kev as any, epss: epss as any });
    expect(r.scan.id).toBe(42);
    expect(r.findings[0].cveIds).toContain("CVE-2021-44228");
    expect(r.findings[0].kev?.cveId).toBe("CVE-2021-44228");
    expect(r.findings[0].epss?.epss).toBeCloseTo(0.97);
    expect(r.scan.summary.critical).toBe(1);
    expect(r.scan.summary.low).toBe(1);
  });
});

describe("renderMarkdown", () => {
  it("contains scan header, summary table, and finding sections", () => {
    const md = renderMarkdown({ scan: baseScan as any, findings: findings as any, kev: kev as any, epss: epss as any });
    expect(md).toContain("# SentinelScope Report — Scan #42");
    expect(md).toContain("## Severity Summary");
    expect(md).toContain("CVE-2021-44228");
    expect(md).toContain("Authorization Notice");
  });

  it("escapes pipes and backticks in user-supplied fields so the table cannot break out", () => {
    const evil = {
      ...findings[0],
      title: "evil | title `with` <script>",
      description: "Has | pipe and `code` and <img>",
    };
    const md = renderMarkdown({ scan: baseScan as any, findings: [evil] as any, kev: [], epss: [] });
    // Expect the raw `<script>` to be neutralized to entities.
    expect(md).not.toMatch(/<script>/);
    // Pipes inside title should be escaped so the row stays intact.
    expect(md).toMatch(/evil \\\| title/);
  });
});

describe("escapeMd", () => {
  it("escapes characters that could break Markdown tables", () => {
    expect(__test__.escapeMd("a|b`c")).toBe("a\\|b\\`c");
  });
  it("encodes angle brackets to mitigate accidental HTML interpretation", () => {
    expect(__test__.escapeMd("<x>")).toBe("&lt;x&gt;");
  });
  it("returns empty string for null/undefined", () => {
    expect(__test__.escapeMd(null)).toBe("");
    expect(__test__.escapeMd(undefined)).toBe("");
  });
  it("escapes emphasis markers so attacker text cannot italicize/bold", () => {
    expect(__test__.escapeMd("a*b_c")).toBe("a\\*b\\_c");
  });
  it("escapes leading-line metacharacters so headings/lists/quotes don't inject", () => {
    // CR/LF collapse to a single space, then leading-of-virtual-line
    // metachars are escaped. Note that `>` is converted to `&gt;` by the
    // angle-bracket protection (so it can never be a Markdown blockquote
    // marker either way).
    expect(__test__.escapeMd("hello\n# heading")).toBe("hello \\# heading");
    expect(__test__.escapeMd("hello\n- item")).toBe("hello \\- item");
    expect(__test__.escapeMd("hello\n> quote")).toBe("hello &gt; quote");
    expect(__test__.escapeMd("hello\n+ plus")).toBe("hello \\+ plus");
  });
  it("collapses CR/LF/CRLF to spaces so banners cannot break out of table rows", () => {
    expect(__test__.escapeMd("a\nb\r\nc\rd")).toBe("a b c d");
  });
});

describe("sanitizeHref", () => {
  const ok = __test__.sanitizeHref;
  it("accepts http and https URLs", () => {
    expect(ok("http://example.com/x")).toBe("http://example.com/x");
    expect(ok("https://nvd.nist.gov/vuln/detail/CVE-1")).toBe("https://nvd.nist.gov/vuln/detail/CVE-1");
  });
  it("rejects javascript:, data:, mailto:, ftp:, file:", () => {
    expect(ok("javascript:alert(1)")).toBeNull();
    expect(ok("data:text/html,<script>x</script>")).toBeNull();
    expect(ok("mailto:a@b.com")).toBeNull();
    expect(ok("ftp://example.com/file")).toBeNull();
    expect(ok("file:///etc/passwd")).toBeNull();
  });
  it("rejects relative paths and bare strings", () => {
    expect(ok("/etc/passwd")).toBeNull();
    expect(ok("example.com")).toBeNull();
    expect(ok("")).toBeNull();
  });
  it("rejects URLs with embedded credentials or whitespace", () => {
    expect(ok("http://user:pw@example.com")).toBeNull();
    expect(ok("http://example.com/foo bar")).toBeNull();
  });
});

describe("renderMarkdown references", () => {
  it("renders only http(s) references as links; others as escaped text", () => {
    const f = {
      ...findings[0],
      references: JSON.stringify([
        "https://example.com/a",
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "not-a-url",
      ]),
    };
    const md = renderMarkdown({ scan: baseScan as any, findings: [f] as any, kev: [], epss: [] });
    expect(md).toContain("[https://example.com/a](https://example.com/a)");
    // javascript: must NOT appear inside a link target
    expect(md).not.toMatch(/\]\(javascript:/);
    // data: must NOT appear inside a link target
    expect(md).not.toMatch(/\]\(data:/);
  });
});
