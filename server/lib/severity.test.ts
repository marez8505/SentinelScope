import { describe, it, expect } from "vitest";
import { severityFromCvss, effectiveSeverity, prioritizeFindings, severityCounts } from "./severity";

describe("severityFromCvss", () => {
  it("maps score buckets correctly", () => {
    expect(severityFromCvss(10)).toBe("critical");
    expect(severityFromCvss(9.0)).toBe("critical");
    expect(severityFromCvss(8.9)).toBe("high");
    expect(severityFromCvss(7.0)).toBe("high");
    expect(severityFromCvss(5.5)).toBe("medium");
    expect(severityFromCvss(4.0)).toBe("medium");
    expect(severityFromCvss(3.9)).toBe("low");
    expect(severityFromCvss(0.1)).toBe("low");
    expect(severityFromCvss(0)).toBe("info");
    expect(severityFromCvss(null)).toBe("info");
    expect(severityFromCvss(undefined)).toBe("info");
  });
});

describe("effectiveSeverity", () => {
  it("KEV bumps to critical", () => {
    expect(effectiveSeverity({ base: "low", isKev: true })).toBe("critical");
  });
  it("EPSS over 0.5 bumps low to high", () => {
    expect(effectiveSeverity({ base: "low", epss: 0.6 })).toBe("high");
  });
  it("EPSS between 0.1 and 0.5 bumps low to medium", () => {
    expect(effectiveSeverity({ base: "low", epss: 0.2 })).toBe("medium");
  });
  it("EPSS does not downgrade", () => {
    expect(effectiveSeverity({ base: "critical", epss: 0.01 })).toBe("critical");
  });
});

describe("prioritizeFindings", () => {
  const sample = [
    { severity: "low", cvssScore: 3, _id: "low-no-kev" },
    { severity: "high", cvssScore: 8, _id: "high-no-kev" },
    { severity: "low", cvssScore: 3, _id: "low-with-kev", cves: ["CVE-2021-44228"] },
  ];

  it("sorts by KEV first, then severity, then CVSS", () => {
    const sorted = prioritizeFindings(
      sample as any,
      new Set(["CVE-2021-44228"]),
      (r: any) => r.cves ?? [],
    );
    expect((sorted[0] as any)._id).toBe("low-with-kev");
    expect((sorted[1] as any)._id).toBe("high-no-kev");
    expect((sorted[2] as any)._id).toBe("low-no-kev");
  });

  it("works with no KEV info", () => {
    const sorted = prioritizeFindings(sample as any);
    expect(sorted[0].severity).toBe("high");
  });
});

describe("severityCounts", () => {
  it("counts by severity", () => {
    expect(severityCounts([{ severity: "high" }, { severity: "high" }, { severity: "low" }])).toEqual({
      critical: 0,
      high: 2,
      medium: 0,
      low: 1,
      info: 0,
    });
  });
});
