import { describe, it, expect } from "vitest";
import { parsePortList, profilePorts, QUICK_PORTS, STANDARD_PORTS, WEB_PORTS } from "./ports";

describe("parsePortList", () => {
  it("parses comma-separated ports", () => {
    expect(parsePortList("22,80,443")).toEqual([22, 80, 443]);
  });

  it("ignores extra whitespace", () => {
    expect(parsePortList(" 22 , 80,  443 ")).toEqual([22, 80, 443]);
  });

  it("expands ranges", () => {
    expect(parsePortList("80-82")).toEqual([80, 81, 82]);
  });

  it("merges and dedupes", () => {
    expect(parsePortList("80,80-82,443")).toEqual([80, 81, 82, 443]);
  });

  it("rejects shell metacharacters", () => {
    expect(() => parsePortList("80;rm -rf /")).toThrow();
    expect(() => parsePortList("80 || curl evil.com")).toThrow();
    expect(() => parsePortList("$(whoami)")).toThrow();
    expect(() => parsePortList("`id`")).toThrow();
  });

  it("rejects out-of-bounds ports", () => {
    expect(() => parsePortList("0")).toThrow();
    expect(() => parsePortList("65536")).toThrow();
    expect(() => parsePortList("-1")).toThrow();
  });

  it("rejects ranges that exceed the per-range cap", () => {
    expect(() => parsePortList("1-1000")).toThrow();
  });

  it("rejects too-many ports overall", () => {
    const big = Array.from({ length: 250 }, (_, i) => i + 100).join(",");
    expect(() => parsePortList(big)).toThrow();
  });

  it("rejects empty input", () => {
    expect(() => parsePortList("")).toThrow();
    expect(() => parsePortList("   ")).toThrow();
  });

  it("rejects invalid range format", () => {
    expect(() => parsePortList("80-")).toThrow();
    expect(() => parsePortList("a-b")).toThrow();
    expect(() => parsePortList("100-50")).toThrow();
  });
});

describe("profilePorts", () => {
  it("returns the quick list for `quick`", () => {
    expect(profilePorts("quick")).toEqual(QUICK_PORTS);
  });
  it("returns the standard list for `standard`", () => {
    expect(profilePorts("standard")).toEqual(STANDARD_PORTS);
  });
  it("returns the web list for `web`", () => {
    expect(profilePorts("web")).toEqual(WEB_PORTS);
  });
  it("requires customPorts when profile is custom", () => {
    expect(() => profilePorts("custom")).toThrow();
    expect(profilePorts("custom", "22")).toEqual([22]);
  });
  it("rejects unknown profile names", () => {
    expect(() => profilePorts("bogus")).toThrow();
  });
});
