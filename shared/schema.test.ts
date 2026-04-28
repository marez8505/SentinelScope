import { describe, it, expect } from "vitest";
import { targetSchema, newScanRequestSchema, portsArraySchema } from "./schema";

describe("targetSchema", () => {
  it("accepts hostnames", () => {
    expect(targetSchema.parse("example.com")).toBe("example.com");
    expect(targetSchema.parse("sub.example.co.uk")).toBe("sub.example.co.uk");
  });

  it("accepts IPv4", () => {
    expect(targetSchema.parse("192.168.1.10")).toBe("192.168.1.10");
  });

  it("accepts IPv6 with or without brackets", () => {
    expect(targetSchema.parse("[::1]")).toBe("::1");
    expect(targetSchema.parse("fe80::1")).toBe("fe80::1");
  });

  it("rejects URLs and schemes", () => {
    expect(() => targetSchema.parse("http://example.com")).toThrow();
    expect(() => targetSchema.parse("https://example.com/admin")).toThrow();
    expect(() => targetSchema.parse("file:///etc/passwd")).toThrow();
  });

  it("rejects credentials and path/query characters", () => {
    expect(() => targetSchema.parse("user:pass@example.com")).toThrow();
    expect(() => targetSchema.parse("example.com/admin")).toThrow();
    expect(() => targetSchema.parse("example.com?a=1")).toThrow();
    expect(() => targetSchema.parse("example.com#frag")).toThrow();
  });

  it("rejects whitespace and shell metacharacters", () => {
    expect(() => targetSchema.parse("example.com ; rm")).toThrow();
    expect(() => targetSchema.parse("$(id)")).toThrow();
    expect(() => targetSchema.parse("a b")).toThrow();
  });

  it("rejects empty input", () => {
    expect(() => targetSchema.parse("")).toThrow();
  });
});

describe("newScanRequestSchema", () => {
  it("requires the authorized acknowledgment", () => {
    expect(() =>
      newScanRequestSchema.parse({
        target: "example.com",
        profile: "quick",
        authorizedAck: false,
      }),
    ).toThrow();
  });

  it("accepts a quick scan with ack", () => {
    const r = newScanRequestSchema.parse({
      target: "example.com",
      profile: "quick",
      authorizedAck: true,
    });
    expect(r.profile).toBe("quick");
  });

  it("rejects unknown profiles", () => {
    expect(() =>
      newScanRequestSchema.parse({
        target: "example.com",
        profile: "stealth",
        authorizedAck: true,
      }),
    ).toThrow();
  });
});

describe("portsArraySchema", () => {
  it("accepts a small list", () => {
    expect(portsArraySchema.parse([22, 80, 443])).toEqual([22, 80, 443]);
  });
  it("rejects out-of-range ports", () => {
    expect(() => portsArraySchema.parse([0])).toThrow();
    expect(() => portsArraySchema.parse([70000])).toThrow();
  });
  it("rejects empty arrays", () => {
    expect(() => portsArraySchema.parse([])).toThrow();
  });
});
