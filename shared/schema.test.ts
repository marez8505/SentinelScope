import { describe, it, expect } from "vitest";
import {
  targetSchema,
  newScanRequestSchema,
  portsArraySchema,
  classifyIp,
  RESTRICTED_TARGET_CLASSES,
} from "./schema";

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

describe("newScanRequestSchema allowPrivate", () => {
  it("omits allowPrivate by default", () => {
    const r = newScanRequestSchema.parse({
      target: "example.com",
      profile: "quick",
      authorizedAck: true,
    });
    expect(r.allowPrivate).toBeUndefined();
  });
  it("accepts allowPrivate=true", () => {
    const r = newScanRequestSchema.parse({
      target: "example.com",
      profile: "quick",
      authorizedAck: true,
      allowPrivate: true,
    });
    expect(r.allowPrivate).toBe(true);
  });
  it("rejects allowPrivate=false (must be true if provided)", () => {
    expect(() =>
      newScanRequestSchema.parse({
        target: "example.com",
        profile: "quick",
        authorizedAck: true,
        allowPrivate: false,
      }),
    ).toThrow();
  });
});

describe("classifyIp", () => {
  it("classifies IPv4 loopback", () => {
    expect(classifyIp("127.0.0.1")).toBe("loopback");
    expect(classifyIp("127.0.0.5")).toBe("loopback");
  });
  it("classifies IPv4 RFC 1918 private ranges", () => {
    expect(classifyIp("10.0.0.1")).toBe("private");
    expect(classifyIp("192.168.1.1")).toBe("private");
    expect(classifyIp("172.16.0.1")).toBe("private");
    expect(classifyIp("172.31.255.254")).toBe("private");
  });
  it("classifies the boundaries of 172.16/12", () => {
    expect(classifyIp("172.15.0.1")).toBe("public"); // just outside
    expect(classifyIp("172.32.0.1")).toBe("public"); // just outside
  });
  it("classifies link-local IPv4 (169.254/16)", () => {
    expect(classifyIp("169.254.169.254")).toBe("link-local");
  });
  it("classifies CGNAT IPv4 (100.64/10)", () => {
    expect(classifyIp("100.64.0.1")).toBe("cgnat");
    expect(classifyIp("100.127.255.254")).toBe("cgnat");
    expect(classifyIp("100.63.0.1")).toBe("public");
    expect(classifyIp("100.128.0.1")).toBe("public");
  });
  it("classifies multicast and reserved IPv4", () => {
    expect(classifyIp("224.0.0.1")).toBe("multicast");
    expect(classifyIp("239.255.255.255")).toBe("multicast");
    expect(classifyIp("240.0.0.1")).toBe("reserved");
    expect(classifyIp("0.0.0.0")).toBe("reserved");
  });
  it("classifies public IPv4", () => {
    expect(classifyIp("8.8.8.8")).toBe("public");
    expect(classifyIp("1.1.1.1")).toBe("public");
  });
  it("classifies IPv6 loopback", () => {
    expect(classifyIp("::1")).toBe("loopback");
    expect(classifyIp("[::1]")).toBe("loopback");
    expect(classifyIp("0:0:0:0:0:0:0:1")).toBe("loopback");
  });
  it("classifies IPv6 link-local (fe80::/10)", () => {
    expect(classifyIp("fe80::1")).toBe("link-local");
    expect(classifyIp("fe80::1%eth0")).toBe("link-local"); // zone id stripped
    expect(classifyIp("feb0::1")).toBe("link-local");
  });
  it("classifies IPv6 unique-local (fc00::/7)", () => {
    expect(classifyIp("fc00::1")).toBe("private");
    expect(classifyIp("fd12:3456:789a::1")).toBe("private");
  });
  it("classifies IPv6 multicast (ff00::/8)", () => {
    expect(classifyIp("ff02::1")).toBe("multicast");
  });
  it("classifies IPv4-mapped IPv6 by the embedded address", () => {
    expect(classifyIp("::ffff:127.0.0.1")).toBe("loopback");
    expect(classifyIp("::ffff:10.0.0.1")).toBe("private");
    expect(classifyIp("::ffff:8.8.8.8")).toBe("public");
  });
  it("classifies public IPv6", () => {
    expect(classifyIp("2001:4860:4860::8888")).toBe("public");
  });
  it("returns unknown on garbage", () => {
    expect(classifyIp("")).toBe("unknown");
    expect(classifyIp("not an ip")).toBe("unknown");
  });
  it("flags the right classes as restricted", () => {
    for (const c of [
      "loopback",
      "link-local",
      "private",
      "cgnat",
      "multicast",
      "reserved",
    ] as const) {
      expect(RESTRICTED_TARGET_CLASSES.has(c)).toBe(true);
    }
    expect(RESTRICTED_TARGET_CLASSES.has("public")).toBe(false);
    expect(RESTRICTED_TARGET_CLASSES.has("unknown")).toBe(false);
  });
});
