import { describe, it, expect } from "vitest";
import { isPrivateLikeText, shouldDisableStart } from "./newScanGating";

/**
 * Default args representing a "happy path" submit attempt: the operator has
 * acknowledged authorization, entered a public target, picked a non-custom
 * profile, and nothing is in flight. Each test overrides only the fields it
 * cares about so the intent of each case is obvious from the diff.
 */
const baseArgs = {
  authorizedAck: true,
  target: "example.com",
  profile: "standard",
  customPorts: "",
  allowPrivate: false,
  isPending: false,
} as const;

describe("isPrivateLikeText", () => {
  it("flags localhost forms", () => {
    expect(isPrivateLikeText("localhost")).toBe(true);
    expect(isPrivateLikeText("dev.localhost")).toBe(true);
    expect(isPrivateLikeText("printer.local")).toBe(true);
    expect(isPrivateLikeText("svc.internal")).toBe(true);
    expect(isPrivateLikeText("nas.lan")).toBe(true);
  });

  it("flags IPv4 loopback / RFC1918 / link-local / CGNAT / 0.0.0.0", () => {
    expect(isPrivateLikeText("127.0.0.1")).toBe(true);
    expect(isPrivateLikeText("127.5.5.5")).toBe(true);
    expect(isPrivateLikeText("10.0.0.1")).toBe(true);
    expect(isPrivateLikeText("192.168.1.5")).toBe(true);
    expect(isPrivateLikeText("172.16.0.1")).toBe(true);
    expect(isPrivateLikeText("172.31.255.254")).toBe(true);
    expect(isPrivateLikeText("169.254.1.1")).toBe(true);
    expect(isPrivateLikeText("100.64.0.1")).toBe(true);
    expect(isPrivateLikeText("0.0.0.0")).toBe(true);
  });

  it("flags IPv6 loopback / link-local / unique-local", () => {
    expect(isPrivateLikeText("::1")).toBe(true);
    expect(isPrivateLikeText("0:0:0:0:0:0:0:1")).toBe(true);
    expect(isPrivateLikeText("fe80::1")).toBe(true);
    expect(isPrivateLikeText("fc00::1")).toBe(true);
    expect(isPrivateLikeText("fd12:3456:789a::1")).toBe(true);
    // bracketed forms (URL-style) should still be detected
    expect(isPrivateLikeText("[::1]")).toBe(true);
  });

  it("does NOT flag obviously public targets", () => {
    expect(isPrivateLikeText("")).toBe(false);
    expect(isPrivateLikeText("example.com")).toBe(false);
    expect(isPrivateLikeText("scanme.nmap.org")).toBe(false);
    expect(isPrivateLikeText("8.8.8.8")).toBe(false);
    expect(isPrivateLikeText("172.32.0.1")).toBe(false); // just outside 172.16/12
    expect(isPrivateLikeText("172.15.0.1")).toBe(false); // just outside 172.16/12
    expect(isPrivateLikeText("100.63.255.255")).toBe(false); // just outside CGNAT
    expect(isPrivateLikeText("100.128.0.1")).toBe(false); // just outside CGNAT
  });
});

describe("shouldDisableStart", () => {
  it("is enabled for a public target with all required acknowledgements", () => {
    expect(shouldDisableStart({ ...baseArgs })).toBe(false);
  });

  it("is disabled when the primary authorized-use box is unchecked", () => {
    expect(shouldDisableStart({ ...baseArgs, authorizedAck: false })).toBe(true);
  });

  it("is disabled when no target is entered", () => {
    expect(shouldDisableStart({ ...baseArgs, target: "" })).toBe(true);
  });

  it("is disabled when the custom profile has no port list", () => {
    expect(
      shouldDisableStart({ ...baseArgs, profile: "custom", customPorts: "" }),
    ).toBe(true);
  });

  it("is enabled for the custom profile when ports are provided", () => {
    expect(
      shouldDisableStart({ ...baseArgs, profile: "custom", customPorts: "22,80-90" }),
    ).toBe(false);
  });

  it("is disabled when a scan request is already in flight", () => {
    expect(shouldDisableStart({ ...baseArgs, isPending: true })).toBe(true);
  });

  // ---- The new rule: mirror the server's allowPrivate gate in the UI ----

  it.each([
    "127.0.0.1",
    "localhost",
    "192.168.1.5",
    "10.0.0.1",
    "169.254.1.1",
    "fe80::1",
    "[::1]",
    "fd12:3456:789a::1",
    "100.64.0.1",
  ])(
    "is disabled for private-like target %s when allowPrivate is unchecked",
    (target) => {
      expect(shouldDisableStart({ ...baseArgs, target, allowPrivate: false })).toBe(true);
    },
  );

  it.each([
    "127.0.0.1",
    "localhost",
    "192.168.1.5",
    "fe80::1",
    "[::1]",
  ])(
    "is enabled for private-like target %s when allowPrivate is checked (and other gates pass)",
    (target) => {
      expect(shouldDisableStart({ ...baseArgs, target, allowPrivate: true })).toBe(false);
    },
  );

  it("does not require allowPrivate for public targets", () => {
    expect(
      shouldDisableStart({ ...baseArgs, target: "scanme.nmap.org", allowPrivate: false }),
    ).toBe(false);
  });

  it("still respects the authorizedAck gate even with allowPrivate checked on a private target", () => {
    expect(
      shouldDisableStart({
        ...baseArgs,
        target: "127.0.0.1",
        allowPrivate: true,
        authorizedAck: false,
      }),
    ).toBe(true);
  });
});
