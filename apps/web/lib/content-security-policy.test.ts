import { describe, expect, it } from "vitest";

import {
  buildContentSecurityPolicy,
  normalizeCspReportUri,
} from "./content-security-policy";

describe("content security policy", () => {
  it("builds the production report-only baseline", () => {
    const policy = buildContentSecurityPolicy();

    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).toContain("connect-src 'self'");
    expect(policy).not.toContain("report-uri");
  });

  it("accepts a relative or HTTPS report destination", () => {
    expect(normalizeCspReportUri("/api/csp-report")).toBe("/api/csp-report");
    expect(normalizeCspReportUri("https://collector.example/csp")).toBe(
      "https://collector.example/csp",
    );

    expect(
      buildContentSecurityPolicy("https://collector.example/csp"),
    ).toContain("report-uri https://collector.example/csp");
  });

  it("rejects insecure or header-injection report destinations", () => {
    expect(normalizeCspReportUri("http://collector.example/csp")).toBeUndefined();
    expect(normalizeCspReportUri("//collector.example/csp")).toBeUndefined();
    expect(
      normalizeCspReportUri("https://collector.example/csp; script-src *"),
    ).toBeUndefined();
    expect(
      normalizeCspReportUri("https://collector.example/csp\nX-Test: bad"),
    ).toBeUndefined();
  });
});
