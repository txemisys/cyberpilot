import { describe, expect, it } from "vitest";
import { inventoryHttpSecurityHeaders, inspectReferrerPolicy, extractCspScriptSources } from "./exposure-http";
import { extractHstsMaxAge, inspectHstsFlags } from "./exposure-hsts";
import { inspectRedirect, inventoryResponseHeaders } from "./exposure-http-observation";
import { validateExposureEvidence } from "./exposure-evidence";
import { inventoryTlsCertificate } from "./exposure-tls";
import { tlsNameMatches } from "./exposure-tls-names";

describe("combined Exposure HTTP/TLS evidence boundary", () => {
  it("allows collected response evidence without certifying security posture", () => {
    const observedAt = "2026-10-29T00:00:00Z";
    const headers = {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'; script-src 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    };
    const scoped = validateExposureEvidence("tenant-a", {
      tenantId: "tenant-a", source: "OBSERVED", collectedAt: observedAt, payload: headers,
    });
    expect(scoped.state).toBe("PRESENT");
    expect(inventoryHttpSecurityHeaders(headers).contentSecurityPolicy).toBe("PRESENT");
    expect(extractHstsMaxAge(headers["Strict-Transport-Security"])).toBe(31536000);
    expect(inspectHstsFlags(headers["Strict-Transport-Security"])?.includeSubDomains).toBe(true);
    expect(extractCspScriptSources(headers["Content-Security-Policy"])).toEqual(["'none'"]);
    expect(inspectReferrerPolicy(headers["Referrer-Policy"])).toBe("strict-origin-when-cross-origin");
    expect(inventoryResponseHeaders(Object.entries(headers)).duplicateNames).toEqual([]);
    expect(inspectRedirect({ status: 301, url: "https://example.test/", location: "/new" }).state).toBe("VALID_TARGET");
    expect(inventoryTlsCertificate({}, observedAt).validity).toBe("UNKNOWN");
    expect(tlsNameMatches("example.test", null)).toBe("UNKNOWN");
  });
  it("fails closed on cross-tenant data even when the underlying observation is valid", () => {
    const result = validateExposureEvidence("tenant-b", {
      tenantId: "tenant-a", source: "OBSERVED", collectedAt: "2026-10-29T00:00:00Z", payload: { token: "private" },
    });
    expect(result.state).toBe("FOREIGN_TENANT");
    expect(JSON.stringify(result)).not.toContain("private");
  });
});
