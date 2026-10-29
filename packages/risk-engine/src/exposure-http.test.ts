import { describe, expect, it } from "vitest";
import { inventoryHttpSecurityHeaders, inspectXContentTypeOptions, inspectReferrerPolicy } from "./exposure-http";

describe("passive HTTP security header inventory", () => {
  it("returns missing for unavailable headers", () => {
    expect(inventoryHttpSecurityHeaders({})).toEqual({
      strictTransportSecurity: "MISSING",
      contentSecurityPolicy: "MISSING",
      xContentTypeOptions: "MISSING",
      referrerPolicy: "MISSING",
    });
  });
  it("recognizes header names without regard to case", () => {
    expect(inventoryHttpSecurityHeaders({
      "Strict-Transport-Security": "max-age=31536000",
      "CONTENT-SECURITY-POLICY": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin",
    })).toEqual({
      strictTransportSecurity: "PRESENT",
      contentSecurityPolicy: "PRESENT",
      xContentTypeOptions: "PRESENT",
      referrerPolicy: "PRESENT",
    });
  });
  it("never treats blank values as evidence of configuration", () => {
    expect(inventoryHttpSecurityHeaders({ "Content-Security-Policy": "  " }).contentSecurityPolicy).toBe("MISSING");
  });
});

describe("X-Content-Type-Options value", () => {
  it("accepts only the nosniff token", () => {
    expect(inspectXContentTypeOptions(" NoSniff ")).toBe("NOSNIFF");
    expect(inspectXContentTypeOptions("nosniff, nosniff")).toBe("INVALID");
    expect(inspectXContentTypeOptions("invalid")).toBe("INVALID");
  });
  it("keeps absent and blank headers separate from invalid values", () => {
    expect(inspectXContentTypeOptions(undefined)).toBe("MISSING");
    expect(inspectXContentTypeOptions("  ")).toBe("MISSING");
  });
});

describe("Referrer-Policy fallback tokens", () => {
  it("selects the final recognized policy", () => {
    expect(inspectReferrerPolicy("no-referrer, strict-origin-when-cross-origin")).toBe("strict-origin-when-cross-origin");
    expect(inspectReferrerPolicy("unknown, SAME-ORIGIN")).toBe("same-origin");
  });
  it("does not treat unknown or empty tokens as configured", () => {
    expect(inspectReferrerPolicy("unknown")).toBeNull();
    expect(inspectReferrerPolicy("")).toBeNull();
    expect(inspectReferrerPolicy(undefined)).toBeNull();
  });
});
