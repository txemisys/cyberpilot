import { describe, expect, it } from "vitest";
import { inventoryHttpSecurityHeaders, inspectXContentTypeOptions, inspectReferrerPolicy, inventoryCspDirectives, extractCspScriptSources, extractCspDefaultSources } from "./exposure-http";

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

describe("CSP directive inventory", () => {
  it("lists supplied directives without assessing enforcement", () => {
    expect(inventoryCspDirectives("default-src 'self'; script-src 'none'; upgrade-insecure-requests")).toEqual([
      "default-src", "script-src", "upgrade-insecure-requests",
    ]);
  });
  it("distinguishes missing input from ambiguous or invalid directives", () => {
    expect(inventoryCspDirectives(undefined)).toBeNull();
    expect(inventoryCspDirectives("   ")).toBeNull();
    expect(inventoryCspDirectives("script-src a; script-src b")).toBeNull();
    expect(inventoryCspDirectives("invalid@directive x")).toBeNull();
  });
});

describe("CSP script-src expressions", () => {
  it("extracts only explicit script-src tokens", () => {
    expect(extractCspScriptSources("default-src 'self'; script-src 'self' https://scripts.example.test")).toEqual(["'self'", "https://scripts.example.test"]);
    expect(extractCspScriptSources("script-src 'none'")).toEqual(["'none'"]);
  });
  it("returns unknown for missing, ambiguous or invalid policies", () => {
    expect(extractCspScriptSources(undefined)).toBeNull();
    expect(extractCspScriptSources("default-src 'self'")).toBeNull();
    expect(extractCspScriptSources("script-src a; script-src b")).toBeNull();
    expect(extractCspScriptSources("bad@directive a; script-src b")).toBeNull();
  });
});

describe("CSP default-src expressions", () => {
  it("extracts only explicit default-src tokens", () => {
    expect(extractCspDefaultSources("default-src 'self' https://cdn.example.test; script-src 'none'")).toEqual(["'self'", "https://cdn.example.test"]);
  });
  it("returns unknown rather than inferring defaults from absent or ambiguous directives", () => {
    expect(extractCspDefaultSources(undefined)).toBeNull();
    expect(extractCspDefaultSources("script-src 'self'")).toBeNull();
    expect(extractCspDefaultSources("default-src a; default-src b")).toBeNull();
  });
});
