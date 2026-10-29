import { describe, expect, it } from "vitest";
import { inventoryHttpSecurityHeaders } from "./exposure-http";

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
