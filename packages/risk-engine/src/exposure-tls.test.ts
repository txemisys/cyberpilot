import { describe, expect, it } from "vitest";
import { inventoryTlsCertificate } from "./exposure-tls";
const observed = "2026-10-29T00:00:00Z";
describe("passive TLS certificate inventory", () => {
  it("keeps absent validity dates unknown", () => {
    expect(inventoryTlsCertificate({}, observed)).toEqual({
      validity: "UNKNOWN", daysUntilExpiry: null, hasSubject: false, hasIssuer: false, dnsNameCount: null,
    });
  });
  it("reports temporal certificate validity without assuming trust", () => {
    const value = inventoryTlsCertificate({
      notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-10-30T00:00:00Z",
      subject: " CN=example.test ", issuer: " CN=Example CA ", dnsNames: ["example.test"],
    }, observed);
    expect(value).toEqual({
      validity: "VALID_AT_OBSERVATION", daysUntilExpiry: 1, hasSubject: true, hasIssuer: true, dnsNameCount: 1,
    });
  });
  it.each([
    ["2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z", "NOT_YET_VALID"],
    ["2026-01-01T00:00:00Z", "2026-10-28T00:00:00Z", "EXPIRED"],
    ["2026-12-01T00:00:00Z", "2026-01-01T00:00:00Z", "INVALID_DATES"],
    ["bad date", "2026-12-01T00:00:00Z", "INVALID_DATES"],
    ["2026-01-01T00:00:00Z", "bad date", "INVALID_DATES"],
  ] as const)("classifies %s to %s as %s", (notBefore, notAfter, expected) => {
    expect(inventoryTlsCertificate({ notBefore, notAfter }, observed).validity).toBe(expected);
  });
  it("treats a missing observation timestamp as invalid evidence", () => {
    expect(inventoryTlsCertificate({
      notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-12-01T00:00:00Z",
    }, "unknown").validity).toBe("INVALID_DATES");
  });
  it("does not invent DNS names when not collected", () => {
    expect(inventoryTlsCertificate({ dnsNames: [] }, observed).dnsNameCount).toBe(0);
    expect(inventoryTlsCertificate({ dnsNames: null }, observed).dnsNameCount).toBeNull();
  });
});
