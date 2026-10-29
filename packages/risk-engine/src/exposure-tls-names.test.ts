import { describe, expect, it } from "vitest";
import { normalizeTlsDnsNames, tlsNameMatches, inspectTlsTransport } from "./exposure-tls-names";
describe("passive TLS SAN and transport metadata", () => {
  it("normalizes case, trailing dot, duplicates and sorts", () => {
    expect(normalizeTlsDnsNames(["B.EXAMPLE.TEST.", "a.example.test", "b.example.test"])).toEqual(["a.example.test", "b.example.test"]);
    expect(normalizeTlsDnsNames(null)).toBeNull();
    expect(normalizeTlsDnsNames([])).toEqual([]);
  });
  it("rejects invalid host labels", () => {
    expect(normalizeTlsDnsNames(["bad..example.test"])).toBeNull();
    expect(normalizeTlsDnsNames(["-bad.example.test"])).toBeNull();
    expect(normalizeTlsDnsNames(["a".repeat(64) + ".example.test"])).toBeNull();
  });
  it("matches names exactly and only single-label wildcards", () => {
    expect(tlsNameMatches("EXAMPLE.TEST", ["example.test"])).toBe("MATCH");
    expect(tlsNameMatches("a.example.test", ["*.example.test"])).toBe("MATCH");
    expect(tlsNameMatches("b.a.example.test", ["*.example.test"])).toBe("NO_MATCH");
    expect(tlsNameMatches("example.test", ["*.example.test"])).toBe("NO_MATCH");
    expect(tlsNameMatches("example.test", null)).toBe("UNKNOWN");
    expect(tlsNameMatches("bad..name", ["example.test"])).toBe("UNKNOWN");
  });
  it("keeps declared metadata separate from verified connection state", () => {
    expect(inspectTlsTransport({})).toEqual({
      version: null, cipher: null, handshakeVerified: "UNKNOWN", inconsistent: false,
    });
    expect(inspectTlsTransport({ version: " TLSv1.3 ", cipher: " TLS_AES_128_GCM_SHA256 ", handshakeVerified: true })).toEqual({
      version: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", handshakeVerified: "TRUE", inconsistent: false,
    });
    expect(inspectTlsTransport({ handshakeVerified: true }).inconsistent).toBe(true);
    expect(inspectTlsTransport({ handshakeVerified: false }).handshakeVerified).toBe("FALSE");
  });
});
