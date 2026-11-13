import { describe, expect, it } from "vitest";
import { sha256V2 } from "@cyberpilot/risk-engine";
import {
  verifyExposureDnsProof, classifyExposureProofForPersisting,
  summarizeExposureDnsProof,
  type ExposureDnsProofInput, type ExposureProofResolver,
} from "./exposure-dns-proof";
const organizationId = "dns-proof-org-12345";
const domain = "example.com";
const token = "a".repeat(64);
const checkedAt = "2026-11-13T14:10:00.000Z";
function input(): ExposureDnsProofInput {
  return {
    organizationId, domain, token, method: "DNS_TOKEN",
    challengeDigest: sha256V2(
      organizationId + "\u0000" + domain + "\u0000DNS_TOKEN\u0000" + token),
    expiresAt: "2026-11-13T14:30:00.000Z", checkedAt,
  };
}
function resolver(records: string[][]): ExposureProofResolver & {
  observedNames: string[];
} {
  const observedNames: string[] = [];
  return {
    observedNames,
    async resolveTxt(host) {
      observedNames.push(host);
      return records;
    },
  };
}
describe("independently collected DNS TXT proof without HTTP scanning", () => {
  it("requires an exact published token at the predetermined domain name", async () => {
    const dns = resolver([["cyberpilot-domain-verification=", token]]);
    const result = await verifyExposureDnsProof(input(), dns);
    expect(dns.observedNames).toEqual([
      "_cyberpilot-verification.example.com",
    ]);
    expect(result.state).toBe("MATCH");
    expect(result.networkQueriesPerformed).toBe(1);
    expect(result.activePortScanningPerformed).toBe(0);
    expect(result.httpRequestsPerformed).toBe(0);
    expect(result.responseDigest).toMatch(/^[a-f0-9]{64}$/);
    const classification = classifyExposureProofForPersisting(result);
    expect(classification.status).toBe("VERIFIED");
    expect(classification.externalConsentProven).toBe(false);
    expect(summarizeExposureDnsProof(result)
      .verifiedOrganizationWideSecurity).toBe(false);
  });
  it("rejects a user-submitted token inconsistent with server digest", async () => {
    const dns = resolver([["cyberpilot-domain-verification=", token]]);
    const invalid = input();
    invalid.token = "b".repeat(64);
    const result = await verifyExposureDnsProof(invalid, dns);
    expect(result.state).toBe("INVALID_CHALLENGE");
    expect(result.networkQueriesPerformed).toBe(0);
    expect(dns.observedNames).toEqual([]);
  });
  it("does not query an expired challenge", async () => {
    const dns = resolver([["cyberpilot-domain-verification=", token]]);
    const expired = input();
    expired.checkedAt = "2026-11-13T15:00:00.000Z";
    const result = await verifyExposureDnsProof(expired, dns);
    expect(result.state).toBe("EXPIRED");
    expect(dns.observedNames).toEqual([]);
  });
  it("treats unrelated records as no proof", async () => {
    const dns = resolver([["v=spf1 -all"]]);
    const result = await verifyExposureDnsProof(input(), dns);
    expect(result.state).toBe("MISSING");
    expect(result.challengeMatched).toBe(false);
  });
  it("detects ambiguous duplicate challenge records", async () => {
    const value = "cyberpilot-domain-verification=" + token;
    const result = await verifyExposureDnsProof(input(),
      resolver([[value], [value]]));
    expect(result.state).toBe("AMBIGUOUS");
  });
  it("enforces upper bounds on TXT output without leaking original records", async () => {
    const dns = resolver([["x".repeat(10000)]]);
    const result = await verifyExposureDnsProof(input(), dns);
    expect(result.state).toBe("OVERSIZED");
    expect(result.responseDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(result)).not.toContain("x".repeat(100));
  });
  it("returns DNS_ERROR on a resolver exception", async () => {
    const failing: ExposureProofResolver = {
      async resolveTxt() { throw Error("EAI_AGAIN"); },
    };
    const result = await verifyExposureDnsProof(input(), failing);
    expect(result.state).toBe("DNS_ERROR");
    expect(result.networkQueriesPerformed).toBe(1);
  });
  it("times out and cancels the resolver", async () => {
    let cancelled = false;
    const pending: ExposureProofResolver = {
      resolveTxt: async () => new Promise<string[][]>(() => {}),
      cancel: () => { cancelled = true; },
    };
    const result = await verifyExposureDnsProof(input(), pending, {
      timeoutMs: 250,
      maxTxtRecords: 20, maxTxtBytes: 8192,
      maxDomainCharacters: 253,
      requireExactToken: true,
      allowRedirects: false, allowUnrelatedDomains: false,
    });
    expect(result.state).toBe("TIMEOUT");
    expect(cancelled).toBe(true);
    expect(result.networkQueriesPerformed).toBe(1);
  });
  it("forbids arbitrary names even when they hold a matching token", async () => {
    const dns = resolver([["cyberpilot-domain-verification=", token]]);
    const invalid = input();
    invalid.domain = "localhost";
    const result = await verifyExposureDnsProof(invalid, dns);
    expect(result.state).toBe("INVALID_CHALLENGE");
    expect(dns.observedNames).toEqual([]);
  });
});
