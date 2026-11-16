import { describe, expect, it } from "vitest";
import {
  defaultPassiveAdmissionPolicy, validatePassivePolicy,
  planPassiveDomainTargets, checkPassiveAdmission,
  inspectPinnedAddresses, acceptPassiveDnsAnswer,
  acceptPassiveTlsAnswer, acceptPassiveHttpAnswer,
  finalizePassiveLedger, verifyPassiveLedger,
  comparePassiveLedgers,
  type PassiveCollectorRequest,
  type PassiveCollectionAttempt,
} from "./exposure-passive-collection-policy";

const organizationId = "exposure-passive-org-12345";
const domain = "example.com";
const now = "2026-11-16T08:30:00.000Z";
function request(): PassiveCollectorRequest {
  const policy = defaultPassiveAdmissionPolicy(organizationId, domain);
  const sources = ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"] as const;
  const targets = planPassiveDomainTargets(domain, [...sources]);
  return {
    schema: "cyberpilot.exposure.passive.request.v1",
    organizationId, domain,
    requestId: "passive-check-12345",
    actorUserId: "admin-12345", requestedAt: now,
    proof: {
      organizationId, domain,
      authorizationId: "proof-authorization-12345",
      authorizationRevision: 3,
      verificationMethod: "DNS_TOKEN",
      verifiedAt: "2026-11-16T08:25:00.000Z",
      expiresAt: "2026-11-16T08:45:00.000Z",
      revokedAt: null, currentState: "VERIFIED",
      actorUserId: "admin-12345",
      consentRecordId: "independent-consent-12345",
      legalConsentIndependentlyVerified: false,
    },
    policy, sources: [...sources],
    allowedDnsNames: targets.allowedDnsNames,
    allowedTlsHostnames: targets.allowedTlsHostnames,
    allowedHttpUrls: targets.allowedHttpUrls,
    explicitlyOptedIn: true,
    tokenInRequest: false,
    credentialsSupplied: false,
    activeScanningRequested: false,
  };
}
function attempt(source: PassiveCollectionAttempt["source"],
  target: string): PassiveCollectionAttempt {
  return {
    requestId: request().requestId,
    source, target, startedAt: now,
    completedAt: now, result: "OBSERVED",
    denialCode: null, bytesRead: 90,
    pinnedAddresses: source === "DNS" ? [] : ["8.8.8.8"],
    verifiedPeerAddress: source === "DNS" ? null : "8.8.8.8",
    networkCalls: 1,
    durableReservationId: "quota-reservation-12345",
    evidenceIds: ["evidence-12345"],
  };
}
describe("Phase 2 Exposure safe passive collector contract", () => {
  it("rejects network collection despite valid DNS proof without legal consent", () => {
    const req = request();
    const admission = checkPassiveAdmission(req, now);
    expect(admission.eligible).toBe(false);
    expect(admission.verifiedAuthorization).toBe(true);
    expect(admission.legalAuthorizationProven).toBe(false);
    expect(admission.issues)
      .toContain("LEGAL_SCOPE_APPROVAL_NOT_VERIFIED");
  });
  it("does not equate a revoked domain authorization with network permission", () => {
    const req = request();
    req.proof.currentState = "REVOKED";
    req.proof.revokedAt = now;
    const result = checkPassiveAdmission(req, now);
    expect(result.eligible).toBe(false);
    expect(result.issues)
      .toContain("VERIFIED_NONREVOKED_PROOF_REQUIRED");
  });
  it("prevents redirect following, active scanning and low-interval collections", () => {
    const policy = defaultPassiveAdmissionPolicy(
      organizationId, domain);
    policy.allowPortScanning = true;
    policy.minimumIntervalMs = 1000;
    expect(validatePassivePolicy(policy)).toContain(
      "FORBIDDEN_NETWORK_CAPABILITY");
    expect(validatePassivePolicy(policy)).toContain(
      "POLICY_LIMIT_minimumIntervalMs");
  });
  it("limits domain collection targets to an explicit canonical allowlist", () => {
    const allowed = planPassiveDomainTargets(domain, [
      "DNS","TLS_HANDSHAKE","HTTPS_HEADERS",
    ]);
    expect(allowed.allowedDnsNames).toEqual([
      "example.com","_dmarc.example.com",
    ]);
    expect(allowed.allowedHttpUrls).toEqual([
      "https://example.com/",
    ]);
    const req = request();
    req.allowedHttpUrls = ["http://169.254.169.254/latest"];
    expect(checkPassiveAdmission(req, now).issues)
      .toContain("ARBITRARY_COLLECTION_TARGET");
  });
  it("rejects private IP, DNS rebinding and mismatched socket peers", () => {
    expect(inspectPinnedAddresses(domain, domain,
      ["8.8.8.8"], ["8.8.8.8"], "8.8.8.8").valid)
      .toBe(true);
    expect(inspectPinnedAddresses(domain, domain,
      ["8.8.8.8"], ["1.1.1.1"], "8.8.8.8").issues)
      .toContain("DNS_REBINDING_DETECTED");
    expect(inspectPinnedAddresses(domain, domain,
      ["8.8.8.8"], ["8.8.8.8"], "127.0.0.1").valid)
      .toBe(false);
  });
  it("normalizes explicitly scoped passive DNS evidence", () => {
    const req = request();
    const observation = acceptPassiveDnsAnswer(req, {
      kind: "TXT", question: "_dmarc.example.com",
      status: "OBSERVED", records: ["v=DMARC1; p=none"],
      resolvedAddresses: ["8.8.8.8"],
      observedAt: now, resolverId: "resolver-test",
      attempts: 1, elapsedMs: 10, bytesRead: 18,
    });
    expect(observation.kind).toBe("DMARC");
    expect(observation.observedFromAuthorizedScope).toBe(true);
    expect(observation.queriedExternalNames).toEqual([]);
  });
  it("refuses DNS requests beyond allowed names", () => {
    expect(() => acceptPassiveDnsAnswer(request(), {
      kind: "TXT", question: "metadata.google.internal",
      status: "OBSERVED", records: ["secret"],
      resolvedAddresses: ["8.8.8.8"],
      observedAt: now, resolverId: "fixture",
      attempts: 1, elapsedMs: 1, bytesRead: 6,
    })).toThrow();
  });
  it("rejects unpinned HTTPS peer, body collection and credentials", () => {
    const req = request();
    const raw = {
      url: "https://example.com/",
      requestMethod: "HEAD" as const,
      pinnedAddress: "8.8.8.8",
      peerAddress: "8.8.8.8",
      status: "OBSERVED" as const, statusCode: 200,
      headers: [["strict-transport-security", "max-age=31536000"]] as
        Array<[string,string]>,
      redirectLocation: null, responseBodyBytes: 0 as const,
      redirectsFollowed: 0 as const, requestBytes: 100,
      responseHeaderBytes: 35, observedAt: now, durationMs: 100,
      cookiesSent: false as const, credentialsSent: false as const,
      verifiedRemotePeer: true,
    };
    expect(acceptPassiveHttpAnswer(req, raw, [
      "8.8.8.8",
    ], ["8.8.8.8"]).bodyCollected).toBe(false);
    expect(() => acceptPassiveHttpAnswer(req, {
      ...raw, peerAddress: "127.0.0.1",
    }, ["8.8.8.8"], ["8.8.8.8"])).toThrow();
  });
  it("validates passive TLS observation only when peer is pinned", () => {
    const result = acceptPassiveTlsAnswer(request(), {
      host: domain, address: "8.8.8.8", port: 443,
      status: "OBSERVED",
      version: "TLSv1.3", certificatePresent: true,
      notBefore: null, notAfter: null,
      certificateDnsNames: ["example.com"],
      trustedByTLSClient: true,
      observedAt: now, elapsedMs: 50,
      errorCode: null, verifiedPeerAddress: "8.8.8.8",
      handshakeOnly: true,
    }, ["8.8.8.8"], ["8.8.8.8"]);
    expect(result.remoteAddress).toBe("8.8.8.8");
    expect(result.port).toBe(443);
  });
  it("builds SHA-bound ledger preserving unknown failures", () => {
    const req = request();
    const entry = attempt("DNS", "example.com");
    const ledger = finalizePassiveLedger(req, [entry],
      [], [], [], "2026-11-16T08:31:00.000Z");
    expect(ledger.manifest.totalNetworkCalls).toBe(1);
    expect(ledger.manifest.unknown).toContain("TLS_HANDSHAKE");
    expect(verifyPassiveLedger(ledger, organizationId).valid)
      .toBe(true);
    ledger.manifest.totalNetworkCalls = 999;
    expect(verifyPassiveLedger(ledger).valid).toBe(false);
  });
  it("rejects cross-tenant and reverse-time report comparisons", () => {
    const req = request();
    const a = finalizePassiveLedger(req, [], [], [], [],
      "2026-11-16T08:30:30.000Z");
    const b = finalizePassiveLedger(req, [], [], [], [],
      "2026-11-16T08:30:50.000Z");
    expect(comparePassiveLedgers(a, b)
      .riskReductionProven).toBe(false);
    expect(() => comparePassiveLedgers(b, a)).toThrow();
    expect(verifyPassiveLedger(a, "foreign-tenant-12345")
      .valid).toBe(false);
  });
});
