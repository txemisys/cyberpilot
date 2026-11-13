import { describe, expect, it } from "vitest";
import {
  prepareExposureAuthorizationChallenge,
  validateExposureAuthorizationRequest,
  evaluateExposureAuthorization,
  verifyExposureAuthorizationDecision,
  buildExposureTargetPolicy, inspectExposureRedirect,
  planExposureCollectionQuota, verifyExposureCollectionBudget,
  type ExposureAuthorizationRequest,
  type ExposureVerificationEvidence,
} from "./exposure-domain-authorization";
const organizationId = "proof-tenant-12345";
const issuedAt = "2026-11-13T14:00:00.000Z";
const checkedAt = "2026-11-13T14:10:00.000Z";
const token = "a".repeat(64);
function request(): ExposureAuthorizationRequest {
  return {
    schema: "cyberpilot.exposure.domain.authorization.request.v1",
    organizationId, domain: "example.com", method: "DNS_TOKEN",
    token, issuedAt, expiresAt: "2026-11-13T14:30:00.000Z",
    issuedBy: "owner-12345", purpose: "PASSIVE_EXTERNAL_OBSERVATION",
    allowActivePortScanning: false,
    allowSubdomainEnumeration: false,
    allowThirdPartyHost: false,
  };
}
function evidence(): ExposureVerificationEvidence {
  const challenge = prepareExposureAuthorizationChallenge(request());
  return {
    schema: "cyberpilot.exposure.authorization.evidence.v1",
    organizationId, domain: "example.com", method: "DNS_TOKEN",
    requestedName: challenge.expectedName,
    observedValues: [challenge.expectedValue],
    observedAt: checkedAt, collectionStatus: "COMPLETE",
    collectorTrusted: true, networkOriginVerified: true,
    originIp: "8.8.8.8", redirectFollowed: false,
    pagesRead: 1, expectedPages: 1,
    recordDigest: "b".repeat(64),
  };
}
describe("Exposure domain ownership proof and dry-run policy", () => {
  it("creates bounded challenge for a public canonical domain", () => {
    const proof = request();
    const checked = validateExposureAuthorizationRequest(proof);
    expect(checked.valid).toBe(true);
    const challenge = prepareExposureAuthorizationChallenge(proof);
    expect(challenge.expectedName).toBe(
      "_cyberpilot-verification.example.com");
    expect(challenge.expectedValue).toContain(token);
    expect(challenge.mayTriggerNetworkScan).toBe(false);
  });
  it("rejects noncanonical, reserved and private domain targets", () => {
    for (const domain of ["localhost", "service.local",
      "10.0.0.1", "Example.COM", "foo.invalid"]) {
      const proof = request();
      proof.domain = domain;
      expect(validateExposureAuthorizationRequest(proof).valid).toBe(false);
    }
  });
  it("rejects self-declared, missing and partial proof as ownership", () => {
    const proof = request();
    expect(evaluateExposureAuthorization(proof, null, checkedAt).state)
      .toBe("PENDING");
    const untrusted = evidence();
    untrusted.collectorTrusted = false;
    expect(evaluateExposureAuthorization(proof, untrusted, checkedAt).state)
      .toBe("PENDING");
    const partial = evidence();
    partial.collectionStatus = "PARTIAL";
    expect(evaluateExposureAuthorization(proof, partial, checkedAt).state)
      .toBe("PENDING");
  });
  it("binds independent complete observation but does not authorize active scanning", () => {
    const result = evaluateExposureAuthorization(
      request(), evidence(), checkedAt);
    expect(result.state).toBe("VERIFIED");
    expect(result.activeScanPermissionGranted).toBe(false);
    expect(result.signedExternalApprovalEstablished).toBe(false);
    expect(verifyExposureAuthorizationDecision(
      result, request(), evidence()).valid).toBe(true);
    const policy = buildExposureTargetPolicy(result);
    expect(policy.directConnectionsAuthorizedByPolicyAlone).toBe(false);
    expect(policy.maxRedirects).toBe(0);
    expect(policy.maxConcurrent).toBe(1);
  });
  it("never treats an expired token as authenticated", () => {
    const result = evaluateExposureAuthorization(request(),
      evidence(), "2026-11-13T16:00:00.000Z");
    expect(result.state).toBe("EXPIRED");
    expect(() => buildExposureTargetPolicy(result)).toThrow();
  });
  it("rejects foreign-tenant and missing domain evidence", () => {
    const foreign = evidence();
    foreign.organizationId = "foreign-tenant-12345";
    expect(evaluateExposureAuthorization(request(), foreign, checkedAt).state)
      .toBe("PENDING");
    const missing = evidence();
    missing.observedValues = ["unrelated-token"];
    expect(evaluateExposureAuthorization(request(), missing, checkedAt).state)
      .toBe("PENDING");
  });
  it("rejects private IP provenance", () => {
    const privateIp = evidence();
    privateIp.originIp = "127.0.0.1";
    expect(evaluateExposureAuthorization(request(), privateIp, checkedAt).state)
      .toBe("PENDING");
  });
  it("denies redirected proofs and cross-origin navigation", () => {
    const redirected = evidence();
    (redirected as unknown as Record<string, unknown>).redirectFollowed =
      true;
    expect(evaluateExposureAuthorization(request(), redirected, checkedAt)
      .state).toBe("PENDING");
    const cross = inspectExposureRedirect(
      "https://example.com/", "http://127.0.0.1/admin", "example.com");
    expect(cross.mayFollowAutomatically).toBe(false);
    expect(cross.decision).toBe("CROSS_ORIGIN_DENIED");
  });
  it("denies HTTPS downgrade and unauthenticated hosts", () => {
    const downgrade = inspectExposureRedirect(
      "https://example.com/path", "/next",
      "example.com");
    expect(downgrade.decision).toBe("SAME_AUTHORIZED_ORIGIN");
    const unsafe = inspectExposureRedirect(
      "https://example.com/path", "http://example.com/",
      "example.com");
    expect(unsafe.decision).toBe("SCHEME_DOWNGRADE_DENIED");
  });
  it("calculates strict quotas but performs no requests", () => {
    const policy = buildExposureTargetPolicy(
      evaluateExposureAuthorization(request(), evidence(), checkedAt));
    const budget = planExposureCollectionQuota(
      policy, checkedAt, [
        { requestId: "request-12345", kind: "DNS",
          target: "example.com", resolvedIps: ["8.8.8.8"],
          hasCredentials: false },
        { requestId: "request-23456", kind: "HTTP",
          target: "https://example.com", resolvedIps: ["10.0.0.1"],
          hasCredentials: false },
        { requestId: "request-34567", kind: "TLS",
          target: "https://example.com", resolvedIps: ["8.8.8.8"],
          hasCredentials: true },
      ]);
    expect(budget.usedDns).toBe(1);
    expect(budget.usedHttp).toBe(0);
    expect(budget.trafficExecuted).toBe(0);
    expect(budget.reservations[1]?.decision)
      .toBe("DENIED_PRIVATE_ADDRESS");
    expect(budget.reservations[2]?.decision)
      .toBe("DENIED_CREDENTIALS");
    expect(verifyExposureCollectionBudget(budget).valid).toBe(true);
  });
});
