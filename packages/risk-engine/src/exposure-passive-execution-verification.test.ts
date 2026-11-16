import { describe, it, expect, vi } from "vitest";
import {
  defaultPassiveAdmissionPolicy,
  planPassiveDomainTargets,
  type PassiveCollectorRequest,
} from "./exposure-passive-collection-policy";
import {
  type PassiveExecutionLease,
  type PassiveExecutionOptions,
} from "./exposure-passive-execution-guard";
import {
  reconcilePassiveExecution,
  verifyPassiveExecutionEvidence,
  comparePassiveExecutionEvidence,
  exportPassiveExecutionEvidence,
} from "./exposure-passive-execution-verification";
import {
  executeAndVerifyPassiveCollection,
  buildPassiveExecutionPortfolio,
  verifyPassiveExecutionPortfolio,
  comparePassiveExecutionPortfolios,
} from "./exposure-passive-execution-portfolio";
const now = "2026-11-16T10:00:00.000Z";
function buildRequest(): PassiveCollectorRequest {
  const domain = "example.com";
  const sources = ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"] as const;
  const policy = defaultPassiveAdmissionPolicy("org-alpha", domain);
  const targets = planPassiveDomainTargets(domain, [...sources]);
  return {
    schema: "cyberpilot.exposure.passive.request.v1",
    organizationId: "org-alpha", domain, requestId: "request-one",
    actorUserId: "actor-admin", requestedAt: now,
    proof: {
      organizationId: "org-alpha", domain,
      authorizationId: "authorization-one",
      authorizationRevision: 1, verificationMethod: "DNS_TOKEN",
      verifiedAt: now, expiresAt: "2026-11-16T10:04:00.000Z",
      revokedAt: null, currentState: "VERIFIED",
      actorUserId: "actor-admin", consentRecordId: "consent-one",
      legalConsentIndependentlyVerified: true,
    },
    sources: [...sources],
    allowedDnsNames: targets.allowedDnsNames,
    allowedTlsHostnames: targets.allowedTlsHostnames,
    allowedHttpUrls: targets.allowedHttpUrls,
    policy, explicitlyOptedIn: true,
    tokenInRequest: false, credentialsSupplied: false,
    activeScanningRequested: false,
  };
}
function lease(request: PassiveCollectorRequest): PassiveExecutionLease {
  return {
    schema: "cyberpilot.exposure.execution.lease.v1",
    organizationId: request.organizationId,
    domain: request.domain, requestId: request.requestId,
    authorizationId: request.proof.authorizationId,
    authorizationRevision: 1,
    consentRecordId: request.proof.consentRecordId,
    reservationId: "reservation-one",
    issuedAt: now, expiresAt: "2026-11-16T10:02:00.000Z",
    grantedSources: [...request.sources],
    budget: { DNS: 7, TLS_HANDSHAKE: 1, HTTPS_HEADERS: 1 },
    approvedByIndependentAuthority: true,
    approvedScopeDigest: "a".repeat(64),
  };
}
function options(): PassiveExecutionOptions {
  return {
    now: () => now,
    authority: {
      verifyIndependentConsent: vi.fn(async () => true),
      consumeReservedCall: vi.fn(async () => true),
    },
    transport: {
      resolve: vi.fn(async () => ["93.184.215.14"]),
      collectDns: vi.fn(async () => ({
        records: ["v=spf1 -all"], bytes: 30,
      })),
      collectTls: vi.fn(async () => ({
        peer: "93.184.215.14", bytes: 128, handshakeOnly: true as const,
      })),
      collectHead: vi.fn(async () => ({
        peer: "93.184.215.14", bytes: 120,
        method: "HEAD" as const, redirectCount: 0 as const,
        bodyBytes: 0 as const, authenticated: false as const,
      })),
    },
  };
}
describe("independent Exposure execution evidence", () => {
  it("reconciles an injected no-live transport without asserting risk", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    expect(output.result.state).toBe("COMPLETED");
    expect(output.reportIntegrityVerified).toBe(true);
    expect(output.evidence.verdict).toBe("TRACEABLE");
    expect(output.evidence.consumedCalls.total).toBe(9);
    expect(output.evidence.consumedCalls.DNS).toBe(5);
    expect(output.evidence.remoteEndpointSecurityCertified).toBe(false);
    expect(output.evidence.independentLegalAuthorizationApprovedByVerifier)
      .toBe(false);
  });
  it("denies an absent independent lease without invoking a transport", async () => {
    const request = buildRequest();
    const dependencies = options();
    const output = await executeAndVerifyPassiveCollection(
      request, null, dependencies,
    );
    expect(output.result.state).toBe("DENIED");
    expect(output.evidence.verdict).toBe("DENIED");
    expect(output.evidence.consumedCalls.total).toBe(0);
    expect(dependencies.transport.collectDns).not.toHaveBeenCalled();
  });
  it("rejects unauthorized scope without positive evidence", async () => {
    const request = buildRequest();
    const wrong = { ...lease(request), organizationId: "org-other" };
    const output = await executeAndVerifyPassiveCollection(
      request, wrong, options(),
    );
    expect(output.result.state).toBe("DENIED");
    expect(output.reportIntegrityVerified).toBe(true);
    expect(output.evidence.verdict).toBe("DENIED");
  });
  it("denies a tampered forensic digest and overclaimed safety", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    output.evidence.remoteEndpointSecurityCertified = true as false;
    const verification = verifyPassiveExecutionEvidence(output.evidence);
    expect(verification.errors).toContain("EVIDENCE_DIGEST_INVALID");
    expect(verification.errors).toContain("SECURITY_OVERCLAIM");
  });
  it("detects a foreign organization even with a matching local digest", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    expect(verifyPassiveExecutionEvidence(
      output.evidence, "org-foreign").errors)
      .toContain("FOREIGN_TENANT_EVIDENCE");
  });
  it("flags a positive claim unbacked by DNS reservations", async () => {
    const request = buildRequest();
    const result = (await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    )).result;
    result.calls.DNS = 0;
    const review = reconcilePassiveExecution(
      request, lease(request), result, now,
    );
    expect(review.gates.find(g => g.id === "PRE_POST_DNS_QUOTA")?.state)
      .toBe("BLOCK");
    expect(review.verdict).toBe("INVALID");
  });
  it("exports verified reports without invented certifications", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    expect(exportPassiveExecutionEvidence(
      output.evidence, "CSV").text).toContain("SOCKET_PEER_RECORDED");
    expect(exportPassiveExecutionEvidence(
      output.evidence, "MARKDOWN").text).toContain("No remote security");
    expect(JSON.parse(exportPassiveExecutionEvidence(
      output.evidence, "JSON").text)
      .independentLegalAuthorizationApprovedByVerifier).toBe(false);
  });
  it("builds a tenant-scoped portfolio with no LIVE approval", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    const portfolio = buildPassiveExecutionPortfolio(
      "org-alpha", [output.evidence], now,
    );
    expect(portfolio.samples).toBe(1);
    expect(portfolio.totals.traceable).toBe(1);
    expect(portfolio.totals.dnsCalls).toBe(7);
    expect(portfolio.legalApprovalInferred).toBe(false);
    expect(portfolio.perDomain[0]?.observedSecurityPosture)
      .toBe("NOT_DETERMINED");
    expect(verifyPassiveExecutionPortfolio(portfolio, "org-alpha").valid)
      .toBe(true);
  });
  it("flags duplicate requests without double counting their traffic", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    const portfolio = buildPassiveExecutionPortfolio(
      "org-alpha", [output.evidence, output.evidence], now,
    );
    expect(portfolio.samples).toBe(1);
    expect(portfolio.anomalies.some(x =>
      x.code === "DUPLICATE_REQUEST_ID")).toBe(true);
  });
  it("rejects cross-tenant evidence from the portfolio", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    const portfolio = buildPassiveExecutionPortfolio(
      "org-other", [output.evidence], now,
    );
    expect(portfolio.samples).toBe(0);
    expect(portfolio.anomalies.length).toBe(1);
  });
  it("compares two bounded portfolios without interpreting risk posture", async () => {
    const request = buildRequest();
    const output = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    const first = buildPassiveExecutionPortfolio(
      "org-alpha", [], now,
    );
    const later = buildPassiveExecutionPortfolio(
      "org-alpha", [output.evidence], "2026-11-16T10:05:00.000Z",
    );
    const diff = comparePassiveExecutionPortfolios(first, later);
    expect(diff.sourceCountDelta).toBe(1);
    expect(diff.improvedSecurityPostureInferred).toBe(false);
    expect(diff.legalConsentStillRequired).toBe(true);
  });
  it("compares digest-pinned local execution without certifying improvement", async () => {
    const request = buildRequest();
    const result = await executeAndVerifyPassiveCollection(
      request, lease(request), options(),
    );
    const older = reconcilePassiveExecution(
      request, lease(request), result.result, now,
    );
    const newer = reconcilePassiveExecution(
      request, lease(request), result.result,
      "2026-11-16T10:01:00.000Z",
    );
    const comparison = comparePassiveExecutionEvidence(older, newer);
    expect(comparison.independentlyVerifiedRiskReduction).toBe(false);
  });
});
