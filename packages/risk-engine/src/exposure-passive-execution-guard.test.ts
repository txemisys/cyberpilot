import { describe, expect, it, vi } from "vitest";
import {
  defaultPassiveAdmissionPolicy,
  planPassiveDomainTargets,
  type PassiveCollectorRequest,
} from "./exposure-passive-collection-policy";
import {
  executePassiveCollection, verifyPassiveExecutionLease,
  type PassiveExecutionLease, type PassiveExecutionTransport,
  type PassiveExecutionAuthority,
} from "./exposure-passive-execution-guard";
const now = "2026-11-16T10:00:00.000Z";
function fixture(sources: PassiveCollectorRequest["sources"] =
  ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"]): PassiveCollectorRequest {
  const domain = "example.com";
  const policy = defaultPassiveAdmissionPolicy("org-test", domain);
  const target = planPassiveDomainTargets(domain, sources);
  return {
    schema: "cyberpilot.exposure.passive.request.v1",
    organizationId: "org-test", domain, requestId: "request-test",
    actorUserId: "actor-test", requestedAt: now,
    proof: {
      organizationId: "org-test", domain,
      authorizationId: "auth-test",
      authorizationRevision: 1,
      verificationMethod: "DNS_TOKEN",
      verifiedAt: now,
      expiresAt: "2026-11-16T10:04:00.000Z",
      revokedAt: null, currentState: "VERIFIED",
      actorUserId: "actor-test",
      consentRecordId: "consent-test",
      legalConsentIndependentlyVerified: true,
    },
    sources,
    allowedDnsNames: target.allowedDnsNames,
    allowedTlsHostnames: target.allowedTlsHostnames,
    allowedHttpUrls: target.allowedHttpUrls,
    policy, explicitlyOptedIn: true,
    tokenInRequest: false, credentialsSupplied: false,
    activeScanningRequested: false,
  };
}
function lease(request: PassiveCollectorRequest):
  PassiveExecutionLease {
  return {
    schema: "cyberpilot.exposure.execution.lease.v1",
    organizationId: request.organizationId,
    domain: request.domain, requestId: request.requestId,
    authorizationId: request.proof.authorizationId,
    authorizationRevision: request.proof.authorizationRevision,
    consentRecordId: request.proof.consentRecordId,
    reservationId: "reservation-test",
    issuedAt: now, expiresAt: "2026-11-16T10:02:00.000Z",
    grantedSources: [...request.sources],
    budget: {
      DNS: request.sources.includes("DNS") ? 1 : 0,
      TLS_HANDSHAKE: request.sources.includes("TLS_HANDSHAKE") ? 1 : 0,
      HTTPS_HEADERS: request.sources.includes("HTTPS_HEADERS") ? 1 : 0,
    }, approvedByIndependentAuthority: true,
    approvedScopeDigest: "a".repeat(64),
  };
}
function dependencies() {
  const transport: PassiveExecutionTransport = {
    resolve: vi.fn(async () => ["93.184.215.14"]),
    collectDns: vi.fn(async () => ({
      records: ["v=spf1 -all"], bytes: 24,
    })),
    collectTls: vi.fn(async () => ({
      peer: "93.184.215.14", bytes: 20, handshakeOnly: true as const,
    })),
    collectHead: vi.fn(async () => ({
      peer: "93.184.215.14", bytes: 128,
      method: "HEAD" as const, redirectCount: 0 as const, bodyBytes: 0 as const,
      authenticated: false as const,
    })),
  };
  const authority: PassiveExecutionAuthority = {
    verifyIndependentConsent: vi.fn(async () => true),
    consumeReservedCall: vi.fn(async () => true),
  };
  return { transport, authority, now: () => now };
}
describe("independently authorized Exposure passive execution", () => {
  it("rejects missing leases without invoking transport or quota", async () => {
    const deps = dependencies();
    const output = await executePassiveCollection(fixture(), null, deps);
    expect(output.state).toBe("DENIED");
    expect(output.events[0]?.code).toContain("INDEPENDENT_LEASE_REQUIRED");
    expect(deps.transport.resolve).not.toHaveBeenCalled();
    expect(deps.authority.consumeReservedCall).not.toHaveBeenCalled();
  });
  it("rejects cross-organization lease before network", async () => {
    const request = fixture();
    const deps = dependencies();
    const output = await executePassiveCollection(request,
      { ...lease(request), organizationId: "org-foreign" }, deps);
    expect(output.state).toBe("DENIED");
    expect(output.events[0]?.code).toContain("LEASE_SCOPE_MISMATCH");
    expect(deps.transport.collectDns).not.toHaveBeenCalled();
  });
  it("rejects old authorization and fake digest", () => {
    const request = fixture();
    expect(verifyPassiveExecutionLease(request,
      { ...lease(request), authorizationRevision: 2 }, now))
      .toContain("LEASE_SCOPE_MISMATCH");
    expect(verifyPassiveExecutionLease(request,
      { ...lease(request), approvedScopeDigest: "signed" }, now))
      .toContain("INDEPENDENT_APPROVAL_INVALID");
  });
  it("rejects missing independent legal approval in the source proof", async () => {
    const request = fixture();
    request.proof.legalConsentIndependentlyVerified = false;
    const deps = dependencies();
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("DENIED");
    expect(output.events[0]?.code)
      .toContain("LEGAL_SCOPE_APPROVAL_NOT_VERIFIED");
    expect(deps.transport.collectHead).not.toHaveBeenCalled();
  });
  it("rejects expired leases and forbidden over-budget capabilities", () => {
    const request = fixture();
    expect(verifyPassiveExecutionLease(request,
      { ...lease(request), expiresAt: now }, now))
      .toContain("LEASE_EXPIRED_OR_UNBOUNDED");
    const budget = {
      ...lease(request).budget, TLS_HANDSHAKE: 2,
    };
    expect(verifyPassiveExecutionLease(request,
      { ...lease(request), budget }, now))
      .toContain("LEASE_BUDGET_TLS_HANDSHAKE");
  });
  it("uses injected test transport only and preserves no-certification flags", async () => {
    const request = fixture();
    const deps = dependencies();
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("COMPLETED");
    expect(output.calls).toEqual({
      DNS: 1, TLS_HANDSHAKE: 1, HTTPS_HEADERS: 1,
    });
    expect(output.sourceResults).toHaveLength(3);
    expect(output.legacyCyberScoreModified).toBe(false);
    expect(output.securityOrRemediationCertified).toBe(false);
    expect(deps.transport.collectHead).toHaveBeenCalledWith(
      "https://example.com/", "93.184.215.14", 4000,
    );
  });
  it("fails closed on durable quota denial", async () => {
    const request = fixture(["DNS"]);
    const deps = dependencies();
    deps.authority.consumeReservedCall = vi.fn(async () => false);
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("PARTIAL");
    expect(output.sourceResults[0]?.status).toBe("DENIED");
    expect(deps.transport.collectDns).not.toHaveBeenCalled();
  });
  it("fails closed when consent is revoked before a source", async () => {
    const request = fixture(["DNS"]);
    const deps = dependencies();
    deps.authority.verifyIndependentConsent = vi.fn(async () => false);
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("PARTIAL");
    expect(output.events.some(e =>
      e.code === "CONSENT_REVOKED_OR_UNVERIFIED")).toBe(true);
    expect(deps.transport.collectDns).not.toHaveBeenCalled();
  });
  it("does not promote a rebinding TLS peer to OBSERVED", async () => {
    const request = fixture(["TLS_HANDSHAKE"]);
    const deps = dependencies();
    deps.transport.resolve = vi.fn()
      .mockResolvedValueOnce(["93.184.215.14"])
      .mockResolvedValueOnce(["8.8.8.8"]);
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("PARTIAL");
    expect(output.sourceResults[0]?.status).toBe("UNKNOWN");
  });
  it("does not accept redirects, response bodies or authentication on HEAD", async () => {
    const request = fixture(["HTTPS_HEADERS"]);
    const deps = dependencies();
    deps.transport.collectHead = vi.fn(async () => ({
      peer: "93.184.215.14", bytes: 128,
      method: "HEAD" as const, redirectCount: 0 as const,
      bodyBytes: 2 as 0, authenticated: false as const,
    }));
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.sourceResults[0]?.status).toBe("UNKNOWN");
  });
  it("does not call later sources after revoked consent", async () => {
    const request = fixture(["DNS","TLS_HANDSHAKE"]);
    const deps = dependencies();
    let count = 0;
    deps.authority.verifyIndependentConsent = vi.fn(async () => ++count === 1);
    const output = await executePassiveCollection(request, lease(request), deps);
    expect(output.state).toBe("PARTIAL");
    expect(deps.transport.collectTls).not.toHaveBeenCalled();
  });
});
