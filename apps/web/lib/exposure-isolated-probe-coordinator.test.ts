import { describe, expect, it, vi } from "vitest";
import {
  IsolatedExposureProbeCoordinator,
  verifyPassiveProbeReport,
  exportPassiveProbeReport,
  type PassiveProbeInput,
} from "./exposure-isolated-probe-coordinator";
import {
  defaultPassiveAdmissionPolicy,
  planPassiveDomainTargets,
  type PassiveCollectorRequest,
} from "@cyberpilot/risk-engine";
import type {
  ExecutionLeaseRequest,
  ExecutionLedgerActor,
  LedgerAuthority,
  ExposureExecutionLedgerService,
} from "./exposure-execution-ledger-service";
import type {
  IsolatedNetworkOperator,
} from "./exposure-isolated-network-transport";
const current = "2026-11-16T10:00:00.000Z";
function fixture(): PassiveProbeInput {
  const domain = "example.com";
  const sources = ["DNS"] as const;
  const targets = planPassiveDomainTargets(domain,[...sources]);
  const actor: ExecutionLedgerActor = {
    organizationId: "org-test", userId: "actor-test",
    role: "OWNER",
  };
  const request: PassiveCollectorRequest = {
    schema: "cyberpilot.exposure.passive.request.v1",
    organizationId: "org-test", domain,
    requestId: "request-test", actorUserId: "actor-test",
    requestedAt: current,
    proof: {
      organizationId: "org-test",
      domain, authorizationId: "auth-test",
      authorizationRevision: 1, verificationMethod: "DNS_TOKEN",
      verifiedAt: current,
      expiresAt: "2026-11-16T10:04:00.000Z",
      revokedAt: null, currentState: "VERIFIED",
      actorUserId: "actor-test",
      consentRecordId: "consent-test",
      legalConsentIndependentlyVerified: true,
    },
    sources: [...sources],
    allowedDnsNames: targets.allowedDnsNames,
    allowedTlsHostnames: targets.allowedTlsHostnames,
    allowedHttpUrls: targets.allowedHttpUrls,
    policy: defaultPassiveAdmissionPolicy("org-test",domain),
    explicitlyOptedIn: true,
    tokenInRequest: false, credentialsSupplied: false,
    activeScanningRequested: false,
  };
  const command: ExecutionLeaseRequest = {
    requestId: "request-test", organizationId: "org-test",
    domain, scheduleId: "schedule-test",
    authorizationId: "auth-test",
    authorizationRevision: 1,
    consentReport: {} as never,
    requiredSources: ["DNS"],
    quotas: { DNS: 3, TLS_HANDSHAKE: 0, HTTPS_HEADERS: 0 },
    maxTotal: 3,
    expiresAt: "2026-11-16T10:02:00.000Z",
    actorUserId: "actor-test",
  };
  const operator: IsolatedNetworkOperator = {
    schema: "cyberpilot.exposure.network.operator.v1",
    liveFeatureEnabled: true,
    operatorId: "worker-test",
    independentlyApprovedWorker: true,
    isolatedExecutionEnvironment: true,
    trustedQuotaAdapterPresent: true,
    scopedExecutionLeasePresent: true,
  };
  return { actor, request, command, operator };
}
function dependencies() {
  const ledger = {
    issueWithAuthority: vi.fn(async () => {
      throw Error("INDEPENDENT_AUTHORITY_DENIED");
    }),
    closeWithAuthority: vi.fn(async () => ({})),
  } as unknown as ExposureExecutionLedgerService;
  const authority: LedgerAuthority = {
    independentlyOperated: true,
    authorizeExecution: vi.fn(async () => false),
    authorizeCharge: vi.fn(async () => false),
  };
  const transport = vi.fn(() => {
    throw Error("TRANSPORT_MUST_NOT_BE_CREATED");
  });
  return { ledger, authority, transport, now: () => current };
}
describe("operator-only isolated probe orchestration", () => {
  it("denies issuance when no trust authority exists without network", async () => {
    const deps = dependencies();
    const coordinator = new IsolatedExposureProbeCoordinator({
      ...deps, authority: null as unknown as LedgerAuthority,
    });
    const output = await coordinator.run(fixture());
    expect(output.state).toBe("DENIED");
    expect(output.consumedNetworkCalls).toBe(0);
    expect(output.leaseId).toBeNull();
    expect(deps.transport).not.toHaveBeenCalled();
    expect(verifyPassiveProbeReport(output).valid).toBe(true);
  });
  it("rejects actor tenant mismatch before the lease or worker", async () => {
    const deps = dependencies();
    const input = fixture();
    input.actor.organizationId = "org-foreign";
    const output = await new IsolatedExposureProbeCoordinator(deps).run(input);
    expect(output.state).toBe("DENIED");
    expect(deps.transport).not.toHaveBeenCalled();
  });
  it("denies forged technical consent before touching the ledger", async () => {
    const deps = dependencies();
    const input = fixture();
    input.request.proof.legalConsentIndependentlyVerified = false;
    const output = await new IsolatedExposureProbeCoordinator(deps).run(input);
    expect(output.state).toBe("DENIED");
    expect(deps.ledger.issueWithAuthority).not.toHaveBeenCalled();
  });
  it("refuses mismatched DNS quota planning before issuance", async () => {
    const deps = dependencies();
    const input = fixture();
    input.command.quotas.DNS = 1;
    const output = await new IsolatedExposureProbeCoordinator(deps).run(input);
    expect(output.state).toBe("DENIED");
    expect(deps.ledger.issueWithAuthority).not.toHaveBeenCalled();
  });
  it("fails closed on independent authority denial", async () => {
    const deps = dependencies();
    const output = await new IsolatedExposureProbeCoordinator(deps)
      .run(fixture());
    expect(output.state).toBe("DENIED");
    expect(output.denialCodes).not.toHaveLength(0);
    expect(output.legalConsentIssuedByCyberPilot).toBe(false);
    expect(output.externalRemediationPerformed).toBe(false);
    expect(deps.transport).not.toHaveBeenCalled();
  });
  it("exports a denied report without presenting missing evidence as safe", async () => {
    const output = await new IsolatedExposureProbeCoordinator(
      dependencies(),
    ).run(fixture());
    const json = exportPassiveProbeReport(output,"JSON");
    const csv = exportPassiveProbeReport(output,"CSV");
    const md = exportPassiveProbeReport(output,"MARKDOWN");
    expect(JSON.parse(json.content).state).toBe("DENIED");
    expect(csv.content).toContain("peerPinned");
    expect(md.content).toContain("No remote security certification");
  });
  it("detects tampered no-network assertions", async () => {
    const output = await new IsolatedExposureProbeCoordinator(
      dependencies(),
    ).run(fixture());
    output.legalConsentIssuedByCyberPilot = true as false;
    expect(verifyPassiveProbeReport(output).errors)
      .toContain("PROBE_FALSE_SECURITY_CLAIM");
    expect(verifyPassiveProbeReport(output).errors)
      .toContain("PROBE_REPORT_DIGEST_MISMATCH");
  });
});
