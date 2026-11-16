import { describe, it, expect } from "vitest";
import {
  buildExposureOperationalCloseout,
  verifyExposureOperationalCloseout,
  exportExposureOperationalCloseout,
  compareExposureOperationalCloseouts,
  type ExposureCloseoutInput,
} from "./exposure-operational-closeout";

const at = "2026-11-16T10:00:00.000Z";
const hash = "a".repeat(64);
function sample(): ExposureCloseoutInput {
  return {
    organizationId: "org-test", generatedAt: at,
    collectionCounts: {
      authorizations: 1, authorizationEvents: 1,
      schedules: 1, scheduleEvents: 1, reservations: 1,
    },
    collectionCaps: {
      authorizations: 100, authorizationEvents: 500,
      schedules: 100, scheduleEvents: 500, reservations: 1000,
    },
    authorizations: [{
      id: "auth-test", organizationId: "org-test",
      domain: "example.com", revision: 1, state: "VERIFIED",
      method: "DNS_TOKEN", challengeExpiresAt: "2026-11-16T11:00:00.000Z",
      verifiedAt: "2026-11-16T09:00:00.000Z",
      revokedAt: null, evidenceDigest: hash, updatedAt: at,
    }],
    authorizationEvents: [{
      id: "auth-event", organizationId: "org-test",
      authorizationId: "auth-test", revision: 1,
      action: "VERIFY", priorState: "PENDING", newState: "VERIFIED",
      actorUserId: "actor-admin", createdAt: at,
    }],
    schedules: [{
      id: "schedule-test", organizationId: "org-test",
      authorizationId: "auth-test", domain: "example.com",
      revision: 1, state: "DISABLED", sources: ["DNS"],
      policyDigest: hash, legalConsentVerified: false,
      dailyDnsLimit: 8, dailyTlsLimit: 1, dailyHttpLimit: 1,
      minimumIntervalMs: 60000, lastAttemptAt: null,
      nextEligibleAt: null, updatedAt: at,
    }],
    scheduleEvents: [{
      id: "schedule-event", organizationId: "org-test",
      scheduleId: "schedule-test", revision: 1,
      action: "CREATE", priorState: "NONE",
      currentState: "DISABLED", actorUserId: "actor-admin",
      createdAt: at,
    }],
    reservations: [{
      id: "reservation-test", organizationId: "org-test",
      scheduleId: "schedule-test", requestId: "request-test",
      authorizationRevision: 1, status: "DENIED",
      requestedSources: ["DNS"], reservedDns: 0, reservedTls: 0,
      reservedHttp: 0, actualDns: 0, actualTls: 0, actualHttp: 0,
      periodStart: at, leaseExpiresAt: at,
      finishedAt: null, rejectionCode: "CONSENT_REQUIRED",
      evidenceDigest: null, createdAt: at,
    }],
  };
}
describe("Exposure operational read-only readiness", () => {
  it("recognizes coherent local events without creating consent", () => {
    const report = buildExposureOperationalCloseout(sample());
    expect(report.verdict).toBe("BLOCKED");
    expect(report.domains[0]?.blockers)
      .toContain("CONSENT_NOT_INDEPENDENTLY_ATTESTED");
    expect(report.domains[0]?.blockers)
      .toContain("TRUSTED_WORKER_UNAVAILABLE");
    expect(report.gates.every(gate => gate.severity === "PASS")).toBe(true);
    expect(report.total.actualNetworkCallsReported).toBe(0);
    expect(report.providerTrafficPermitted).toBe(false);
    expect(verifyExposureOperationalCloseout(report, "org-test").valid)
      .toBe(true);
  });
  it("rejects cross-organization event read", () => {
    const fixture = sample();
    fixture.scheduleEvents[0]!.organizationId = "org-foreign";
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g => g.id === "TENANT_SCOPE")?.severity)
      .toBe("BLOCK");
  });
  it("detects inconsistent authorization audit sequence", () => {
    const fixture = sample();
    fixture.authorizationEvents[0]!.revision = 2;
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "DOMAIN_OWNERSHIP_CAS_AUDIT")?.severity).toBe("BLOCK");
  });
  it("detects schedule audit state mismatch", () => {
    const fixture = sample();
    fixture.scheduleEvents[0]!.currentState = "READY";
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "SCHEDULE_CAS_AUDIT")?.severity).toBe("BLOCK");
  });
  it("detects duplicate request id and quota overstatement", () => {
    const fixture = sample();
    fixture.reservations.push({
      ...fixture.reservations[0]!, id: "reservation-second",
    });
    fixture.collectionCounts.reservations = 2;
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "RESERVATION_IDEMPOTENCY")?.severity).toBe("BLOCK");
  });
  it("rejects fabricated actual traffic without independently verified collector", () => {
    const fixture = sample();
    fixture.reservations[0]!.actualTls = 1;
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "NO_UNVERIFIED_LIVE_COLLECTION")?.severity).toBe("BLOCK");
    expect(report.gates.find(g =>
      g.id === "QUOTA_LEDGER_INTEGRITY")?.severity).toBe("BLOCK");
  });
  it("treats unverified ready schedule as blocked, not approved", () => {
    const fixture = sample();
    fixture.schedules[0]!.state = "READY";
    fixture.schedules[0]!.legalConsentVerified = true;
    fixture.scheduleEvents[0]!.currentState = "READY";
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "INDEPENDENT_CONSENT_GUARD")?.severity).toBe("BLOCK");
    expect(report.providerTrafficPermitted).toBe(false);
  });
  it("rejects missing parents, including reservations", () => {
    const fixture = sample();
    fixture.reservations[0]!.scheduleId = "schedule-foreign";
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.gates.find(g =>
      g.id === "FOREIGN_KEY_PROVENANCE")?.severity).toBe("BLOCK");
  });
  it("fails closed when source collection was truncated", () => {
    const fixture = sample();
    fixture.collectionCounts.reservations = 1001;
    const report = buildExposureOperationalCloseout(fixture);
    expect(report.sourceBounded).toBe(false);
    expect(report.gates.find(g =>
      g.id === "BOUNDED_DATABASE_READ")?.severity).toBe("BLOCK");
  });
  it("detects a changed digest and false LIVE state", () => {
    const report = buildExposureOperationalCloseout(sample());
    report.domains[0]!.liveCollectionAllowed = true as false;
    const invalid = verifyExposureOperationalCloseout(report);
    expect(invalid.errors).toContain("CLOSEOUT_DIGEST_INVALID");
    expect(invalid.errors).toContain("FALSE_DOMAIN_AUTHORIZATION");
  });
  it("exports consistent CSV, Markdown and JSON", () => {
    const report = buildExposureOperationalCloseout(sample());
    const csv = exportExposureOperationalCloseout(report, "CSV");
    const markdown = exportExposureOperationalCloseout(report, "MARKDOWN");
    const json = exportExposureOperationalCloseout(report, "JSON");
    expect(csv.content).toContain("example.com");
    expect(markdown.content).toContain("LIVE collection authorized: NO");
    expect(JSON.parse(json.content).providerTrafficPermitted).toBe(false);
  });
  it("compares real evidence differences without claiming customer authorization", () => {
    const first = buildExposureOperationalCloseout(sample());
    const secondInput = sample();
    secondInput.generatedAt = "2026-11-16T11:00:00.000Z";
    secondInput.schedules = [];
    secondInput.scheduleEvents = [];
    secondInput.reservations = [];
    secondInput.collectionCounts.schedules = 0;
    secondInput.collectionCounts.scheduleEvents = 0;
    secondInput.collectionCounts.reservations = 0;
    const second = buildExposureOperationalCloseout(secondInput);
    const diff = compareExposureOperationalCloseouts(first, second);
    expect(diff.newBlockers).toContain("example.com:SCHEDULE_MISSING");
    expect(diff.externalCollectionAuthorized).toBe(false);
    expect(diff.securityImprovementProven).toBe(false);
  });
});
