import { describe, expect, it } from "vitest";
import {
  parseDispatchAlertQuery, parseDispatchAlertAction,
  normalizeAlertObservation, evaluateDispatchAlertObservations,
  alertTransitionAllowed,
} from "./assets-osv-dispatch-alerts";
import type { DispatchOperationalReport } from "./assets-osv-dispatch-observability";
const evaluatedAt = "2026-11-10T12:00:00.000Z";
const action = {
  alertId: "osv-alert-12345",
  expectedRevision: 2,
  expectedEvidenceDigest: "a".repeat(64),
  operation: "ACKNOWLEDGE",
  reason: "Investigated the scheduling anomaly and verified persisted logs.",
};
const report: DispatchOperationalReport = {
  schema: "cyberpilot.assets.osv.signed-dispatch.operations.v1",
  organizationId: "organization-12345",
  evaluatedAt,
  policy: {
    lookbackHours: 24, maximumRecent: 50,
    alertAfterMinutes: 45, alertFailureThreshold: 3,
    alertUnsettledThreshold: 1,
  },
  configuration: {
    schema: "cyberpilot.assets.osv.signed-dispatch.readiness.v1",
    enabled: false, scopedKeys: 0,
    organizationId: "organization-12345",
    eligibleKeyIds: [], hasTenantKey: false,
    replayStorage: "POSTGRESQL",
    maxRequestAgeSeconds: 120, maxClockSkewSeconds: 30,
    grantsScheduleCreation: false,
    grantsConsentModification: false,
    grantsQuotaOverride: false, installsCron: false,
    warnings: [],
  },
  acceptedNoncesInWindow: 1, displayed: 1,
  truncated: false, unmatchedAcceptedNonces: 1,
  failedClaimsInWindow: 3, unknownClaimsInWindow: 0,
  unsettledClaims: 1, oldestUnsettledMinutes: 60,
  recent: [{
    requestDigest: "b".repeat(64),
    nonceDigest: "c".repeat(64),
    keyId: "signed-key-12345",
    scheduleId: "schedule-12345",
    acceptedAt: "2026-11-10T11:00:00.000Z",
    expiresAt: "2026-11-10T11:01:00.000Z",
    minutesSinceAccepted: 60,
    hasRunClaim: false, runId: null,
    runState: null, associatedSlotAt: null,
    warningCode: "ACCEPTED_WITHOUT_OBSERVED_CLAIM",
  }],
  alerts: [{
    code: "SERVICE_CREDENTIAL_NOT_READY",
    severity: "WARNING",
    summary: "No enabled credentials were found.",
    action: "Investigate secret configuration before enabling.",
  }, {
    code: "UNSETTLED_CLAIM_THRESHOLD",
    severity: "CRITICAL",
    summary: "One historical schedule claim remains unsettled.",
    action: "Review the claim and do not retry uncertain provider requests.",
  }],
  warnings: [],
};
describe("OSV dispatch alert parsing, identity and lifecycle", () => {
  it("accepts bounded pagination and optional severity and state", () => {
    expect(parseDispatchAlertQuery({})).toEqual({
      offset: 0, limit: 25, state: null, severity: null,
    });
    expect(parseDispatchAlertQuery({
      offset: 20, limit: 40, state: "OPEN",
      severity: "CRITICAL",
    })).toMatchObject({
      offset: 20, limit: 40, state: "OPEN",
      severity: "CRITICAL",
    });
  });
  it.each([
    { offset: -1 }, { offset: 1.5 }, { offset: "3" },
    { limit: 0 }, { limit: 101 },
    { state: "CLAIMED" }, { severity: "IMPORTANT" },
    { state: false }, { unknown: true },
  ])("rejects invalid incident list filters %j", patch => {
    expect(() => parseDispatchAlertQuery(patch)).toThrow();
  });
  it("requires explicit revision, exact evidence digest and reason", () => {
    expect(parseDispatchAlertAction(action)).toMatchObject(action);
    expect(() => parseDispatchAlertAction({
      ...action, expectedRevision: 0,
    })).toThrow();
    expect(() => parseDispatchAlertAction({
      ...action, expectedEvidenceDigest: "not-a-hash",
    })).toThrow();
    expect(() => parseDispatchAlertAction({
      ...action, reason: "Short",
    })).toThrow();
  });
  it.each([
    { operation: "CANCEL" }, { alertId: "short" },
    { reason: "a".repeat(501) },
    { reason: "unsafe\u0000control" },
    { expectedRevision: 1.2 }, { unexpected: true },
  ])("rejects malformed triage mutations %j", patch => {
    expect(() => parseDispatchAlertAction({
      ...action, ...patch,
    })).toThrow();
  });
  it("requires strict OPEN -> ACKNOWLEDGED -> RESOLVED ordering", () => {
    expect(alertTransitionAllowed("OPEN", "ACKNOWLEDGE")).toBe(true);
    expect(alertTransitionAllowed("ACKNOWLEDGED", "RESOLVE")).toBe(true);
    expect(alertTransitionAllowed("RESOLVED", "REOPEN")).toBe(true);
    expect(alertTransitionAllowed("OPEN", "RESOLVE")).toBe(false);
    expect(alertTransitionAllowed("ACKNOWLEDGED", "ACKNOWLEDGE")).toBe(false);
    expect(alertTransitionAllowed("RESOLVED", "RESOLVE")).toBe(false);
    expect(alertTransitionAllowed("OPEN", "REOPEN")).toBe(false);
  });
  it("produces stable evidence fingerprints without wallclock timestamps", () => {
    const first = normalizeAlertObservation(
      "UNSETTLED_CLAIM_THRESHOLD", "tenant", "CRITICAL",
      "A claim was left open", "Review quota first",
      { unsettled: 1, failed: 2 }, evaluatedAt);
    const second = normalizeAlertObservation(
      "UNSETTLED_CLAIM_THRESHOLD", "tenant", "CRITICAL",
      "A claim was left open", "Review quota first",
      { unsettled: 1, failed: 2 },
      "2026-11-11T12:00:00.000Z");
    expect(first.evidenceDigest).toBe(second.evidenceDigest);
    expect(first.evidence.evaluatedAt).not.toBe(second.evidence.evaluatedAt);
    expect(first.evidenceDigest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("changes evidence fingerprint when metrics or severity change", () => {
    const a = normalizeAlertObservation(
      "DISPATCH_FAILURE_THRESHOLD", "tenant", "CRITICAL",
      "Failures", "Investigate", { failed: 3 }, evaluatedAt);
    const b = normalizeAlertObservation(
      "DISPATCH_FAILURE_THRESHOLD", "tenant", "CRITICAL",
      "Failures", "Investigate", { failed: 4 }, evaluatedAt);
    const c = normalizeAlertObservation(
      "DISPATCH_FAILURE_THRESHOLD", "tenant", "WARNING",
      "Failures", "Investigate", { failed: 3 }, evaluatedAt);
    expect(a.evidenceDigest).not.toBe(b.evidenceDigest);
    expect(a.evidenceDigest).not.toBe(c.evidenceDigest);
  });
  it("normalizes tenant signals and request-specific incidents separately", () => {
    const alerts = evaluateDispatchAlertObservations(report);
    expect(alerts).toHaveLength(3);
    expect(alerts.map(item => item.code))
      .toContain("ACCEPTED_WITHOUT_OBSERVED_CLAIM");
    const req = alerts.find(item =>
      item.code === "ACCEPTED_WITHOUT_OBSERVED_CLAIM");
    expect(req?.subjectKey).toBe("req:" + "b".repeat(48));
    expect(req?.evidence.metrics.keyId).toBe("signed-key-12345");
  });
  it("does not fabricate CVE or provider findings from local signals", () => {
    const alerts = evaluateDispatchAlertObservations(report);
    expect(alerts.every(item =>
      item.evidence.source === "LOCAL_DISPATCH_LEDGER")).toBe(true);
    expect(JSON.stringify(alerts)).not.toMatch(/endpoint is (safe|vulnerable)/i);
  });
  it("ignores request entries without an anomaly code", () => {
    const normal = evaluateDispatchAlertObservations({
      ...report, alerts: [],
      recent: [{ ...report.recent[0]!, warningCode: null }],
    });
    expect(normal).toEqual([]);
  });
  it("rejects subject and alert code injection", () => {
    expect(() => normalizeAlertObservation(
      "bad/code", "tenant", "WARNING", "summary", "review",
      {}, evaluatedAt)).toThrow();
    expect(() => normalizeAlertObservation(
      "PROVIDER_ERROR", "../foreign", "WARNING",
      "summary", "review", {}, evaluatedAt)).toThrow();
  });
});
