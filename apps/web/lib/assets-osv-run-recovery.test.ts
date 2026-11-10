import { describe, expect, it } from "vitest";
import {
  parseOsvRunRecoveryPolicy, parseOsvRunRecoveryCommand,
  classifyRunClaim, toOsvRunRecoveryCandidate,
} from "./assets-osv-run-recovery";
import {
  hypotheticalWorkerIdentity, parseOsvWorkerReadinessPolicy,
  evaluateWorkerSchedule,
} from "./assets-osv-worker-readiness";

const now = new Date("2026-11-10T12:00:00.000Z");
const run = {
  id: "claim-recovery-run-12345",
  organizationId: "org-run-12345",
  scheduleId: "schedule-run-12345",
  slotAt: new Date("2026-11-10T10:00:00.000Z"),
  claimedAt: new Date("2026-11-10T10:01:00.000Z"),
  claimExpiresAt: new Date("2026-11-10T10:30:00.000Z"),
  state: "CLAIMED",
  commandDigest: "a".repeat(64),
  inspectionId: null,
};
const command = {
  runId: run.id, confirmRunId: run.id,
  expectedCommandDigest: "a".repeat(64),
  minimumExpiredMinutes: 30,
  reason: "Worker stopped unexpectedly after the remote call was initiated.",
  acknowledgeUnknownNetwork: true,
};
describe("OSV schedule incident input boundaries", () => {
  it("defaults to conservative claim-expiry investigation delay", () => {
    expect(parseOsvRunRecoveryPolicy()).toMatchObject({
      minimumExpiredMinutes: 30,
      maximumListed: 50,
      includeRecentlyClaimed: false,
    });
  });
  it.each([
    { minimumExpiredMinutes: 0 },
    { minimumExpiredMinutes: 14 },
    { minimumExpiredMinutes: 10081 },
    { maximumListed: 0 },
    { maximumListed: 101 },
    { maximumListed: 1.5 },
    { includeRecentlyClaimed: "true" },
    { unknown: 100 },
  ])("rejects invalid preview policies %j", patch => {
    expect(() => parseOsvRunRecoveryPolicy(patch)).toThrow();
  });
  it("requires exact double entry and provider uncertainty acknowledgment", () => {
    expect(parseOsvRunRecoveryCommand(command)).toEqual(command);
    expect(() => parseOsvRunRecoveryCommand({
      ...command, confirmRunId: "something-else",
    })).toThrow();
    expect(() => parseOsvRunRecoveryCommand({
      ...command, acknowledgeUnknownNetwork: false,
    })).toThrow();
    expect(() => parseOsvRunRecoveryCommand({
      ...command, acknowledgeUnknownNetwork: undefined,
    })).toThrow();
  });
  it.each([
    { runId: "x" }, { expectedCommandDigest: "bad" },
    { expectedCommandDigest: "z".repeat(64) },
    { reason: "short" },
    { reason: "contains\u0000control" },
    { minimumExpiredMinutes: 1 },
    { reason: "a".repeat(501) },
    { unknownField: true },
  ])("rejects malformed recovery command %j", patch => {
    expect(() => parseOsvRunRecoveryCommand({
      ...command, ...patch,
    })).toThrow();
  });
  it("allows classification only after expiry plus separate investigation delay", () => {
    expect(classifyRunClaim(run, now, 30)).toMatchObject({
      eligible: true, expiredMinutes: 90,
    });
    expect(classifyRunClaim({
      ...run, claimExpiresAt: new Date("2026-11-10T11:45:00.000Z"),
    }, now, 30).eligible).toBe(false);
  });
  it("never classifies active, already terminated or future claims", () => {
    expect(classifyRunClaim({
      ...run, state: "COMPLETE",
    }, now, 30).eligible).toBe(false);
    expect(classifyRunClaim({
      ...run, state: "UNKNOWN",
    }, now, 30).eligible).toBe(false);
    expect(classifyRunClaim({
      ...run, claimExpiresAt: new Date("2026-11-10T13:00:00.000Z"),
    }, now, 30).eligible).toBe(false);
  });
  it("attaches quota provenance to historical run without interpretation", () => {
    const candidate = toOsvRunRecoveryCandidate(
      run, now, 30, { state: "RESERVED", reservedRequests: 12 },
      "inspection-persisted-12345");
    expect(candidate.eligible).toBe(true);
    expect(candidate.associatedQuotaRequests).toBe(12);
    expect(candidate.associatedQuotaState).toBe("RESERVED");
    expect(candidate.associatedInspectionId)
      .toBe("inspection-persisted-12345");
    expect(candidate.commandDigest).toBe("a".repeat(64));
    expect(candidate.sourceRequestKey).toMatch(/^scheduled-[a-f0-9]{48}$/);
  });
});
describe("OSV worker readiness policy and least-privilege contract", () => {
  const baseSchedule = {
    id: "schedule-example-12345", name: "Provider check",
    enabled: true, outboundConsent: true,
    consentedAt: new Date("2026-11-09T09:00:00.000Z"),
    nextDueAt: new Date("2026-11-10T11:00:00.000Z"),
    cadenceMinutes: 1440, revision: 2,
    consentDigest: "a".repeat(64),
    inventoryImportId: "inventory-12345",
  };
  const policy = parseOsvWorkerReadinessPolicy({});
  it("uses bounded and conservative defaults", () => {
    expect(policy).toMatchObject({
      maxSchedules: 50, lookbackHours: 168,
      staleClaimMinutes: 30, maximumPendingPerOrg: 1,
      requireNoStalledRuns: true,
      requireNoUnsettledQuota: true,
    });
  });
  it.each([
    { maxSchedules: 51 }, { lookbackHours: 0 },
    { lookbackHours: 721 }, { staleClaimMinutes: 1 },
    { maximumPendingPerOrg: 11 },
    { requireNoStalledRuns: "yes" },
    { requireNoUnsettledQuota: null },
    { unrecognized: "unexpected" },
  ])("rejects unsafe worker policies %j", patch => {
    expect(() => parseOsvWorkerReadinessPolicy(patch)).toThrow();
  });
  it("proposes a restricted service identity without granting it", () => {
    const identity = hypotheticalWorkerIdentity("organization-12345");
    expect(identity).toMatchObject({
      actorType: "SERVICE", mayManageSchedules: false,
      mayOverrideQuota: false, mayAlterFindings: false,
      mayUpdateCyberScore: false,
      requiresSignedDispatch: true,
      requiresOperationalActivation: true,
      maximumClaimsPerPoll: 1,
      maximumParallelClaimsPerTenant: 1,
    });
    expect(identity.permittedActions).not.toContain(
      "assets.osv.schedule.enable");
  });
  it("labels consented due schedule as manually reviewable", () => {
    const result = evaluateWorkerSchedule(
      baseSchedule, now, true, true, 0, 0, policy);
    expect(result.eligibleForManualReview).toBe(true);
    expect(result.blockingReasons).toEqual([]);
  });
  it("does not accept disabled or unconsented schedules", () => {
    const result = evaluateWorkerSchedule({
      ...baseSchedule, enabled: false, outboundConsent: false,
      consentedAt: null,
    }, now, true, true, 0, 0, policy);
    expect(result.eligibleForManualReview).toBe(false);
    expect(result.blockingReasons.join(" ")).toMatch(/disabled/i);
    expect(result.blockingReasons.join(" ")).toMatch(/consent/i);
  });
  it("blocks retired inventory, disputed consent and old due date", () => {
    const result = evaluateWorkerSchedule({
      ...baseSchedule,
      nextDueAt: new Date("2026-09-01T12:00:00.000Z"),
    }, now, false, false, 0, 0, policy);
    expect(result.eligibleForManualReview).toBe(false);
    expect(result.staleDue).toBe(true);
    expect(result.blockingReasons.join(" ")).toMatch(/inventory/i);
    expect(result.blockingReasons.join(" ")).toMatch(/authorization/i);
  });
  it("blocks stale claims and unsettled quota after a crash", () => {
    const result = evaluateWorkerSchedule(
      baseSchedule, now, true, true, 2, 1, policy);
    expect(result.eligibleForManualReview).toBe(false);
    expect(result.blockingReasons).toHaveLength(2);
    expect(result.blockingReasons.join(" ")).toMatch(/quota/i);
  });
  it("permits pure readiness policy overrides but never installs a worker", () => {
    const relaxed = parseOsvWorkerReadinessPolicy({
      requireNoStalledRuns: false,
      requireNoUnsettledQuota: false,
    });
    const result = evaluateWorkerSchedule(
      baseSchedule, now, true, true, 2, 1, relaxed);
    expect(result.eligibleForManualReview).toBe(true);
  });
});
