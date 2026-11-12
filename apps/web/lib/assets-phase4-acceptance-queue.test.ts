import { describe, expect, it } from "vitest";
import {
  parseAcceptanceQueuePolicy, assessAcceptanceQueueRun,
  assembleAcceptanceQueue, verifyAcceptanceQueue,
  acceptanceQueueActionPlan,
} from "./assets-phase4-acceptance-queue";
import { initialOperatorSteps } from "./assets-offline-acceptance-run-service";

const now = new Date("2026-11-12T10:00:00.000Z");
const org = "org-test-12345";
const hash = "a".repeat(64);
const reason = "An authorized human operator documented the source limitations.";
function run(extra: Record<string, unknown> = {}) {
  return {
    id: "run-test-12345", organizationId: org,
    importId: "import-test-12345", inspectionId: "inspect-test-12345",
    idempotencyKey: "idempotency-test-12345",
    dossierDigest: hash, sourceDigest: hash,
    state: "DRAFT", revision: 1,
    operatorUserId: "admin-test-12345", openingReason: reason,
    steps: initialOperatorSteps(), limitations: [],
    humanAcknowledgements: [], completedSteps: 0, blockedSteps: 0,
    startedAt: now, updatedAt: now,
    submittedAt: null, submittedByUserId: null,
    submittedReason: null, ...extra,
  };
}
function audit(extra: Record<string, unknown> = {}) {
  return {
    id: "audit-test-12345", organizationId: org,
    resourceType: "AssetOfflineAcceptanceRun",
    resourceId: "run-test-12345",
    action: "assetAcceptance.run.created", actorType: "USER",
    actorUserId: "admin-test-12345", occurredAt: now,
    metadata: { revision: 1, schema: "cyberpilot.assets.operator.acceptance.audit.v1" },
    ...extra,
  };
}
function assess(extra: Record<string, unknown> = {}) {
  return assessAcceptanceQueueRun({
    row: run(), reviews: [], audits: [audit()],
    releaseState: null, retentionState: null,
    policy: parseAcceptanceQueuePolicy(), now, ...extra,
  });
}
describe("Phase 4 tenant acceptance queue", () => {
  it("restricts bounded read-only query policy", () => {
    expect(parseAcceptanceQueuePolicy({})).toMatchObject({
      maxRuns: 20, offset: 0, maxAgeDays: 30,
      maxReviewerAgeDays: 14, maxAuditsPerRun: 100,
    });
  });
  it.each([
    { maxRuns: 0 }, { maxRuns: 51 },
    { maxRuns: "20" }, { offset: -1 },
    { offset: 100001 }, { maxAgeDays: 0 },
    { maxReviewerAgeDays: 3651 },
    { maxAuditsPerRun: 0 }, { maxAuditsPerRun: 1001 },
    { includeDrafts: "true" },
    { includeHumanReasons: "false" },
    { organizationId: "foreign" },
    { accepted: true }, { mergeAuthorized: true },
  ])("rejects invalid queue request %j", input => {
    expect(() => parseAcceptanceQueuePolicy(input)).toThrow();
  });
  it("keeps an unstarted run blocked and signed-off flags false", () => {
    const result = assess();
    expect(result.blockers).toBeGreaterThan(0);
    expect(result.signals.map(s => s.code))
      .toContain("STEPS_INCOMPLETE");
    expect(result.signals.map(s => s.code))
      .toContain("INDEPENDENT_REVIEW_MISSING");
    expect(result.signals.map(s => s.code))
      .toContain("RELEASE_DECISION_MISSING");
    expect(result.signals.map(s => s.code))
      .toContain("PRIVACY_DECISION_PENDING");
    expect(result.acceptedByProduct).toBe(false);
    expect(result.mergeAuthorized).toBe(false);
    expect(result.backupsErased).toBe(false);
    expect(result.externalProviderVerified).toBe(false);
  });
  it("identifies missing and extra audit events as a blocking discrepancy", () => {
    expect(assess({ audits: [] }).signals.map(s => s.code))
      .toContain("AUDIT_MISSING");
    expect(assess({ audits: [audit(), audit({
      id: "extra-audit-12345",
    })] }).signals.map(s => s.code))
      .toContain("AUDIT_REVISION_MISMATCH");
  });
  it("detects actor and foreign resource evidence", () => {
    const result = assess({ audits: [audit({
      organizationId: "foreign", actorUserId: null,
    })] });
    expect(result.signals.map(s => s.code))
      .toContain("AUDIT_RESOURCE_MISMATCH");
  });
  it("detects an aged operator record without inventing a scheduler", () => {
    const stale = assess({
      row: run({ updatedAt: new Date("2026-01-01T00:00:00.000Z") }),
    });
    expect(stale.ageDays).toBeGreaterThan(30);
    expect(stale.signals.map(s => s.code)).toContain("RUN_AGE_LIMIT");
  });
  it("distinguishes present release review from actual human approval", () => {
    const result = assess({
      releaseState: "IN_REVIEW",
      retentionState: "IN_REVIEW",
    });
    expect(result.signals.map(s => s.code))
      .toContain("RELEASE_DECISION_PENDING");
    expect(result.signals.map(s => s.code))
      .toContain("RETENTION_EXCEPTION_OPEN");
  });
  it("produces page-only totals and action prioritization", () => {
    const first = assess();
    const second = assess({ row: run({
      id: "run-test-12346", state: "IN_PROGRESS",
    }), audits: [audit({ resourceId: "run-test-12346" })] });
    const report = assembleAcceptanceQueue({
      organizationId: org, rows: [first, second], total: 4,
      policy: parseAcceptanceQueuePolicy({ maxRuns: 2 }), evaluatedAt: now,
    });
    expect(report.returned).toBe(2);
    expect(report.moreResults).toBe(true);
    expect(report.summary.coverage).toBe("PAGE_ONLY");
    expect(report.summary.blockedRuns).toBe(2);
    expect(verifyAcceptanceQueue(report).valid).toBe(true);
    const actions = acceptanceQueueActionPlan(report);
    expect(actions).toHaveLength(2);
    expect(actions.every(a =>
      a.verifiedByHuman === false &&
      a.actionExecuted === false)).toBe(true);
  });
  it("fails closed on foreign-tenant queue rows", () => {
    expect(() => assembleAcceptanceQueue({
      organizationId: org,
      rows: [assess({ row: run({
        organizationId: "other-org",
      }) })],
      policy: parseAcceptanceQueuePolicy(), total: 1,
      evaluatedAt: now,
    })).toThrow();
  });
  it("detects tampering with summary or approval flags", () => {
    const report = assembleAcceptanceQueue({
      organizationId: org, policy: parseAcceptanceQueuePolicy(),
      rows: [assess()], total: 1, evaluatedAt: now,
    });
    report.summary.blockedRuns = 0;
    expect(verifyAcceptanceQueue(report).valid).toBe(false);
    expect(() => acceptanceQueueActionPlan(report)).toThrow();
  });
  it("cannot silently grant phase approval even if the local report is edited", () => {
    const report = assembleAcceptanceQueue({
      organizationId: org, policy: parseAcceptanceQueuePolicy(),
      rows: [assess()], total: 1, evaluatedAt: now,
    });
    report.rows[0]!.mergeAuthorized = true as false;
    expect(verifyAcceptanceQueue(report).valid).toBe(false);
  });
});
