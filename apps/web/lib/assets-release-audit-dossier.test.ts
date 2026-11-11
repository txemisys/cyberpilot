import { describe, expect, it } from "vitest";
import {
  nextReleaseAuditState, parseReleaseAuditOptions,
  evaluateReleaseAuditDossier, verifyReleaseAuditDossier,
  auditIncidentPlaybook, summarizeReleaseAuditDossiers,
} from "./assets-release-audit-dossier";
import type { ReleaseAuditDossier } from "./assets-release-audit-dossier";

const stamp = new Date("2026-11-11T10:00:00.000Z");
const sourceId = "review_demo123";
const org = "tenant_demo123";
const reason = "Human operator reviewed the evidence and its limitations.";
function input() {
  return { reviewId: sourceId, maximumEvents: 100,
    includeMetadata: false, includeDecisionReasons: false };
}
function row(operation: string, revision: number, overrides:
  Record<string, unknown> = {}) {
  const states = ["PENDING", "IN_REVIEW", "REJECTED"];
  const action = "assets.release.review." + operation;
  const meta = operation === "created" ? {
    schema: "cyberpilot.assets.release.audit.v1",
    revision: 1, state: "PENDING",
    reason, evidenceBundleDigest: "a".repeat(64),
  } : {
    schema: "cyberpilot.assets.release.audit.v1",
    revisionBefore: revision - 1, revisionAfter: revision,
    from: states[revision - 2], to: states[revision - 1],
    reason, evidenceBundleDigest: "a".repeat(64),
    manualOperatorDecision: true,
    noLiveProviderAttestation: true,
    acknowledgements: [], blockersAtDecision: [],
  };
  return {
    id: "audit_" + revision, organizationId: org,
    actorType: "USER", actorUserId: "actor_demo123" as string | null,
    action, resourceType: "AssetReleaseReview",
    resourceId: sourceId, occurredAt: new Date(
      stamp.getTime() + revision * 1000),
    metadata: { ...meta, ...overrides },
  };
}
function review(overrides: Record<string, unknown> = {}) {
  return {
    id: sourceId, organizationId: org,
    importId: "import_demo123", inspectionId: "inspect_demo123",
    inventoryDigest: "a".repeat(64),
    inspectionDigest: "b".repeat(64),
    acceptanceDigest: "c".repeat(64),
    privacyDigest: "d".repeat(64),
    scenarioDigest: "e".repeat(64),
    evidenceBundleDigest: "a".repeat(64),
    policyDigest: "f".repeat(64),
    state: "REJECTED", revision: 3,
    operatorUserId: "actor_demo123",
    operatorReason: reason,
    operatorAcknowledgements: [],
    exclusions: [], acceptanceSnapshot: {},
    privacySnapshot: {}, scenarioSummary: {},
    createdAt: stamp, updatedAt: stamp,
    decidedAt: stamp,
    decidedByUserId: "actor_demo123",
    decisionReason: reason,
    ...overrides,
  };
}
function dossier(events: ReturnType<typeof row>[],
  options = input()) {
  return evaluateReleaseAuditDossier(
    review(), events, options, stamp);
}
describe("Fase 4 offline release audit dossier", () => {
  it("validates explicitly bounded and private audit inspection options", () => {
    expect(parseReleaseAuditOptions({ reviewId: sourceId }))
      .toEqual({ reviewId: sourceId, maximumEvents: 250,
        includeDecisionReasons: false, includeMetadata: false });
    expect(parseReleaseAuditOptions(input())).toEqual(input());
  });
  it.each([
    {}, { reviewId: "" }, { reviewId: "../foreign" },
    { reviewId: sourceId, organizationId: "foreign" },
    { reviewId: sourceId, maximumEvents: 0 },
    { reviewId: sourceId, maximumEvents: 1001 },
    { reviewId: sourceId, maximumEvents: 1.5 },
    { reviewId: sourceId, includeDecisionReasons: "true" },
    { reviewId: sourceId, includeMetadata: 1 },
    { reviewId: sourceId, offset: -1 },
  ])("rejects malformed or unauthorized options %j", value => {
    expect(() => parseReleaseAuditOptions(value)).toThrow();
  });
  it("implements all legal manual state transitions", () => {
    expect(nextReleaseAuditState(null, "CREATED")).toBe("PENDING");
    expect(nextReleaseAuditState("PENDING", "START_REVIEW"))
      .toBe("IN_REVIEW");
    expect(nextReleaseAuditState("IN_REVIEW", "ACCEPT_OFFLINE"))
      .toBe("ACCEPTED_OFFLINE");
    expect(nextReleaseAuditState("IN_REVIEW", "REJECT"))
      .toBe("REJECTED");
    expect(nextReleaseAuditState("PENDING", "REJECT"))
      .toBe("REJECTED");
    expect(nextReleaseAuditState("ACCEPTED_OFFLINE", "REOPEN"))
      .toBe("REOPENED");
    expect(nextReleaseAuditState("REJECTED", "REOPEN"))
      .toBe("REOPENED");
    expect(nextReleaseAuditState("REOPENED", "START_REVIEW"))
      .toBe("IN_REVIEW");
  });
  it("never allows implicit acceptance, resurrection or a duplicate creation", () => {
    expect(nextReleaseAuditState("PENDING", "ACCEPT_OFFLINE")).toBeNull();
    expect(nextReleaseAuditState("ACCEPTED_OFFLINE", "ACCEPT_OFFLINE"))
      .toBeNull();
    expect(nextReleaseAuditState("ACCEPTED_OFFLINE", "START_REVIEW"))
      .toBeNull();
    expect(nextReleaseAuditState("IN_REVIEW", "REOPEN")).toBeNull();
    expect(nextReleaseAuditState("PENDING", "CREATED")).toBeNull();
    expect(nextReleaseAuditState("REJECTED", "ACCEPT_OFFLINE"))
      .toBeNull();
  });
  it("reconstructs revisions but does not call fake source evidence valid", () => {
    const report = dossier([
      row("created", 1), row("start_review", 2), row("reject", 3),
    ]);
    expect(report.revisions.map(entry => entry.revision))
      .toEqual([1, 2, 3]);
    expect(report.revisions.map(entry => entry.to))
      .toEqual(["PENDING", "IN_REVIEW", "REJECTED"]);
    expect(report.evidenceConsistent).toBe(false);
    expect(report.decisionComplete).toBe(false);
    expect(report.acceptanceRecorded).toBe(false);
    expect(report.liveProviderChecked).toBe(false);
    expect(report.mutationCount).toBe(0);
    expect(verifyReleaseAuditDossier(report).valid).toBe(true);
  });
  it("does not expose decision reasons by default", () => {
    const report = dossier([row("created", 1)]);
    expect(report.events[0]?.reason).toBeNull();
    const withReasons = dossier([row("created", 1)],
      { ...input(), includeDecisionReasons: true });
    expect(withReasons.events[0]?.reason).toBe(reason);
  });
  it("detects missing first event and missing revisions", () => {
    const report = dossier([row("reject", 3)]);
    expect(report.issues.map(item => item.code))
      .toContain("MISSING_CREATION");
    expect(report.issues.map(item => item.code))
      .toContain("REVISION_GAP");
  });
  it("detects duplicate claimed revisions", () => {
    const report = dossier([
      row("created", 1),
      { ...row("created", 1), id: "duplicate_audit" },
    ]);
    expect(report.issues.map(item => item.code))
      .toContain("REVISION_REPEATED");
    expect(report.issues.map(item => item.code))
      .toContain("DUPLICATE_CREATION");
  });
  it("detects a tampered event metadata schema and missing actor", () => {
    const broken = { ...row("created", 1, { schema: "fake" }),
      actorUserId: null };
    const report = dossier([broken]);
    expect(report.issues.map(item => item.code))
      .toContain("EVENT_METADATA_INVALID");
    expect(report.issues.map(item => item.code))
      .toContain("ACTOR_MISSING");
  });
  it("detects a changed resource ID or tenant", () => {
    const changed = { ...row("created", 1),
      organizationId: "foreign", resourceId: "foreign_review" };
    const report = dossier([changed]);
    expect(report.issues.some(item =>
      item.code === "EVENT_RESOURCE_MISMATCH")).toBe(true);
  });
  it("keeps a tampered report from being exported as valid", () => {
    const report = dossier([row("created", 1)]);
    expect(verifyReleaseAuditDossier(report).valid).toBe(true);
    report.persistedRevision++;
    expect(verifyReleaseAuditDossier(report).valid).toBe(false);
  });
  it("rejects partial audit fetches before declaring history complete", () => {
    const report = evaluateReleaseAuditDossier(review(),
      [row("created", 1)], input(), stamp, false);
    expect(report.completeEventSet).toBe(false);
    expect(report.auditConsistent).toBe(false);
    expect(report.issues.map(item => item.code))
      .toContain("AUDIT_LIMIT_EXCEEDED");
  });
  it("rejects evaluation of a mismatched review identity", () => {
    expect(() => evaluateReleaseAuditDossier(
      review({ id: "another_review" }), [], input(), stamp))
      .toThrow();
  });
  it("counts only actually verified offline human decisions", () => {
    const reports = [dossier([row("created", 1)]),
      dossier([row("created", 1), row("start_review", 2)])];
    const summary = summarizeReleaseAuditDossiers(reports);
    expect(summary.reviewed).toBe(2);
    expect(summary.accepted).toBe(0);
    expect(summary.invalid).toBe(2);
    expect(summary.operations.some(row => row.name === "CREATED" &&
      row.count === 2)).toBe(true);
  });
  it("produces specific, conservative remediation instructions", () => {
    const report = dossier([]);
    const playbook = auditIncidentPlaybook(report);
    expect(playbook.some(row =>
      row.issue === "REVIEW_WITHOUT_AUDIT")).toBe(true);
    expect(playbook.some(row =>
      row.instruction.toLowerCase().includes("audit"))).toBe(true);
  });
});
