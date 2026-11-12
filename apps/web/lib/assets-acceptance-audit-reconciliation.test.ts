import { describe, expect, it } from "vitest";
import {
  parseReconciliationOptions, reconstructAcceptanceAudit,
  verifyAuditReconciliation, auditReconciliationManifest,
  auditReconciliationPlaybook,
} from "./assets-acceptance-audit-reconciliation";
import { initialOperatorSteps } from "./assets-offline-acceptance-run-service";
import { referenceFingerprint } from "./assets-evidence-independent-review";

const now = new Date("2026-11-11T13:00:00.000Z");
const reason = "A documented operator checked the persisted source evidence carefully.";
const org = "org-demo01";
const id = "run-demo01";
const hash = "a".repeat(64);
function run(changes: Record<string, unknown> = {}) {
  return {
    id, organizationId: org, importId: "import-demo01",
    inspectionId: "inspect-demo01",
    revision: 1, state: "DRAFT", sourceDigest: hash,
    dossierDigest: hash, operatorUserId: "admin-demo01",
    idempotencyKey: "audit-source-demo01", openingReason: reason,
    limitations: [], humanAcknowledgements: [], updatedAt: now,
    steps: initialOperatorSteps(),
    completedSteps: 0, blockedSteps: 0, startedAt: now,
    submittedAt: null, submittedByUserId: null, submittedReason: null,
    ...changes,
  };
}
function event(action: string, revision: number,
  changes: Record<string, unknown> = {}) {
  return {
    id: "audit-event-" + revision, organizationId: org,
    resourceType: "AssetOfflineAcceptanceRun", resourceId: id,
    action, actorType: "USER", actorUserId: "admin-demo01",
    occurredAt: new Date(now.getTime() + revision * 1000),
    metadata: action.endsWith(".created") ? {
      schema: "cyberpilot.assets.operator.acceptance.audit.v1",
      revision: 1, state: "DRAFT", sourceDigest: hash,
      dossierDigest: hash, signedOff: false, mergeAuthorized: false,
    } : {
      schema: "cyberpilot.assets.operator.acceptance.audit.v1",
      revisionBefore: revision - 1, revisionAfter: revision,
      from: "DRAFT", to: "IN_PROGRESS",
      sourceDigest: hash, dossierDigest: hash,
      signedOff: false, mergeAuthorized: false,
    }, ...changes,
  };
}
function report(changes: Record<string, unknown> = {}) {
  const input = {
    run: run(), reviews: [],
    runEvents: [event("assetAcceptance.run.created", 1)],
    reviewEvents: [], runTotal: 1, reviewTotal: 0,
    checkedAt: now, ...changes,
  };
  return reconstructAcceptanceAudit(input);
}
describe("Fase 4 independent operator/reviewer CAS audit reconstruction", () => {
  it("parses only scoped bounded requests", () => {
    expect(parseReconciliationOptions({ runId: id })).toEqual({
      runId: id, maximumRunEvents: 250,
      maximumReviewEvents: 250, includeEventDetails: false,
    });
  });
  it.each([
    {}, { runId: "../other" }, { runId: "x" },
    { runId: id, organizationId: "foreign" },
    { runId: id, maximumRunEvents: 0 },
    { runId: id, maximumReviewEvents: 1001 },
    { runId: id, maximumRunEvents: "10" },
    { runId: id, includeEventDetails: "true" },
    { runId: id, legalSignoffVerified: true },
  ])("rejects malformed reconciliation requests %j", value => {
    expect(() => parseReconciliationOptions(value)).toThrow();
  });
  it("reconstructs a single valid pending audit without a human approval", () => {
    const result = report();
    expect(result.runAuditComplete).toBe(true);
    expect(result.localAuditIntegrityVerified).toBe(true);
    expect(result.readyForIndependentHumanDecision).toBe(false);
    expect(result.externallySigned).toBe(false);
    expect(result.legallyApproved).toBe(false);
    expect(result.mergeAuthorized).toBe(false);
    expect(result.noDatabaseWrites).toBe(true);
    expect(verifyAuditReconciliation(result).valid).toBe(true);
  });
  it("blocks absent first audit and missing revisions", () => {
    const result = report({ runEvents: [], runTotal: 0 });
    expect(result.issues.map(x => x.code)).toContain("MISSING_AUDIT");
    expect(result.issues.map(x => x.code)).toContain("REVISION_GAP");
    expect(result.runAuditComplete).toBe(false);
  });
  it("blocks duplicate or skipped operator CAS revisions", () => {
    const result = report({
      run: run({ revision: 3, state: "IN_PROGRESS" }),
      runEvents: [
        event("assetAcceptance.run.created", 1),
        event("assetAcceptance.run.start", 2),
        { ...event("assetAcceptance.run.start", 2),
          id: "audit-event-duplicate" },
      ],
      runTotal: 3,
    });
    expect(result.issues.map(x => x.code)).toContain("DUPLICATE_REVISION");
  });
  it("rejects incomplete audit query instead of presenting partial success", () => {
    const result = report({ runTotal: 2 });
    expect(result.runAuditComplete).toBe(false);
    expect(result.issues.some(x =>
      x.code === "TRUNCATED_AUDIT")).toBe(true);
  });
  it("detects a mismatched organization and unknown action", () => {
    const result = report({
      runEvents: [event("assetAcceptance.run.unknown", 1, {
        organizationId: "foreign",
      })],
    });
    expect(result.issues.map(x => x.code)).toContain("FOREIGN_TENANT");
    expect(result.issues.map(x => x.code)).toContain("UNEXPECTED_ACTION");
  });
  it("blocks fake event-level authorization and unauthenticated actor", () => {
    const result = report({
      runEvents: [event("assetAcceptance.run.created", 1, {
        actorUserId: null,
        metadata: {
          schema: "cyberpilot.assets.operator.acceptance.audit.v1",
          revision: 1, state: "DRAFT", sourceDigest: hash,
          dossierDigest: hash, signedOff: true, mergeAuthorized: true,
        },
      })],
    });
    expect(result.issues.map(x => x.code))
      .toContain("AUDIT_UNSUPPORTED_CLAIM");
    expect(result.issues.map(x => x.code)).toContain("ACTOR_MISSING");
  });
  it("checks persisted review against current operator reference", () => {
    const steps = initialOperatorSteps();
    steps[0] = {
      ...steps[0]!, status: "EVIDENCE_RECORDED",
      evidenceId: "source-evidence-0001",
      evidenceDescription: "Operator reviewed source report reference.",
      recordedByUserId: "admin-demo01",
      recordedAt: now.toISOString(), reason,
    };
    const review = {
      id: "review-demo01", organizationId: org, acceptanceRunId: id,
      stepCode: "CSV_IMPORT_REVIEW", sourceRunRevision: 2,
      evidenceDigest: referenceFingerprint(steps[0]!),
      reviewState: "REFERENCE_MATCHED", revision: 1,
      originalOperatorUserId: "admin-demo01",
      reviewerUserId: "reviewer-demo01",
      reviewerReason: reason,
      referenceLocation: "internal-record-0001",
      referenceObservedAt: now, crossCheckedIdentifiers: ["row-0001"],
      limitations: [], createdAt: now, updatedAt: now,
    };
    const reviewEvent = {
      id: "review-audit-0001", organizationId: org,
      resourceType: "AssetEvidenceReview",
      resourceId: review.id, action: "assetEvidence.review.created",
      actorType: "USER", actorUserId: "reviewer-demo01", occurredAt: now,
      metadata: {
        schema: "cyberpilot.assets.evidence.review.audit.v1",
        runId: id, stepCode: "CSV_IMPORT_REVIEW",
        sourceRunRevision: 2, state: "REFERENCE_MATCHED",
        evidenceDigest: review.evidenceDigest,
        reviewerId: "reviewer-demo01",
      },
    };
    const result = report({
      run: run({ revision: 2, state: "IN_PROGRESS",
        steps, completedSteps: 1 }),
      reviews: [review],
      runEvents: [
        event("assetAcceptance.run.created", 1),
        event("assetAcceptance.run.start", 2),
      ],
      runTotal: 2, reviewEvents: [reviewEvent], reviewTotal: 1,
    });
    expect(result.reviewCount).toBe(1);
    expect(result.reviewReferencesCurrent).toBe(true);
    expect(result.independentlyReviewedSteps).toBe(1);
    expect(result.readyForIndependentHumanDecision).toBe(false);
  });
  it("reports independent review self-approval and stale source evidence", () => {
    const steps = initialOperatorSteps();
    steps[0] = {
      ...steps[0]!, status: "EVIDENCE_RECORDED",
      evidenceId: "source-evidence-0001",
      evidenceDescription: "Operator reviewed source report reference.",
      recordedByUserId: "admin-demo01",
      recordedAt: now.toISOString(), reason,
    };
    const review = {
      id: "review-demo01", organizationId: org, acceptanceRunId: id,
      stepCode: "CSV_IMPORT_REVIEW", sourceRunRevision: 1,
      evidenceDigest: "f".repeat(64), reviewState: "REFERENCE_MATCHED",
      revision: 1, originalOperatorUserId: "admin-demo01",
      reviewerUserId: "admin-demo01", reviewerReason: reason,
      referenceLocation: null, referenceObservedAt: now,
      crossCheckedIdentifiers: ["row-0001"], limitations: [],
      createdAt: now, updatedAt: now,
    };
    const result = report({
      run: run({ steps, completedSteps: 1 }),
      reviews: [review],
      reviewTotal: 0,
    });
    expect(result.issues.map(x => x.code)).toContain("SELF_REVIEW");
    expect(result.issues.map(x => x.code)).toContain("REVIEW_STALE");
    expect(result.issues.map(x => x.code)).toContain("REVIEW_AUDIT_MISSING");
  });
  it("detects modified manifest and refuses export of its digest", () => {
    const result = report();
    expect(auditReconciliationManifest(result).externalSignatureVerified)
      .toBe(false);
    result.reviewCount++;
    expect(verifyAuditReconciliation(result).valid).toBe(false);
    expect(() => auditReconciliationManifest(result)).toThrow();
  });
  it("offers specific manual investigation rather than automatic repair", () => {
    const result = report({ runEvents: [], runTotal: 0 });
    const playbook = auditReconciliationPlaybook(result);
    expect(playbook).not.toHaveLength(0);
    expect(playbook.every(x => x.noAutomaticRepair)).toBe(true);
    expect(playbook.some(x => x.code === "MISSING_AUDIT")).toBe(true);
  });
});
