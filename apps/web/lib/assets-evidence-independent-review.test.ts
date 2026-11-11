import { describe, expect, it } from "vitest";
import {
  parseEvidenceReviewCreate, parseEvidenceReviewRevision,
  parseEvidenceReviewQuery, referenceFingerprint,
  inspectEvidenceReview, verifyEvidenceAttestation,
  summarizeIndependentReviews, independenceReconciliationPlan,
} from "./assets-evidence-independent-review";
import { initialOperatorSteps } from "./assets-offline-acceptance-run-service";
const hash = "a".repeat(64);
const reason = "I independently compared the recorded CSV and inventory identifiers.";
const steps = initialOperatorSteps();
steps[0] = {
  ...steps[0]!, status: "EVIDENCE_RECORDED",
  evidenceId: "record-00001",
  evidenceDescription: "A persisted inventory report with exact source rows",
  recordedByUserId: "operator-0001",
  recordedAt: "2026-11-11T12:00:00.000Z",
  reason, limitations: [],
};
const command = (changes: Record<string, unknown> = {}) => ({
  runId: "run-12345",
  stepCode: "CSV_IMPORT_REVIEW",
  expectedRunRevision: 4,
  expectedEvidenceDigest: referenceFingerprint(steps[0]!),
  state: "REFERENCE_MATCHED",
  reason,
  referenceLocation: "secure-internal-file-0001",
  referenceObservedAt: "2026-11-11T12:10:00.000Z",
  crossCheckedIdentifiers: ["inventory-row-0001"],
  limitations: [],
  ...changes,
});
function row(changes: Record<string, unknown> = {}) {
  return {
    id: "review-0001", organizationId: "org-0001",
    acceptanceRunId: "run-12345", stepCode: "CSV_IMPORT_REVIEW",
    sourceRunRevision: 4,
    evidenceDigest: referenceFingerprint(steps[0]!),
    reviewState: "REFERENCE_MATCHED", revision: 1,
    originalOperatorUserId: "operator-0001",
    reviewerUserId: "reviewer-0001",
    reviewerReason: reason,
    referenceLocation: "secure-internal-file-0001",
    referenceObservedAt: new Date("2026-11-11T12:10:00.000Z"),
    crossCheckedIdentifiers: ["inventory-row-0001"],
    limitations: [],
    createdAt: new Date("2026-11-11T12:10:00.000Z"),
    updatedAt: new Date("2026-11-11T12:10:00.000Z"),
    ...changes,
  };
}
describe("Phase 4 independent evidence corroboration", () => {
  it("parses exact source-bound review commands", () => {
    expect(parseEvidenceReviewCreate(command())).toMatchObject({
      runId: "run-12345", expectedRunRevision: 4,
      state: "REFERENCE_MATCHED",
    });
  });
  it.each([
    { runId: "../other" }, { stepCode: "FABRICATED" },
    { expectedRunRevision: 0 }, { expectedRunRevision: "4" },
    { expectedEvidenceDigest: "bad" },
    { state: "LEGALLY_APPROVED" }, { reason: "too short" },
    { crossCheckedIdentifiers: [] },
    { crossCheckedIdentifiers: ["a"] },
    { referenceObservedAt: "tomorrow" },
    { organizationId: "foreign" }, { reviewerUserId: "forged" },
    { externalSignatureVerified: true },
    { signedOff: true },
  ])("rejects unauthorized or invalid evidence claims %j", bad => {
    expect(() => parseEvidenceReviewCreate(command(bad))).toThrow();
  });
  it("requires explicit review CAS for updates", () => {
    expect(parseEvidenceReviewRevision({
      ...command(), reviewId: "review-12345",
      expectedReviewRevision: 3,
    })).toMatchObject({ expectedReviewRevision: 3 });
    expect(() => parseEvidenceReviewRevision({
      ...command(), reviewId: "review-12345",
      expectedReviewRevision: 0,
    })).toThrow();
  });
  it("does not leak reason unless explicitly selected", () => {
    expect(parseEvidenceReviewQuery({ runId: "run-12345" }))
      .toMatchObject({
        includeStale: true, includeOperatorReason: false,
      });
    expect(() => parseEvidenceReviewQuery({
      runId: "run-12345", includeOperatorReason: "yes",
    })).toThrow();
  });
  it("creates a SHA256 fingerprint of the complete operator reference", () => {
    const original = referenceFingerprint(steps[0]!);
    expect(original).toMatch(/^[a-f0-9]{64}$/);
    expect(referenceFingerprint({
      ...steps[0]!, evidenceDescription: "Altered report reference",
    })).not.toBe(original);
  });
  it("recognizes a matched reference without external authorization", () => {
    const checked = inspectEvidenceReview({
      organizationId: "org-0001", runId: "run-12345", runRevision: 4,
    }, steps[0]!, row(), new Date("2026-11-11T12:15:00.000Z"));
    expect(checked.sourceVerified).toBe(true);
    expect(checked.referenceStillMatches).toBe(true);
    expect(checked.reviewerIsIndependent).toBe(true);
    expect(checked.externalSignatureVerified).toBe(false);
    expect(checked.operatorObservationAuthenticated).toBe(false);
    expect(verifyEvidenceAttestation(checked).valid).toBe(true);
  });
  it("rejects self review even when the reference matches", () => {
    const checked = inspectEvidenceReview({
      organizationId: "org-0001", runId: "run-12345", runRevision: 4,
    }, steps[0]!, row({ reviewerUserId: "operator-0001" }));
    expect(checked.sourceVerified).toBe(false);
    expect(checked.issues.some(i =>
      i.code === "REVIEWER_SAME_AS_OPERATOR")).toBe(true);
  });
  it("detects changed source fingerprints", () => {
    const checked = inspectEvidenceReview({
      organizationId: "org-0001", runId: "run-12345", runRevision: 5,
    }, { ...steps[0]!, evidenceId: "different-evidence" }, row());
    expect(checked.sourceVerified).toBe(false);
    expect(checked.issues.some(i => i.code === "REFERENCE_CHANGED")).toBe(true);
  });
  it("detects missing, disputed and stale attestations", () => {
    for (const [record, issue] of [
      [null, "REVIEW_NOT_CHECKED"],
      [row({ reviewState: "DISPUTED" }), "REVIEW_DISPUTED"],
      [row({ reviewState: "STALE_REFERENCE" }), "REVIEW_STALE"],
    ] as const) {
      const checked = inspectEvidenceReview({
        organizationId: "org-0001", runId: "run-12345", runRevision: 4,
      }, steps[0]!, record);
      expect(checked.sourceVerified).toBe(false);
      expect(checked.issues.some(i => i.code === issue)).toBe(true);
    }
  });
  it("detects altered attestations and fake external signatures", () => {
    const checked = inspectEvidenceReview({
      organizationId: "org-0001", runId: "run-12345", runRevision: 4,
    }, steps[0]!, row());
    checked.result = "DISPUTED";
    expect(verifyEvidenceAttestation(checked).valid).toBe(false);
  });
  it("summarizes nine independent checks without claiming signoff", () => {
    const summary = summarizeIndependentReviews({
      organizationId: "org-0001", runId: "run-12345",
      revision: 4, state: "IN_PROGRESS",
      steps, reviews: [row()],
    });
    expect(summary.independentReferencesMatched).toBe(1);
    expect(summary.missing).toBe(8);
    expect(summary.readyForHumanSignoff).toBe(false);
    expect(summary.externalOriginVerified).toBe(false);
    expect(summary.mergeAuthorized).toBe(false);
    expect(independenceReconciliationPlan(summary)).toHaveLength(8);
  });
});
