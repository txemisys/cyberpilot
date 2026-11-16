import { describe, expect, it } from "vitest";
import {
  buildBaselineDevelopmentDossier,
  compareBaselineDevelopmentDossiers,
  exportBaselineDevelopmentDossier,
  verifyBaselineDevelopmentDossier,
  type BaselineDossierInput,
} from "./baseline-development-dossier";
const digest = (c: string) => c.repeat(64);
const time = "2026-11-16T09:00:00.000Z";
function fixture(): BaselineDossierInput {
  return {
    organizationId: "org-baseline",
    generatedAt: "2026-11-16T10:00:00.000Z",
    queryCaps: {
      drafts: 1, revisions: 100, reviews: 100,
      reviewEvents: 100, actions: 100, actionEvents: 100,
    },
    sourceCounts: {
      drafts: 1, revisions: 2, reviews: 1,
      reviewEvents: 1, actions: 1, actionEvents: 1,
    },
    draft: {
      id: "draft-source", organizationId: "org-baseline",
      revision: 2, status: "SUBMITTED",
      responsesDigest: digest("a"),
      submittedAt: time, updatedAt: time,
    },
    revisions: [{
      id: "revision-create",
      organizationId: "org-baseline",
      draftId: "draft-source", revision: 1,
      eventKind: "CREATE", responsesDigest: digest("b"),
      reportDigest: null, storedReportValid: false,
      reportOrganizationId: null,
      actorUserId: "actor-owner", createdAt: time,
    }, {
      id: "revision-submit",
      organizationId: "org-baseline",
      draftId: "draft-source", revision: 2,
      eventKind: "SUBMIT", responsesDigest: digest("a"),
      reportDigest: digest("c"), storedReportValid: true,
      reportOrganizationId: "org-baseline",
      actorUserId: "actor-owner", createdAt: time,
    }],
    reviews: [{
      id: "review-one",
      organizationId: "org-baseline",
      draftId: "draft-source", sourceRevision: 2,
      reportDigest: digest("c"), revision: 1,
      state: "TECHNICALLY_REVIEWED",
      scope: "DEVELOPMENT_REVIEW",
      issueCount: 0, blockingIssueCount: 0,
      findingsDigest: digest("d"),
      reviewerUserId: "actor-reviewer",
      completedAt: time, updatedAt: time,
    }],
    reviewEvents: [{
      id: "review-event-one",
      organizationId: "org-baseline",
      reviewId: "review-one", revision: 1,
      action: "COMPLETE", previousState: "IN_REVIEW",
      newState: "TECHNICALLY_REVIEWED",
      findingsDigest: digest("d"),
      actorUserId: "actor-reviewer",
      createdAt: time,
    }],
    actions: [{
      id: "action-one", organizationId: "org-baseline",
      questionId: "sample-question", sourceDraftRevision: 2,
      revision: 1, status: "OPEN",
      ownerUserId: null, evidenceReference: null,
      dueAt: null, completedAt: null, updatedAt: time,
    }],
    actionEvents: [{
      id: "action-event-one", organizationId: "org-baseline",
      followUpId: "action-one", revision: 1,
      action: "INITIALIZE", previousStatus: "NONE",
      nextStatus: "OPEN", actorUserId: "actor-owner",
      createdAt: time,
    }],
  };
}
describe("Baseline development dossier integrity", () => {
  it("reconciles versioned evidence without claiming customer approval", () => {
    const report = buildBaselineDevelopmentDossier(fixture());
    expect(report.verdict).toBe("TECHNICALLY_TRACEABLE");
    expect(report.gates.every(x => x.state === "PASS")).toBe(true);
    expect(report.sourceCompleteness.allTenantScoped).toBe(true);
    expect(report.sourceCompleteness.revisionsContiguous).toBe(true);
    expect(report.actions.total).toBe(1);
    expect(report.actions.independentRemediationsVerified).toBe(0);
    expect(report.customerApprovalRecorded).toBe(false);
    expect(report.independentlyValidatedSecurityControls).toBe(0);
    expect(verifyBaselineDevelopmentDossier(report, "org-baseline"))
      .toEqual({ valid: true, errors: [] });
  });
  it("blocks cross tenant sources", () => {
    const data = fixture();
    data.actions[0]!.organizationId = "org-foreign";
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.verdict).toBe("BLOCKED");
    expect(report.gates.find(x => x.id === "TENANT_BOUNDARY")?.state)
      .toBe("BLOCK");
    expect(report.customerApprovalRecorded).toBe(false);
  });
  it("blocks reports which have not passed independent report verification", () => {
    const data = fixture();
    data.revisions[1]!.storedReportValid = false;
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "SUBMITTED_REPORT_INTEGRITY")?.state).toBe("BLOCK");
  });
  it("blocks missing revision history", () => {
    const data = fixture();
    data.revisions.shift();
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x => x.id === "REVISION_SEQUENCE")?.state)
      .toBe("BLOCK");
  });
  it("blocks duplicate internal reviews for the same source", () => {
    const data = fixture();
    data.reviews.push({ ...data.reviews[0]!, id: "review-two" });
    data.sourceCounts.reviews = 2;
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "ONE_REVIEW_PER_SUBMISSION")?.state).toBe("BLOCK");
  });
  it("detects a missing immutable review event", () => {
    const data = fixture();
    data.reviewEvents = [];
    data.sourceCounts.reviewEvents = 0;
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "REVIEW_CAS_AUDIT_SEQUENCE")?.state).toBe("BLOCK");
  });
  it("detects impossible completed review with open blockers", () => {
    const data = fixture();
    data.reviews[0]!.issueCount = 1;
    data.reviews[0]!.blockingIssueCount = 1;
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "REVIEW_STATE_CONSERVATIVE")?.state).toBe("BLOCK");
  });
  it("detects missing action sequence and changed action status", () => {
    const data = fixture();
    data.actions[0]!.revision = 2;
    data.actions[0]!.status = "IN_PROGRESS";
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "ACTION_CAS_AUDIT_SEQUENCE")?.state).toBe("BLOCK");
  });
  it("reports overdue and unowned work as advisory, not remediated", () => {
    const data = fixture();
    data.actions[0]!.status = "IN_PROGRESS";
    data.actionEvents[0]!.nextStatus = "IN_PROGRESS";
    data.actions[0]!.dueAt = "2026-11-15T10:00:00.000Z";
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.verdict).toBe("REVIEW_REQUIRED");
    expect(report.actions.overdue).toBe(1);
    expect(report.actions.missingOwners).toBe(1);
    expect(report.actualRemediationVerified).toBe(false);
  });
  it("detects truncated bounded source collections", () => {
    const data = fixture();
    data.sourceCounts.revisions = 101;
    const report = buildBaselineDevelopmentDossier(data);
    expect(report.gates.find(x =>
      x.id === "BOUNDED_SOURCE_COMPLETENESS")?.state).toBe("BLOCK");
  });
  it("rejects post-processing modifications despite unchanged digest", () => {
    const report = buildBaselineDevelopmentDossier(fixture());
    report.gates[0]!.state = "BLOCK";
    expect(verifyBaselineDevelopmentDossier(report).errors)
      .toContain("DOSSIER_INTEGRITY_INVALID");
  });
  it("rejects invented legal approval flags", () => {
    const report = buildBaselineDevelopmentDossier(fixture());
    const tampered = {
      ...report, customerApprovalRecorded: true as false,
    };
    expect(verifyBaselineDevelopmentDossier(tampered).errors)
      .toContain("FORBIDDEN_CERTIFICATION_CLAIM");
  });
  it("exports only verified JSON, CSV or Markdown", () => {
    const report = buildBaselineDevelopmentDossier(fixture());
    const json = exportBaselineDevelopmentDossier(report, "JSON");
    const csv = exportBaselineDevelopmentDossier(report, "CSV");
    const markdown = exportBaselineDevelopmentDossier(report, "MARKDOWN");
    expect(json.filename).toMatch(/\.json$/);
    expect(JSON.parse(json.text).customerApprovalRecorded).toBe(false);
    expect(csv.text).toContain("TENANT_BOUNDARY");
    expect(markdown.text).toContain("not constitute legal signoff");
    report.verdict = "BLOCKED";
    expect(() => exportBaselineDevelopmentDossier(report, "JSON"))
      .toThrow(/tampered/);
  });
  it("compares two immutable report digests without claiming improvement", () => {
    const older = buildBaselineDevelopmentDossier(fixture());
    const input = fixture();
    input.generatedAt = "2026-11-16T11:00:00.000Z";
    input.actions[0]!.status = "IN_PROGRESS";
    input.actionEvents[0]!.nextStatus = "IN_PROGRESS";
    input.actions[0]!.dueAt = "2026-11-16T10:30:00.000Z";
    const newer = buildBaselineDevelopmentDossier(input);
    const diff = compareBaselineDevelopmentDossiers(older, newer);
    expect(diff.newlyBlocked).toEqual([]);
    expect(diff.newlyAdvisory).toContain("FOLLOW_UP_ACCOUNTABILITY");
    expect(diff.customerImprovementProven).toBe(false);
    expect(diff.technicalRemediationProven).toBe(false);
  });
});
