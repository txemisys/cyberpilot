import { describe, expect, it } from "vitest";
import { BASELINE_IG1_QUESTIONS, type BaselineSubmission } from "./baseline-questions";
import { assessBaselineOfflineV2, verifyBaselineOfflineV2,
  compareBaselineOfflineV2, validateBaselineV2Submission,
  type BaselineV2AssessmentOptions } from "./baseline-offline-v2";
import { buildBaselineReportV2, verifyBaselineReportV2,
  exportBaselineReportV2, buildBaselineActionPlanV2,
  verifyBaselineActionPlanV2, compareBaselineReportsV2,
} from "./baseline-offline-report-v2";
const org = "baseline-org-12345";
const at = "2026-11-12T14:00:00.000Z";
function opts(): BaselineV2AssessmentOptions {
  return {
    organizationId: org, snapshotId: "baseline-snap-12345",
    evaluatedAt: at, completedBy: "test-operator-12345",
    notePolicy: "DISCARD_CONTENT",
    referencePolicy: "OPAQUE_IDENTIFIERS_ONLY",
    maxActions: 50,
  };
}
function submission(): BaselineSubmission {
  return {
    organizationId: org, submittedAt: at,
    questionnaireVersion: 1,
    responses: [
      { questionId: "mfa", answer: "YES",
        notes: "Sensitive internal discussion",
        evidenceReference: "doc-mfa-12345" },
      { questionId: "backups", answer: "NO" },
      { questionId: "restore-tests", answer: "UNKNOWN" },
      { questionId: "incident-plan", answer: "PARTIAL" },
      { questionId: "inventory-hardware", answer: "NOT_APPLICABLE" },
    ],
  };
}
describe("CIS IG1-themed declarative baseline v2", () => {
  it("summarizes all existing questionnaire questions without pretending technical coverage", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    expect(assessment.expectedQuestions)
      .toBe(BASELINE_IG1_QUESTIONS.length);
    expect(assessment.evidence).toHaveLength(BASELINE_IG1_QUESTIONS.length);
    expect(assessment.score).toBeNull();
    expect(assessment.verifiedTechnicalControls).toBe(0);
    expect(assessment.customerComplianceCertified).toBe(false);
    expect(assessment.historicalCyberScoreModified).toBe(false);
    expect(verifyBaselineOfflineV2(
      assessment, submission(), opts()).valid).toBe(true);
  });
  it("does not convert YES with evidence reference into verified security", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    const mfa = assessment.evidence.find(x =>
      x.questionId === "mfa")!;
    expect(mfa.state).toBe("TECHNICAL_REFERENCE_UNVERIFIED");
    expect(mfa.observedSecurityState).toBe("NOT_DETERMINED");
    expect(mfa.scoreEligible).toBe(false);
    expect(mfa.evidenceReferenceVerified).toBe(false);
    expect(mfa.evidenceReference).toBe("doc-mfa-12345");
  });
  it("strips free-form notes and unsafe references from exported evidence", () => {
    const input = submission();
    input.responses[0]!.evidenceReference = "https://example.com/private?token=123";
    const assessment = assessBaselineOfflineV2(input, opts());
    expect(JSON.stringify(assessment)).not.toContain("Sensitive internal discussion");
    expect(JSON.stringify(assessment)).not.toContain("token=123");
    expect(assessment.evidence.find(x =>
      x.questionId === "mfa")!.evidenceReference).toBeNull();
  });
  it("enforces organizational boundary", () => {
    const input = submission();
    input.organizationId = "foreign-tenant-12345";
    expect(validateBaselineV2Submission(input, opts()).valid).toBe(false);
    expect(() => assessBaselineOfflineV2(input, opts())).toThrow();
  });
  it("renders negative answers as proposed remediation, not executed", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    const action = assessment.actions.find(x =>
      x.questionId === "backups")!;
    expect(action.priority).toBe("CRITICAL");
    expect(action.automaticallyExecuted).toBe(false);
    expect(action.verifiedRemediation).toBe(false);
    expect(action.ownerAssigned).toBe(false);
  });
  it("creates report and action plan with explicit gaps", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    const report = buildBaselineReportV2(assessment);
    expect(report.sections).toHaveLength(22);
    expect(report.summary.securityStatus).toBe("NOT_DETERMINED");
    expect(verifyBaselineReportV2(
      report, assessment).valid).toBe(true);
    const plan = buildBaselineActionPlanV2(report);
    expect(plan.prioritized.length).toBeGreaterThan(3);
    expect(verifyBaselineActionPlanV2(plan, report).valid).toBe(true);
  });
  it("exports JSON, CSV and Markdown with no raw note content", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    const report = buildBaselineReportV2(assessment);
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const exported = exportBaselineReportV2(report, format);
      expect(exported.payload.length).toBeGreaterThan(100);
      expect(exported.payload).not.toContain("Sensitive internal discussion");
      expect(exported.containsRawNotes).toBe(false);
      expect(exported.securityCertified).toBe(false);
    }
  });
  it("preserves historical separation and rejects a forged score", () => {
    const assessment = assessBaselineOfflineV2(
      submission(), opts());
    (assessment as unknown as Record<string, unknown>).score = 100;
    expect(verifyBaselineOfflineV2(assessment).valid).toBe(false);
    expect(() => buildBaselineReportV2(assessment)).toThrow();
  });
  it("compares self-declaration revisions without claiming remediation", () => {
    const before = assessBaselineOfflineV2(submission(), opts());
    const newInput = submission();
    newInput.submittedAt = "2026-11-13T14:00:00.000Z";
    newInput.responses[1]!.answer = "YES";
    const newOpts = {
      ...opts(), snapshotId: "baseline-snap-54321",
      evaluatedAt: "2026-11-13T14:00:00.000Z",
    };
    const after = assessBaselineOfflineV2(newInput, newOpts);
    const delta = compareBaselineOfflineV2(before, after);
    expect(delta.apparentImprovements).toContain("backups");
    expect(delta.technicallyVerifiedImprovement).toBe(false);
    const reports = compareBaselineReportsV2(
      buildBaselineReportV2(before),
      buildBaselineReportV2(after));
    expect(reports.changingAnswersProofOfRemediation).toBe(false);
  });
});
