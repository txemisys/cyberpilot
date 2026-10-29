import { describe, expect, it } from "vitest";
import { BASELINE_IG1_QUESTIONS } from "./baseline-questions";
import { validateBaselineSubmission, summarizeBaseline } from "./baseline-evaluation";
import type { BaselineSubmission } from "./baseline-questions";
const base: BaselineSubmission = {
  questionnaireVersion: 1, organizationId: "org-a", submittedAt: "2026-10-29T12:00:00Z", responses: [],
};
describe("Baseline v1 50-question questionnaire", () => {
  it("defines 50 unique prompts with a domain, guidance and evidence hint", () => {
    expect(BASELINE_IG1_QUESTIONS).toHaveLength(50);
    expect(new Set(BASELINE_IG1_QUESTIONS.map((q) => q.id)).size).toBe(50);
    for (const question of BASELINE_IG1_QUESTIONS) {
      expect(question.prompt.length).toBeGreaterThan(10);
      expect(question.guidance.length).toBeGreaterThan(4);
      expect(question.evidenceHint.length).toBeGreaterThan(3);
    }
  });
  it("never treats unanswered questions as assessed", () => {
    const result = summarizeBaseline(base, "org-a")!;
    expect(result.total).toBe(50);
    expect(result.answered).toBe(0);
    expect(result.coverage).toBe("UNASSESSED");
    expect(result.declaredYes).toBe(0);
  });
  it("counts declared yes, partial and no separately without assigning a CyberScore", () => {
    const submission = { ...base, responses: [
      { questionId: BASELINE_IG1_QUESTIONS[0]!.id, answer: "YES" as const },
      { questionId: BASELINE_IG1_QUESTIONS[1]!.id, answer: "PARTIAL" as const },
      { questionId: BASELINE_IG1_QUESTIONS[2]!.id, answer: "NO" as const },
    ] };
    const result = summarizeBaseline(submission, "org-a")!;
    expect(result.coverage).toBe("PARTIAL");
    expect([result.declaredYes, result.declaredPartial, result.declaredNo]).toEqual([1, 1, 1]);
    expect("score" in result).toBe(false);
  });
  it("counts unknown and not-applicable separately from answered", () => {
    const questions = BASELINE_IG1_QUESTIONS.slice(0, 2);
    const submission = { ...base, responses: [
      { questionId: questions[0]!.id, answer: "UNKNOWN" as const },
      { questionId: questions[1]!.id, answer: "NOT_APPLICABLE" as const },
    ] };
    const result = summarizeBaseline(submission, "org-a", questions)!;
    expect(result.answered).toBe(0);
    expect(result.unknown).toBe(1);
    expect(result.notApplicable).toBe(1);
    expect(result.coverage).toBe("UNASSESSED");
  });
  it("reports complete questionnaire coverage while keeping answers declared", () => {
    const submission = { ...base, responses: BASELINE_IG1_QUESTIONS.map((q) => ({ questionId: q.id, answer: "YES" as const })) };
    const result = summarizeBaseline(submission, "org-a")!;
    expect(result.coverage).toBe("COMPLETE");
    expect(result.declaredYes).toBe(50);
  });
  it("rejects organization mismatch without leaking answers", () => {
    const submission = { ...base, responses: [{ questionId: BASELINE_IG1_QUESTIONS[0]!.id, answer: "YES" as const, notes: "confidential" }] };
    const result = validateBaselineSubmission(submission, "org-b");
    expect(result).toEqual({ valid: false, errors: ["ORGANIZATION_MISMATCH"], accepted: [] });
    expect(summarizeBaseline(submission, "org-b")).toBeNull();
  });
  it("rejects duplicate answers, unsupported IDs and invalid timestamps", () => {
    const id = BASELINE_IG1_QUESTIONS[0]!.id;
    expect(validateBaselineSubmission({ ...base, responses: [{ questionId: id, answer: "YES" }, { questionId: id, answer: "NO" }] }, "org-a").valid).toBe(false);
    expect(validateBaselineSubmission({ ...base, responses: [{ questionId: "other", answer: "YES" }] }, "org-a").valid).toBe(false);
    expect(validateBaselineSubmission({ ...base, submittedAt: "invalid" }, "org-a").valid).toBe(false);
  });
  it("bounds freeform notes and references", () => {
    const id = BASELINE_IG1_QUESTIONS[0]!.id;
    expect(validateBaselineSubmission({ ...base, responses: [{ questionId: id, answer: "YES", notes: "x".repeat(4001) }] }, "org-a").valid).toBe(false);
    expect(validateBaselineSubmission({ ...base, responses: [{ questionId: id, answer: "YES", evidenceReference: "x".repeat(1025) }] }, "org-a").valid).toBe(false);
  });
});
