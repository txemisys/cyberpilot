import { BASELINE_IG1_QUESTIONS } from "./baseline-questions";
import type { BaselineAnswer, BaselineQuestion, BaselineResponse, BaselineSubmission, BaselineDomain } from "./baseline-questions";

export type BaselineValidation = {
  valid: boolean;
  errors: string[];
  accepted: BaselineResponse[];
};
export type BaselineSummary = {
  questionnaireVersion: 1;
  total: number;
  answered: number;
  notApplicable: number;
  unknown: number;
  declaredYes: number;
  declaredPartial: number;
  declaredNo: number;
  coverage: "UNASSESSED" | "PARTIAL" | "COMPLETE";
  byDomain: Record<BaselineDomain, { total: number; answered: number; yes: number; partial: number; no: number; unknown: number; notApplicable: number }>;
};

/** Strictly declarative intake; questionnaire answers are never security observations. */
export function validateBaselineSubmission(
  submission: BaselineSubmission,
  expectedOrganizationId: string,
  questions: readonly BaselineQuestion[] = BASELINE_IG1_QUESTIONS,
): BaselineValidation {
  const errors: string[] = [];
  if (!expectedOrganizationId || !submission.organizationId || submission.organizationId !== expectedOrganizationId) {
    return { valid: false, errors: ["ORGANIZATION_MISMATCH"], accepted: [] };
  }
  if (submission.questionnaireVersion !== 1) errors.push("UNSUPPORTED_VERSION");
  const parsedTime = Date.parse(submission.submittedAt);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(submission.submittedAt) || !Number.isFinite(parsedTime)) errors.push("INVALID_DATE");
  const validIds = new Set(questions.map((question) => question.id));
  const answers = new Set<BaselineAnswer>(["YES", "PARTIAL", "NO", "UNKNOWN", "NOT_APPLICABLE"]);
  const seen = new Set<string>();
  const accepted: BaselineResponse[] = [];
  for (const response of submission.responses) {
    if (seen.has(response.questionId)) { errors.push("DUPLICATE_QUESTION"); continue; }
    seen.add(response.questionId);
    if (!validIds.has(response.questionId)) { errors.push("UNKNOWN_QUESTION"); continue; }
    if (!answers.has(response.answer)) { errors.push("INVALID_ANSWER"); continue; }
    if (response.notes != null && response.notes.length > 4000) { errors.push("NOTES_TOO_LONG"); continue; }
    if (response.evidenceReference != null && response.evidenceReference.length > 1024) { errors.push("REFERENCE_TOO_LONG"); continue; }
    accepted.push({ questionId: response.questionId, answer: response.answer, notes: response.notes ?? null, evidenceReference: response.evidenceReference ?? null });
  }
  return { valid: errors.length === 0, errors, accepted: errors.length === 0 ? accepted : [] };
}

/** Summarize declared answers as coverage, never as CyberScore or verified security. */
export function summarizeBaseline(
  submission: BaselineSubmission,
  organizationId: string,
  questions: readonly BaselineQuestion[] = BASELINE_IG1_QUESTIONS,
): BaselineSummary | null {
  const validation = validateBaselineSubmission(submission, organizationId, questions);
  if (!validation.valid) return null;
  const byDomain = {} as BaselineSummary["byDomain"];
  for (const question of questions) {
    const entry = byDomain[question.domain] ?? { total: 0, answered: 0, yes: 0, partial: 0, no: 0, unknown: 0, notApplicable: 0 };
    entry.total++;
    byDomain[question.domain] = entry;
  }
  const mapping = new Map(questions.map((question) => [question.id, question.domain]));
  let answered = 0, notApplicable = 0, unknown = 0, declaredYes = 0, declaredPartial = 0, declaredNo = 0;
  for (const response of validation.accepted) {
    const domain = mapping.get(response.questionId)!;
    const entry = byDomain[domain]!;
    if (response.answer === "NOT_APPLICABLE") { notApplicable++; entry.notApplicable++; }
    else if (response.answer === "UNKNOWN") { unknown++; entry.unknown++; }
    else {
      answered++; entry.answered++;
      if (response.answer === "YES") { declaredYes++; entry.yes++; }
      if (response.answer === "PARTIAL") { declaredPartial++; entry.partial++; }
      if (response.answer === "NO") { declaredNo++; entry.no++; }
    }
  }
  const total = questions.length;
  const coverage = answered === 0 ? "UNASSESSED" : answered + notApplicable + unknown === total ? "COMPLETE" : "PARTIAL";
  return { questionnaireVersion: 1, total, answered, notApplicable, unknown, declaredYes, declaredPartial, declaredNo, coverage, byDomain };
}
