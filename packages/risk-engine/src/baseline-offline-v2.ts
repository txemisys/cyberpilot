import {
  BASELINE_IG1_QUESTIONS, BASELINE_QUESTIONNAIRE_VERSION,
  type BaselineAnswer, type BaselineDomain,
  type BaselineResponse, type BaselineSubmission,
} from "./baseline-questions";
import {
  summarizeBaseline, validateBaselineSubmission,
} from "./baseline-evaluation";
import { canonicalV2 } from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";

/**
 * Existing questionnaire v1 is the source of truth.
 * This secondary v2 report never promotes an operator's YES to
 * an independently observed, audited or CIS-certified control.
 */
export type BaselineV2EvidenceStatus =
  "DECLARED" | "UNKNOWN" | "NOT_APPLICABLE" |
  "TECHNICAL_REFERENCE_UNVERIFIED";
export type BaselineV2Priority =
  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" |
  "UNKNOWN" | "NOT_APPLICABLE";
export type BaselineV2Question = {
  questionId: string; domain: BaselineDomain;
  prompt: string; guidance: string;
  evidenceHint: string;
  answer: BaselineAnswer | "UNANSWERED";
  state: BaselineV2EvidenceStatus;
  observedSecurityState: "NOT_DETERMINED";
  evidenceReference: string | null;
  evidenceReferenceVerified: false;
  evidenceNotePresent: boolean;
  priority: BaselineV2Priority;
  completeness: "RESPONDED" | "NOT_RESPONDED";
  requiresVerification: boolean;
  uncertainty: string[];
  scoreEligible: false;
  cisCertificationClaimed: false;
};
export type BaselineV2DomainSummary = {
  domain: BaselineDomain;
  expected: number;
  responded: number;
  affirmative: number;
  partial: number;
  negative: number;
  unknown: number;
  notApplicable: number;
  unanswered: number;
  completionPercent: number;
  declaredAffirmativePercent: number;
  technicallyVerified: 0;
  technicalCoveragePercent: 0;
  riskStatus: "NOT_DETERMINED";
  certificationStatus: "NOT_CERTIFIED";
  topGaps: string[];
  nextAction: string;
};
export type BaselineV2Action = {
  id: string; questionId: string;
  domain: BaselineDomain;
  priority: BaselineV2Priority;
  status: "PROPOSED" | "NEEDS_SCOPE_REVIEW" |
    "NEEDS_TECHNICAL_EVIDENCE";
  title: string; reason: string;
  steps: string[];
  evidenceNeeded: string;
  targetDays: number | null;
  evidenceReference: string | null;
  assertedCISRequirement: false;
  automaticallyExecuted: false;
  verifiedRemediation: false;
  ownerAssigned: false;
};
export type BaselineV2Assessment = {
  schema: "cyberpilot.baseline.offline.assessment.v2";
  organizationId: string;
  snapshotId: string;
  questionnaireVersion: 1;
  evaluatedAt: string;
  completedBy: string;
  source: "ORGANIZATIONAL_SELF_ASSESSMENT";
  domainCount: number;
  expectedQuestions: number;
  suppliedAnswers: number;
  unansweredQuestions: number;
  declaredControls: number;
  unknownControls: number;
  notApplicableControls: number;
  verifiedTechnicalControls: 0;
  declaredCompletionPercent: number;
  technicalCoveragePercent: 0;
  posture: "UNDETERMINED";
  score: null;
  evidence: BaselineV2Question[];
  domains: BaselineV2DomainSummary[];
  actions: BaselineV2Action[];
  limitations: string[];
  privacy: {
    rawNotesPersisted: false;
    rawNamesPersisted: false;
    evidenceReferencesUnverified: true;
    personalDataInExport: false;
  };
  historicalCyberScoreModified: false;
  customerComplianceCertified: false;
  independentlyVerifiedCisControls: 0;
  digest: string;
};
export type BaselineV2AssessmentOptions = {
  organizationId: string;
  snapshotId: string;
  evaluatedAt: string;
  completedBy: string;
  notePolicy: "DISCARD_CONTENT";
  referencePolicy: "OPAQUE_IDENTIFIERS_ONLY";
  maxActions: number;
};
export type BaselineV2ValidationResult = {
  valid: boolean;
  errors: string[]; warnings: string[];
  accepted: number; rejected: number;
  privateDetailsDiscarded: true;
  organizationBoundaryEnforced: true;
  noTechnicalComplianceInferred: true;
};
const PRIORITY: Record<BaselineDomain, number> = {
  ASSETS: 7, SOFTWARE: 7, DATA: 8,
  CONFIGURATION: 8, ACCOUNTS: 9,
  ACCESS: 10, VULNERABILITIES: 9,
  LOGGING: 7, EMAIL_WEB: 8, MALWARE: 9,
  RECOVERY: 10, NETWORK: 7,
  AWARENESS: 6, SERVICE_PROVIDERS: 7,
  APPLICATIONS: 7, INCIDENT_RESPONSE: 10, TESTING: 6,
};
const highRiskQuestions = new Set([
  "mfa", "admin-separation", "offboarding",
  "backups", "restore-tests", "backup-protection",
  "incident-plan", "endpoint-protection",
  "patch-inventory", "patch-deadlines",
  "provider-offboarding", "least-privilege",
]);
function validId(raw: unknown) {
  return typeof raw === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(raw);
}
function time(raw: unknown): raw is string {
  return typeof raw === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/
      .test(raw) &&
    Number.isFinite(Date.parse(raw)) &&
    new Date(raw).toISOString() === raw;
}
function opaqueReference(raw: string | null | undefined) {
  if (!raw?.trim()) return null;
  const id = raw.trim();
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,95}$/.test(id) ?
    id : null;
}
function hash(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function percent(numerator: number, denominator: number) {
  return denominator > 0 ?
    Math.round(numerator * 100 / denominator) : 0;
}
function domainPriority(domain: BaselineDomain,
  questionId: string, answer: BaselineAnswer | "UNANSWERED"):
  BaselineV2Priority {
  if (answer === "NOT_APPLICABLE") return "NOT_APPLICABLE";
  if (answer === "YES") return "LOW";
  if (answer === "UNANSWERED" || answer === "UNKNOWN")
    return "UNKNOWN";
  const value = PRIORITY[domain] +
    (answer === "NO" ? 3 : 1) +
    (highRiskQuestions.has(questionId) ? 2 : 0);
  if (value >= 14) return "CRITICAL";
  if (value >= 11) return "HIGH";
  if (value >= 8) return "MEDIUM";
  return "LOW";
}
function uncertainty(
  answer: BaselineAnswer | "UNANSWERED",
  reference: string | null,
): string[] {
  const notes = [
    "Questionnaire answers are self-declarations, not technical observations.",
    "A declared YES does not demonstrate control compliance.",
  ];
  if (answer === "UNANSWERED")
    notes.push("No response was supplied for this control.");
  else if (answer === "UNKNOWN")
    notes.push("Respondent explicitly marked control as unknown.");
  else if (answer === "NOT_APPLICABLE")
    notes.push("Applicability was declared, not independently evaluated.");
  else if (answer === "PARTIAL")
    notes.push("Partial implementation requires scoping and follow-up.");
  else if (answer === "NO")
    notes.push("Negative declaration is a candidate gap to verify.");
  if (reference)
    notes.push("Evidence reference is a local pointer, not verified proof.");
  return notes;
}
export function validateBaselineV2Submission(
  submission: BaselineSubmission,
  options: BaselineV2AssessmentOptions,
): BaselineV2ValidationResult {
  const errors: string[] = [], warnings: string[] = [];
  if (!validId(options.organizationId) ||
      options.organizationId !== submission.organizationId ||
      !validId(options.snapshotId) ||
      !validId(options.completedBy) ||
      !time(options.evaluatedAt))
    errors.push("ASSESSMENT_SCOPE_INVALID");
  if (submission.submittedAt > options.evaluatedAt)
    errors.push("SUBMISSION_IN_FUTURE");
  if (options.notePolicy !== "DISCARD_CONTENT" ||
      options.referencePolicy !== "OPAQUE_IDENTIFIERS_ONLY")
    errors.push("UNSAFE_PII_POLICY");
  if (!Number.isSafeInteger(options.maxActions) ||
      options.maxActions < 1 || options.maxActions > 100)
    errors.push("ACTION_CAPACITY_INVALID");
  const original = validateBaselineSubmission(
    submission, options.organizationId);
  errors.push(...original.errors);
  for (const answer of submission.responses) {
    if (answer.evidenceReference &&
        !opaqueReference(answer.evidenceReference))
      warnings.push("Unverified or potentially sensitive evidence reference was discarded.");
    if (answer.notes?.trim())
      warnings.push("Free-form notes are intentionally not exported.");
  }
  if (submission.responses.length > BASELINE_IG1_QUESTIONS.length)
    errors.push("TOO_MANY_RESPONSES");
  if (BASELINE_QUESTIONNAIRE_VERSION !== 1)
    errors.push("QUESTIONNAIRE_VERSION_UNSUPPORTED");
  if (!time(submission.submittedAt))
    errors.push("INVALID_SUBMISSION_DATE");
  return {
    valid: errors.length === 0, errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
    accepted: original.accepted.length,
    rejected: errors.length === 0 ? 0 : submission.responses.length,
    privateDetailsDiscarded: true,
    organizationBoundaryEnforced: true,
    noTechnicalComplianceInferred: true,
  };
}
function questionStatus(
  question: typeof BASELINE_IG1_QUESTIONS[number],
  reply: BaselineResponse | undefined,
): BaselineV2Question {
  const answer = reply?.answer ?? "UNANSWERED";
  const reference = opaqueReference(reply?.evidenceReference);
  const state: BaselineV2EvidenceStatus =
    answer === "NOT_APPLICABLE" ? "NOT_APPLICABLE" :
      answer === "UNANSWERED" || answer === "UNKNOWN" ?
        "UNKNOWN" : reference ?
          "TECHNICAL_REFERENCE_UNVERIFIED" : "DECLARED";
  return {
    questionId: question.id, domain: question.domain,
    prompt: question.prompt, guidance: question.guidance,
    evidenceHint: question.evidenceHint,
    answer, state,
    observedSecurityState: "NOT_DETERMINED",
    evidenceReference: reference,
    evidenceReferenceVerified: false,
    evidenceNotePresent: Boolean(reply?.notes?.trim()),
    priority: domainPriority(question.domain, question.id, answer),
    completeness: reply ? "RESPONDED" : "NOT_RESPONDED",
    requiresVerification: answer !== "NOT_APPLICABLE",
    uncertainty: uncertainty(answer, reference),
    scoreEligible: false,
    cisCertificationClaimed: false,
  };
}
function domainSummary(domain: BaselineDomain,
  questions: readonly BaselineV2Question[]): BaselineV2DomainSummary {
  const rows = questions.filter(x => x.domain === domain);
  const count = (predicate: (q: BaselineV2Question) => boolean) =>
    rows.filter(predicate).length;
  const expected = rows.length;
  const responded = count(x => x.completeness === "RESPONDED");
  const affirmative = count(x => x.answer === "YES");
  const partial = count(x => x.answer === "PARTIAL");
  const negative = count(x => x.answer === "NO");
  const unknown = count(x => x.answer === "UNKNOWN");
  const notApplicable = count(x => x.answer === "NOT_APPLICABLE");
  const unanswered = count(x => x.answer === "UNANSWERED");
  const topGaps = rows.filter(x =>
    x.answer === "NO" || x.answer === "PARTIAL" ||
      x.answer === "UNANSWERED" || x.answer === "UNKNOWN")
    .sort((a, b) => PRIORITY[b.domain] - PRIORITY[a.domain] ||
      a.questionId.localeCompare(b.questionId))
    .slice(0, 5).map(x => x.questionId);
  return {
    domain, expected, responded, affirmative,
    partial, negative, unknown,
    notApplicable, unanswered,
    completionPercent: percent(responded, expected),
    declaredAffirmativePercent: percent(affirmative, expected),
    technicallyVerified: 0, technicalCoveragePercent: 0,
    riskStatus: "NOT_DETERMINED",
    certificationStatus: "NOT_CERTIFIED",
    topGaps,
    nextAction: topGaps.length ?
      "Request scoped evidence for " + topGaps.slice(0, 3).join(", ") :
      "Verify declarations with independent technical evidence.",
  };
}
function targetDays(priority: BaselineV2Priority) {
  if (priority === "CRITICAL") return 7;
  if (priority === "HIGH") return 14;
  if (priority === "MEDIUM") return 30;
  if (priority === "LOW") return 90;
  return null;
}
function actionFor(q: BaselineV2Question): BaselineV2Action {
  const isUnknown = q.answer === "UNKNOWN" ||
    q.answer === "UNANSWERED";
  const isNAT = q.answer === "NOT_APPLICABLE";
  return {
    id: "baseline-act-" + q.questionId,
    questionId: q.questionId,
    domain: q.domain, priority: q.priority,
    status: isNAT ? "NEEDS_SCOPE_REVIEW" :
      isUnknown ? "NEEDS_SCOPE_REVIEW" :
        "NEEDS_TECHNICAL_EVIDENCE",
    title: isUnknown ?
      "Clarify " + q.prompt :
      "Validate and address " + q.prompt,
    reason: q.uncertainty.join(" "),
    steps: [
      "Confirm the scope, applicability and owner for this control.",
      q.guidance,
      "Collect dated, independently verifiable evidence.",
      "Record actual remediation and rerun the assessment.",
    ],
    evidenceNeeded: q.evidenceHint,
    targetDays: targetDays(q.priority),
    evidenceReference: q.evidenceReference,
    assertedCISRequirement: false,
    automaticallyExecuted: false,
    verifiedRemediation: false,
    ownerAssigned: false,
  };
}
export function assessBaselineOfflineV2(
  submission: BaselineSubmission,
  options: BaselineV2AssessmentOptions,
): BaselineV2Assessment {
  const checked = validateBaselineV2Submission(submission, options);
  if (!checked.valid)
    throw Error("Invalid Baseline input: " + checked.errors.join(","));
  const responses = new Map(submission.responses.map(x =>
    [x.questionId, x]));
  const evidence = BASELINE_IG1_QUESTIONS.map(question =>
    questionStatus(question, responses.get(question.id)));
  const domainIds = [...new Set(BASELINE_IG1_QUESTIONS.map(q =>
    q.domain))];
  const domains = domainIds.map(domain =>
    domainSummary(domain, evidence));
  const original = summarizeBaseline(submission, options.organizationId)!;
  const actions = evidence.filter(x =>
    x.answer === "NO" || x.answer === "PARTIAL" ||
    x.answer === "UNKNOWN" || x.answer === "UNANSWERED" ||
    x.answer === "NOT_APPLICABLE").map(actionFor);
  const rank: Record<BaselineV2Priority, number> = {
    CRITICAL: 5, HIGH: 4, MEDIUM: 3,
    LOW: 2, UNKNOWN: 1, NOT_APPLICABLE: 0,
  };
  actions.sort((a, b) =>
    rank[b.priority] - rank[a.priority] ||
      a.questionId.localeCompare(b.questionId));
  const canonical = {
    schema: "cyberpilot.baseline.offline.assessment.v2" as const,
    organizationId: options.organizationId,
    snapshotId: options.snapshotId,
    questionnaireVersion: 1 as const,
    evaluatedAt: options.evaluatedAt,
    completedBy: options.completedBy,
    source: "ORGANIZATIONAL_SELF_ASSESSMENT" as const,
    domainCount: domains.length,
    expectedQuestions: BASELINE_IG1_QUESTIONS.length,
    suppliedAnswers: original.answered +
      original.unknown + original.notApplicable,
    unansweredQuestions: evidence.filter(x =>
      x.answer === "UNANSWERED").length,
    declaredControls: evidence.filter(x =>
      x.state === "DECLARED" ||
      x.state === "TECHNICAL_REFERENCE_UNVERIFIED").length,
    unknownControls: evidence.filter(x =>
      x.state === "UNKNOWN").length,
    notApplicableControls: original.notApplicable,
    verifiedTechnicalControls: 0 as const,
    declaredCompletionPercent: percent(submission.responses.length,
      BASELINE_IG1_QUESTIONS.length),
    technicalCoveragePercent: 0 as const,
    posture: "UNDETERMINED" as const,
    score: null,
    evidence, domains, actions: actions.slice(0, options.maxActions),
    limitations: [...new Set([
      ...checked.warnings,
      "This diagnostic is declarative, not CIS Controls certification.",
      "Affirmative answers are not verified technical observations.",
      "A partially completed questionnaire does not imply a safe business.",
      "Referenced evidence is a local pointer, not an independent audit.",
      "CyberScore v1 and v2 are not updated by this projection.",
    ])],
    privacy: {
      rawNotesPersisted: false as const,
      rawNamesPersisted: false as const,
      evidenceReferencesUnverified: true as const,
      personalDataInExport: false as const,
    },
    historicalCyberScoreModified: false as const,
    customerComplianceCertified: false as const,
    independentlyVerifiedCisControls: 0 as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyBaselineOfflineV2(
  assessment: BaselineV2Assessment,
  source?: BaselineSubmission,
  options?: BaselineV2AssessmentOptions,
) {
  const { digest, ...canonical } = assessment;
  const issues: string[] = [];
  if (hash(canonical) !== digest)
    issues.push("BASELINE_DIGEST_INVALID");
  if (assessment.verifiedTechnicalControls !== 0 ||
      assessment.technicalCoveragePercent !== 0 ||
      assessment.posture !== "UNDETERMINED" ||
      assessment.score !== null ||
      assessment.customerComplianceCertified ||
      assessment.historicalCyberScoreModified ||
      assessment.evidence.some(x =>
        x.scoreEligible || x.evidenceReferenceVerified ||
        x.cisCertificationClaimed))
    issues.push("DECLARATION_PROMOTED_TO_COMPLIANCE");
  if (source && options && (
      !validateBaselineV2Submission(source, options).valid ||
      assessBaselineOfflineV2(source, options).digest !== digest))
    issues.push("SOURCE_NOT_BOUND_TO_ASSESSMENT");
  return { valid: issues.length === 0, issues };
}
export function compareBaselineOfflineV2(
  older: BaselineV2Assessment,
  newer: BaselineV2Assessment,
) {
  if (!verifyBaselineOfflineV2(older).valid ||
      !verifyBaselineOfflineV2(newer).valid ||
      older.organizationId !== newer.organizationId ||
      older.questionnaireVersion !== newer.questionnaireVersion ||
      older.evaluatedAt >= newer.evaluatedAt)
    throw Error("Invalid longitudinal Baseline comparison.");
  const before = new Map(older.evidence.map(x =>
    [x.questionId, x]));
  const changed = newer.evidence.filter(x =>
    before.get(x.questionId)?.answer !== x.answer);
  const apparentImprovements = changed.filter(x =>
    x.answer === "YES" && before.get(x.questionId)?.answer !== "YES");
  return {
    organizationId: newer.organizationId,
    previousSnapshotId: older.snapshotId,
    currentSnapshotId: newer.snapshotId,
    previousCompletion: older.declaredCompletionPercent,
    currentCompletion: newer.declaredCompletionPercent,
    completionDelta: newer.declaredCompletionPercent -
      older.declaredCompletionPercent,
    changedDeclarations: changed.map(x => ({
      questionId: x.questionId, domain: x.domain,
      before: before.get(x.questionId)?.answer ?? "UNANSWERED",
      after: x.answer, technicallyReverified: false as const,
    })),
    apparentImprovements: apparentImprovements.map(x =>
      x.questionId),
    confirmedRemediations: [] as string[],
    technicallyVerifiedImprovement: false as const,
    complianceCertificationIssued: false as const,
    legacyCyberScoreTouched: false as const,
  };
}
export function baselineV2DomainGaps(
  assessment: BaselineV2Assessment,
) {
  if (!verifyBaselineOfflineV2(assessment).valid)
    throw Error("Cannot summarize tampered Baseline assessment.");
  return assessment.domains.map(x => ({
    domain: x.domain,
    missing: x.unanswered + x.unknown,
    potentiallyNegative: x.negative + x.partial,
    declaredYes: x.affirmative,
    declaredNotApplicable: x.notApplicable,
    coveragePercent: x.completionPercent,
    technicalCoveragePercent: 0 as const,
    topQuestions: [...x.topGaps],
    requiresIndependentVerification: true as const,
    certifiedSecure: false as const,
  }));
}
