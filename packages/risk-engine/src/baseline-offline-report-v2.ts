import { sha256V2 } from "./multisource-v2-history";
import { canonicalV2 } from "./multisource-v2-contract";
import {
  type BaselineV2Assessment, type BaselineV2Action,
  type BaselineV2DomainSummary, type BaselineV2Question,
  verifyBaselineOfflineV2, baselineV2DomainGaps,
} from "./baseline-offline-v2";
import type { BaselineDomain } from "./baseline-questions";

/** Reporting is a view of declarations, not an audited compliance statement. */
export type BaselineReportV2Section = {
  id: "EXECUTIVE" | "COVERAGE" | "EVIDENCE" |
    "PRIORITIES" | "LIMITATIONS" | BaselineDomain;
  title: string; description: string;
  answered: number; unanswered: number;
  negative: number; partial: number; unknown: number;
  observedTechnicalControls: 0;
  status: "DECLARED_WITH_GAPS" | "NOT_ASSESSED";
  needsIndependentVerification: true;
};
export type BaselineReportV2 = {
  schema: "cyberpilot.baseline.report.v2";
  organizationId: string; snapshotId: string;
  model: "baseline-questionnaire-v1-v2-projection";
  evaluatedAt: string;
  sourceDigest: string;
  summary: {
    questions: number;
    answered: number;
    completionPercent: number;
    positiveDeclarations: number;
    negativeDeclarations: number;
    partialDeclarations: number;
    unknownOrUnanswered: number;
    notApplicableDeclarations: number;
    technicallyVerified: 0;
    securityScore: null;
    securityStatus: "NOT_DETERMINED";
    isCisCertification: false;
    noMicrosoft365Required: true;
  };
  sections: BaselineReportV2Section[];
  actions: BaselineV2Action[];
  evidence: Array<{
    questionId: string; domain: BaselineDomain;
    answer: string; state: string;
    evidenceReference: string | null;
    evidenceIndependentlyVerified: false;
    urgency: string;
    scopeUnknown: boolean;
    noRawFreeText: true;
  }>;
  domainGaps: ReturnType<typeof baselineV2DomainGaps>;
  quality: {
    integrityVerifiedLocally: true;
    privateNotesExcluded: true;
    allAnswersDeclarative: true;
    customerApproved: false;
    targetEnvironmentCertified: false;
  };
  limitations: string[];
  signedByIndependentAuditor: false;
  originalCyberScoreMutated: false;
  digest: string;
};
export type BaselineReportV2Export = {
  schema: "cyberpilot.baseline.report.export.v2";
  organizationId: string; snapshotId: string;
  format: "JSON" | "CSV" | "MARKDOWN";
  filename: string; mimeType: string;
  payload: string; reportDigest: string;
  exportDigest: string; bytes: number;
  containsRawNotes: false; securityCertified: false;
};
export type BaselineReportV2Audit = {
  valid: boolean; issues: string[];
  integrityValid: boolean;
  sourceBound: boolean;
  questionsComplete: boolean;
  declarationsNotPromoted: boolean;
  permissionsNotInferred: boolean;
  originalScoreUnchanged: boolean;
};
export type BaselineActionPlanV2 = {
  schema: "cyberpilot.baseline.action.plan.v2";
  organizationId: string; snapshotId: string;
  evaluatedAt: string;
  categories: Array<{
    domain: BaselineDomain;
    actions: number; urgent: number; unknown: number;
    earliestTargetDays: number | null;
    readyForAutomaticRemediation: false;
  }>;
  prioritized: Array<{
    actionId: string; rank: number; questionId: string;
    domain: BaselineDomain; title: string; priority: string;
    guidance: string[];
    requiredEvidence: string;
    evidenceState: "UNVERIFIED";
    externallyApproved: false;
    executed: false; completed: false;
  }>;
  visibleUnknowns: string[];
  limits: string[];
  noAccountChanges: true;
  digest: string;
};
export type BaselineReportDeltaV2 = {
  organizationId: string;
  from: string; to: string;
  completionDelta: number;
  newlyAnswered: string[];
  newlyUnknown: string[];
  changedAnswers: Array<{
    questionId: string; prior: string; current: string;
  }>;
  changingAnswersProofOfRemediation: false;
  sourceEvidenceReverified: false;
  legacyScoreAdjusted: false;
};
function sha(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function sectionsForDomain(
  domain: BaselineV2DomainSummary,
): BaselineReportV2Section {
  const unverified = domain.expected -
    domain.technicallyVerified;
  return {
    id: domain.domain,
    title: domain.domain.replaceAll("_", " ").toLowerCase(),
    description: domain.topGaps.length ?
      "Declaration gaps: " + domain.topGaps.join(", ") :
      "No declared gaps, but technical coverage is not verified.",
    answered: domain.responded,
    unanswered: domain.unanswered,
    negative: domain.negative,
    partial: domain.partial,
    unknown: domain.unknown,
    observedTechnicalControls: 0,
    status: unverified === domain.expected &&
      domain.responded === 0 ?
        "NOT_ASSESSED" : "DECLARED_WITH_GAPS",
    needsIndependentVerification: true,
  };
}
function section(
  id: BaselineReportV2Section["id"],
  title: string, explanation: string,
  assessment: BaselineV2Assessment,
): BaselineReportV2Section {
  const rows = assessment.evidence;
  return {
    id, title, description: explanation,
    answered: rows.filter(x =>
      x.completeness === "RESPONDED").length,
    unanswered: assessment.unansweredQuestions,
    negative: rows.filter(x => x.answer === "NO").length,
    partial: rows.filter(x => x.answer === "PARTIAL").length,
    unknown: rows.filter(x => x.answer === "UNKNOWN").length,
    observedTechnicalControls: 0,
    status: assessment.suppliedAnswers ?
      "DECLARED_WITH_GAPS" : "NOT_ASSESSED",
    needsIndependentVerification: true,
  };
}
export function buildBaselineReportV2(
  assessment: BaselineV2Assessment,
): BaselineReportV2 {
  if (!verifyBaselineOfflineV2(assessment).valid)
    throw Error("Cannot report modified or invalid baseline.");
  const declarations = assessment.evidence;
  const positive = declarations.filter(x => x.answer === "YES").length;
  const negative = declarations.filter(x => x.answer === "NO").length;
  const partial = declarations.filter(x =>
    x.answer === "PARTIAL").length;
  const unknown = declarations.filter(x =>
    x.answer === "UNKNOWN" || x.answer === "UNANSWERED").length;
  const na = declarations.filter(x =>
    x.answer === "NOT_APPLICABLE").length;
  const sections = [
    section("EXECUTIVE", "Management overview",
      "The baseline describes management declarations, not tested security.",
      assessment),
    section("COVERAGE", "Questionnaire coverage",
      "Unanswered controls cannot be considered compliant.",
      assessment),
    section("EVIDENCE", "Evidence references",
      "Document references are opaque and have not been authenticated.",
      assessment),
    section("PRIORITIES", "Recommended remediation",
      "Recommendations are proposals and have not been executed.",
      assessment),
    ...assessment.domains.map(sectionsForDomain),
    section("LIMITATIONS", "Limitations and scope",
      "No CIS accreditation or full customer security attestation.",
      assessment),
  ];
  const canonical = {
    schema: "cyberpilot.baseline.report.v2" as const,
    organizationId: assessment.organizationId,
    snapshotId: assessment.snapshotId,
    model: "baseline-questionnaire-v1-v2-projection" as const,
    evaluatedAt: assessment.evaluatedAt,
    sourceDigest: assessment.digest,
    summary: {
      questions: declarations.length,
      answered: assessment.suppliedAnswers,
      completionPercent: assessment.declaredCompletionPercent,
      positiveDeclarations: positive,
      negativeDeclarations: negative,
      partialDeclarations: partial,
      unknownOrUnanswered: unknown,
      notApplicableDeclarations: na,
      technicallyVerified: 0 as const,
      securityScore: null,
      securityStatus: "NOT_DETERMINED" as const,
      isCisCertification: false as const,
      noMicrosoft365Required: true as const,
    },
    sections, actions: [...assessment.actions],
    evidence: declarations.map(x => ({
      questionId: x.questionId, domain: x.domain,
      answer: x.answer, state: x.state,
      evidenceReference: x.evidenceReference,
      evidenceIndependentlyVerified: false as const,
      urgency: x.priority,
      scopeUnknown: x.answer === "NOT_APPLICABLE" ||
        x.answer === "UNKNOWN" || x.answer === "UNANSWERED",
      noRawFreeText: true as const,
    })),
    domainGaps: baselineV2DomainGaps(assessment),
    quality: {
      integrityVerifiedLocally: true as const,
      privateNotesExcluded: true as const,
      allAnswersDeclarative: true as const,
      customerApproved: false as const,
      targetEnvironmentCertified: false as const,
    },
    limitations: [...assessment.limitations,
      "A positive declaration does not prove security or compliance.",
      "A negative declaration indicates a potential improvement opportunity.",
      "Do not compare questionnaire completion to technical control coverage."],
    signedByIndependentAuditor: false as const,
    originalCyberScoreMutated: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyBaselineReportV2(
  report: BaselineReportV2,
  assessment?: BaselineV2Assessment,
): BaselineReportV2Audit {
  const { digest, ...canonical } = report;
  const issues: string[] = [];
  const integrityValid = sha(canonical) === digest;
  if (!integrityValid) issues.push("REPORT_TAMPERED");
  const sourceBound = !assessment ||
    verifyBaselineOfflineV2(assessment).valid &&
      assessment.digest === report.sourceDigest &&
      assessment.organizationId === report.organizationId &&
      assessment.snapshotId === report.snapshotId &&
      buildBaselineReportV2(assessment).digest === report.digest;
  if (!sourceBound) issues.push("SOURCE_NOT_BOUND_TO_REPORT");
  const questionsComplete = report.summary.questions ===
    report.evidence.length &&
    report.sections.length === 5 +
      new Set(report.evidence.map(x => x.domain)).size;
  if (!questionsComplete)
    issues.push("QUESTIONNAIRE_SECTIONS_INCOMPLETE");
  const declarationsNotPromoted =
    report.summary.securityScore === null &&
    report.summary.technicallyVerified === 0 &&
    report.summary.securityStatus === "NOT_DETERMINED" &&
    !report.summary.isCisCertification &&
    report.evidence.every(x =>
      !x.evidenceIndependentlyVerified);
  if (!declarationsNotPromoted)
    issues.push("DECLARATIONS_MISREPRESENTED_AS_VERIFIED");
  const permissionsNotInferred =
    !report.quality.customerApproved &&
    !report.quality.targetEnvironmentCertified &&
    !report.signedByIndependentAuditor;
  if (!permissionsNotInferred)
    issues.push("FALSE_EXTERNAL_APPROVAL");
  const originalScoreUnchanged = !report.originalCyberScoreMutated;
  if (!originalScoreUnchanged)
    issues.push("LEGACY_CYBERSCORE_MUTATED");
  return {
    valid: issues.length === 0, issues, integrityValid,
    sourceBound, questionsComplete,
    declarationsNotPromoted, permissionsNotInferred,
    originalScoreUnchanged,
  };
}
function csvCell(value: string | number | null) {
  const text = String(value ?? "");
  const escaped = /^[=+@-]/.test(text) ? "'" + text : text;
  return '"' + escaped.replaceAll('"', '""')
    .replace(/[\u0000-\u001f\u007f]/g, " ") + '"';
}
export function exportBaselineReportV2(
  report: BaselineReportV2,
  format: BaselineReportV2Export["format"],
): BaselineReportV2Export {
  if (!verifyBaselineReportV2(report).valid)
    throw Error("Cannot export unverified baseline.");
  if (!["JSON", "CSV", "MARKDOWN"].includes(format))
    throw Error("Unsupported Baseline export.");
  let payload: string;
  if (format === "JSON")
    payload = JSON.stringify(report, null, 2) + "\n";
  else if (format === "CSV") {
    const rows: Array<Array<string | number | null>> = [
      ["questionId", "domain", "answer", "state",
        "evidenceReference", "independentlyVerified"],
      ...report.evidence.map(x => [
        x.questionId, x.domain, x.answer, x.state,
        x.evidenceReference, "false",
      ]),
    ];
    payload = rows.map(row => row.map(csvCell)
      .join(",")).join("\r\n") + "\r\n";
  } else {
    const lines = [
      "# CyberPilot — Organizational Baseline",
      "",
      "Organization: " + report.organizationId,
      "Date: " + report.evaluatedAt,
      "Completion: " + report.summary.completionPercent + "%",
      "Technical security state: NOT DETERMINED",
      "", "This questionnaire is not an accredited CIS assessment.",
    ];
    for (const item of report.sections) {
      lines.push("", "## " + item.title, item.description,
        "Answered: " + item.answered,
        "Unknown: " + item.unknown +
          " / Unanswered: " + item.unanswered);
    }
    lines.push("", "## Recommendations");
    for (const action of report.actions)
      lines.push("- " + action.title + ": " +
        action.steps.join(" "));
    lines.push("", "## Limitations",
      ...report.limitations.map(item => "- " + item));
    payload = lines.join("\n") + "\n";
  }
  return {
    schema: "cyberpilot.baseline.report.export.v2",
    organizationId: report.organizationId,
    snapshotId: report.snapshotId,
    format,
    filename: "baseline-" + report.snapshotId +
      (format === "JSON" ? ".json" :
        format === "CSV" ? ".csv" : ".md"),
    mimeType: format === "JSON" ? "application/json" :
      format === "CSV" ? "text/csv" : "text/markdown",
    payload, reportDigest: report.digest,
    exportDigest: sha256V2(payload),
    bytes: new TextEncoder().encode(payload).length,
    containsRawNotes: false, securityCertified: false,
  };
}
export function buildBaselineActionPlanV2(
  report: BaselineReportV2,
): BaselineActionPlanV2 {
  if (!verifyBaselineReportV2(report).valid)
    throw Error("Invalid Baseline before planning.");
  const domains = [...new Set(report.actions.map(x =>
    x.domain))];
  const rank: Record<BaselineV2Action["priority"], number> = {
    CRITICAL: 5, HIGH: 4, MEDIUM: 3,
    LOW: 2, UNKNOWN: 1, NOT_APPLICABLE: 0,
  };
  const sorted = [...report.actions].sort((a, b) =>
    rank[b.priority] - rank[a.priority] ||
      a.questionId.localeCompare(b.questionId));
  const canonical = {
    schema: "cyberpilot.baseline.action.plan.v2" as const,
    organizationId: report.organizationId,
    snapshotId: report.snapshotId,
    evaluatedAt: report.evaluatedAt,
    categories: domains.map(domain => {
      const scoped = report.actions.filter(x =>
        x.domain === domain);
      const deadlines = scoped.flatMap(x =>
        x.targetDays === null ? [] : [x.targetDays]);
      return {
        domain, actions: scoped.length,
        urgent: scoped.filter(x =>
          x.priority === "CRITICAL" || x.priority === "HIGH").length,
        unknown: scoped.filter(x =>
          x.priority === "UNKNOWN").length,
        earliestTargetDays: deadlines.length ?
          Math.min(...deadlines) : null,
        readyForAutomaticRemediation: false as const,
      };
    }),
    prioritized: sorted.map((item, index) => ({
      actionId: item.id, rank: index + 1,
      questionId: item.questionId, domain: item.domain,
      title: item.title, priority: item.priority,
      guidance: [...item.steps],
      requiredEvidence: item.evidenceNeeded,
      evidenceState: "UNVERIFIED" as const,
      externallyApproved: false as const,
      executed: false as const, completed: false as const,
    })),
    visibleUnknowns: report.evidence.filter(x =>
      x.answer === "UNKNOWN" || x.answer === "UNANSWERED")
      .map(x => x.questionId),
    limits: [
      "Action targets are planning suggestions, not regulatory deadlines.",
      "No ticket ownership or automatic remediation is inferred.",
      "CIS IG1-related themes are editorial, not official certification.",
    ],
    noAccountChanges: true as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function compareBaselineReportsV2(
  previous: BaselineReportV2,
  current: BaselineReportV2,
): BaselineReportDeltaV2 {
  if (!verifyBaselineReportV2(previous).valid ||
      !verifyBaselineReportV2(current).valid ||
      previous.organizationId !== current.organizationId ||
      previous.model !== current.model ||
      previous.evaluatedAt >= current.evaluatedAt)
    throw Error("Cannot compare different Baseline organizations or revisions.");
  const older = new Map(previous.evidence.map(x =>
    [x.questionId, x]));
  const newer = new Map(current.evidence.map(x =>
    [x.questionId, x]));
  const changedAnswers = [...newer].filter(([id, item]) =>
    item.answer !== older.get(id)?.answer).map(([id, item]) => ({
    questionId: id, prior: older.get(id)?.answer ?? "UNANSWERED",
    current: item.answer,
  }));
  return {
    organizationId: current.organizationId,
    from: previous.evaluatedAt, to: current.evaluatedAt,
    completionDelta: current.summary.completionPercent -
      previous.summary.completionPercent,
    newlyAnswered: [...newer].filter(([id, item]) =>
      older.get(id)?.answer === "UNANSWERED" &&
      item.answer !== "UNANSWERED").map(([id]) => id),
    newlyUnknown: [...newer].filter(([id, item]) =>
      (item.answer === "UNKNOWN" || item.answer === "UNANSWERED") &&
      oldAnswerKnown(older.get(id)?.answer)).map(([id]) => id),
    changedAnswers,
    changingAnswersProofOfRemediation: false,
    sourceEvidenceReverified: false,
    legacyScoreAdjusted: false,
  };
}
function oldAnswerKnown(answer: string | undefined) {
  return answer !== undefined &&
    answer !== "UNKNOWN" && answer !== "UNANSWERED";
}
export function verifyBaselineActionPlanV2(
  plan: BaselineActionPlanV2,
  report?: BaselineReportV2,
) {
  const { digest, ...canonical } = plan;
  const issues: string[] = [];
  if (digest !== sha(canonical))
    issues.push("PLAN_INTEGRITY");
  if (!plan.noAccountChanges ||
      plan.prioritized.some(x =>
        x.executed || x.completed || x.externallyApproved ||
        x.evidenceState !== "UNVERIFIED"))
    issues.push("FALSE_REMEDIATION_OR_APPROVAL");
  if (report && (
      !verifyBaselineReportV2(report).valid ||
      report.organizationId !== plan.organizationId ||
      buildBaselineActionPlanV2(report).digest !== digest))
    issues.push("PLAN_SOURCE_MISMATCH");
  return { valid: issues.length === 0, issues };
}
