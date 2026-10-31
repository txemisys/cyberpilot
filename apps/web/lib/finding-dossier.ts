import type { ReviewFinding } from "./finding-evidence-review";
import { buildFindingEvidenceReview } from "./finding-evidence-review";
import { assessControlAssurance } from "./control-assurance";
import { buildControlChronology } from "./control-chronology";
import { createFindingVerificationTasks } from "./verification-plan";
import { classifyFindingEvidenceGap } from "./evidence-gap-report";

export type DossierSection = {
  heading: string;
  statements: string[];
  warnings: string[];
};
export type FindingDossier = {
  findingId: string;
  title: string;
  severity: string;
  findingStatus: string;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedAt: Date | null;
  assessment: string;
  nextAction: string;
  assurance: string;
  gap: string;
  observed: number;
  declared: number;
  unknown: number;
  errors: number;
  remediations: number;
  verifiedRemediations: number;
  latestEvidenceAt: Date | null;
  latestWorkAt: Date | null;
  latestVerificationAt: Date | null;
  sections: DossierSection[];
  warnings: string[];
  evidenceIds: string[];
  actionIds: string[];
};
const iso = (value: Date | null): string => value?.toISOString() ?? "Not recorded";
export function buildFindingDossier(finding: ReviewFinding): FindingDossier {
  const assessment = buildFindingEvidenceReview(finding);
  const assurance = assessControlAssurance(finding);
  const chronology = buildControlChronology(finding);
  const gap = classifyFindingEvidenceGap(finding);
  const tasks = createFindingVerificationTasks(finding);
  const warnings = [
    ...assurance.limitations,
    ...chronology.warnings,
    ...tasks.flatMap(task => task.warnings),
  ];
  const uniqueWarnings = [...new Set(warnings)];
  const sourceSection: DossierSection = {
    heading: "Evidence and provenance",
    statements: [
      `Matched observed records: ${assessment.observedCount}`,
      `Matched declared records: ${assessment.declaredCount}`,
      `Unknown records: ${assessment.unknownCount}`,
      `Errored records: ${assessment.errorCount}`,
      `Last observed signal: ${iso(assessment.mostRecentObservationAt)}`,
      `Evidence gap classification: ${gap.kind}`,
      `Suggested evidence follow-up: ${gap.nextStep}`,
    ],
    warnings: finding.evidence.length === 0
      ? ["No exact identifier evidence is attributed. This does not prove evidence is absent."]
      : [],
  };
  const actionsSection: DossierSection = {
    heading: "Remediation activity",
    statements: [
      `Remediation workflows: ${assessment.actionCount}`,
      `Verified workflow records: ${assessment.verifiedActionCount}`,
      `Guided steps acknowledged: ${assessment.acknowledgedStepCount} / ${assessment.totalStepCount}`,
      `Last recorded work: ${iso(chronology.lastWorkAt)}`,
      `Last recorded workflow verification: ${iso(chronology.lastVerificationAt)}`,
      `Observed evidence after work: ${chronology.observationAfterWork ? "YES (review result)" : "NOT ESTABLISHED"}`,
    ],
    warnings: assessment.verifiedActionCount === 0
      ? ["No verified remediation outcome is recorded in the available actions."]
      : finding.status === "OPEN"
        ? ["A verified remediation record exists while the finding remains open."]
        : [],
  };
  const taskSection: DossierSection = {
    heading: "Remaining verification tasks",
    statements: tasks.flatMap((task, index) => [
      `Task ${index + 1}: ${task.title}`,
      `Workflow state: ${task.status}`,
      `Recommended step: ${task.suggestedNextStep}`,
      ...task.successCriteria.map((criterion, position) =>
        `Criterion ${position + 1}: ${criterion}`),
    ]),
    warnings: tasks.some(task => task.status === "collect-evidence")
      ? ["Fresh evidence is required; acknowledgements do not establish remediation."]
      : [],
  };
  const chronologySection: DossierSection = {
    heading: "Chronology",
    statements: [
      `Finding first seen: ${iso(finding.firstSeenAt)}`,
      `Finding last seen: ${iso(finding.lastSeenAt)}`,
      `Finding resolved: ${iso(finding.resolvedAt)}`,
      `Total dated events: ${chronology.count}`,
      `Finding events: ${chronology.findingEvents}`,
      `Workflow events: ${chronology.workflowEvents}`,
      `Observed evidence events: ${chronology.observations}`,
      `Work newer than observed evidence: ${chronology.workAfterObservation ? "YES" : "NO / NOT KNOWN"}`,
    ],
    warnings: chronology.warnings,
  };
  return {
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    findingStatus: finding.status,
    firstSeenAt: finding.firstSeenAt,
    lastSeenAt: finding.lastSeenAt,
    resolvedAt: finding.resolvedAt,
    assessment: assessment.status,
    nextAction: assessment.nextAction,
    assurance: assurance.level,
    gap: gap.kind,
    observed: assessment.observedCount,
    declared: assessment.declaredCount,
    unknown: assessment.unknownCount,
    errors: assessment.errorCount,
    remediations: assessment.actionCount,
    verifiedRemediations: assessment.verifiedActionCount,
    latestEvidenceAt: assessment.mostRecentObservationAt,
    latestWorkAt: chronology.lastWorkAt,
    latestVerificationAt: chronology.lastVerificationAt,
    sections: [sourceSection, actionsSection, taskSection, chronologySection],
    warnings: uniqueWarnings,
    evidenceIds: finding.evidence.map(item => item.id),
    actionIds: finding.actions.map(item => item.id),
  };
}
export type PortfolioDossier = {
  findings: FindingDossier[];
  total: number;
  open: number;
  resolved: number;
  withObserved: number;
  withDeclared: number;
  withVerifiedRemediation: number;
  awaitingEvidence: number;
  withoutMatchedEvidence: number;
  outstandingWarnings: number;
};
export function buildPortfolioDossier(findings: readonly ReviewFinding[]): PortfolioDossier {
  const entries = findings.map(buildFindingDossier);
  const severityOrder: Record<string, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
  };
  entries.sort((left, right) =>
    (severityOrder[left.severity] ?? 5) - (severityOrder[right.severity] ?? 5) ||
    left.findingId.localeCompare(right.findingId));
  return {
    findings: entries,
    total: entries.length,
    open: entries.filter(item => item.findingStatus === "OPEN").length,
    resolved: entries.filter(item => item.findingStatus === "RESOLVED").length,
    withObserved: entries.filter(item => item.observed > 0).length,
    withDeclared: entries.filter(item => item.declared > 0).length,
    withVerifiedRemediation: entries.filter(item => item.verifiedRemediations > 0).length,
    awaitingEvidence: entries.filter(item => item.assessment === "ready-for-check" ||
      item.assessment === "needs-observation").length,
    withoutMatchedEvidence: entries.filter(item =>
      item.observed + item.declared + item.unknown + item.errors === 0).length,
    outstandingWarnings: entries.reduce((sum, item) => sum + item.warnings.length, 0),
  };
}
export function serializeFindingDossier(dossier: FindingDossier): string {
  const lines = [
    "CYBERPILOT — SECURITY FINDING EVIDENCE DOSSIER",
    "Read-only operational documentation; not an independent certification.",
    "",
    "Finding: " + dossier.title,
    "Finding ID: " + dossier.findingId,
    "Severity: " + dossier.severity,
    "Finding status: " + dossier.findingStatus,
    "Evidence review: " + dossier.assessment,
    "Assurance classification: " + dossier.assurance,
    "Evidence gap: " + dossier.gap,
    "Next action: " + dossier.nextAction,
    "",
  ];
  for (const section of dossier.sections) {
    lines.push(section.heading.toUpperCase());
    lines.push(...section.statements);
    if (section.warnings.length) {
      lines.push("Section limitations:");
      lines.push(...section.warnings.map(warning => "- " + warning));
    }
    lines.push("");
  }
  lines.push("REVIEW LIMITATIONS");
  lines.push(...(dossier.warnings.length
    ? dossier.warnings.map(warning => "- " + warning)
    : ["- Matching and scope must still be checked by a competent reviewer."]));
  lines.push("", "This document does not change the underlying finding or CyberScore.");
  return lines.join("\n") + "\n";
}
export function serializePortfolioDossier(portfolio: PortfolioDossier): string {
  const header = [
    "CYBERPILOT — ORGANIZATION SECURITY EVIDENCE DOSSIER",
    "This report describes stored records and is not proof of compliance.",
    "",
    "Findings: " + portfolio.total,
    "Open findings: " + portfolio.open,
    "Resolved findings: " + portfolio.resolved,
    "Findings with observed signals: " + portfolio.withObserved,
    "Findings with declarations: " + portfolio.withDeclared,
    "Findings with verified remediation records: " + portfolio.withVerifiedRemediation,
    "Awaiting evidence review: " + portfolio.awaitingEvidence,
    "Without matched evidence: " + portfolio.withoutMatchedEvidence,
    "Recorded limitations: " + portfolio.outstandingWarnings,
    "",
  ];
  return header.join("\n") + portfolio.findings
    .map(serializeFindingDossier).join("\n" + "-".repeat(48) + "\n");
}
