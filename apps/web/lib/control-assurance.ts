import type { ReviewFinding, ReviewAction, ReviewEvidence } from "./finding-evidence-review";

export type AssuranceLevel = "verified-record" | "observed-after-work" | "observed-before-work" | "declaration-only" | "unavailable";
export type AssuranceDecision = "review-closure" | "request-observation" | "inspect-change" | "investigate-source" | "continue-work" | "review-record";
export type AssuranceControl = {
  findingId: string;
  title: string;
  description: string;
  ruleId?: string;
  severity: string;
  findingStatus: string;
  level: AssuranceLevel;
  decision: AssuranceDecision;
  decisionReason: string;
  recommendedAction: string;
  observations: number;
  declarations: number;
  errors: number;
  unknown: number;
  workflows: number;
  verifiedWorkflows: number;
  acknowledgedSteps: number;
  totalSteps: number;
  lastFindingAt: Date;
  lastObservationAt: Date | null;
  lastWorkAt: Date | null;
  lastVerificationAt: Date | null;
  observedAfterWork: boolean;
  supportingEvidence: string[];
  limitations: string[];
};
export type AssuranceSummary = {
  assessed: number;
  recordedVerified: number;
  observedAfterWork: number;
  observedBeforeWork: number;
  declarationOnly: number;
  unavailable: number;
  unresolved: number;
  readyForReview: number;
  sourceErrors: number;
};
const ranks: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const decisions: Record<AssuranceDecision, { title: string; next: string }> = {
  "review-closure": {
    title: "Review closure evidence and control scope",
    next: "Confirm that the stored resolution or verification addresses the full affected control scope.",
  },
  "request-observation": {
    title: "Collect fresh observed control evidence",
    next: "Use an authorized collection workflow after remediation and compare the result to the finding.",
  },
  "inspect-change": {
    title: "Inspect the observed control after work",
    next: "Review whether the recent observation actually demonstrates the expected security control.",
  },
  "investigate-source": {
    title: "Investigate missing or inconclusive evidence",
    next: "Check control identifiers, source availability and errors before asserting a result.",
  },
  "continue-work": {
    title: "Continue approved remediation",
    next: "Finish approved instructions or review failed execution, then request verification.",
  },
  "review-record": {
    title: "Review the existing evidence",
    next: "Check the finding, the matched control identifiers and the available evidence provenance.",
  },
};
function validDate(date: Date | null): date is Date {
  return date instanceof Date && Number.isFinite(date.getTime());
}
function latest(dates: readonly (Date | null)[]): Date | null {
  let best: Date | null = null;
  for (const date of dates) {
    if (validDate(date) && (!best || date.getTime() > best.getTime())) best = date;
  }
  return best;
}
function lastWorkflowWork(action: ReviewAction): Date | null {
  return latest([action.completedAt, action.startedAt, action.approvedAt]);
}
function lastObservedEvidence(item: ReviewEvidence): Date | null {
  if (item.source !== "OBSERVED") return null;
  return latest([item.lastObservedAt, item.capturedAt]);
}
function acknowledged(action: ReviewAction): number {
  let count = 0;
  for (let index = 0; index < action.steps.length; index++) {
    if (action.acknowledgedSteps.has(index)) count++;
  }
  return count;
}
function isVerified(action: ReviewAction): boolean {
  return action.status === "VERIFIED" && validDate(action.verifiedAt);
}
function pendingWork(action: ReviewAction): boolean {
  if (["APPROVED", "EXECUTING", "FAILED"].includes(action.status)) return true;
  return action.status === "PROPOSED";
}
export function assessControlAssurance(finding: ReviewFinding): AssuranceControl {
  const evidence = finding.evidence;
  const observed = evidence.filter(item => item.source === "OBSERVED");
  const declared = evidence.filter(item => item.source === "DECLARED");
  const errors = evidence.filter(item => item.source === "ERROR");
  const unknown = evidence.filter(item => item.source === "UNKNOWN");
  const observedAt = latest(observed.map(lastObservedEvidence));
  const workAt = latest(finding.actions.map(lastWorkflowWork));
  const verifiedActions = finding.actions.filter(isVerified);
  const verifiedAt = latest(verifiedActions.map(action => action.verifiedAt));
  const anyWorkRecorded = finding.actions.some(action =>
    Boolean(action.completedAt) || action.status === "SUCCEEDED");
  const observationAfterWork = Boolean(observedAt && workAt &&
    observedAt.getTime() >= workAt.getTime());
  let level: AssuranceLevel;
  if (verifiedActions.length > 0) level = "verified-record";
  else if (observationAfterWork) level = "observed-after-work";
  else if (observed.length > 0) level = "observed-before-work";
  else if (declared.length > 0) level = "declaration-only";
  else level = "unavailable";
  const limitations: string[] = [];
  if (!evidence.length) limitations.push(
    "No exact control-identifier evidence was matched; absence of a match does not prove absence of security.",
  );
  if (declared.length) limitations.push(
    "Declared evidence records a statement rather than an independently observed security outcome.",
  );
  if (errors.length || unknown.length) limitations.push(
    "Unknown or errored evidence cannot establish a verified control state.",
  );
  if (observedAt && workAt && observedAt.getTime() < workAt.getTime()) limitations.push(
    "The most recent matched observation predates recorded remediation activity.",
  );
  if (verifiedActions.length && finding.status === "OPEN") limitations.push(
    "An action has a verified workflow record, but the associated finding remains open.",
  );
  if (observed.length && !observedAt) limitations.push(
    "An observed-status record exists without a valid observation timestamp.",
  );
  if (finding.actions.length > 100) limitations.push(
    "Only a bounded number of linked remediation workflows may be present in this review.",
  );
  let decision: AssuranceDecision;
  if (finding.status === "RESOLVED" || verifiedActions.length > 0) {
    decision = "review-closure";
  } else if (anyWorkRecorded && !observationAfterWork) {
    decision = "request-observation";
  } else if (observationAfterWork) {
    decision = "inspect-change";
  } else if (!observed.length) {
    decision = "investigate-source";
  } else if (finding.actions.some(pendingWork)) {
    decision = "continue-work";
  } else {
    decision = "review-record";
  }
  const observedIds = observed.map(item => item.id);
  const decisionText = decisions[decision];
  const steps = finding.actions.reduce((count, action) => count + action.steps.length, 0);
  const confirmed = finding.actions.reduce((count, action) => count + acknowledged(action), 0);
  return {
    findingId: finding.id,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    findingStatus: finding.status,
    level,
    decision,
    decisionReason: decisionText.title,
    recommendedAction: decisionText.next,
    observations: observed.length,
    declarations: declared.length,
    errors: errors.length,
    unknown: unknown.length,
    workflows: finding.actions.length,
    verifiedWorkflows: verifiedActions.length,
    acknowledgedSteps: confirmed,
    totalSteps: steps,
    lastFindingAt: finding.lastSeenAt,
    lastObservationAt: observedAt,
    lastWorkAt: workAt,
    lastVerificationAt: verifiedAt,
    observedAfterWork: observationAfterWork,
    supportingEvidence: observedIds,
    limitations,
  };
}
export function buildControlAssurancePortfolio(
  findings: readonly ReviewFinding[],
): { controls: AssuranceControl[]; summary: AssuranceSummary } {
  const controls = findings.map(assessControlAssurance);
  const decisionRank: Record<AssuranceDecision, number> = {
    "request-observation": 0,
    "investigate-source": 1,
    "continue-work": 2,
    "inspect-change": 3,
    "review-record": 4,
    "review-closure": 5,
  };
  controls.sort((a, b) =>
    decisionRank[a.decision] - decisionRank[b.decision] ||
    (ranks[a.severity] ?? 5) - (ranks[b.severity] ?? 5) ||
    a.findingId.localeCompare(b.findingId));
  const count = (level: AssuranceLevel) => controls.filter(x => x.level === level).length;
  const summary: AssuranceSummary = {
    assessed: controls.length,
    recordedVerified: count("verified-record"),
    observedAfterWork: count("observed-after-work"),
    observedBeforeWork: count("observed-before-work"),
    declarationOnly: count("declaration-only"),
    unavailable: count("unavailable"),
    unresolved: controls.filter(x => x.findingStatus === "OPEN").length,
    readyForReview: controls.filter(x => x.decision === "request-observation" ||
      x.decision === "inspect-change").length,
    sourceErrors: controls.reduce((sum, x) => sum + x.errors, 0),
  };
  return { controls, summary };
}
const csv = (text: string): string => {
  const value = /^[\s]*[=+@\-]/.test(text) ? "'" + text : text;
  return '"' + value.replaceAll('"', '""') + '"';
};
export function exportControlAssuranceCsv(controls: readonly AssuranceControl[]): string {
  const rows = [
    ["Finding ID", "Finding", "Severity", "Finding status", "Assurance classification",
      "Recommended review", "Observed", "Declared", "Unknown", "Errors",
      "Workflows", "Verified workflows", "Steps acknowledged", "Total steps",
      "Last finding UTC", "Last observation UTC", "Last work UTC", "Last verification UTC",
      "Limitations"],
    ...controls.map(item => [
      item.findingId, item.title, item.severity, item.findingStatus,
      item.level, item.recommendedAction, String(item.observations),
      String(item.declarations), String(item.unknown), String(item.errors),
      String(item.workflows), String(item.verifiedWorkflows),
      String(item.acknowledgedSteps), String(item.totalSteps),
      item.lastFindingAt.toISOString(),
      item.lastObservationAt?.toISOString() ?? "",
      item.lastWorkAt?.toISOString() ?? "",
      item.lastVerificationAt?.toISOString() ?? "",
      item.limitations.join(" | "),
    ]),
  ];
  return "\uFEFF" + rows.map(row => row.map(csv).join(",")).join("\r\n") + "\r\n";
}
export function exportControlAssuranceText(controls: readonly AssuranceControl[]): string {
  const lines = [
    "CYBERPILOT — SECURITY CONTROL ASSURANCE REVIEW",
    "Operational evidence classification; not a security certification.",
    "",
    "Controls reviewed: " + controls.length,
  ];
  for (const [index, item] of controls.entries()) {
    lines.push(
      "",
      String(index + 1) + ". " + item.title,
      "Finding ID: " + item.findingId,
      "Severity: " + item.severity,
      "Finding state: " + item.findingStatus,
      "Evidence classification: " + item.level,
      "Observed: " + item.observations,
      "Declared: " + item.declarations,
      "Unknown: " + item.unknown,
      "Errors: " + item.errors,
      "Last observed: " + (item.lastObservationAt?.toISOString() ?? "Not recorded"),
      "Last work: " + (item.lastWorkAt?.toISOString() ?? "Not recorded"),
      "Verification timestamp: " + (item.lastVerificationAt?.toISOString() ?? "Not recorded"),
      "Recommended next step: " + item.recommendedAction,
      "Limitations:",
      ...item.limitations.map(text => "  - " + text),
    );
  }
  lines.push(
    "",
    "A recorded observation is not automatically a successful control test.",
    "A recorded action or acknowledgement is not proof of remediation.",
    "",
  );
  return lines.join("\n");
}
