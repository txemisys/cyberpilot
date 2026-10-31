import type { ReviewFinding, ReviewAction, ReviewEvidence } from "./finding-evidence-review";

export type VerificationTaskStatus =
  | "pending-approval"
  | "perform-work"
  | "collect-evidence"
  | "inspect-evidence"
  | "review-closure"
  | "complete"
  | "needs-investigation";

export type VerificationTask = {
  id: string;
  findingId: string;
  findingTitle: string;
  severity: string;
  actionId: string | null;
  actionTitle: string | null;
  status: VerificationTaskStatus;
  title: string;
  description: string;
  rationale: string;
  successCriteria: string[];
  prerequisites: string[];
  warnings: string[];
  relatedEvidenceIds: string[];
  createdAt: Date;
  lastFindingSeenAt: Date;
  lastObservationAt: Date | null;
  verifiedAt: Date | null;
  actionable: boolean;
  suggestedNextStep: string;
  priority: number;
};

export type VerificationPlan = {
  items: VerificationTask[];
  total: number;
  pendingApproval: number;
  performWork: number;
  collectEvidence: number;
  investigate: number;
  reviewClosure: number;
  complete: number;
  highestPriority: VerificationTask | null;
};

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const statusOrder: Record<VerificationTaskStatus, number> = {
  "collect-evidence": 0,
  "needs-investigation": 1,
  "perform-work": 2,
  "pending-approval": 3,
  "inspect-evidence": 4,
  "review-closure": 5,
  complete: 6,
};

function newestObservation(records: readonly ReviewEvidence[]): Date | null {
  let recent: Date | null = null;
  for (const evidence of records) {
    if (evidence.source !== "OBSERVED") continue;
    const date = evidence.lastObservedAt ?? evidence.capturedAt;
    if (date && (!recent || recent.getTime() < date.getTime())) recent = date;
  }
  return recent;
}

function acknowledged(action: ReviewAction): number {
  let count = 0;
  for (let index = 0; index < action.steps.length; index++) {
    if (action.acknowledgedSteps.has(index)) count++;
  }
  return count;
}

function hasVerifiedTimestamp(action: ReviewAction): boolean {
  return action.status === "VERIFIED" && action.verifiedAt !== null;
}

function nextIncompleteStep(action: ReviewAction): string | null {
  for (let index = 0; index < action.steps.length; index++) {
    if (!action.acknowledgedSteps.has(index)) {
      return action.steps[index] ?? null;
    }
  }
  return null;
}

function createTask(
  finding: ReviewFinding,
  action: ReviewAction | null,
): VerificationTask {
  const observation = newestObservation(finding.evidence);
  const observed = finding.evidence.filter(x => x.source === "OBSERVED");
  const declared = finding.evidence.filter(x => x.source === "DECLARED");
  const errored = finding.evidence.filter(x =>
    x.source === "ERROR" || x.source === "UNKNOWN");
  const lastSeen = finding.lastSeenAt;
  const completed = action ? acknowledged(action) : 0;
  const allAcknowledged = Boolean(action && action.steps.length > 0 &&
    completed === action.steps.length);
  const verified = action ? hasVerifiedTimestamp(action) : false;
  const changedAfterObservation = Boolean(action?.completedAt &&
    (!observation || observation.getTime() < action.completedAt.getTime()));
  const verificationList = action?.verification.filter(item => item.trim()) ?? [];

  let status: VerificationTaskStatus;
  let title: string;
  let description: string;
  let nextStep: string;
  const prerequisites: string[] = [];
  const warnings: string[] = [];
  const criteria: string[] = [];

  if (finding.status === "RESOLVED") {
    status = "review-closure";
    title = "Review closure provenance";
    description = "The stored finding is resolved; confirm its closure record before sharing results.";
    nextStep = "Review resolution time and evidence lineage.";
  } else if (verified) {
    status = "complete";
    title = "Review verified remediation";
    description = "The action has a verification timestamp. Confirm whether the finding is also resolved.";
    nextStep = "Inspect the finding status and verification record.";
  } else if (!action) {
    status = "needs-investigation";
    title = "Prepare a remediation plan";
    description = "No remediation has been recorded for the finding.";
    nextStep = "Identify an appropriate action and validation checklist.";
    prerequisites.push("Review finding description and available evidence.");
  } else if (action.status === "FAILED") {
    status = "needs-investigation";
    title = "Investigate failed remediation";
    description = "The latest action failed. Examine the recorded failure before retrying.";
    nextStep = "Inspect the action failure and decide whether to retry or change the plan.";
    warnings.push("A previous failed execution is not evidence of an effective control.");
  } else if (action.status === "PROPOSED") {
    status = "pending-approval";
    title = "Review and approve the proposed action";
    description = "Work must be authorized through the existing remediation workflow.";
    nextStep = "Review the proposed steps and approve only if appropriate.";
    prerequisites.push("Confirm approval rights and the scope of the proposed change.");
  } else if (action.status === "SUCCEEDED" || allAcknowledged ||
    changedAfterObservation) {
    status = "collect-evidence";
    title = "Collect fresh evidence after remediation";
    description = "Recorded work cannot establish the fix until evidence is refreshed.";
    nextStep = "Collect a new observation and compare it with the verification checklist.";
    warnings.push("Acknowledged steps and successful execution do not verify the finding.");
  } else if (action.status === "EXECUTING" ||
    action.status === "APPROVED") {
    status = "perform-work";
    title = "Continue approved remediation";
    description = "Finish the applicable work instructions before seeking fresh evidence.";
    nextStep = nextIncompleteStep(action) ??
      "Review execution status and record the work result.";
  } else if (observed.length === 0) {
    status = "inspect-evidence";
    title = "Inspect missing observed evidence";
    description = "No observed signal was attributed to this finding.";
    nextStep = "Check whether an authorized evidence source can provide observations.";
  } else {
    status = "inspect-evidence";
    title = "Inspect remediation and supporting evidence";
    description = "The workflow has not established a verified security improvement.";
    nextStep = "Review the finding and determine which evidence is still required.";
  }

  // Verification must assess the same affected control and scope. A recorded
  // timestamp or an unrelated signal must not be used as proof of closure.
  prerequisites.push(
    "Confirm the original finding's affected identities, systems and control scope.",
  );
  if (finding.status === "OPEN") {
    criteria.push(
      "Confirm whether the latest stored finding still reports an open issue.",
    );
  }
  if (observed.length === 0) {
    prerequisites.push(
      "Identify an authorized source capable of observing the relevant control.",
    );
  }
  if (action?.completedAt && !observation) {
    warnings.push(
      "No matched observation is available to compare with recorded completion.",
    );
  }
  if (verificationList.length) criteria.push(...verificationList);
  else criteria.push(
    "Inspect a fresh authoritative observation.",
    "Compare the observation against the original security finding.",
    "Record whether the finding remains open or has been resolved.",
  );
  if (declared.length) warnings.push(
    `${declared.length} declared signals cannot independently prove control effectiveness.`,
  );
  if (errored.length) warnings.push(
    `${errored.length} unknown or errored signals require separate investigation.`,
  );
  if (action && !verified && observation && action.completedAt &&
    observation.getTime() < action.completedAt.getTime()) {
    warnings.push("The most recent observation predates completed remediation work.");
  }
  const actionable = status !== "complete" && status !== "review-closure";
  const priority = statusOrder[status] * 10 +
    (severityOrder[finding.severity] ?? 5);
  return {
    id: action ? `${finding.id}:${action.id}` : `${finding.id}:unassigned`,
    findingId: finding.id,
    findingTitle: finding.title,
    severity: finding.severity,
    actionId: action?.id ?? null,
    actionTitle: action?.title ?? null,
    status,
    title,
    description,
    rationale: `Finding ${finding.status}; ${observed.length} observed, ${declared.length} declared, and ${errored.length} inconclusive signals.`,
    successCriteria: criteria,
    prerequisites,
    warnings,
    relatedEvidenceIds: finding.evidence.map(item => item.id),
    createdAt: action?.createdAt ?? finding.firstSeenAt,
    lastFindingSeenAt: lastSeen,
    lastObservationAt: observation,
    verifiedAt: verified ? action?.verifiedAt ?? null : null,
    actionable,
    suggestedNextStep: nextStep,
    priority,
  };
}

export function createFindingVerificationTasks(
  finding: ReviewFinding,
): VerificationTask[] {
  if (!finding.actions.length) return [createTask(finding, null)];
  return finding.actions.map(action => createTask(finding, action));
}

export function buildVerificationPlan(findings: readonly ReviewFinding[]): VerificationPlan {
  const items = findings.flatMap(createFindingVerificationTasks);
  items.sort((a, b) =>
    a.priority - b.priority ||
    a.findingId.localeCompare(b.findingId) ||
    a.id.localeCompare(b.id));
  const count = (status: VerificationTaskStatus) =>
    items.filter(item => item.status === status).length;
  return {
    items,
    total: items.length,
    pendingApproval: count("pending-approval"),
    performWork: count("perform-work"),
    collectEvidence: count("collect-evidence") + count("inspect-evidence"),
    investigate: count("needs-investigation"),
    reviewClosure: count("review-closure"),
    complete: count("complete"),
    highestPriority: items.find(item => item.actionable) ?? null,
  };
}

export function renderVerificationPlanText(plan: VerificationPlan): string {
  const lines = [
    "CYBERPILOT — EVIDENCE VERIFICATION PLAN",
    "Operational review only. Not a security certification.",
    `Tasks: ${plan.total}`,
    `Awaiting approval: ${plan.pendingApproval}`,
    `Work in progress: ${plan.performWork}`,
    `Collect or inspect evidence: ${plan.collectEvidence}`,
    `Requires investigation: ${plan.investigate}`,
    "",
  ];
  for (const [index, task] of plan.items.entries()) {
    lines.push(
      `TASK ${index + 1}: ${task.title}`,
      `Finding: ${task.findingTitle}`,
      `Severity: ${task.severity}`,
      `State: ${task.status}`,
      `Action: ${task.actionTitle ?? "Unassigned"}`,
      `Next step: ${task.suggestedNextStep}`,
      "Success criteria:",
      ...task.successCriteria.map((item, n) => `  ${n + 1}. ${item}`),
      "Warnings:",
      ...(task.warnings.length ? task.warnings.map(x => "  - " + x) :
        ["  None recorded"]),
      "",
    );
  }
  lines.push("Verification must be supported by current evidence, not step acknowledgements.");
  return lines.join("\n") + "\n";
}
