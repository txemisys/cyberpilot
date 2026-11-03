import { WorkInputError } from "./remediation-work-input";
import type { IntegrityReviewDeadlineReport } from "./work-integrity-remediation-review-deadlines";
import type { IntegrityReviewEvidenceReport } from "./work-integrity-remediation-review-evidence";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityReviewGateReport } from "./work-integrity-remediation-review-gate";

export type IntegrityReviewEscalationReason =
  | "ACKNOWLEDGMENT_OVERDUE" | "RESOLUTION_OVERDUE"
  | "ESCALATION_DEADLINE" | "EVIDENCE_UNMATCHED"
  | "EVIDENCE_WITHDRAWN" | "EVIDENCE_CROSS_SCOPE"
  | "REVIEW_GATE_BLOCKED" | "UNASSIGNED_REVIEW";
export type IntegrityReviewEscalation = {
  escalationId: string;
  taskId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  reasons: IntegrityReviewEscalationReason[];
  sourceFindingCodes: string[];
  dueAt: string;
  evaluatedAt: string;
  priority: number;
  position: number;
  suggestedActions: string[];
  affectedEvidenceRefs: string[];
  requiresHumanReview: true;
  notificationDispatched: false;
};
export type IntegrityReviewEscalationPolicy = {
  includeWarnings: boolean;
  escalateMissingEvidence: boolean;
  escalateUnassignedReview: boolean;
  escalateGateBlockers: boolean;
  minimumPriority: number;
  maximumEscalations: number;
};
export type IntegrityReviewEscalationReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewEscalationPolicy;
  escalations: IntegrityReviewEscalation[];
  totals: {
    generated: number;
    returned: number;
    truncated: boolean;
    critical: number;
    high: number;
    medium: number;
    affectedTasks: number;
    evidenceRelated: number;
    byReason: Record<string, number>;
  };
  limitation: string;
};
export type IntegrityReviewEscalationQuery = {
  taskIds?: string[];
  severities?: IntegrityReviewEscalation["severity"][];
  reasons?: IntegrityReviewEscalationReason[];
  offset?: number;
  limit?: number;
};
export type IntegrityReviewEscalationPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  escalations: IntegrityReviewEscalation[];
};
const defaults: IntegrityReviewEscalationPolicy = {
  includeWarnings: true,
  escalateMissingEvidence: true,
  escalateUnassignedReview: true,
  escalateGateBlockers: true,
  minimumPriority: 0,
  maximumEscalations: 1000,
};
const reasons: IntegrityReviewEscalationReason[] = [
  "ACKNOWLEDGMENT_OVERDUE", "RESOLUTION_OVERDUE",
  "ESCALATION_DEADLINE", "EVIDENCE_UNMATCHED",
  "EVIDENCE_WITHDRAWN", "EVIDENCE_CROSS_SCOPE",
  "REVIEW_GATE_BLOCKED", "UNASSIGNED_REVIEW",
];
const severities: IntegrityReviewEscalation["severity"][] = [
  "CRITICAL", "HIGH", "MEDIUM",
];
function record(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityReviewEscalationPolicy(
  value: unknown,
): IntegrityReviewEscalationPolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "review escalation policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown escalation policy field.");
  const result = { ...defaults };
  for (const key of [
    "includeWarnings", "escalateMissingEvidence",
    "escalateUnassignedReview", "escalateGateBlockers",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid escalation flag.");
      result[key] = raw[key] as boolean;
    }
  }
  if (raw.minimumPriority !== undefined)
    result.minimumPriority = integer(raw.minimumPriority,
      "minimum escalation priority", 0, 1000);
  if (raw.maximumEscalations !== undefined)
    result.maximumEscalations = integer(raw.maximumEscalations,
      "maximum escalations", 1, 5000);
  return result;
}
export function buildIntegrityReviewEscalations(
  queue: IntegrityCapacityReviewQueue,
  deadlines: IntegrityReviewDeadlineReport,
  evidence: IntegrityReviewEvidenceReport | null,
  gate: IntegrityReviewGateReport | null,
  policy: IntegrityReviewEscalationPolicy = defaults,
): IntegrityReviewEscalationReport {
  if (queue.captureId !== deadlines.captureId ||
      (evidence && evidence.captureId !== queue.captureId) ||
      (gate && gate.captureId !== queue.captureId))
    throw new WorkInputError("INVALID", "Escalation capture mismatch.");
  const escalations: IntegrityReviewEscalation[] = [];
  for (const task of queue.tasks) {
    if (!policy.includeWarnings && task.severity === "INFO") continue;
    const deadline = deadlines.tasks.find(x => x.taskId === task.taskId);
    if (!deadline)
      throw new WorkInputError("INVALID", "Escalation deadline task missing.");
    const related = evidence?.references.filter(x =>
      x.taskId === task.taskId) ?? [];
    const gateTask = gate?.tasks.find(x => x.taskId === task.taskId);
    const found: IntegrityReviewEscalationReason[] = [];
    const actions: string[] = [];
    if (deadline.acknowledgmentBreached) {
      found.push("ACKNOWLEDGMENT_OVERDUE");
      actions.push("Request an explicit acknowledgment from the reviewer.");
    }
    if (deadline.resolutionBreached) {
      found.push("RESOLUTION_OVERDUE");
      actions.push("Review the outstanding resolution and its dependencies.");
    }
    if (deadline.escalationRequired) {
      found.push("ESCALATION_DEADLINE");
      actions.push("Escalate to the accountable human owner.");
    }
    if (policy.escalateMissingEvidence && related.some(x =>
      x.status === "UNKNOWN" || x.status === "FUTURE" ||
      x.status === "AMBIGUOUS")) {
      found.push("EVIDENCE_UNMATCHED");
      actions.push("Reconcile references against the recorded link audit.");
    }
    if (policy.escalateMissingEvidence && related.some(x =>
      x.status === "WITHDRAWN")) {
      found.push("EVIDENCE_WITHDRAWN");
      actions.push("Replace withdrawn evidence and repeat review.");
    }
    if (policy.escalateMissingEvidence && related.some(x =>
      x.status === "CROSS_TASK" || x.status === "CROSS_CAPTURE")) {
      found.push("EVIDENCE_CROSS_SCOPE");
      actions.push("Verify the task and capture boundary for every reference.");
    }
    if (policy.escalateGateBlockers && gateTask && !gateTask.ready) {
      found.push("REVIEW_GATE_BLOCKED");
      actions.push("Resolve conservative review gate blockers.");
    }
    if (policy.escalateUnassignedReview &&
        gateTask && !gateTask.ownerId && !deadline.completedAt) {
      found.push("UNASSIGNED_REVIEW");
      actions.push("Identify an authorized reviewer and record acknowledgment.");
    }
    if (!found.length) continue;
    const critical = task.severity === "ERROR" &&
      (found.includes("EVIDENCE_CROSS_SCOPE") ||
        found.includes("ESCALATION_DEADLINE") ||
        found.includes("EVIDENCE_WITHDRAWN"));
    const severity: IntegrityReviewEscalation["severity"] =
      critical ? "CRITICAL" :
      task.severity === "ERROR" || found.length >= 3 ? "HIGH" : "MEDIUM";
    const priority = (severity === "CRITICAL" ? 600 :
      severity === "HIGH" ? 400 : 200) +
      Math.min(150, found.length * 25) +
      (deadline.resolutionBreached ? 50 : 0);
    if (priority < policy.minimumPriority) continue;
    const sourceFindingCodes = evidence?.findings.filter(x =>
      x.taskId === task.taskId).map(x => x.code) ?? [];
    escalations.push({
      escalationId: "review-escalation:" + task.taskId,
      taskId: task.taskId, severity, reasons: found,
      sourceFindingCodes: [...new Set(sourceFindingCodes)].sort(),
      dueAt: deadline.escalationDeadline,
      evaluatedAt: deadlines.evaluatedAt,
      priority, position: 0,
      suggestedActions: actions,
      affectedEvidenceRefs: [...new Set(related.filter(x =>
        x.status !== "ACTIVE").map(x => x.reference))].sort(),
      requiresHumanReview: true,
      notificationDispatched: false,
    });
  }
  escalations.sort((a, b) =>
    b.priority - a.priority ||
    a.dueAt.localeCompare(b.dueAt) ||
    a.taskId.localeCompare(b.taskId));
  const generated = escalations.length;
  const selected = escalations.slice(0, policy.maximumEscalations);
  selected.forEach((x, index) => { x.position = index + 1; });
  const byReason: Record<string, number> = {};
  for (const escalation of selected)
    for (const reason of escalation.reasons)
      byReason[reason] = (byReason[reason] ?? 0) + 1;
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: deadlines.evaluatedAt,
    policy, escalations: selected,
    totals: {
      generated, returned: selected.length,
      truncated: generated > selected.length,
      critical: selected.filter(x =>
        x.severity === "CRITICAL").length,
      high: selected.filter(x => x.severity === "HIGH").length,
      medium: selected.filter(x => x.severity === "MEDIUM").length,
      affectedTasks: new Set(selected.map(x => x.taskId)).size,
      evidenceRelated: selected.filter(x => x.reasons.some(reason =>
        reason.startsWith("EVIDENCE_"))).length,
      byReason,
    },
    limitation: "Escalations are computed recommendations only; no notifications are dispatched, no ownership is assigned, and caller-provided evidence is not independently verified.",
  };
}
export function parseIntegrityReviewEscalationQuery(
  value: unknown,
): IntegrityReviewEscalationQuery {
  const raw = record(value, "review escalation query");
  if (Object.keys(raw).some(x => ![
    "taskIds", "severities", "reasons", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown escalation query field.");
  const selectedSeverities = raw.severities === undefined ? undefined :
    identifiers(raw.severities, "escalation severities", severities.length);
  const selectedReasons = raw.reasons === undefined ? undefined :
    identifiers(raw.reasons, "escalation reasons", reasons.length);
  if (selectedSeverities?.some(x => !severities.includes(
    x as IntegrityReviewEscalation["severity"])) ||
      selectedReasons?.some(x => !reasons.includes(
        x as IntegrityReviewEscalationReason)))
    throw new WorkInputError("INVALID", "Unknown escalation filter.");
  return {
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "escalation task IDs", 500),
    }),
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities as IntegrityReviewEscalation["severity"][],
    }),
    ...(selectedReasons === undefined ? {} : {
      reasons: selectedReasons as IntegrityReviewEscalationReason[],
    }),
    offset: integer(raw.offset ?? 0, "escalation offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "escalation limit", 1, 500),
  };
}
export function queryIntegrityReviewEscalations(
  report: IntegrityReviewEscalationReport,
  query: IntegrityReviewEscalationQuery,
): IntegrityReviewEscalationPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.escalations.filter(x =>
    (!query.taskIds || query.taskIds.includes(x.taskId)) &&
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.reasons || x.reasons.some(reason =>
      query.reasons!.includes(reason))));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    escalations: selected.slice(offset, offset + limit),
  };
}
