import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityGovernanceReport,
} from "./work-integrity-remediation-capacity-governance";
import type {
  IntegrityCapacityDecisionReport,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacityReviewQueue,
} from "./work-integrity-remediation-capacity-review-queue";
import type {
  IntegrityReviewReplay,
  IntegrityReviewTaskState,
} from "./work-integrity-remediation-review-event-replay";

export type IntegrityReviewGatePolicy = {
  requireAllRequiredReviews: boolean;
  allowWaivedWarnings: boolean;
  allowWaivedErrors: boolean;
  rejectAnyEventFailure: boolean;
  requireResolvedEvidence: boolean;
  requireOwnerForCompletion: boolean;
  requireGovernanceAcceptable: boolean;
  requireUnchangedSelection: boolean;
  maximumOutstandingOptional: number;
};
export type IntegrityReviewGateBlocker = {
  code: string;
  taskId: string | null;
  severity: "ERROR" | "WARNING";
  detail: string;
  suggestedAction: string;
};
export type IntegrityReviewGateTask = {
  taskId: string;
  action: string;
  severity: "ERROR" | "WARNING" | "INFO";
  required: boolean;
  disposition: string;
  ownerId: string | null;
  version: number;
  evidenceCount: number;
  acceptedEventCount: number;
  rejectedEventCount: number;
  ready: boolean;
  blockers: string[];
};
export type IntegrityReviewGateReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewGatePolicy;
  status: "BLOCKED" | "REVIEW_REQUIRED" | "ANALYTICALLY_REVIEWED";
  selectedBundleId: string | null;
  tasks: IntegrityReviewGateTask[];
  blockers: IntegrityReviewGateBlocker[];
  totals: {
    tasks: number;
    required: number;
    completed: number;
    outstanding: number;
    optionalOutstanding: number;
    blockedTasks: number;
    resolvedWithEvidence: number;
    waived: number;
    rejectedEvents: number;
    blockers: number;
    errorBlockers: number;
    warningBlockers: number;
  };
  limitation: string;
};
export type IntegrityReviewGateQuery = {
  onlyBlocked?: boolean;
  onlyRequired?: boolean;
  statuses?: Array<IntegrityReviewGateReport["status"]>;
  taskIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityReviewGatePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityReviewGateTask[];
};
const defaults: IntegrityReviewGatePolicy = {
  requireAllRequiredReviews: true,
  allowWaivedWarnings: true,
  allowWaivedErrors: false,
  rejectAnyEventFailure: true,
  requireResolvedEvidence: true,
  requireOwnerForCompletion: true,
  requireGovernanceAcceptable: false,
  requireUnchangedSelection: false,
  maximumOutstandingOptional: 100,
};
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
export function parseIntegrityReviewGatePolicy(
  value: unknown,
): IntegrityReviewGatePolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "review gate policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown review gate policy field.");
  const policy = { ...defaults };
  for (const key of [
    "requireAllRequiredReviews", "allowWaivedWarnings",
    "allowWaivedErrors", "rejectAnyEventFailure",
    "requireResolvedEvidence", "requireOwnerForCompletion",
    "requireGovernanceAcceptable", "requireUnchangedSelection",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid gate flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumOutstandingOptional !== undefined)
    policy.maximumOutstandingOptional = integer(
      raw.maximumOutstandingOptional, "optional review limit", 0, 10000);
  return policy;
}
function taskBlockers(
  task: IntegrityCapacityReviewQueue["tasks"][number],
  state: IntegrityReviewTaskState,
  policy: IntegrityReviewGatePolicy,
): string[] {
  const blockers: string[] = [];
  if (state.disposition === "WAIVED") {
    if (task.severity === "ERROR" && !policy.allowWaivedErrors)
      blockers.push("ERROR_WAIVER_NOT_ACCEPTED");
    if (task.severity === "WARNING" && !policy.allowWaivedWarnings)
      blockers.push("WARNING_WAIVER_NOT_ACCEPTED");
  } else if (state.disposition !== "RESOLVED") {
    blockers.push("REVIEW_NOT_COMPLETED");
  }
  if (state.disposition === "RESOLVED" &&
      policy.requireResolvedEvidence &&
      !state.resolutionEvidenceRefs.length)
    blockers.push("RESOLUTION_EVIDENCE_MISSING");
  if (state.terminal && policy.requireOwnerForCompletion &&
      !state.ownerId)
    blockers.push("REVIEW_OWNER_MISSING");
  if (state.terminal && !state.resolutionReason?.trim())
    blockers.push("REVIEW_RATIONALE_MISSING");
  return blockers;
}
export function evaluateIntegrityReviewGate(
  governance: IntegrityCapacityGovernanceReport,
  decision: IntegrityCapacityDecisionReport,
  queue: IntegrityCapacityReviewQueue,
  replay: IntegrityReviewReplay,
  policy: IntegrityReviewGatePolicy = defaults,
): IntegrityReviewGateReport {
  const captureId = governance.captureId;
  if (decision.captureId !== captureId ||
      queue.captureId !== captureId || replay.captureId !== captureId)
    throw new WorkInputError("INVALID", "Review gate capture mismatch.");
  if (decision.selectedBundleId !== governance.selectedBundleId)
    throw new WorkInputError("INVALID", "Review gate selection mismatch.");
  const states = new Map(replay.tasks.map(x => [x.taskId, x]));
  if (states.size !== replay.tasks.length ||
      states.size !== queue.tasks.length ||
      queue.tasks.some(x => !states.has(x.taskId)))
    throw new WorkInputError("INVALID", "Review gate task set mismatch.");
  const tasks: IntegrityReviewGateTask[] = queue.tasks.map(task => {
    const state = states.get(task.taskId)!;
    const blockers = taskBlockers(task, state, policy);
    return {
      taskId: task.taskId, action: task.action,
      severity: task.severity, required: task.reviewRequired,
      disposition: state.disposition, ownerId: state.ownerId,
      version: state.version,
      evidenceCount: state.resolutionEvidenceRefs.length,
      acceptedEventCount: state.history.filter(x => x.accepted).length,
      rejectedEventCount: state.history.filter(x => !x.accepted).length,
      ready: blockers.length === 0,
      blockers,
    };
  });
  const blockers: IntegrityReviewGateBlocker[] = [];
  const add = (
    code: string,
    severity: "ERROR" | "WARNING",
    detail: string,
    suggestedAction: string,
    taskId: string | null = null,
  ) => blockers.push({ code, severity, detail, suggestedAction, taskId });
  if (!decision.selectedBundleId)
    add("NO_SCENARIO_SELECTED", "ERROR",
      "No eligible capacity scenario is selected.",
      "Review the eligibility constraints and recompute the portfolio.");
  if (governance.status === "BLOCKED")
    add("GOVERNANCE_BLOCKED", "ERROR",
      "Governance reports blocking analytical findings.",
      "Resolve blocking governance findings before review sign-off.");
  if (policy.requireGovernanceAcceptable &&
      governance.status !== "ANALYTICALLY_ACCEPTABLE")
    add("GOVERNANCE_NOT_ACCEPTABLE", "ERROR",
      "Governance is not analytically acceptable.",
      "Review outstanding governance warnings.");
  if (policy.requireUnchangedSelection &&
      governance.totals.comparedPolicySelectionChanged)
    add("POLICY_SELECTION_UNSTABLE", "ERROR",
      "The preferred scenario changes under the comparison policy.",
      "Document and resolve the policy selection disagreement.");
  if (policy.rejectAnyEventFailure && replay.totals.rejectedEvents)
    add("REJECTED_REVIEW_EVENTS", "ERROR",
      "One or more supplied review events failed validation.",
      "Correct the event sequence and optimistic versions.");
  const optionalOutstanding = tasks.filter(x =>
    !x.required && !x.ready).length;
  if (optionalOutstanding > policy.maximumOutstandingOptional)
    add("OPTIONAL_REVIEW_LIMIT", "WARNING",
      "Too many optional reviews remain outstanding.",
      "Complete optional reviews or adjust the bounded policy.");
  for (const task of tasks) {
    if (task.ready) continue;
    if (!task.required && policy.requireAllRequiredReviews) continue;
    for (const code of task.blockers)
      add(code, task.severity === "ERROR" ? "ERROR" : "WARNING",
        "Review task " + task.taskId + " is not ready.",
        "Complete or explicitly waive the task with the required rationale.",
        task.taskId);
  }
  blockers.sort((a, b) =>
    Number(b.severity === "ERROR") -
      Number(a.severity === "ERROR") ||
    a.code.localeCompare(b.code) ||
    (a.taskId ?? "").localeCompare(b.taskId ?? ""));
  const errors = blockers.filter(x => x.severity === "ERROR").length;
  const warnings = blockers.length - errors;
  return {
    schemaVersion: 1, captureId,
    evaluatedAt: replay.evaluatedAt,
    policy,
    status: errors ? "BLOCKED" : warnings ?
      "REVIEW_REQUIRED" : "ANALYTICALLY_REVIEWED",
    selectedBundleId: decision.selectedBundleId,
    tasks, blockers,
    totals: {
      tasks: tasks.length,
      required: tasks.filter(x => x.required).length,
      completed: tasks.filter(x => x.ready).length,
      outstanding: tasks.filter(x => !x.ready).length,
      optionalOutstanding,
      blockedTasks: tasks.filter(x => x.blockers.length).length,
      resolvedWithEvidence: tasks.filter(x =>
        x.disposition === "RESOLVED" && x.evidenceCount > 0).length,
      waived: tasks.filter(x => x.disposition === "WAIVED").length,
      rejectedEvents: replay.totals.rejectedEvents,
      blockers: blockers.length,
      errorBlockers: errors,
      warningBlockers: warnings,
    },
    limitation: "ANALYTICALLY_REVIEWED means only that caller-supplied review events satisfy the analytical policy. It is not authenticated human approval, persisted workflow state, or verified evidence.",
  };
}
export function parseIntegrityReviewGateQuery(
  value: unknown,
): IntegrityReviewGateQuery {
  const raw = record(value, "review gate query");
  if (Object.keys(raw).some(x => ![
    "onlyBlocked", "onlyRequired", "taskIds", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown review gate query field.");
  for (const key of ["onlyBlocked", "onlyRequired"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid review gate filter.");
  }
  let taskIds: string[] | undefined;
  if (raw.taskIds !== undefined) {
    if (!Array.isArray(raw.taskIds) || raw.taskIds.length > 500 ||
        raw.taskIds.some(x => typeof x !== "string" || !x ||
          x.length > 300))
      throw new WorkInputError("INVALID", "Invalid review gate task IDs.");
    taskIds = [...new Set(raw.taskIds as string[])];
  }
  return {
    onlyBlocked: raw.onlyBlocked === true,
    onlyRequired: raw.onlyRequired === true,
    ...(taskIds === undefined ? {} : { taskIds }),
    offset: integer(raw.offset ?? 0, "review gate offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "review gate limit", 1, 500),
  };
}
export function queryIntegrityReviewGate(
  report: IntegrityReviewGateReport,
  query: IntegrityReviewGateQuery,
): IntegrityReviewGatePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const tasks = report.tasks.filter(x =>
    (!query.onlyBlocked || !x.ready) &&
    (!query.onlyRequired || x.required) &&
    (!query.taskIds || query.taskIds.includes(x.taskId)));
  return {
    captureId: report.captureId, total: tasks.length,
    offset, limit, hasMore: offset + limit < tasks.length,
    tasks: tasks.slice(offset, offset + limit),
  };
}
