import { createHash } from "node:crypto";
import type { AssuranceHandoffBoard, AssuranceHandoff,
  HandoffPriority } from "./incident-assurance-handoff-domain";

/**
 * Internal escalation dispatch planner. A scheduled check produces an
 * OFFLINE assessment; dispatch is not external notification or remediation.
 */
export type EscalationRule = {
  id: string;
  priority: HandoffPriority;
  status: "UNASSIGNED" | "ASSIGNED" | "ACCEPTED" |
    "NEEDS_EVIDENCE" | "ESCALATED_INTERNAL" | "REOPENED";
  trigger: "PAST_DUE" | "DUE_SOON" | "UNASSIGNED_AGE" |
    "UNACCEPTED_AGE" | "STALE_REVIEW" | "MISSING_EVIDENCE";
  minimumAgeMinutes: number;
  warningMinutes: number;
  maximumFrequencyMinutes: number;
  escalationLevel: 1 | 2 | 3;
  recommendedRole: "OWNER" | "ADMIN" | "SECURITY_REVIEWER";
  requireIndependentReview: boolean;
};
export type EscalationPolicy = {
  schema: "cyberpilot.incident.escalation.policy.v1";
  id: string;
  effectiveAt: string;
  rules: EscalationRule[];
  concurrencyPerTenant: number;
  maxDispatchesPerCycle: number;
  minReevaluationMinutes: number;
  schedulingHorizonMinutes: number;
  riskAcceptedForInternalReadOnly: true;
  externalNotificationsAllowed: false;
  providerWritesAllowed: false;
};
export type EscalationCandidate = {
  schema: "cyberpilot.incident.escalation.candidate.v1";
  organizationId: string;
  incidentId: string;
  boardId: string;
  boardRevision: number;
  handoffId: string;
  handoffRevision: number;
  controlId: string;
  priority: HandoffPriority;
  status: AssuranceHandoff["status"];
  ruleId: string;
  trigger: EscalationRule["trigger"];
  level: 1 | 2 | 3;
  eligibleAt: string;
  dueAt: string;
  evaluatedAt: string;
  assignedUserId: string | null;
  recommendedRole: EscalationRule["recommendedRole"];
  requiresIndependentReview: boolean;
  evidenceMissing: boolean;
  ageMinutes: number;
  lateMinutes: number;
  previousEscalationAt: string | null;
  shouldSchedule: boolean;
  reason: "ELIGIBLE" | "COOLDOWN" | "FUTURE" |
    "TERMINAL" | "UNSUPPORTED" | "ASSIGNEE_REQUIRED";
  boardDigest: string;
  idempotencyKey: string;
  providerWrites: 0;
};
export type EscalationDispatch = {
  schema: "cyberpilot.incident.escalation.dispatch.v1";
  organizationId: string;
  incidentId: string;
  boardId: string;
  handoffId: string;
  ruleId: string;
  scheduledAt: string;
  expiresAt: string;
  idempotencyKey: string;
  payload: {
    incidentId: string;
    boardId: string;
    handoffId: string;
    ruleId: string;
    boardRevision: number;
    handoffRevision: number;
    boardDigest: string;
    expectedPriority: HandoffPriority;
    expectedStatus: AssuranceHandoff["status"];
    dispatchedAt: string;
    plannedFor: string;
    internalOnly: true;
    externalNotificationsAllowed: false;
  };
  authorizedProviderMutations: 0;
  notificationDeliveries: 0;
};
export type EscalationPlan = {
  schema: "cyberpilot.incident.escalation.plan.v1";
  organizationId: string;
  incidentId: string;
  policyId: string;
  generatedAt: string;
  sourceBoards: number;
  sourceHandoffs: number;
  eligible: number;
  delayed: number;
  omitted: number;
  saturated: boolean;
  candidates: EscalationCandidate[];
  dispatches: EscalationDispatch[];
  reasons: Record<string, number>;
  planDigest: string;
  externalWrites: 0;
  notificationsSent: 0;
};
export type EscalationExecutionResult = {
  schema: "cyberpilot.incident.escalation.execution.v1";
  organizationId: string;
  incidentId: string;
  boardId: string;
  handoffId: string;
  policyId: string;
  ruleId: string;
  evaluatedAt: string;
  status: "STILL_ACTIONABLE" | "RESOLVED_INTERNAL" |
    "STALE_SNAPSHOT" | "UNAVAILABLE" | "NOT_DUE";
  currentRevision: number | null;
  previousRevision: number;
  reason: string;
  canEscalateInternally: boolean;
  recommendedRole: string | null;
  nextReviewAt: string | null;
  externalNotificationDispatched: false;
  providerWrites: 0;
  executedControlChanges: 0;
};
export type EscalationQueueState = "PLANNED" | "ADMITTED" |
  "CLAIMED" | "OBSERVED" | "DEFERRED" | "CANCELLED" | "DEAD_LETTER";
export type EscalationQueueEvent = {
  schema: "cyberpilot.incident.escalation.queue-event.v1";
  organizationId: string;
  incidentId: string;
  dispatchKey: string;
  revision: number;
  kind: EscalationQueueState;
  actorId: string;
  at: string;
  before: EscalationQueueState | null;
  after: EscalationQueueState;
  priorDigest: string | null;
  eventDigest: string;
  providerWrites: 0;
};
export type EscalationQueueSnapshot = {
  schema: "cyberpilot.incident.escalation.queue.v1";
  organizationId: string;
  incidentId: string;
  dispatchKey: string;
  revision: number;
  state: EscalationQueueState;
  dispatch: EscalationDispatch;
  admittedAt: string | null;
  claimedAt: string | null;
  observedAt: string | null;
  cancelledAt: string | null;
  lastActorId: string;
  lastResult: EscalationExecutionResult | null;
  eventDigest: string;
  externallyExecuted: false;
};
export type EscalationAssignmentHint = {
  handoffId: string;
  boardId: string;
  priority: HandoffPriority;
  eligibility: "ASSIGNED" | "UNASSIGNED" | "REVOKED" | "UNKNOWN";
  assignedUserId: string | null;
  recommendedRole: string;
  independentReviewNeeded: boolean;
  memberScopeConfirmed: boolean;
  providerWrites: 0;
};
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso = (x: unknown): x is string => typeof x === "string" &&
  Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const sha = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const reject = (code: string): never => { throw Error(code); };
function canonical(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canonical);
  if (x !== null && typeof x === "object") {
    const r = x as Record<string, unknown>;
    return Object.fromEntries(Object.keys(r).sort()
      .filter(k => r[k] !== undefined).map(k => [k, canonical(r[k])]));
  }
  return x;
}
export const escalationDigest = (x: unknown) => createHash("sha256")
  .update(JSON.stringify(canonical(x))).digest("hex");
function minutes(now: string, before: string) {
  return Math.max(0, Math.floor(
    (Date.parse(now) - Date.parse(before)) / 60000));
}
function plus(now: string, offset: number) {
  return new Date(Date.parse(now) + offset * 60000).toISOString();
}
function ruleStatuses() {
  return ["UNASSIGNED", "ASSIGNED", "ACCEPTED", "NEEDS_EVIDENCE",
    "ESCALATED_INTERNAL", "REOPENED"];
}
function activeStatus(status: string) {
  return !["REVIEWED_INTERNAL"].includes(status);
}
export function validateEscalationPolicy(policy: EscalationPolicy) {
  const errors: string[] = [];
  if (!policy || policy.schema !==
      "cyberpilot.incident.escalation.policy.v1" ||
      !ident(policy.id) || !iso(policy.effectiveAt))
    errors.push("ESCALATION_POLICY_HEADER_INVALID");
  if (!Array.isArray(policy?.rules) || policy.rules.length > 100 ||
      policy.rules.length === 0)
    errors.push("ESCALATION_RULES_INVALID");
  else {
    const seen = new Set<string>();
    for (const rule of policy.rules) {
      if (!ident(rule.id) || seen.has(rule.id))
        errors.push("ESCALATION_RULE_ID_INVALID");
      seen.add(rule.id);
      if (!["P0", "P1", "P2"].includes(rule.priority) ||
          !ruleStatuses().includes(rule.status) ||
          !["PAST_DUE", "DUE_SOON", "UNASSIGNED_AGE",
            "UNACCEPTED_AGE", "STALE_REVIEW", "MISSING_EVIDENCE"]
            .includes(rule.trigger))
        errors.push("ESCALATION_RULE_SELECTION_INVALID");
      if (!Number.isSafeInteger(rule.minimumAgeMinutes) ||
          rule.minimumAgeMinutes < 0 || rule.minimumAgeMinutes > 525600 ||
          !Number.isSafeInteger(rule.warningMinutes) ||
          rule.warningMinutes < 0 || rule.warningMinutes > 525600 ||
          !Number.isSafeInteger(rule!.maximumFrequencyMinutes) ||
          rule!.maximumFrequencyMinutes < 1 ||
          rule!.maximumFrequencyMinutes > 525600)
        errors.push("ESCALATION_RULE_TIMING_INVALID");
      if (![1, 2, 3].includes(rule.escalationLevel) ||
          !["OWNER", "ADMIN", "SECURITY_REVIEWER"]
            .includes(rule!.recommendedRole) ||
          typeof rule.requireIndependentReview !== "boolean")
        errors.push("ESCALATION_RULE_APPROVAL_INVALID");
    }
  }
  if (!Number.isSafeInteger(policy?.concurrencyPerTenant) ||
      policy.concurrencyPerTenant < 1 || policy.concurrencyPerTenant > 20 ||
      !Number.isSafeInteger(policy?.maxDispatchesPerCycle) ||
      policy.maxDispatchesPerCycle < 1 ||
      policy.maxDispatchesPerCycle > 100 ||
      !Number.isSafeInteger(policy?.minReevaluationMinutes) ||
      policy.minReevaluationMinutes < 1 ||
      policy.minReevaluationMinutes > 525600 ||
      !Number.isSafeInteger(policy?.schedulingHorizonMinutes) ||
      policy.schedulingHorizonMinutes < 1 ||
      policy.schedulingHorizonMinutes > 525600)
    errors.push("ESCALATION_POLICY_CAPACITY_INVALID");
  if (policy?.riskAcceptedForInternalReadOnly !== true ||
      policy?.externalNotificationsAllowed !== false ||
      policy?.providerWritesAllowed !== false)
    errors.push("ESCALATION_EXTERNAL_PERMISSION_FORGED");
  return [...new Set(errors)];
}
export function validateEscalationCandidate(candidate: EscalationCandidate) {
  const errors: string[] = [];
  if (candidate?.schema !== "cyberpilot.incident.escalation.candidate.v1" ||
      ![candidate.organizationId, candidate.incidentId, candidate.boardId,
        candidate.handoffId, candidate.controlId, candidate.ruleId]
        .every(ident))
    errors.push("ESCALATION_CANDIDATE_SCOPE_INVALID");
  if (!sha(candidate?.boardDigest) ||
      !ident(candidate?.idempotencyKey))
    errors.push("ESCALATION_CANDIDATE_DIGEST_INVALID");
  if (![candidate?.eligibleAt, candidate?.dueAt,
    candidate?.evaluatedAt].every(iso) ||
    candidate?.previousEscalationAt !== null &&
      !iso(candidate?.previousEscalationAt))
    errors.push("ESCALATION_CANDIDATE_TIME_INVALID");
  if (!Number.isSafeInteger(candidate?.boardRevision) ||
      candidate.boardRevision < 1 ||
      !Number.isSafeInteger(candidate?.handoffRevision) ||
      candidate.handoffRevision < 1 ||
      !Number.isSafeInteger(candidate?.ageMinutes) ||
      candidate.ageMinutes < 0 ||
      !Number.isSafeInteger(candidate?.lateMinutes) ||
      candidate.lateMinutes < 0)
    errors.push("ESCALATION_CANDIDATE_REVISION_INVALID");
  if (candidate?.providerWrites !== 0)
    errors.push("ESCALATION_CANDIDATE_EXTERNAL_FORGED");
  if (candidate?.assignedUserId !== null &&
      !ident(candidate?.assignedUserId))
    errors.push("ESCALATION_CANDIDATE_ASSIGNEE_INVALID");
  if (typeof candidate?.shouldSchedule !== "boolean" ||
      typeof candidate?.evidenceMissing !== "boolean" ||
      typeof candidate?.requiresIndependentReview !== "boolean")
    errors.push("ESCALATION_CANDIDATE_STATE_INVALID");
  return errors;
}
function qualifies(rule: EscalationRule, board: AssuranceHandoffBoard,
  item: AssuranceHandoff, at: string) {
  const age = minutes(at, item.updatedAt);
  const dueIn = Math.ceil((Date.parse(item.dueAt) - Date.parse(at)) / 60000);
  const elapsedSinceAssignment = item.assignedAt ?
    minutes(at, item.assignedAt) : 0;
  const evidenceMissing = item.needsEvidence.length > 0 ||
    item.evidenceReferences.length === 0;
  const result = rule.trigger === "PAST_DUE" ?
    dueIn < 0 : rule.trigger === "DUE_SOON" ?
    dueIn >= 0 && dueIn <= rule.warningMinutes :
    rule.trigger === "UNASSIGNED_AGE" ?
      item.assignedUserId === null && age >= rule.minimumAgeMinutes :
    rule.trigger === "UNACCEPTED_AGE" ?
      item.assignedUserId !== null && item.acceptedBy === null &&
      elapsedSinceAssignment >= rule.minimumAgeMinutes :
    rule.trigger === "STALE_REVIEW" ?
      age >= rule.minimumAgeMinutes && board.status === "ACTIVE" :
    evidenceMissing && age >= rule.minimumAgeMinutes;
  return { result, age, dueIn, evidenceMissing };
}
function candidateFrom(rule: EscalationRule, board: AssuranceHandoffBoard,
  item: AssuranceHandoff, at: string): EscalationCandidate {
  const checked = qualifies(rule, board, item, at);
  const cooldown = item.lastEscalatedAt !== null &&
    minutes(at, item.lastEscalatedAt) < rule!.maximumFrequencyMinutes;
  const terminal = !activeStatus(item.status) ||
    board.status !== "ACTIVE";
  const future = at < item.updatedAt || at < board.createdAt;
  const allowed = checked.result && !cooldown && !terminal && !future;
  const reason: EscalationCandidate["reason"] = terminal ? "TERMINAL" :
    future ? "FUTURE" : cooldown ? "COOLDOWN" :
    !checked.result ? "UNSUPPORTED" : "ELIGIBLE";
  const token = escalationDigest({
    organizationId: board.organizationId, incidentId: board.incidentId,
    boardId: board.id, handoffId: item.id, ruleId: rule.id,
    handoffRevision: item.revision,
    boardRevision: board.revision,
    eligibleWindow: Math.floor(Date.parse(at) /
      (rule!.maximumFrequencyMinutes * 60000)),
  });
  const idempotencyKey = "escalation:" + token.slice(0, 64);
  return {
    schema: "cyberpilot.incident.escalation.candidate.v1",
    organizationId: board.organizationId,
    incidentId: board.incidentId, boardId: board.id,
    boardRevision: board.revision,
    handoffId: item.id, handoffRevision: item.revision,
    controlId: item.controlId, priority: item.priority,
    status: item.status, ruleId: rule.id, trigger: rule.trigger,
    level: rule.escalationLevel, eligibleAt: at,
    dueAt: item.dueAt, evaluatedAt: at,
    assignedUserId: item.assignedUserId,
    recommendedRole: rule!.recommendedRole,
    requiresIndependentReview: rule.requireIndependentReview,
    evidenceMissing: checked.evidenceMissing,
    ageMinutes: checked.age,
    lateMinutes: Math.max(0, -checked.dueIn),
    previousEscalationAt: item.lastEscalatedAt,
    shouldSchedule: allowed, reason,
    boardDigest: escalationDigest(board),
    idempotencyKey, providerWrites: 0,
  };
}
function dispatchFor(candidate: EscalationCandidate, policy: EscalationPolicy,
  at: string): EscalationDispatch {
  const scheduledAt = at;
  const expiresAt = plus(scheduledAt,
    Math.max(5, Math.min(policy.schedulingHorizonMinutes, 4320)));
  const payload: EscalationDispatch["payload"] = {
    incidentId: candidate.incidentId, boardId: candidate.boardId,
    handoffId: candidate.handoffId, ruleId: candidate.ruleId,
    boardRevision: candidate.boardRevision,
    handoffRevision: candidate.handoffRevision,
    boardDigest: candidate.boardDigest,
    expectedPriority: candidate.priority,
    expectedStatus: candidate.status,
    dispatchedAt: at, plannedFor: scheduledAt,
    internalOnly: true, externalNotificationsAllowed: false,
  };
  return {
    schema: "cyberpilot.incident.escalation.dispatch.v1",
    organizationId: candidate.organizationId,
    incidentId: candidate.incidentId, boardId: candidate.boardId,
    handoffId: candidate.handoffId, ruleId: candidate.ruleId,
    scheduledAt, expiresAt,
    idempotencyKey: candidate.idempotencyKey,
    payload,
    authorizedProviderMutations: 0, notificationDeliveries: 0,
  };
}
export function planIncidentEscalations(args: {
  organizationId: string; incidentId: string;
  policy: EscalationPolicy; boards: AssuranceHandoffBoard[];
  at: string;
}): EscalationPlan {
  if (!ident(args.organizationId) || !ident(args.incidentId) ||
      !iso(args.at)) reject("ESCALATION_SCOPE_INVALID");
  const issues = validateEscalationPolicy(args.policy);
  if (issues.length) reject(issues.join(","));
  if (args.policy.effectiveAt > args.at)
    reject("ESCALATION_POLICY_NOT_ACTIVE");
  if (!Array.isArray(args.boards) || args.boards.length > 500)
    reject("ESCALATION_BOARD_LIMIT");
  let sourceHandoffs = 0;
  const seenBoards = new Set<string>();
  const candidates: EscalationCandidate[] = [];
  for (const board of args.boards) {
    if (board.organizationId !== args.organizationId ||
        board.incidentId !== args.incidentId)
      reject("ESCALATION_CROSS_TENANT_BOARD");
    if (seenBoards.has(board.id))
      reject("ESCALATION_DUPLICATE_BOARD");
    seenBoards.add(board.id);
    if (board.providerWrites !== 0 ||
        board.providerContainmentVerified !== false)
      reject("ESCALATION_FALSE_CONTAINMENT_CLAIM");
    if (!Array.isArray(board.handoffs) || board.handoffs.length > 300)
      reject("ESCALATION_HANDOFF_LIMIT");
    sourceHandoffs += board.handoffs.length;
    for (const item of board.handoffs) {
      for (const rule of args.policy.rules.filter(r =>
        r.priority === item.priority && r.status === item.status)) {
        const candidate = candidateFrom(rule, board, item, args.at);
        const issues = validateEscalationCandidate(candidate);
        if (issues.length) reject(issues.join(","));
        candidates.push(candidate);
      }
    }
  }
  if (candidates.length > 15000)
    reject("ESCALATION_CANDIDATE_LIMIT");
  const level = (c: EscalationCandidate) => c.level;
  const priority = (c: EscalationCandidate) =>
    c.priority === "P0" ? 3 : c.priority === "P1" ? 2 : 1;
  candidates.sort((a, b) =>
    Number(b.shouldSchedule) - Number(a.shouldSchedule) ||
    level(b) - level(a) ||
    priority(b) - priority(a) ||
    b.lateMinutes - a.lateMinutes ||
    a.dueAt.localeCompare(b.dueAt) ||
    a.handoffId.localeCompare(b.handoffId) ||
    a.ruleId.localeCompare(b.ruleId));
  const selected = new Set<string>();
  const dispatches: EscalationDispatch[] = [];
  const cap = args.policy.maxDispatchesPerCycle;
  for (const c of candidates) {
    if (!c.shouldSchedule || dispatches.length >= cap) continue;
    const item = c.boardId + ":" + c.handoffId;
    if (selected.has(item)) continue;
    selected.add(item);
    dispatches.push(dispatchFor(c, args.policy, args.at));
  }
  const reasons: Record<string, number> = {};
  for (const c of candidates)
    reasons[c.reason] = (reasons[c.reason] ?? 0) + 1;
  const plan: Omit<EscalationPlan, "planDigest"> = {
    schema: "cyberpilot.incident.escalation.plan.v1",
    organizationId: args.organizationId,
    incidentId: args.incidentId, policyId: args.policy.id,
    generatedAt: args.at, sourceBoards: args.boards.length,
    sourceHandoffs, eligible: candidates.filter(x =>
      x.shouldSchedule).length,
    delayed: candidates.filter(x => x.reason === "COOLDOWN" ||
      x.reason === "FUTURE").length,
    omitted: candidates.length - dispatches.length,
    saturated: candidates.filter(x => x.shouldSchedule).length >
      dispatches.length,
    candidates, dispatches, reasons, externalWrites: 0,
    notificationsSent: 0,
  };
  return { ...plan, planDigest: escalationDigest(plan) };
}
export function verifyEscalationPlan(plan: EscalationPlan) {
  const issues: string[] = [];
  if (!plan || plan.schema !== "cyberpilot.incident.escalation.plan.v1" ||
      !ident(plan.organizationId) || !ident(plan.incidentId) ||
      !iso(plan.generatedAt))
    issues.push("ESCALATION_PLAN_HEADER_INVALID");
  if (plan?.planDigest !== escalationDigest({ ...plan,
    planDigest: undefined }))
    issues.push("ESCALATION_PLAN_HASH_INVALID");
  if (plan?.externalWrites !== 0 || plan?.notificationsSent !== 0)
    issues.push("ESCALATION_PLAN_FALSE_EXTERNAL_ACTION");
  if (!Array.isArray(plan?.dispatches) ||
      !Array.isArray(plan?.candidates))
    issues.push("ESCALATION_PLAN_ARRAYS_INVALID");
  else {
    if (new Set(plan.dispatches.map(x => x.idempotencyKey)).size !==
      plan.dispatches.length)
      issues.push("ESCALATION_DISPATCH_IDEMPOTENCY_DUPLICATE");
    for (const dispatch of plan.dispatches) {
      if (dispatch.organizationId !== plan.organizationId ||
          dispatch.incidentId !== plan.incidentId ||
          dispatch.authorizedProviderMutations !== 0 ||
          dispatch.notificationDeliveries !== 0)
        issues.push("ESCALATION_DISPATCH_SCOPE_INVALID");
      if (dispatch.payload.internalOnly !== true ||
          dispatch.payload.externalNotificationsAllowed !== false ||
          dispatch.payload.boardId !== dispatch.boardId ||
          dispatch.payload.handoffId !== dispatch.handoffId)
        issues.push("ESCALATION_DISPATCH_UNSAFE");
    }
  }
  return [...new Set(issues)];
}
export function evaluateEscalationDispatch(args: {
  dispatch: EscalationDispatch; board: AssuranceHandoffBoard | null;
  policy: EscalationPolicy; at: string;
}): EscalationExecutionResult {
  const d = args.dispatch;
  if (!d || !iso(args.at) || !iso(d.scheduledAt) ||
      !ident(d.organizationId) || !ident(d.incidentId) ||
      d.authorizedProviderMutations !== 0 ||
      d.notificationDeliveries !== 0 ||
      d.payload.internalOnly !== true ||
      d.payload.externalNotificationsAllowed !== false)
    reject("ESCALATION_DISPATCH_INVALID");
  if (validateEscalationPolicy(args.policy).length)
    reject("ESCALATION_DISPATCH_POLICY_INVALID");
  const rule = args.policy.rules.find(x => x.id === d.ruleId);
  if (!rule) reject("ESCALATION_DISPATCH_RULE_NOT_FOUND");
  const empty = (status: EscalationExecutionResult["status"],
    reason: string, revision: number | null,
    role: string | null = null, nextReviewAt: string | null = null):
    EscalationExecutionResult => ({
    schema: "cyberpilot.incident.escalation.execution.v1",
    organizationId: d.organizationId, incidentId: d.incidentId,
    boardId: d.boardId, handoffId: d.handoffId,
    policyId: args.policy.id, ruleId: d.ruleId, evaluatedAt: args.at,
    status, currentRevision: revision,
    previousRevision: d.payload.boardRevision,
    reason, canEscalateInternally: status === "STILL_ACTIONABLE",
    recommendedRole: role, nextReviewAt,
    externalNotificationDispatched: false, providerWrites: 0,
    executedControlChanges: 0,
  });
  if (args.at < d.scheduledAt) return empty("NOT_DUE",
    "DISPATCH_NOT_DUE", null, null, d.scheduledAt);
  if (!args.board) return empty("UNAVAILABLE",
    "BOARD_NOT_FOUND_OR_NOT_AUTHORIZED", null);
  const board = args.board;
  if (board.organizationId !== d.organizationId ||
      board.incidentId !== d.incidentId || board.id !== d.boardId)
    reject("ESCALATION_CROSS_TENANT_DISPATCH");
  const item = board.handoffs.find(x => x.id === d.handoffId);
  if (!item) return empty("RESOLVED_INTERNAL",
    "HANDOFF_NO_LONGER_PRESENT", board.revision);
  const previous = d.payload;
  if (board.revision !== previous.boardRevision ||
      item.revision !== previous.handoffRevision ||
      escalationDigest(board) !== previous.boardDigest)
    return empty("STALE_SNAPSHOT",
      "BOARD_REVISED_REPLAN_REQUIRED", board.revision);
  if (board.status !== "ACTIVE" || !activeStatus(item.status))
    return empty("RESOLVED_INTERNAL", "BOARD_OR_ITEM_NOT_ACTIVE",
      board.revision);
  const q = qualifies(rule!, board, item, args.at);
  if (!q.result) return empty("RESOLVED_INTERNAL",
    "TRIGGER_NO_LONGER_SATISFIED", board.revision);
  if (item.lastEscalatedAt &&
      minutes(args.at, item.lastEscalatedAt) <
        rule!.maximumFrequencyMinutes)
    return empty("NOT_DUE", "ESCALATION_COOLDOWN_ACTIVE",
      board.revision, rule!.recommendedRole,
      plus(item.lastEscalatedAt, rule!.maximumFrequencyMinutes));
  return empty("STILL_ACTIONABLE", "INTERNAL_REVIEW_SUGGESTED",
    board.revision, rule!.recommendedRole,
    plus(args.at, args.policy.minReevaluationMinutes));
}
export function validateEscalationQueue(
  snapshot: EscalationQueueSnapshot, events: EscalationQueueEvent[],
) {
  const problems: string[] = [];
  if (!snapshot || snapshot.schema !==
      "cyberpilot.incident.escalation.queue.v1" ||
      !ident(snapshot.organizationId) || !ident(snapshot.incidentId) ||
      !ident(snapshot.lastActorId) ||
      !ident(snapshot.dispatchKey))
    problems.push("ESCALATION_QUEUE_IDENTITY_INVALID");
  if (snapshot?.externallyExecuted !== false)
    problems.push("ESCALATION_QUEUE_EXTERNAL_CLAIM");
  if (!Number.isSafeInteger(snapshot?.revision) ||
      snapshot.revision < 1 || snapshot.revision !== events.length ||
      !sha(snapshot?.eventDigest))
    problems.push("ESCALATION_QUEUE_REVISION_INVALID");
  let previous: EscalationQueueEvent | null = null;
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (e.schema !== "cyberpilot.incident.escalation.queue-event.v1" ||
        e.organizationId !== snapshot.organizationId ||
        e.incidentId !== snapshot.incidentId ||
        e.dispatchKey !== snapshot.dispatchKey ||
        e.revision !== i + 1 || e.providerWrites !== 0 ||
        !iso(e.at) || !ident(e.actorId))
      problems.push("ESCALATION_QUEUE_EVENT_SCOPE_INVALID");
    if (e.before !== (previous?.after ?? null) ||
        e.priorDigest !== (previous?.eventDigest ?? null))
      problems.push("ESCALATION_QUEUE_EVENT_CHAIN_INVALID");
    if (e.eventDigest !== escalationDigest({ ...e,
      eventDigest: undefined }))
      problems.push("ESCALATION_QUEUE_EVENT_HASH_INVALID");
    previous = e;
  }
  if (previous?.eventDigest !== snapshot?.eventDigest ||
      previous?.after !== snapshot?.state)
    problems.push("ESCALATION_QUEUE_SNAPSHOT_MISMATCH");
  return [...new Set(problems)];
}
export function createEscalationQueue(dispatch: EscalationDispatch,
  actorId: string, at: string) {
  if (!ident(actorId) || !iso(at) || dispatch.authorizedProviderMutations !== 0)
    reject("ESCALATION_QUEUE_ADMISSION_INVALID");
  const event: Omit<EscalationQueueEvent, "eventDigest"> = {
    schema: "cyberpilot.incident.escalation.queue-event.v1",
    organizationId: dispatch.organizationId,
    incidentId: dispatch.incidentId,
    dispatchKey: dispatch.idempotencyKey,
    revision: 1, kind: "PLANNED", actorId, at,
    before: null, after: "PLANNED",
    priorDigest: null, providerWrites: 0,
  };
  const final = { ...event, eventDigest: escalationDigest(event) };
  const snapshot: EscalationQueueSnapshot = {
    schema: "cyberpilot.incident.escalation.queue.v1",
    organizationId: dispatch.organizationId,
    incidentId: dispatch.incidentId,
    dispatchKey: dispatch.idempotencyKey,
    revision: 1, state: "PLANNED", dispatch,
    admittedAt: null, claimedAt: null, observedAt: null,
    cancelledAt: null, lastActorId: actorId,
    lastResult: null, eventDigest: final.eventDigest,
    externallyExecuted: false,
  };
  return { snapshot, event: final };
}
export function applyEscalationQueueTransition(
  snapshot: EscalationQueueSnapshot, events: EscalationQueueEvent[],
  input: {
    expectedRevision: number; actorId: string; at: string;
    state: EscalationQueueState; result?: EscalationExecutionResult;
  },
) {
  if (validateEscalationQueue(snapshot, events).length)
    reject("ESCALATION_QUEUE_CORRUPT");
  if (input.expectedRevision !== snapshot.revision ||
      !ident(input.actorId) || !iso(input.at) ||
      input.at < events[events.length - 1]!.at)
    reject("ESCALATION_QUEUE_CAS_REJECTED");
  const allowed: Record<EscalationQueueState, EscalationQueueState[]> = {
    PLANNED: ["ADMITTED", "CANCELLED"],
    ADMITTED: ["CLAIMED", "DEFERRED", "CANCELLED", "DEAD_LETTER"],
    CLAIMED: ["OBSERVED", "DEFERRED", "DEAD_LETTER"],
    OBSERVED: [], DEFERRED: ["ADMITTED", "CANCELLED"],
    CANCELLED: [], DEAD_LETTER: [],
  };
  if (!allowed[snapshot.state].includes(input.state))
    reject("ESCALATION_QUEUE_TRANSITION_DENIED");
  if (input.state === "OBSERVED" &&
      (!input.result || input.result.providerWrites !== 0 ||
        input.result.externalNotificationDispatched !== false))
    reject("ESCALATION_QUEUE_RESULT_REQUIRED");
  const e: Omit<EscalationQueueEvent, "eventDigest"> = {
    schema: "cyberpilot.incident.escalation.queue-event.v1",
    organizationId: snapshot.organizationId,
    incidentId: snapshot.incidentId,
    dispatchKey: snapshot.dispatchKey,
    revision: snapshot.revision + 1,
    kind: input.state, actorId: input.actorId,
    at: input.at, before: snapshot.state,
    after: input.state, priorDigest: snapshot.eventDigest,
    providerWrites: 0,
  };
  const event = { ...e, eventDigest: escalationDigest(e) };
  const next: EscalationQueueSnapshot = {
    ...snapshot, revision: snapshot.revision + 1,
    state: input.state, lastActorId: input.actorId,
    eventDigest: event.eventDigest,
    admittedAt: input.state === "ADMITTED" ? input.at :
      snapshot.admittedAt,
    claimedAt: input.state === "CLAIMED" ? input.at :
      snapshot.claimedAt,
    observedAt: input.state === "OBSERVED" ? input.at :
      snapshot.observedAt,
    cancelledAt: input.state === "CANCELLED" ? input.at :
      snapshot.cancelledAt,
    lastResult: input.result ?? snapshot.lastResult,
  };
  if (validateEscalationQueue(next, [...events, event]).length)
    reject("ESCALATION_QUEUE_NEXT_INVALID");
  return { snapshot: next, event };
}
export function assessEscalationAssignment(
  board: AssuranceHandoffBoard,
  memberRoles: ReadonlyMap<string, string>,
): EscalationAssignmentHint[] {
  const results: EscalationAssignmentHint[] = [];
  for (const item of board.handoffs) {
    const role = item.assignedUserId === null ? null :
      memberRoles.get(item.assignedUserId) ?? null;
    const eligibility = item.assignedUserId === null ? "UNASSIGNED" :
      role === null ? "REVOKED" :
      ["OWNER", "ADMIN"].includes(role) ? "ASSIGNED" : "UNKNOWN";
    results.push({
      handoffId: item.id, boardId: board.id,
      priority: item.priority, eligibility,
      assignedUserId: item.assignedUserId,
      recommendedRole: item.priority === "P0" ? "OWNER" : "ADMIN",
      independentReviewNeeded: item.acceptedBy === item.assignedBy &&
        item.acceptedBy !== null,
      memberScopeConfirmed: eligibility === "ASSIGNED",
      providerWrites: 0,
    });
  }
  return results;
}
export function groupEscalationsByOwner(plan: EscalationPlan) {
  if (verifyEscalationPlan(plan).length)
    reject("ESCALATION_PLAN_INVALID");
  const groups = new Map<string, EscalationCandidate[]>();
  for (const c of plan.candidates.filter(x => x.shouldSchedule)) {
    const owner = c.assignedUserId ?? "UNASSIGNED";
    const group = groups.get(owner) ?? [];
    group.push(c); groups.set(owner, group);
  }
  return [...groups].map(([owner, candidates]) => ({
    owner, count: candidates.length,
    highPriority: candidates.filter(x => x.priority === "P0").length,
    overdue: candidates.filter(x => x.lateMinutes > 0).length,
    highestLevel: Math.max(...candidates.map(x => x.level)),
    distinctBoards: new Set(candidates.map(x => x.boardId)).size,
    allInternal: true as const,
  })).sort((a, b) => b.highPriority - a.highPriority ||
    b.count - a.count || a.owner.localeCompare(b.owner));
}
export function compareEscalationPlans(before: EscalationPlan,
  after: EscalationPlan) {
  if (verifyEscalationPlan(before).length ||
      verifyEscalationPlan(after).length)
    reject("ESCALATION_COMPARE_UNVERIFIED");
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId ||
      before.policyId !== after.policyId)
    reject("ESCALATION_COMPARE_SCOPE_INVALID");
  if (after.generatedAt < before.generatedAt)
    reject("ESCALATION_COMPARE_TIME_REGRESSION");
  const key = (d: EscalationDispatch) =>
    d.boardId + ":" + d.handoffId + ":" + d.ruleId;
  const b = new Set(before.dispatches.map(key));
  const a = new Set(after.dispatches.map(key));
  return {
    schema: "cyberpilot.incident.escalation.compare.v1" as const,
    beforeDigest: before.planDigest, afterDigest: after.planDigest,
    added: after.dispatches.filter(d => !b.has(key(d))),
    removed: before.dispatches.filter(d => !a.has(key(d))),
    unchanged: [...a].filter(x => b.has(x)).length,
    capReached: after.saturated,
    externalNotificationDelta: 0 as const,
    providerRemediationDelta: 0 as const,
  };
}
export function exportEscalationPlanCSV(plan: EscalationPlan) {
  if (verifyEscalationPlan(plan).length)
    reject("ESCALATION_EXPORT_INTEGRITY_INVALID");
  const fields = ["boardId", "handoffId", "ruleId", "scheduledAt",
    "expiresAt", "idempotencyKey"];
  const escape = (x: string) => {
    const safe = /^\s*[=+@-]/.test(x) ? "'" + x : x;
    return '"' + safe.replaceAll('"', '""') + '"';
  };
  return [fields.join(","), ...plan.dispatches.map(d =>
    fields.map(k => escape(String(
      (d as unknown as Record<string, unknown>)[k] ?? "")))
      .join(","))].join("\r\n") + "\r\n";
}
export function exportEscalationPlanJSON(plan: EscalationPlan) {
  if (verifyEscalationPlan(plan).length)
    reject("ESCALATION_EXPORT_INTEGRITY_INVALID");
  return JSON.stringify(plan, null, 2);
}
export function summarizeEscalationPlan(plan: EscalationPlan) {
  if (verifyEscalationPlan(plan).length)
    reject("ESCALATION_SUMMARY_INTEGRITY_INVALID");
  const priorities: HandoffPriority[] = ["P0", "P1", "P2"];
  return {
    schema: "cyberpilot.incident.escalation.summary.v1" as const,
    incidentId: plan.incidentId, organizationId: plan.organizationId,
    planDigest: plan.planDigest,
    actionable: plan.dispatches.length, saturated: plan.saturated,
    deferred: plan.delayed,
    categories: priorities.map(priority => ({
      priority,
      eligible: plan.candidates.filter(x =>
        x.priority === priority && x.shouldSchedule).length,
      scheduled: plan.dispatches.filter(x =>
        plan.candidates.some(c =>
          c.idempotencyKey === x.idempotencyKey &&
          c.priority === priority)).length,
      missingEvidence: plan.candidates.filter(x =>
        x.priority === priority && x.evidenceMissing).length,
    })),
    noExternalNotifications: true as const,
    noProviderControlChanges: true as const,
  };
}
