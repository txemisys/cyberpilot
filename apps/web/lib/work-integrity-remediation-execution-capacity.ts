import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionRemediationQueue,
  IntegrityExecutionRemediationQueueItem,
} from "./work-integrity-remediation-execution-queue";

export type IntegrityExecutionCapacityMember = {
  actorUserId: string;
  maximumConcurrent: number;
  maximumPoints: number;
  supportedActions: string[];
  supportedSteps: string[];
  excludedCaseKeys: string[];
  assignedCandidateIds: string[];
};
export type IntegrityExecutionCapacityPolicy = {
  maximumAssignments: number;
  maximumCandidatesPerCase: number;
  defaultEffortPoints: number;
  effortByAction: Record<string, number>;
  effortByStep: Record<string, number>;
  enforceDistinctWorkItems: boolean;
  prioritizeUnassigned: boolean;
  allowReadyCandidates: boolean;
};
export type IntegrityExecutionCapacityAssignment = {
  candidateId: string;
  actorUserId: string;
  caseKey: string | null;
  workItemId: string | null;
  action: string;
  nextStep: string;
  score: number;
  effortPoints: number;
  assignedAt: string;
  source: "EXISTING" | "PROPOSED";
};
export type IntegrityExecutionCapacityUnassignedReason =
  | "READY" | "QUEUE_LIMIT" | "NO_CAPABLE_MEMBER"
  | "CAPACITY_EXHAUSTED" | "CASE_LIMIT"
  | "DUPLICATE_WORK_ITEM" | "CONFLICTING_EXISTING_ASSIGNMENT";
export type IntegrityExecutionCapacityUnassigned = {
  candidateId: string;
  caseKey: string | null;
  workItemId: string | null;
  score: number;
  effortPoints: number;
  reason: IntegrityExecutionCapacityUnassignedReason;
  eligibleMemberIds: string[];
};
export type IntegrityExecutionCapacityMemberSummary = {
  actorUserId: string;
  assigned: number;
  existing: number;
  proposed: number;
  consumedPoints: number;
  remainingPoints: number;
  remainingSlots: number;
  utilizationPercent: number;
  assignedCandidateIds: string[];
};
export type IntegrityExecutionCapacityPlan = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityExecutionCapacityPolicy;
  assignments: IntegrityExecutionCapacityAssignment[];
  unassigned: IntegrityExecutionCapacityUnassigned[];
  members: IntegrityExecutionCapacityMemberSummary[];
  totals: {
    queued: number;
    assigned: number;
    existing: number;
    proposed: number;
    unassigned: number;
    totalEffortPoints: number;
    assignedEffortPoints: number;
    unassignedEffortPoints: number;
    availablePoints: number;
    remainingPoints: number;
    availableSlots: number;
    remainingSlots: number;
    assignmentPercent: number;
    byUnassignedReason: Record<IntegrityExecutionCapacityUnassignedReason, number>;
  };
  limitation: string;
};
export type IntegrityExecutionCapacityQuery = {
  actorUserIds?: string[];
  candidateIds?: string[];
  source?: Array<IntegrityExecutionCapacityAssignment["source"]>;
  minimumScore?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionCapacityPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  assignments: IntegrityExecutionCapacityAssignment[];
};
const unassignedReasons: IntegrityExecutionCapacityUnassignedReason[] = [
  "READY", "QUEUE_LIMIT", "NO_CAPABLE_MEMBER", "CAPACITY_EXHAUSTED",
  "CASE_LIMIT", "DUPLICATE_WORK_ITEM", "CONFLICTING_EXISTING_ASSIGNMENT",
];
const defaults: IntegrityExecutionCapacityPolicy = {
  maximumAssignments: 10000,
  maximumCandidatesPerCase: 100,
  defaultEffortPoints: 3,
  effortByAction: {},
  effortByStep: {},
  enforceDistinctWorkItems: true,
  prioritizeUnassigned: false,
  allowReadyCandidates: false,
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function int(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function list(value: unknown, label: string, maximum = 10000) {
  if (!Array.isArray(value) || value.length > maximum ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  const result = value as string[];
  if (new Set(result).size !== result.length)
    throw new WorkInputError("INVALID", "Duplicate " + label);
  return [...result];
}
function weights(value: unknown, label: string) {
  const raw = object(value, label);
  if (Object.keys(raw).length > 1000)
    throw new WorkInputError("INVALID", "Too many effort weights.");
  return Object.fromEntries(Object.entries(raw).map(([key, amount]) => {
    if (!key || key.length > 150)
      throw new WorkInputError("INVALID", "Invalid effort weight key.");
    return [key, int(amount, label, 1, 10000)];
  })) as Record<string, number>;
}
export function parseIntegrityExecutionCapacityPolicy(
  value: unknown,
): IntegrityExecutionCapacityPolicy {
  if (value === undefined) return {
    ...defaults, effortByAction: {}, effortByStep: {},
  };
  const raw = object(value, "capacity policy");
  if (Object.keys(raw).some(key => !Object.keys(defaults).includes(key)))
    throw new WorkInputError("INVALID", "Unknown capacity policy field.");
  const policy = parseIntegrityExecutionCapacityPolicy(undefined);
  for (const key of [
    "maximumAssignments", "maximumCandidatesPerCase", "defaultEffortPoints",
  ] as const) {
    if (raw[key] !== undefined)
      policy[key] = int(raw[key], key, 1, 10000);
  }
  for (const key of [
    "enforceDistinctWorkItems", "prioritizeUnassigned",
    "allowReadyCandidates",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid capacity flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.effortByAction !== undefined)
    policy.effortByAction = weights(raw.effortByAction, "action effort");
  if (raw.effortByStep !== undefined)
    policy.effortByStep = weights(raw.effortByStep, "step effort");
  return policy;
}
export function parseIntegrityExecutionCapacityMembers(
  value: unknown,
): IntegrityExecutionCapacityMember[] {
  if (!Array.isArray(value) || value.length > 1000)
    throw new WorkInputError("INVALID", "Invalid capacity member collection.");
  const members = value.map(entry => {
    const raw = object(entry, "capacity member");
    if (Object.keys(raw).some(key => ![
      "actorUserId", "maximumConcurrent", "maximumPoints",
      "supportedActions", "supportedSteps", "excludedCaseKeys",
      "assignedCandidateIds",
    ].includes(key)))
      throw new WorkInputError("INVALID", "Unknown capacity member field.");
    if (typeof raw.actorUserId !== "string" ||
        !raw.actorUserId || raw.actorUserId.length > 150)
      throw new WorkInputError("INVALID", "Invalid capacity actor.");
    return {
      actorUserId: raw.actorUserId,
      maximumConcurrent: int(raw.maximumConcurrent,
        "concurrent assignments", 0, 10000),
      maximumPoints: int(raw.maximumPoints,
        "available effort points", 0, 1000000),
      supportedActions: list(raw.supportedActions ?? [], "supported actions"),
      supportedSteps: list(raw.supportedSteps ?? [], "supported steps"),
      excludedCaseKeys: list(raw.excludedCaseKeys ?? [], "excluded cases"),
      assignedCandidateIds: list(raw.assignedCandidateIds ?? [],
        "existing candidate assignments"),
    };
  });
  if (new Set(members.map(x => x.actorUserId)).size !== members.length)
    throw new WorkInputError("INVALID", "Duplicate capacity member.");
  return members;
}
function effort(
  item: IntegrityExecutionRemediationQueueItem,
  policy: IntegrityExecutionCapacityPolicy,
) {
  return policy.effortByStep[item.recommendedNextStep] ??
    policy.effortByAction[item.action] ?? policy.defaultEffortPoints;
}
function capable(
  item: IntegrityExecutionRemediationQueueItem,
  member: IntegrityExecutionCapacityMember,
) {
  return (!member.supportedActions.length ||
    member.supportedActions.includes(item.action)) &&
    (!member.supportedSteps.length ||
      member.supportedSteps.includes(item.recommendedNextStep)) &&
    (item.caseKey === null ||
      !member.excludedCaseKeys.includes(item.caseKey));
}
type MutableMember = {
  member: IntegrityExecutionCapacityMember;
  assignments: IntegrityExecutionCapacityAssignment[];
  consumed: number;
};
function timestamp(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid capacity evaluation time.");
}
export function planIntegrityExecutionCapacity(
  queue: IntegrityExecutionRemediationQueue,
  members: readonly IntegrityExecutionCapacityMember[],
  evaluatedAt: string,
  policy: IntegrityExecutionCapacityPolicy = defaults,
): IntegrityExecutionCapacityPlan {
  timestamp(evaluatedAt);
  const ids = new Set<string>();
  for (const member of members) {
    if (ids.has(member.actorUserId))
      throw new WorkInputError("INVALID", "Duplicate capacity member.");
    ids.add(member.actorUserId);
  }
  const candidates = new Map(queue.items.map(item =>
    [item.candidateId, item]));
  if (candidates.size !== queue.items.length)
    throw new WorkInputError("INVALID", "Duplicate queue candidate.");
  const mutable = members.map(member => ({
    member, assignments: [] as IntegrityExecutionCapacityAssignment[],
    consumed: 0,
  }));
  const existing = new Map<string, string>();
  for (const member of members) {
    for (const id of member.assignedCandidateIds) {
      if (existing.has(id))
        throw new WorkInputError("INVALID",
          "Candidate assigned to multiple capacity members.");
      existing.set(id, member.actorUserId);
    }
  }
  const assignments: IntegrityExecutionCapacityAssignment[] = [];
  const unassigned: IntegrityExecutionCapacityUnassigned[] = [];
  const caseCounts = new Map<string, number>();
  const usedWork = new Set<string>();
  const ordered = [...queue.items].sort((a, b) =>
    (policy.prioritizeUnassigned ?
      Number(!existing.has(b.candidateId)) -
      Number(!existing.has(a.candidateId)) : 0) ||
    b.score - a.score || a.candidateId.localeCompare(b.candidateId));
  for (const item of ordered) {
    const points = effort(item, policy);
    const qualified = mutable.filter(x => capable(item, x.member));
    const alreadyAssigned = existing.get(item.candidateId);
    const reason = (code: IntegrityExecutionCapacityUnassignedReason) => {
      unassigned.push({
        candidateId: item.candidateId, caseKey: item.caseKey,
        workItemId: item.workItemId, score: item.score,
        effortPoints: points, reason,
        eligibleMemberIds: qualified.map(x => x.member.actorUserId),
      });
    };
    if (item.ready && !policy.allowReadyCandidates) {
      reason("READY");
      continue;
    }
    if (assignments.length >= policy.maximumAssignments) {
      reason("QUEUE_LIMIT");
      continue;
    }
    if (item.caseKey &&
        (caseCounts.get(item.caseKey) ?? 0) >=
        policy.maximumCandidatesPerCase) {
      reason("CASE_LIMIT");
      continue;
    }
    if (policy.enforceDistinctWorkItems && item.workItemId &&
        usedWork.has(item.workItemId)) {
      reason("DUPLICATE_WORK_ITEM");
      continue;
    }
    if (!qualified.length) {
      reason("NO_CAPABLE_MEMBER");
      continue;
    }
    const candidatesForAssignment = alreadyAssigned
      ? qualified.filter(x => x.member.actorUserId === alreadyAssigned)
      : qualified;
    if (alreadyAssigned && !candidatesForAssignment.length) {
      reason("CONFLICTING_EXISTING_ASSIGNMENT");
      continue;
    }
    const available = candidatesForAssignment.filter(x =>
      x.assignments.length < x.member.maximumConcurrent &&
      x.consumed + points <= x.member.maximumPoints);
    if (!available.length) {
      reason("CAPACITY_EXHAUSTED");
      continue;
    }
    available.sort((a, b) => {
      const utilizationA = a.member.maximumPoints ?
        a.consumed / a.member.maximumPoints : 1;
      const utilizationB = b.member.maximumPoints ?
        b.consumed / b.member.maximumPoints : 1;
      return utilizationA - utilizationB ||
        a.assignments.length - b.assignments.length ||
        a.member.actorUserId.localeCompare(b.member.actorUserId);
    });
    const chosen = available[0]!;
    const assignment: IntegrityExecutionCapacityAssignment = {
      candidateId: item.candidateId,
      actorUserId: chosen.member.actorUserId,
      caseKey: item.caseKey, workItemId: item.workItemId,
      action: item.action, nextStep: item.recommendedNextStep,
      score: item.score, effortPoints: points, assignedAt: evaluatedAt,
      source: alreadyAssigned ? "EXISTING" : "PROPOSED",
    };
    assignments.push(assignment);
    chosen.assignments.push(assignment);
    chosen.consumed += points;
    if (item.caseKey)
      caseCounts.set(item.caseKey, (caseCounts.get(item.caseKey) ?? 0) + 1);
    if (item.workItemId) usedWork.add(item.workItemId);
  }
  const summaries = mutable.map(x => ({
    actorUserId: x.member.actorUserId,
    assigned: x.assignments.length,
    existing: x.assignments.filter(a => a.source === "EXISTING").length,
    proposed: x.assignments.filter(a => a.source === "PROPOSED").length,
    consumedPoints: x.consumed,
    remainingPoints: x.member.maximumPoints - x.consumed,
    remainingSlots: x.member.maximumConcurrent - x.assignments.length,
    utilizationPercent: x.member.maximumPoints ?
      Math.round(100 * x.consumed / x.member.maximumPoints) : 0,
    assignedCandidateIds: x.assignments.map(a => a.candidateId),
  }));
  const byUnassignedReason = Object.fromEntries(unassignedReasons.map(code =>
    [code, unassigned.filter(x => x.reason === code).length])) as
    Record<IntegrityExecutionCapacityUnassignedReason, number>;
  const availablePoints = members.reduce((sum, x) =>
    sum + x.maximumPoints, 0);
  const availableSlots = members.reduce((sum, x) =>
    sum + x.maximumConcurrent, 0);
  return {
    schemaVersion: 1, captureId: queue.captureId, evaluatedAt, policy,
    assignments, unassigned, members: summaries,
    limitation: "Assignments are proposals only; no work items are modified, no actors are authorized, and capacity is declared rather than measured.",
    totals: {
      queued: queue.items.length,
      assigned: assignments.length,
      existing: assignments.filter(x => x.source === "EXISTING").length,
      proposed: assignments.filter(x => x.source === "PROPOSED").length,
      unassigned: unassigned.length,
      totalEffortPoints: queue.items.reduce((sum, x) =>
        sum + effort(x, policy), 0),
      assignedEffortPoints: assignments.reduce((sum, x) =>
        sum + x.effortPoints, 0),
      unassignedEffortPoints: unassigned.reduce((sum, x) =>
        sum + x.effortPoints, 0),
      availablePoints,
      remainingPoints: summaries.reduce((sum, x) =>
        sum + x.remainingPoints, 0),
      availableSlots,
      remainingSlots: summaries.reduce((sum, x) =>
        sum + x.remainingSlots, 0),
      assignmentPercent: queue.items.length ?
        Math.round(100 * assignments.length / queue.items.length) : 100,
      byUnassignedReason,
    },
  };
}
export function parseIntegrityExecutionCapacityQuery(
  value: unknown,
): IntegrityExecutionCapacityQuery {
  const raw = object(value, "capacity query");
  if (Object.keys(raw).some(x => ![
    "actorUserIds", "candidateIds", "source",
    "minimumScore", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown capacity query field.");
  const sources = raw.source === undefined ? undefined :
    list(raw.source, "capacity sources", 2);
  if (sources?.some(x => x !== "EXISTING" && x !== "PROPOSED"))
    throw new WorkInputError("INVALID", "Unknown capacity assignment source.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  int(offset, "capacity offset", 0, 1000000);
  int(limit, "capacity limit", 1, 1000);
  const minimumScore = raw.minimumScore === undefined ? undefined :
    int(raw.minimumScore, "minimum capacity score", 0, 1000000);
  return {
    ...(raw.actorUserIds === undefined ? {} :
      { actorUserIds: list(raw.actorUserIds, "capacity actors", 1000) }),
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: list(raw.candidateIds, "capacity candidates", 1000) }),
    ...(sources === undefined ? {} :
      { source: sources as Array<IntegrityExecutionCapacityAssignment["source"]> }),
    ...(minimumScore === undefined ? {} : { minimumScore }),
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionCapacity(
  plan: IntegrityExecutionCapacityPlan,
  query: IntegrityExecutionCapacityQuery,
): IntegrityExecutionCapacityPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = plan.assignments.filter(x =>
    (!query.actorUserIds || query.actorUserIds.includes(x.actorUserId)) &&
    (!query.candidateIds || query.candidateIds.includes(x.candidateId)) &&
    (!query.source || query.source.includes(x.source)) &&
    (query.minimumScore === undefined || x.score >= query.minimumScore));
  return {
    captureId: plan.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    assignments: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityExecutionCapacity(
  before: IntegrityExecutionCapacityPlan,
  after: IntegrityExecutionCapacityPlan,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Capacity comparison capture mismatch.");
  const old = new Map(before.assignments.map(x => [x.candidateId, x]));
  const current = new Map(after.assignments.map(x => [x.candidateId, x]));
  return {
    captureId: before.captureId,
    newlyAssigned: after.assignments.filter(x =>
      !old.has(x.candidateId)).map(x => x.candidateId),
    noLongerAssigned: before.assignments.filter(x =>
      !current.has(x.candidateId)).map(x => x.candidateId),
    reassigned: after.assignments.filter(x =>
      old.has(x.candidateId) &&
      old.get(x.candidateId)!.actorUserId !== x.actorUserId).map(x => ({
        candidateId: x.candidateId,
        from: old.get(x.candidateId)!.actorUserId,
        to: x.actorUserId,
      })),
    assignedDelta: after.totals.assigned - before.totals.assigned,
    unassignedDelta: after.totals.unassigned - before.totals.unassigned,
    assignedEffortDelta: after.totals.assignedEffortPoints -
      before.totals.assignedEffortPoints,
    utilization: after.members.map(x => ({
      actorUserId: x.actorUserId,
      previous: before.members.find(y =>
        y.actorUserId === x.actorUserId)?.utilizationPercent ?? null,
      current: x.utilizationPercent,
    })),
  };
}
