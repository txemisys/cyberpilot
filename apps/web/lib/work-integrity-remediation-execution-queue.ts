import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionReadinessReport,
  IntegrityExecutionReadinessCandidate,
  IntegrityExecutionReadinessBlocker,
} from "./work-integrity-remediation-execution-readiness";
import type {
  IntegrityExecutionReadinessHistory,
} from "./work-integrity-remediation-readiness-history";

export type IntegrityExecutionRemediationQueuePolicy = {
  priorityWeights: Record<string, number>;
  blockerWeights: Record<IntegrityExecutionReadinessBlocker, number>;
  agingDays: number;
  agingPointsPerPeriod: number;
  maximumAgingPoints: number;
  maximumQueueSize: number;
  includeReady: boolean;
};
export type IntegrityExecutionRemediationQueueItem = {
  candidateId: string;
  caseKey: string | null;
  workItemId: string | null;
  priority: string;
  action: string;
  state: string;
  ready: boolean;
  blockers: IntegrityExecutionReadinessBlocker[];
  score: number;
  priorityPoints: number;
  blockerPoints: number;
  agingPoints: number;
  firstBlockedAt: string | null;
  lastChangedAt: string | null;
  blockedDays: number;
  attentionReasons: string[];
  recommendedNextStep: string;
};
export type IntegrityExecutionRemediationQueue = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityExecutionRemediationQueuePolicy;
  limitation: string;
  items: IntegrityExecutionRemediationQueueItem[];
  totals: {
    candidates: number;
    queued: number;
    omittedReady: number;
    withHistory: number;
    withoutHistory: number;
    urgent: number;
    high: number;
    normal: number;
    low: number;
    totalScore: number;
    averageScore: number;
    maximumScore: number;
    oldestBlockedDays: number;
    byNextStep: Record<string, number>;
  };
};
export type IntegrityExecutionRemediationQueueQuery = {
  candidateIds?: string[];
  blockerCodes?: IntegrityExecutionReadinessBlocker[];
  nextSteps?: string[];
  minimumScore?: number;
  maximumScore?: number;
  onlyUnassigned?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionRemediationQueuePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  items: IntegrityExecutionRemediationQueueItem[];
};
const blockerWeights: Record<IntegrityExecutionReadinessBlocker, number> = {
  UNKNOWN_CANDIDATE: 100,
  NOT_APPROVED: 25,
  CONTROL_ERROR: 80,
  CONTROL_WARNING: 10,
  PROVENANCE_ERROR: 75,
  PROVENANCE_WARNING: 10,
  NO_ACTIVE_ASSOCIATION: 55,
  NO_COMPLETION_REFERENCE: 45,
  EXECUTION_NOT_COMPLETED: 20,
  EXECUTION_FAILED: 70,
  EXECUTION_BLOCKED: 50,
  EXECUTION_CANCELLED: 35,
  UNVERIFIED_EVIDENCE: 65,
  UNBOUND_WORK_ITEM: 40,
  MISSING_EXECUTION_CONTROLS: 90,
  MISSING_PROVENANCE: 90,
};
const defaultPolicy: IntegrityExecutionRemediationQueuePolicy = {
  priorityWeights: { P0: 100, P1: 70, P2: 40, P3: 15, CRITICAL: 100, HIGH: 70, MEDIUM: 40, LOW: 15 },
  blockerWeights,
  agingDays: 7,
  agingPointsPerPeriod: 5,
  maximumAgingPoints: 40,
  maximumQueueSize: 10000,
  includeReady: false,
};
const steps: Array<{
  blockers: IntegrityExecutionReadinessBlocker[];
  step: string;
}> = [
  { blockers: ["UNKNOWN_CANDIDATE"], step: "RECONCILE_CANDIDATE" },
  { blockers: ["MISSING_EXECUTION_CONTROLS", "CONTROL_ERROR"],
    step: "REVIEW_EXECUTION_CONTROLS" },
  { blockers: ["MISSING_PROVENANCE", "PROVENANCE_ERROR"],
    step: "REVIEW_AUDIT_PROVENANCE" },
  { blockers: ["NOT_APPROVED"], step: "REQUEST_REMEDIATION_APPROVAL" },
  { blockers: ["UNBOUND_WORK_ITEM"], step: "ASSIGN_WORK_ITEM" },
  { blockers: ["NO_ACTIVE_ASSOCIATION"],
    step: "LINK_ACTIVE_WORK_EVIDENCE" },
  { blockers: ["EXECUTION_FAILED", "EXECUTION_CANCELLED"],
    step: "REVIEW_FAILED_EXECUTION" },
  { blockers: ["EXECUTION_BLOCKED"], step: "RESOLVE_EXECUTION_BLOCKER" },
  { blockers: ["EXECUTION_NOT_COMPLETED"],
    step: "CONTINUE_EXECUTION" },
  { blockers: ["NO_COMPLETION_REFERENCE"],
    step: "COLLECT_COMPLETION_REFERENCE" },
  { blockers: ["UNVERIFIED_EVIDENCE"],
    step: "VERIFY_EVIDENCE_INDEPENDENTLY" },
  { blockers: ["CONTROL_WARNING", "PROVENANCE_WARNING"],
    step: "REVIEW_WARNINGS" },
];
function validTime(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid queue evaluation time.");
}
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function number(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
export function parseIntegrityExecutionRemediationQueuePolicy(
  value: unknown,
): IntegrityExecutionRemediationQueuePolicy {
  if (value === undefined) return {
    ...defaultPolicy,
    priorityWeights: { ...defaultPolicy.priorityWeights },
    blockerWeights: { ...defaultPolicy.blockerWeights },
  };
  const raw = object(value, "remediation queue policy");
  if (Object.keys(raw).some(x => ![
    "priorityWeights", "blockerWeights", "agingDays",
    "agingPointsPerPeriod", "maximumAgingPoints",
    "maximumQueueSize", "includeReady",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown queue policy field.");
  const policy = parseIntegrityExecutionRemediationQueuePolicy(undefined);
  if (raw.priorityWeights !== undefined) {
    const weights = object(raw.priorityWeights, "priority weights");
    if (Object.keys(weights).length > 100)
      throw new WorkInputError("INVALID", "Too many priority weights.");
    for (const [key, value] of Object.entries(weights)) {
      if (!key || key.length > 100)
        throw new WorkInputError("INVALID", "Invalid priority key.");
      policy.priorityWeights[key] = number(value, "priority weight", 0, 1000);
    }
  }
  if (raw.blockerWeights !== undefined) {
    const weights = object(raw.blockerWeights, "blocker weights");
    for (const [key, value] of Object.entries(weights)) {
      if (!(key in blockerWeights))
        throw new WorkInputError("INVALID", "Unknown blocker weight.");
      policy.blockerWeights[key as IntegrityExecutionReadinessBlocker] =
        number(value, "blocker weight", 0, 1000);
    }
  }
  for (const key of [
    "agingDays", "agingPointsPerPeriod",
    "maximumAgingPoints", "maximumQueueSize",
  ] as const) {
    if (raw[key] !== undefined)
      policy[key] = number(raw[key], key,
        key === "agingDays" || key === "maximumQueueSize" ? 1 : 0,
        key === "maximumQueueSize" ? 10000 : 1000);
  }
  if (raw.includeReady !== undefined) {
    if (typeof raw.includeReady !== "boolean")
      throw new WorkInputError("INVALID", "Invalid includeReady flag.");
    policy.includeReady = raw.includeReady;
  }
  return policy;
}
function nextStep(candidate: IntegrityExecutionReadinessCandidate) {
  if (candidate.ready) return "NO_ACTION_REQUIRED";
  for (const rule of steps) {
    if (candidate.blockers.some(x => rule.blockers.includes(x)))
      return rule.step;
  }
  return "REVIEW_REMEDIATION";
}
function ageOf(
  candidateId: string,
  history: IntegrityExecutionReadinessHistory | null,
  evaluatedAt: string,
) {
  if (!history) return {
    firstBlockedAt: null, lastChangedAt: null, blockedDays: 0,
  };
  let firstBlockedAt: string | null = null;
  let lastChangedAt: string | null = null;
  for (const checkpoint of history.checkpoints) {
    if (checkpoint.at > evaluatedAt) continue;
    if (checkpoint.changes.some(x => x.candidateId === candidateId))
      lastChangedAt = checkpoint.at;
    const blocked = checkpoint.changes.some(x =>
      x.candidateId === candidateId &&
      (x.kind === "BLOCKER_ADDED" || x.kind === "LOST_READINESS"));
    const recovered = checkpoint.changes.some(x =>
      x.candidateId === candidateId && x.kind === "BECAME_READY");
    if (recovered) firstBlockedAt = null;
    if (blocked && firstBlockedAt === null)
      firstBlockedAt = checkpoint.at;
  }
  return {
    firstBlockedAt, lastChangedAt,
    blockedDays: firstBlockedAt === null ? 0 :
      Math.max(0, Math.floor((Date.parse(evaluatedAt) -
        Date.parse(firstBlockedAt)) / 86400000)),
  };
}
export function prioritizeIntegrityExecutionRemediation(
  readiness: IntegrityExecutionReadinessReport,
  history: IntegrityExecutionReadinessHistory | null,
  evaluatedAt: string,
  policy: IntegrityExecutionRemediationQueuePolicy = defaultPolicy,
): IntegrityExecutionRemediationQueue {
  validTime(evaluatedAt);
  if (history && history.captureId !== readiness.captureId)
    throw new WorkInputError("INVALID", "Queue history capture mismatch.");
  const items = readiness.candidates.filter(x =>
    policy.includeReady || !x.ready).map(candidate => {
    const age = ageOf(candidate.candidateId, history, evaluatedAt);
    const priorityPoints = policy.priorityWeights[candidate.priority] ?? 0;
    const blockerPoints = candidate.blockers.reduce((sum, blocker) =>
      sum + policy.blockerWeights[blocker], 0);
    const agingPoints = Math.min(policy.maximumAgingPoints,
      Math.floor(age.blockedDays / policy.agingDays) *
      policy.agingPointsPerPeriod);
    return {
      candidateId: candidate.candidateId,
      caseKey: candidate.caseKey, workItemId: candidate.workItemId,
      priority: candidate.priority, action: candidate.action,
      state: candidate.executionState, ready: candidate.ready,
      blockers: candidate.blockers, score:
        priorityPoints + blockerPoints + agingPoints,
      priorityPoints, blockerPoints, agingPoints,
      ...age, attentionReasons: candidate.blockers.map(x =>
        x.replaceAll("_", " ").toLowerCase()),
      recommendedNextStep: nextStep(candidate),
    };
  }).sort((a, b) => b.score - a.score ||
    b.blockers.length - a.blockers.length ||
    a.candidateId.localeCompare(b.candidateId))
    .slice(0, policy.maximumQueueSize);
  const byNextStep: Record<string, number> = {};
  for (const item of items) {
    byNextStep[item.recommendedNextStep] =
      (byNextStep[item.recommendedNextStep] ?? 0) + 1;
  }
  const totalScore = items.reduce((sum, x) => sum + x.score, 0);
  return {
    schemaVersion: 1, captureId: readiness.captureId, evaluatedAt,
    policy, limitation: "Priority is a diagnostic queue score, not a security risk score or an instruction to execute remediation.",
    items, totals: {
      candidates: readiness.totals.candidates,
      queued: items.length,
      omittedReady: readiness.candidates.filter(x => x.ready &&
        !policy.includeReady).length,
      withHistory: items.filter(x => x.lastChangedAt !== null).length,
      withoutHistory: items.filter(x => x.lastChangedAt === null).length,
      urgent: items.filter(x => x.score >= 200).length,
      high: items.filter(x => x.score >= 120 && x.score < 200).length,
      normal: items.filter(x => x.score >= 60 && x.score < 120).length,
      low: items.filter(x => x.score < 60).length,
      totalScore,
      averageScore: items.length ? Math.round(totalScore / items.length) : 0,
      maximumScore: items[0]?.score ?? 0,
      oldestBlockedDays: Math.max(0, ...items.map(x => x.blockedDays)),
      byNextStep,
    },
  };
}
export function parseIntegrityExecutionRemediationQueueQuery(
  value: unknown,
): IntegrityExecutionRemediationQueueQuery {
  const raw = object(value, "remediation queue query");
  if (Object.keys(raw).some(x => ![
    "candidateIds", "blockerCodes", "nextSteps",
    "minimumScore", "maximumScore", "onlyUnassigned",
    "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown queue query field.");
  const list = (value: unknown) => {
    if (!Array.isArray(value) || value.length > 1000 ||
        value.some(x => typeof x !== "string" || !x ||
          x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
      throw new WorkInputError("INVALID", "Invalid queue filter.");
    return [...new Set(value as string[])];
  };
  const blockers = raw.blockerCodes === undefined ? undefined :
    list(raw.blockerCodes);
  if (blockers?.some(x => !(x in blockerWeights)))
    throw new WorkInputError("INVALID", "Unknown queue blocker.");
  if (raw.onlyUnassigned !== undefined &&
      typeof raw.onlyUnassigned !== "boolean")
    throw new WorkInputError("INVALID", "Invalid unassigned flag.");
  const min = raw.minimumScore === undefined ? undefined :
    number(raw.minimumScore, "minimum score", 0, 1000000);
  const max = raw.maximumScore === undefined ? undefined :
    number(raw.maximumScore, "maximum score", 0, 1000000);
  if (min !== undefined && max !== undefined && min > max)
    throw new WorkInputError("INVALID", "Reversed score range.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  number(offset, "queue offset", 0, 1000000);
  number(limit, "queue limit", 1, 1000);
  return {
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: list(raw.candidateIds) }),
    ...(blockers === undefined ? {} :
      { blockerCodes: blockers as IntegrityExecutionReadinessBlocker[] }),
    ...(raw.nextSteps === undefined ? {} :
      { nextSteps: list(raw.nextSteps) }),
    ...(min === undefined ? {} : { minimumScore: min }),
    ...(max === undefined ? {} : { maximumScore: max }),
    onlyUnassigned: raw.onlyUnassigned === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionRemediationQueue(
  queue: IntegrityExecutionRemediationQueue,
  query: IntegrityExecutionRemediationQueueQuery,
): IntegrityExecutionRemediationQueuePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = queue.items.filter(x =>
    (!query.candidateIds || query.candidateIds.includes(x.candidateId)) &&
    (!query.blockerCodes || x.blockers.some(code =>
      query.blockerCodes!.includes(code))) &&
    (!query.nextSteps || query.nextSteps.includes(x.recommendedNextStep)) &&
    (query.minimumScore === undefined || x.score >= query.minimumScore) &&
    (query.maximumScore === undefined || x.score <= query.maximumScore) &&
    (!query.onlyUnassigned || x.workItemId === null));
  return {
    captureId: queue.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    items: selected.slice(offset, offset + limit),
  };
}
