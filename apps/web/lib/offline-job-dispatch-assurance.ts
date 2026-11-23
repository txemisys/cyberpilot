import { createHash } from "node:crypto";
import type { OfflineJobSnapshot, OfflineJobStatus, OfflineJobType,
  OfflineJobFailureClass, JobEvent, OfflineJobPolicy } from "./durable-offline-job-domain";
import { jobDigest, validateJobSnapshot, validateJobPolicy,
  DEFAULT_OFFLINE_JOB_POLICY } from "./durable-offline-job-domain";

export type QueueDispatchDecision = "READY" | "WAIT_SCHEDULE" | "WAIT_CAPACITY" |
  "WAIT_DEPENDENCY" | "LEASE_EXPIRED" | "EXHAUSTED" | "EXPIRED" |
  "TERMINAL" | "INVALID" | "FOREIGN_TENANT";
export type QueueRisk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type QueueDispatchPolicy = OfflineJobPolicy & {
  maxBurstPerTenant: number; maxWaitingHours: number;
  deadLetterReviewHours: number; maxSimultaneousClaimCandidates: number;
  priorityOrder: OfflineJobType[];
  retryableFailureClasses: OfflineJobFailureClass[];
};
export const DEFAULT_QUEUE_DISPATCH_POLICY: QueueDispatchPolicy = {
  ...DEFAULT_OFFLINE_JOB_POLICY, maxBurstPerTenant: 10,
  maxWaitingHours: 24, deadLetterReviewHours: 12,
  maxSimultaneousClaimCandidates: 30,
  priorityOrder: ["RECOVERY_FAULT_MATRIX", "CAPTURE_TIMELINE_AUDIT"],
  retryableFailureClasses: ["TRANSIENT", "TIMEOUT", "UNCLASSIFIED"],
};
export type QueueDispatchCandidate = {
  id: string; organizationId: string; type: OfflineJobType;
  status: OfflineJobStatus; revision: number;
  scheduledAt: string; expiresAt: string;
  attempts: number; maxAttempts: number; leaseExpiresAt: string | null;
  decision: QueueDispatchDecision; risk: QueueRisk;
  reasons: string[]; readyInSeconds: number | null;
  ageSeconds: number; priority: number; claimPermitted: boolean;
  externalWrites: false; claimToken: null;
};
export type QueueDispatchPlan = {
  schema: "cyberpilot.offline.dispatch.plan.v1";
  organizationId: string; generatedAt: string;
  policyDigest: string; snapshotDigest: string;
  totalObserved: number; truncated: boolean;
  occupiedLeases: number; availableCapacity: number;
  admissionSlots: number; claimCandidates: QueueDispatchCandidate[];
  stalledLeases: QueueDispatchCandidate[];
  deadLetters: QueueDispatchCandidate[];
  deferred: QueueDispatchCandidate[];
  rejected: QueueDispatchCandidate[];
  selected: string[]; selectedCount: number;
  reasons: string[]; dispatchPerformed: false;
  providerCalls: 0; unattendedExecutionEnabled: false;
};
export type DispatchEntry = { job: OfflineJobSnapshot; blockedByIds?: string[] };
function nowMs(value: string): number {
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value)
    throw Error("QUEUE_DISPATCH_TIME_INVALID");
  return ms;
}
function safeInt(value: unknown, min: number, max: number) {
  return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
}
export function validateQueueDispatchPolicy(p: QueueDispatchPolicy): string[] {
  const issues = validateJobPolicy(p);
  if (!safeInt(p.maxBurstPerTenant, 1, 100))
    issues.push("DISPATCH_BURST_LIMIT_INVALID");
  if (!safeInt(p.maxWaitingHours, 1, 720))
    issues.push("DISPATCH_WAIT_LIMIT_INVALID");
  if (!safeInt(p.deadLetterReviewHours, 1, 720))
    issues.push("DISPATCH_DEAD_REVIEW_LIMIT_INVALID");
  if (!safeInt(p.maxSimultaneousClaimCandidates, 1, 100))
    issues.push("DISPATCH_MAX_CANDIDATES_INVALID");
  if (!Array.isArray(p.priorityOrder) || p.priorityOrder.length !== 2 ||
      new Set(p.priorityOrder).size !== 2 ||
      !p.priorityOrder.includes("CAPTURE_TIMELINE_AUDIT") ||
      !p.priorityOrder.includes("RECOVERY_FAULT_MATRIX"))
    issues.push("DISPATCH_PRIORITY_ORDER_INVALID");
  const types: OfflineJobFailureClass[] = [
    "TRANSIENT", "PERMANENT", "AUTHORIZATION", "DATA_INTEGRITY",
    "TIMEOUT", "UNCLASSIFIED",
  ];
  if (!Array.isArray(p.retryableFailureClasses) ||
      p.retryableFailureClasses.length > 3 ||
      new Set(p.retryableFailureClasses).size !== p.retryableFailureClasses.length ||
      p.retryableFailureClasses.some(x => !types.includes(x) ||
        x === "PERMANENT" || x === "AUTHORIZATION" ||
        x === "DATA_INTEGRITY"))
    issues.push("DISPATCH_RETRY_CLASSES_UNSAFE");
  return issues;
}
function classify(entry: DispatchEntry, organizationId: string,
  at: string, policy: QueueDispatchPolicy): QueueDispatchCandidate {
  const s = entry.job, time = nowMs(at);
  const ageSeconds = Math.max(0, Math.floor((time - Date.parse(s.createdAt)) / 1000));
  const priority = policy.priorityOrder.indexOf(s.type);
  const reasons: string[] = [];
  let decision: QueueDispatchDecision = "INVALID";
  let readyInSeconds: number | null = null;
  const errors = validateJobSnapshot(s);
  if (s.organizationId !== organizationId) {
    decision = "FOREIGN_TENANT"; reasons.push("ORGANIZATION_MISMATCH");
  } else if (errors.length) {
    decision = "INVALID"; reasons.push(...errors);
  } else if (["SUCCEEDED", "CANCELLED"].includes(s.status)) {
    decision = "TERMINAL"; reasons.push("ALREADY_TERMINAL");
  } else if (s.status === "DEAD_LETTER") {
    decision = "TERMINAL"; reasons.push("MANUAL_DEAD_LETTER_REVIEW");
  } else if (s.attempts >= s.maxAttempts && s.status !== "LEASED") {
    decision = "EXHAUSTED"; reasons.push("MAX_ATTEMPTS_REACHED");
  } else if (time >= Date.parse(s.expiresAt)) {
    decision = "EXPIRED"; reasons.push("JOB_TTL_REACHED");
  } else if (s.status === "LEASED") {
    if (s.leaseExpiresAt && time >= Date.parse(s.leaseExpiresAt)) {
      decision = "LEASE_EXPIRED"; reasons.push("FENCED_LEASE_RECOVERY_REQUIRED");
    } else {
      decision = "WAIT_CAPACITY"; reasons.push("LEASE_CURRENTLY_ACTIVE");
    }
  } else if ((entry.blockedByIds?.length ?? 0) > 0) {
    decision = "WAIT_DEPENDENCY"; reasons.push("DEPENDENCY_INCOMPLETE");
  } else if (Date.parse(s.scheduledAt) > time) {
    decision = "WAIT_SCHEDULE";
    readyInSeconds = Math.ceil((Date.parse(s.scheduledAt) - time) / 1000);
    reasons.push("NOT_YET_SCHEDULED");
  } else {
    decision = "READY"; reasons.push("ELIGIBLE_FOR_FENCED_CLAIM");
  }
  const staleSeconds = Math.max(0, Math.floor((time -
    Date.parse(s.updatedAt)) / 1000));
  if (staleSeconds >= policy.maxWaitingHours * 3600 &&
      s.status !== "SUCCEEDED" && s.status !== "CANCELLED")
    reasons.push("WAITING_OVER_POLICY");
  if (s.attempts > 1) reasons.push("PREVIOUS_RETRY_OBSERVED");
  if (s.failureClass === "DATA_INTEGRITY")
    reasons.push("DATA_INTEGRITY_REVIEW_REQUIRED");
  if (s.failureClass === "AUTHORIZATION")
    reasons.push("AUTHORIZATION_REVIEW_REQUIRED");
  const risk: QueueRisk = decision === "INVALID" ||
    decision === "FOREIGN_TENANT" || s.failureClass === "DATA_INTEGRITY" ?
    "CRITICAL" : decision === "EXHAUSTED" || decision === "EXPIRED" ||
    decision === "LEASE_EXPIRED" || s.failureClass === "AUTHORIZATION" ?
    "HIGH" : ageSeconds >= policy.maxWaitingHours * 3600 ||
    decision === "WAIT_DEPENDENCY" ? "MEDIUM" : "LOW";
  return { id: s.id, organizationId: s.organizationId,
    type: s.type, status: s.status, revision: s.revision,
    scheduledAt: s.scheduledAt, expiresAt: s.expiresAt,
    attempts: s.attempts, maxAttempts: s.maxAttempts,
    leaseExpiresAt: s.leaseExpiresAt, decision, risk, reasons,
    readyInSeconds, ageSeconds, priority: priority < 0 ? 99 : priority,
    claimPermitted: decision === "READY",
    externalWrites: false, claimToken: null };
}
export function buildQueueDispatchPlan(
  organizationId: string, entries: DispatchEntry[], at: string,
  policy: QueueDispatchPolicy = DEFAULT_QUEUE_DISPATCH_POLICY,
  truncated = false,
): QueueDispatchPlan {
  if (!organizationId || validateQueueDispatchPolicy(policy).length ||
      entries.length > 10000) throw Error("QUEUE_DISPATCH_INPUT_INVALID");
  nowMs(at);
  const ids = new Set<string>();
  for (const entry of entries) {
    if (ids.has(entry.job.id)) throw Error("QUEUE_DUPLICATE_JOB_ID");
    ids.add(entry.job.id);
    if (entry.blockedByIds && (entry.blockedByIds.length > 30 ||
        entry.blockedByIds.some(x => typeof x !== "string" || x === entry.job.id)))
      throw Error("QUEUE_DEPENDENCY_INVALID");
  }
  const candidates = entries.map(x => classify(x, organizationId, at, policy));
  const occupiedLeases = candidates.filter(c => c.status === "LEASED" &&
    c.decision === "WAIT_CAPACITY").length;
  const availableCapacity = Math.max(0, policy.concurrencyPerTenant - occupiedLeases);
  const ready = candidates.filter(x => x.decision === "READY").sort((a, b) =>
    a.priority - b.priority ||
      a.scheduledAt.localeCompare(b.scheduledAt) ||
      a.attempts - b.attempts || a.id.localeCompare(b.id));
  const available = Math.min(availableCapacity, policy.maxBurstPerTenant,
    policy.maxSimultaneousClaimCandidates);
  const selected = ready.slice(0, available).map(x => x.id);
  const selectedIds = new Set(selected);
  const deferred = candidates.filter(x =>
    ["WAIT_SCHEDULE", "WAIT_CAPACITY", "WAIT_DEPENDENCY"].includes(x.decision) ||
    x.decision === "READY" && !selectedIds.has(x.id));
  const reasons: string[] = [];
  if (truncated) reasons.push("PAGE_TRUNCATED_DISPATCH_INCOMPLETE");
  if (!availableCapacity) reasons.push("TENANT_CONCURRENCY_SATURATED");
  if (ready.length > selected.length) reasons.push("CAPACITY_EXCEEDED");
  if (candidates.some(x => x.decision === "FOREIGN_TENANT"))
    reasons.push("CROSS_TENANT_INPUT_REJECTED");
  if (candidates.some(x => x.decision === "INVALID"))
    reasons.push("CORRUPT_JOB_INPUT_REJECTED");
  if (truncated) selected.length = 0;
  return {
    schema: "cyberpilot.offline.dispatch.plan.v1",
    organizationId, generatedAt: at,
    policyDigest: jobDigest(policy),
    snapshotDigest: jobDigest(candidates.map(x =>
      [x.id, x.revision, x.decision, x.status])),
    totalObserved: candidates.length, truncated,
    occupiedLeases, availableCapacity,
    admissionSlots: available, claimCandidates: ready,
    stalledLeases: candidates.filter(x => x.decision === "LEASE_EXPIRED"),
    deadLetters: candidates.filter(x => x.status === "DEAD_LETTER"),
    deferred, rejected: candidates.filter(x =>
      ["FOREIGN_TENANT", "INVALID", "EXPIRED", "EXHAUSTED"].includes(x.decision)),
    selected, selectedCount: selected.length,
    reasons, dispatchPerformed: false,
    providerCalls: 0, unattendedExecutionEnabled: false,
  };
}
export type QueueFailureDisposition = {
  kind: "RETRY" | "DEAD_LETTER" | "INSPECT" | "DO_NOT_RETRY";
  code: string; failureClass: OfflineJobFailureClass; retryAfterSeconds: number | null;
  requiresHumanReview: boolean; safeToExecuteUnattended: false;
  statusEffect: "RETRY_WAIT" | "DEAD_LETTER" | "UNCHANGED";
  rationale: string[];
};
export function classifyQueueFailure(
  job: OfflineJobSnapshot, failureCode: string,
  failureClass: OfflineJobFailureClass, at: string,
  policy: QueueDispatchPolicy = DEFAULT_QUEUE_DISPATCH_POLICY,
): QueueFailureDisposition {
  if (validateJobSnapshot(job).length ||
      validateQueueDispatchPolicy(policy).length ||
      typeof failureCode !== "string" ||
      !/^[A-Z][A-Z0-9_]{3,95}$/.test(failureCode))
    throw Error("QUEUE_FAILURE_CLASSIFICATION_INVALID");
  const time = nowMs(at);
  if (job.status !== "LEASED")
    return { kind: "DO_NOT_RETRY", code: failureCode, failureClass,
      retryAfterSeconds: null, requiresHumanReview: true,
      safeToExecuteUnattended: false, statusEffect: "UNCHANGED",
      rationale: ["NO_ACTIVE_LEASE_TO_FAIL"] };
  const irreversible = ["DATA_INTEGRITY", "PERMANENT", "AUTHORIZATION"]
    .includes(failureClass);
  const exhausted = job.attempts >= job.maxAttempts ||
    time >= Date.parse(job.expiresAt);
  const permitted = policy.retryableFailureClasses.includes(failureClass);
  if (irreversible || exhausted || !permitted)
    return { kind: "DEAD_LETTER", code: failureCode, failureClass,
      retryAfterSeconds: null, requiresHumanReview: true,
      safeToExecuteUnattended: false, statusEffect: "DEAD_LETTER",
      rationale: [
        ...(irreversible ? ["NON_RETRYABLE_CLASS"] : []),
        ...(exhausted ? ["BUDGET_OR_TTL_EXHAUSTED"] : []),
        ...(!permitted ? ["RETRY_POLICY_REJECTED"] : []),
      ] };
  const delay = Math.min(policy.maxBackoffSeconds,
    policy.baseBackoffSeconds * 2 ** Math.min(job.attempts - 1, 20));
  return { kind: "RETRY", code: failureCode, failureClass,
    retryAfterSeconds: delay, requiresHumanReview: false,
    safeToExecuteUnattended: false, statusEffect: "RETRY_WAIT",
    rationale: ["BOUNDED_BACKOFF", "NO_LIVE_SIDE_EFFECTS"] };
}
export type QueueDeadLetterReview = {
  schema: "cyberpilot.offline.dead-letter.review.v1"; organizationId: string;
  at: string; total: number; truncated: boolean;
  cases: Array<{ id: string; type: OfflineJobType; failureClass: string | null;
    failureCode: string | null; ageHours: number; attempts: number;
    priority: QueueRisk; decision: "REVIEW_REQUIRED";
    suggestedSteps: string[]; independentRepairVerified: false }>;
  outstanding: number; productionRemediationConfirmed: false;
};
export function reviewDeadLetters(
  organizationId: string, jobs: OfflineJobSnapshot[], at: string,
  policy: QueueDispatchPolicy = DEFAULT_QUEUE_DISPATCH_POLICY,
  truncated = false,
): QueueDeadLetterReview {
  const time = nowMs(at);
  if (validateQueueDispatchPolicy(policy).length ||
      jobs.length > 10000 || jobs.some(x => x.organizationId !== organizationId))
    throw Error("QUEUE_DEAD_LETTER_SCOPE_INVALID");
  const cases = jobs.filter(x => x.status === "DEAD_LETTER").map(x => {
    const ageHours = Math.max(0,
      (time - Date.parse(x.updatedAt)) / 3600000);
    const priority: QueueRisk = x.failureClass === "DATA_INTEGRITY" ||
      x.failureClass === "AUTHORIZATION" ? "CRITICAL" :
      ageHours >= policy.deadLetterReviewHours ? "HIGH" : "MEDIUM";
    const suggestedSteps = [
      "Confirm the failure code and original tenant scope",
      "Review the immutable job event chain and snapshot digest",
      "Verify relevant membership and read permissions",
      "Confirm source data is still available and integrity-valid",
      "Create a new idempotent job only after a separate decision",
    ];
    if (x.failureClass === "DATA_INTEGRITY")
      suggestedSteps.unshift("Preserve original data and stop dependent processing");
    if (x.failureClass === "AUTHORIZATION")
      suggestedSteps.unshift("Do not retry until authorization is separately revalidated");
    return { id: x.id, type: x.type,
      failureClass: x.failureClass, failureCode: x.lastFailure,
      ageHours, attempts: x.attempts, priority,
      decision: "REVIEW_REQUIRED" as const, suggestedSteps,
      independentRepairVerified: false as const };
  }).sort((a, b) => {
    const weight: Record<QueueRisk, number> = { CRITICAL: 0, HIGH: 1,
      MEDIUM: 2, LOW: 3 };
    return weight[a.priority] - weight[b.priority] ||
      b.ageHours - a.ageHours || a.id.localeCompare(b.id);
  });
  return { schema: "cyberpilot.offline.dead-letter.review.v1",
    organizationId, at, total: jobs.length, truncated,
    cases, outstanding: cases.length, productionRemediationConfirmed: false };
}
export type QueueAuditDiagnostic = {
  jobId: string; organizationId: string;
  revision: number; digestConsistent: boolean;
  transitionsConsistent: boolean; sequenceConsistent: boolean;
  staleFences: number; retries: number; heartbeats: number;
  unexpectedStateChanges: number; issues: string[];
  actualProviderRecoveryVerified: false;
};
export function analyzeJobEventChain(
  snapshot: OfflineJobSnapshot, events: readonly JobEvent[],
): QueueAuditDiagnostic {
  if (events.length > 2000) throw Error("QUEUE_AUDIT_EXCESSIVE");
  const issues: string[] = [];
  const sorted = [...events].sort((a, b) => a.revision - b.revision);
  const expected: Record<JobEvent["kind"], OfflineJobStatus> = {
    ADMITTED: "QUEUED", CLAIMED: "LEASED", HEARTBEAT: "LEASED",
    SUCCEEDED: "SUCCEEDED", RETRY_SCHEDULED: "RETRY_WAIT",
    DEAD_LETTERED: "DEAD_LETTER", CANCELLED: "CANCELLED",
    REQUEUED: "RETRY_WAIT",
  };
  let staleFences = 0, unexpectedStateChanges = 0;
  for (let i = 0; i < sorted.length; i++) {
    const event = sorted[i]!;
    if (event.jobId !== snapshot.id ||
        event.organizationId !== snapshot.organizationId)
      throw Error("QUEUE_AUDIT_CROSS_TENANT");
    if (event.revision !== i + 1) issues.push("REVISION_GAP_" + event.revision);
    if (event.next !== expected[event.kind]) {
      unexpectedStateChanges++;
      issues.push("INVALID_TRANSITION_" + event.revision);
    }
    if (i > 0 && event.previous !== sorted[i - 1]!.next)
      issues.push("EVENT_PREDECESSOR_MISMATCH_" + event.revision);
    if (event.kind === "REQUEUED") staleFences++;
    if (event.providerOperations !== 0)
      issues.push("UNSUPPORTED_PROVIDER_WRITE_" + event.revision);
  }
  if (sorted.at(-1)?.digest !== jobDigest(snapshot))
    issues.push("LATEST_DIGEST_MISMATCH");
  if (sorted.at(-1)?.next !== snapshot.status)
    issues.push("LATEST_STATUS_MISMATCH");
  if (events.length !== snapshot.revision)
    issues.push("EVENT_HISTORY_INCOMPLETE");
  return { jobId: snapshot.id, organizationId: snapshot.organizationId,
    revision: snapshot.revision,
    digestConsistent: !issues.includes("LATEST_DIGEST_MISMATCH"),
    transitionsConsistent: unexpectedStateChanges === 0,
    sequenceConsistent: !issues.some(x => x.startsWith("REVISION_GAP") ||
      x.startsWith("EVENT_PREDECESSOR") || x === "EVENT_HISTORY_INCOMPLETE"),
    staleFences, retries: events.filter(x => x.kind === "RETRY_SCHEDULED").length,
    heartbeats: events.filter(x => x.kind === "HEARTBEAT").length,
    unexpectedStateChanges, issues,
    actualProviderRecoveryVerified: false };
}
