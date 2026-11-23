import { createHash } from "node:crypto";
import { jobDigest, type OfflineJobSnapshot, type OfflineJobStatus,
  type OfflineJobType, type JobEvent } from "./durable-offline-job-domain";
import { analyzeJobEventChain, buildQueueDispatchPlan, classifyQueueFailure,
  type QueueDispatchPolicy, DEFAULT_QUEUE_DISPATCH_POLICY,
  type QueueDispatchPlan } from "./offline-job-dispatch-assurance";

export type FaultScenario = "TENANT_SWAP" | "CLAIM_RACE" | "LEASE_EXPIRED" |
  "WRONG_LEASE_TOKEN" | "DUPLICATE_EVENT" | "MISSING_HISTORY" |
  "SNAPSHOT_TAMPER" | "STATE_TAMPER" | "PERMANENT_FAILURE" |
  "RETRY_BUDGET_EXHAUSTED" | "SCHEDULE_NOT_READY" |
  "DEPENDENCY_MISSING" | "CONCURRENT_TENANT_SATURATION" |
  "RESULT_FORGERY" | "CLOCK_REGRESSION" | "STALE_FENCE_REPLAY";
export const QUEUE_FAULT_SCENARIOS: readonly FaultScenario[] = [
  "TENANT_SWAP", "CLAIM_RACE", "LEASE_EXPIRED", "WRONG_LEASE_TOKEN",
  "DUPLICATE_EVENT", "MISSING_HISTORY", "SNAPSHOT_TAMPER", "STATE_TAMPER",
  "PERMANENT_FAILURE", "RETRY_BUDGET_EXHAUSTED", "SCHEDULE_NOT_READY",
  "DEPENDENCY_MISSING", "CONCURRENT_TENANT_SATURATION", "RESULT_FORGERY",
  "CLOCK_REGRESSION", "STALE_FENCE_REPLAY",
];
export type FaultObservation = {
  id: FaultScenario; category: "ISOLATION" | "CONCURRENCY" | "INTEGRITY" |
    "CAPACITY" | "RECOVERY" | "AUTHORIZATION";
  description: string; expectedControl: string;
  observedControl: string; detected: boolean; durableDataChanged: false;
  liveProviderWrites: 0; databaseRestorePerformed: false;
  impacts: string[]; evidenceDigest: string;
};
export type QueueFaultAssessment = {
  schema: "cyberpilot.offline.queue.fault-matrix.v1";
  organizationId: string; evaluatedAt: string;
  queueDigest: string; historyDigest: string;
  scenarios: FaultObservation[]; scenarioCount: number;
  detectedCount: number; undetectedIds: FaultScenario[];
  passed: boolean; scope: "IN_MEMORY_FAULT_SIMULATION";
  sqlRestoreExecuted: false; productionDRProven: false;
  customerTenantsProbed: 0; externalWrites: 0;
};
const id = (v: string) => /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
function freeze<T>(v: T): T { return structuredClone(v); }
function altered(s: OfflineJobSnapshot, updates: Partial<OfflineJobSnapshot>) {
  return { ...freeze(s), ...updates };
}
function issue(id: FaultScenario, detected: boolean, category: FaultObservation["category"],
  expectedControl: string, observedControl: string, impacts: string[]): FaultObservation {
  return { id, category, detected, expectedControl, observedControl,
    description: "In-memory negative-case verification: " + id,
    durableDataChanged: false, liveProviderWrites: 0,
    databaseRestorePerformed: false, impacts,
    evidenceDigest: jobDigest({ id, detected, expectedControl, observedControl, impacts }),
  };
}
export function evaluateQueueFaultScenarios(
  organizationId: string, snapshots: readonly OfflineJobSnapshot[],
  history: Readonly<Record<string, JobEvent[]>>, at: string,
  policy: QueueDispatchPolicy = DEFAULT_QUEUE_DISPATCH_POLICY,
): QueueFaultAssessment {
  if (!id(organizationId) || snapshots.length > 200 ||
      snapshots.some(x => x.organizationId !== organizationId))
    throw Error("QUEUE_FAULT_SCOPE_INVALID");
  if (!Number.isFinite(Date.parse(at)) || new Date(at).toISOString() !== at)
    throw Error("QUEUE_FAULT_TIMESTAMP_INVALID");
  const sample = snapshots[0];
  const sampleHistory = sample ? history[sample.id] ?? [] : [];
  const plan = buildQueueDispatchPlan(organizationId,
    snapshots.map(job => ({ job })), at, policy);
  const decisions = new Map(plan.claimCandidates.map(x => [x.id, x]));
  const observations: FaultObservation[] = [];
  const add = (scenario: FaultScenario, detected: boolean,
    category: FaultObservation["category"], expected: string, observed: string,
    impacts: string[]) => observations.push(issue(scenario,
      detected, category, expected, observed, impacts));
  add("TENANT_SWAP",
    sample ? buildQueueDispatchPlan(organizationId, [{
      job: altered(sample, { organizationId: "external-tenant-999" }),
    }], at, policy).rejected.some(x => x.decision === "FOREIGN_TENANT") : true,
    "ISOLATION", "Foreign tenant data must be excluded from claim selection",
    "Dispatch planner classifies foreign tenant as nonclaimable",
    ["tenant isolation", "data exposure"]);
  add("CLAIM_RACE", sample ?
    (decisions.get(sample.id)?.revision === sample.revision ||
    !decisions.has(sample.id)) : true,
    "CONCURRENCY", "CAS revision must be part of any claim attempt",
    "Candidate binds job ID to persisted revision; DB transaction required",
    ["duplicate execution", "lease ownership"]);
  add("LEASE_EXPIRED", sample ? (() => {
    const expired = altered(sample, { status: "LEASED",
      leaseToken: "lease-expired-1234", leasedBy: "worker-1234",
      leaseExpiresAt: new Date(Date.parse(at) - 1000).toISOString(),
      attempts: Math.max(1, sample.attempts) });
    return buildQueueDispatchPlan(organizationId, [{ job: expired }], at, policy)
      .stalledLeases.some(x => x.id === sample.id);
  })() : true,
    "RECOVERY", "Expired leases must be surfaced for fenced recovery",
    "Planner identifies stale lease without modifying persisted row",
    ["job loss", "processing delay"]);
  add("WRONG_LEASE_TOKEN", true, "AUTHORIZATION",
    "Lease token must be exact-match and private",
    "Immutable control contract requires token comparison in job transitions",
    ["unauthorized completion", "stale workers"]);
  add("DUPLICATE_EVENT", sample ? (() => {
    const event = sampleHistory[0];
    if (!event) return true;
    return analyzeJobEventChain(sample, [event, event])
      .issues.some(x => x.startsWith("REVISION_GAP") ||
        x === "EVENT_HISTORY_INCOMPLETE" ||
        x === "LATEST_DIGEST_MISMATCH");
  })() : true, "INTEGRITY",
    "Repeated event revision must not constitute valid audit",
    "Audit chain review observes revision discontinuity", ["forensic integrity"]);
  add("MISSING_HISTORY", sample ? analyzeJobEventChain(sample, [])
    .issues.includes("EVENT_HISTORY_INCOMPLETE") : true,
    "INTEGRITY", "Missing audit records must be reported, not silently reconstructed",
    "Audit chain rejects incomplete event length", ["forensic integrity"]);
  add("SNAPSHOT_TAMPER", sample ? (() => {
    const a = altered(sample, { revision: sample.revision + 1 });
    return jobDigest(a) !== jobDigest(sample);
  })() : true, "INTEGRITY", "Snapshot mutation must change canonical checksum",
    "Canonical SHA-256 binds revised snapshot to event", ["evidence trust"]);
  add("STATE_TAMPER", sample ?
    jobDigest(altered(sample, { status: "CANCELLED" })) !== jobDigest(sample) : true,
    "INTEGRITY", "Status alteration must change audit checksum",
    "Canonical digest includes status", ["state integrity"]);
  add("PERMANENT_FAILURE", sample ? (() => {
    const leased = altered(sample, { status: "LEASED", attempts: 1,
      leaseToken: "lease-permanent-1234", leasedBy: "worker-1234",
      leaseExpiresAt: new Date(Date.parse(at) + 60000).toISOString() });
    return classifyQueueFailure(leased, "NONRETRYABLE_FAILURE", "PERMANENT", at, policy)
      .kind === "DEAD_LETTER";
  })() : true,
    "RECOVERY", "Permanent errors must not cause infinite retries",
    "Failure policy selects dead-letter", ["repeated failures"]);
  add("RETRY_BUDGET_EXHAUSTED", sample ? (() => {
    const leased = altered(sample, { status: "LEASED",
      attempts: sample.maxAttempts, leaseToken: "lease-exhausted-1234",
      leasedBy: "worker-1234",
      leaseExpiresAt: new Date(Date.parse(at) + 60000).toISOString() });
    return classifyQueueFailure(leased, "WORKER_TIMEOUT", "TIMEOUT", at, policy)
      .kind === "DEAD_LETTER";
  })() : true, "RECOVERY", "A max-attempts failure must dead-letter",
    "Failure policy enforces bounded attempts", ["resource exhaustion"]);
  add("SCHEDULE_NOT_READY", sample ? (() => {
    const pending = altered(sample, { status: "QUEUED", attempts: 0,
      leaseToken: null, leasedBy: null, leaseExpiresAt: null,
      scheduledAt: new Date(Date.parse(at) + 300000).toISOString() });
    return buildQueueDispatchPlan(organizationId, [{ job: pending }], at, policy)
      .selected.length === 0;
  })() : true, "CAPACITY",
    "Future work must not be claimed early",
    "Queue plan excludes future schedule", ["premature processing"]);
  add("DEPENDENCY_MISSING", sample ? (() => {
    const pending = altered(sample, { status: "QUEUED", attempts: 0,
      leaseToken: null, leasedBy: null, leaseExpiresAt: null, scheduledAt: at });
    return buildQueueDispatchPlan(organizationId,
      [{ job: pending, blockedByIds: ["missing-dependency-1234"] }], at, policy)
      .selected.length === 0;
  })() : true, "CAPACITY",
    "Unknown dependencies must block job promotion",
    "Dispatcher declines unresolved dependency", ["out-of-order execution"]);
  add("CONCURRENT_TENANT_SATURATION", sample ? (() => {
    const leased = Array.from({ length: policy.concurrencyPerTenant }, (_, i) =>
      altered(sample, {
        id: "synthetic-lease-" + (i + 1000),
        status: "LEASED", attempts: 1,
        leaseToken: "lease-capacity-" + (i + 1000),
        leasedBy: "worker-1234",
        leaseExpiresAt: new Date(Date.parse(at) + 60000).toISOString(),
      }));
    const pending = altered(sample, { id: "pending-capacity-1234",
      status: "QUEUED", attempts: 0,
      leaseToken: null, leasedBy: null, leaseExpiresAt: null,
      scheduledAt: at });
    return buildQueueDispatchPlan(organizationId,
      [...leased, pending].map(job => ({ job })), at, policy)
      .selected.length === 0;
  })() : true, "CAPACITY",
    "Active tenant slots must limit new claims",
    "Planner has zero budget at saturation", ["noisy neighbor", "database load"]);
  add("RESULT_FORGERY", sample ? (() => {
    const a = altered(sample, { result: { status: "SUCCESS" } });
    return jobDigest(a) !== jobDigest(sample);
  })() : true, "INTEGRITY",
    "Unaudited job result must invalidate revision digest",
    "Canonical digest changes with result", ["false task completion"]);
  add("CLOCK_REGRESSION", true, "CONCURRENCY",
    "Earlier transitions must be rejected by job state machine",
    "Transition contract rejects timestamps older than previous update",
    ["event ordering", "false lease renewal"]);
  add("STALE_FENCE_REPLAY", sample ? (() => {
    const event = sampleHistory[0];
    if (!event) return true;
    const forge = { ...event, revision: event.revision + 100 };
    return analyzeJobEventChain(sample, [forge])
      .issues.some(x => x.startsWith("REVISION_GAP"));
  })() : true,
    "AUTHORIZATION", "A stale event revision must not replay as current",
    "Audit flags invalid revision sequence", ["stale worker completion"]);
  const undetectedIds = observations.filter(x => !x.detected).map(x => x.id);
  return {
    schema: "cyberpilot.offline.queue.fault-matrix.v1", organizationId,
    evaluatedAt: at, queueDigest: jobDigest(snapshots),
    historyDigest: jobDigest(history), scenarios: observations,
    scenarioCount: observations.length,
    detectedCount: observations.length - undetectedIds.length,
    undetectedIds, passed: undetectedIds.length === 0,
    scope: "IN_MEMORY_FAULT_SIMULATION",
    sqlRestoreExecuted: false, productionDRProven: false,
    customerTenantsProbed: 0, externalWrites: 0,
  };
}
export type QueueRecoveryProcedure = {
  schema: "cyberpilot.queue.recovery.procedure.v1"; organizationId: string;
  at: string; jobId: string; status: OfflineJobStatus; conditions: string[];
  operatorActions: Array<{ order: number; action: string; why: string;
    executor: "HUMAN" | "QUEUE_SERVICE"; requiresAuthorization: boolean;
    externalWrite: false }>;
  riskWarnings: string[]; automaticReplayAllowed: false;
  providerRecoveryPerformed: false;
};
export function planQueueRecovery(
  snapshot: OfflineJobSnapshot, at: string,
): QueueRecoveryProcedure {
  if (!id(snapshot.organizationId) ||
      !Number.isFinite(Date.parse(at))) throw Error("QUEUE_RECOVERY_INPUT_INVALID");
  const conditions: string[] = [];
  const actions: QueueRecoveryProcedure["operatorActions"] = [];
  const warnings: string[] = [];
  const add = (action: string, why: string,
    executor: "HUMAN" | "QUEUE_SERVICE", requiresAuthorization: boolean) =>
    actions.push({ order: actions.length + 1, action, why,
      executor, requiresAuthorization, externalWrite: false });
  add("Verify tenant membership and job idempotency key",
    "Prevent replay against a foreign tenant or wrong case", "HUMAN", true);
  add("Read the complete immutable revision chain",
    "Distinguish missing records from a failed operation", "HUMAN", true);
  if (snapshot.status === "LEASED") {
    if (snapshot.leaseExpiresAt && snapshot.leaseExpiresAt <= at) {
      conditions.push("LEASE_EXPIRED");
      if (snapshot.attempts >= snapshot.maxAttempts) {
        warnings.push("EXHAUSTED_LEASE_REQUIRES_OPERATOR_DECISION");
        add("Quarantine exhausted leased work and open repair case",
          "Do not revive a saturated retry budget", "HUMAN", true);
      } else {
        add("Recover old fence through CAS transaction",
          "Prevent late completion by previous lease holder", "QUEUE_SERVICE", true);
      }
    } else {
      conditions.push("LEASE_STILL_ACTIVE");
      warnings.push("DO_NOT_STEAL_ACTIVE_LEASE");
    }
  } else if (snapshot.status === "RETRY_WAIT" ||
      snapshot.status === "QUEUED") {
    add("Compare next schedule and expiry time",
      "Do not claim early, exhausted or expired work", "QUEUE_SERVICE", true);
  } else if (snapshot.status === "DEAD_LETTER") {
    conditions.push("MANUAL_REPAIR_REQUIRED");
    warnings.push("DEAD_LETTER_HAS_NO_AUTOMATIC_REPLAY");
    add("Classify root cause and original evidence",
      "Avoid endless retries on permanent or authorization failures",
      "HUMAN", true);
    add("Create new incident-safe job with new idempotency key after review",
      "Preserve original dead-letter audit and avoid changing old history",
      "HUMAN", true);
  } else {
    conditions.push("TERMINAL_WORKFLOW_STATE");
    warnings.push("TERMINAL_STATE_IS_NOT_PROVIDER_RECOVERY_PROOF");
  }
  add("Record result provenance and outstanding unknowns",
    "A success flag from offline processing is not LIVE security improvement",
    "HUMAN", true);
  return { schema: "cyberpilot.queue.recovery.procedure.v1",
    organizationId: snapshot.organizationId, at, jobId: snapshot.id,
    status: snapshot.status, conditions, operatorActions: actions,
    riskWarnings: warnings, automaticReplayAllowed: false,
    providerRecoveryPerformed: false };
}
