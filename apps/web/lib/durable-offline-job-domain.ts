import { createHash } from "node:crypto";

export const OFFLINE_JOB_TYPES = ["CAPTURE_TIMELINE_AUDIT", "RECOVERY_FAULT_MATRIX",
  "INCIDENT_ESCALATION_REVIEW"] as const;
export type OfflineJobType = typeof OFFLINE_JOB_TYPES[number];
export type OfflineJobStatus = "QUEUED" | "LEASED" | "SUCCEEDED" | "RETRY_WAIT" |
  "DEAD_LETTER" | "CANCELLED";
export type OfflineJobFailureClass = "TRANSIENT" | "PERMANENT" | "AUTHORIZATION" |
  "DATA_INTEGRITY" | "TIMEOUT" | "UNCLASSIFIED";
export type OfflineJobPolicy = {
  maxAttempts: number; leaseSeconds: number; baseBackoffSeconds: number;
  maxBackoffSeconds: number; maxAgeHours: number; maxPayloadBytes: number;
  maxResultBytes: number; concurrencyPerTenant: number;
};
export type OfflineJobRequest = {
  organizationId: string; type: OfflineJobType; idempotencyKey: string;
  payload: Record<string, unknown>; requestedById: string;
  scheduledAt: string; expiresAt: string;
};
export type OfflineJobSnapshot = {
  id: string; organizationId: string; type: OfflineJobType;
  status: OfflineJobStatus; requestDigest: string; idempotencyKey: string;
  payload: Record<string, unknown>; requestedById: string;
  revision: number; attempts: number; maxAttempts: number;
  scheduledAt: string; expiresAt: string; createdAt: string; updatedAt: string;
  leaseToken: string | null; leasedBy: string | null; leaseExpiresAt: string | null;
  completedAt: string | null; resultDigest: string | null;
  result: Record<string, unknown> | null; lastFailure: string | null;
  failureClass: OfflineJobFailureClass | null; providerWrites: 0;
};
export type JobEvent = {
  organizationId: string; jobId: string; revision: number;
  kind: "ADMITTED" | "CLAIMED" | "HEARTBEAT" | "SUCCEEDED" |
    "RETRY_SCHEDULED" | "DEAD_LETTERED" | "CANCELLED" | "REQUEUED";
  previous: OfflineJobStatus; next: OfflineJobStatus;
  occurredAt: string; actorId: string; digest: string; attempts: number;
  providerOperations: 0;
};
export type JobCommand = { kind: JobEvent["kind"]; organizationId: string;
  jobId: string; expectedRevision: number; actorId: string; at: string;
  leaseToken?: string; leaseSeconds?: number;
  result?: Record<string, unknown>; failureCode?: string;
  failureClass?: OfflineJobFailureClass; policy?: OfflineJobPolicy;
};
export const DEFAULT_OFFLINE_JOB_POLICY: OfflineJobPolicy = Object.freeze({
  maxAttempts: 4, leaseSeconds: 90, baseBackoffSeconds: 15,
  maxBackoffSeconds: 900, maxAgeHours: 72, maxPayloadBytes: 8192,
  maxResultBytes: 131072, concurrencyPerTenant: 2,
});
const identifier = (v: unknown): v is string =>
  typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const iso = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v)) &&
  new Date(v).toISOString() === v;
function canonical(v: unknown): string {
  if (v === null || typeof v === "string" || typeof v === "boolean" ||
      typeof v === "number") {
    if (typeof v === "number" && !Number.isFinite(v)) throw Error("JOB_NONFINITE");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.entries(v)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([k, value]) => JSON.stringify(k) + ":" + canonical(value)).join(",") + "}";
  throw Error("JOB_JSON_UNSUPPORTED");
}
export const jobDigest = (value: unknown): string =>
  createHash("sha256").update(canonical(value)).digest("hex");
export function validateJobPolicy(policy: OfflineJobPolicy): string[] {
  const errors: string[] = [];
  if (!Number.isSafeInteger(policy.maxAttempts) || policy.maxAttempts < 1 ||
      policy.maxAttempts > 12) errors.push("JOB_POLICY_MAX_ATTEMPTS_INVALID");
  if (!Number.isSafeInteger(policy.leaseSeconds) || policy.leaseSeconds < 10 ||
      policy.leaseSeconds > 3600) errors.push("JOB_POLICY_LEASE_INVALID");
  if (!Number.isSafeInteger(policy.baseBackoffSeconds) ||
      policy.baseBackoffSeconds < 1 || policy.baseBackoffSeconds > 3600 ||
      !Number.isSafeInteger(policy.maxBackoffSeconds) ||
      policy.maxBackoffSeconds < policy.baseBackoffSeconds ||
      policy.maxBackoffSeconds > 86400)
    errors.push("JOB_POLICY_BACKOFF_INVALID");
  if (!Number.isSafeInteger(policy.maxAgeHours) || policy.maxAgeHours < 1 ||
      policy.maxAgeHours > 720) errors.push("JOB_POLICY_AGE_INVALID");
  if (!Number.isSafeInteger(policy.maxPayloadBytes) ||
      policy.maxPayloadBytes < 256 || policy.maxPayloadBytes > 32768 ||
      !Number.isSafeInteger(policy.maxResultBytes) ||
      policy.maxResultBytes < 1024 || policy.maxResultBytes > 1048576)
    errors.push("JOB_POLICY_SIZE_INVALID");
  if (!Number.isSafeInteger(policy.concurrencyPerTenant) ||
      policy.concurrencyPerTenant < 1 || policy.concurrencyPerTenant > 20)
    errors.push("JOB_POLICY_CONCURRENCY_INVALID");
  return errors;
}
export function validateJobRequest(request: OfflineJobRequest,
  policy: OfflineJobPolicy = DEFAULT_OFFLINE_JOB_POLICY): string[] {
  const errors = validateJobPolicy(policy);
  if (!identifier(request.organizationId) || !identifier(request.requestedById) ||
      !OFFLINE_JOB_TYPES.includes(request.type) ||
      typeof request.idempotencyKey !== "string" ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}$/.test(request.idempotencyKey))
    errors.push("JOB_ADMISSION_IDENTITY_INVALID");
  if (!iso(request.scheduledAt) || !iso(request.expiresAt) ||
      request.expiresAt <= request.scheduledAt ||
      Date.parse(request.expiresAt) - Date.parse(request.scheduledAt) >
        policy.maxAgeHours * 3600000)
    errors.push("JOB_ADMISSION_SCHEDULE_INVALID");
  if (!request.payload || Array.isArray(request.payload) ||
      typeof request.payload !== "object")
    errors.push("JOB_PAYLOAD_INVALID");
  else {
    try {
      if (Buffer.byteLength(canonical(request.payload)) > policy.maxPayloadBytes)
        errors.push("JOB_PAYLOAD_TOO_LARGE");
    } catch { errors.push("JOB_PAYLOAD_NOT_CANONICAL"); }
  }
  return errors;
}
export function admittedJob(input: OfflineJobRequest, id: string, at: string,
  policy: OfflineJobPolicy = DEFAULT_OFFLINE_JOB_POLICY): OfflineJobSnapshot {
  const errors = validateJobRequest(input, policy);
  if (errors.length || !identifier(id) || !iso(at))
    throw Error("JOB_ADMISSION_INVALID:" + errors.join(","));
  return { id, organizationId: input.organizationId, type: input.type,
    status: "QUEUED", requestDigest: jobDigest({
      type: input.type, payload: input.payload,
    }), idempotencyKey: input.idempotencyKey,
    payload: input.payload, requestedById: input.requestedById,
    revision: 1, attempts: 0, maxAttempts: policy.maxAttempts,
    scheduledAt: input.scheduledAt, expiresAt: input.expiresAt,
    createdAt: at, updatedAt: at,
    leaseToken: null, leasedBy: null, leaseExpiresAt: null,
    completedAt: null, resultDigest: null, result: null,
    lastFailure: null, failureClass: null, providerWrites: 0 };
}
export function validateJobSnapshot(s: OfflineJobSnapshot): string[] {
  const issues: string[] = [];
  if (!identifier(s.id) || !identifier(s.organizationId) ||
      !identifier(s.requestedById) || !OFFLINE_JOB_TYPES.includes(s.type) ||
      !/^[a-f0-9]{64}$/.test(s.requestDigest) ||
      s.requestDigest !== jobDigest({ type: s.type, payload: s.payload }))
    issues.push("JOB_SCOPE_OR_REQUEST_CORRUPT");
  if (!["QUEUED", "LEASED", "SUCCEEDED", "RETRY_WAIT",
    "DEAD_LETTER", "CANCELLED"].includes(s.status) ||
    !Number.isSafeInteger(s.revision) || s.revision < 1 ||
    !Number.isSafeInteger(s.attempts) || s.attempts < 0 ||
    !Number.isSafeInteger(s.maxAttempts) || s.maxAttempts < 1 ||
    s.attempts > s.maxAttempts)
    issues.push("JOB_STATE_CORRUPT");
  if (!iso(s.createdAt) || !iso(s.updatedAt) || !iso(s.scheduledAt) ||
      !iso(s.expiresAt) || s.createdAt > s.updatedAt ||
      s.scheduledAt >= s.expiresAt || s.providerWrites !== 0)
    issues.push("JOB_TIMELINE_INVALID");
  if (s.status === "LEASED" &&
      (!identifier(s.leasedBy) || !identifier(s.leaseToken) ||
       !iso(s.leaseExpiresAt)) ||
      s.status !== "LEASED" &&
      (s.leaseToken !== null || s.leaseExpiresAt !== null || s.leasedBy !== null))
    issues.push("JOB_LEASE_STATE_INCONSISTENT");
  if (s.status === "SUCCEEDED" &&
      (!iso(s.completedAt) || !s.result ||
       s.resultDigest !== jobDigest(s.result)) ||
      s.status !== "SUCCEEDED" &&
      (s.completedAt !== null || s.result !== null || s.resultDigest !== null))
    issues.push("JOB_RESULT_STATE_INCONSISTENT");
  return [...new Set(issues)];
}
export function nextBackoffSeconds(attempts: number,
  policy = DEFAULT_OFFLINE_JOB_POLICY): number {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 100 ||
      validateJobPolicy(policy).length) throw Error("JOB_BACKOFF_INVALID");
  return Math.min(policy.maxBackoffSeconds,
    policy.baseBackoffSeconds * 2 ** Math.min(attempts - 1, 20));
}
export type JobCommandResult = { accepted: boolean; code: string;
  previous: OfflineJobSnapshot; next: OfflineJobSnapshot | null;
  event: JobEvent | null; providerWrites: 0 };
function rejected(s: OfflineJobSnapshot, code: string): JobCommandResult {
  return { accepted: false, code, previous: s, next: null,
    event: null, providerWrites: 0 };
}
export function applyJobCommand(s: OfflineJobSnapshot, c: JobCommand): JobCommandResult {
  if (validateJobSnapshot(s).length) return rejected(s, "JOB_PREVIOUS_CORRUPT");
  if (c.organizationId !== s.organizationId || c.jobId !== s.id ||
      !identifier(c.actorId)) return rejected(s, "JOB_SCOPE_INVALID");
  if (c.expectedRevision !== s.revision) return rejected(s, "JOB_REVISION_CONFLICT");
  if (!iso(c.at) || c.at < s.updatedAt) return rejected(s, "JOB_TIME_INVALID");
  if (c.kind === "ADMITTED") return rejected(s, "JOB_ALREADY_ADMITTED");
  const n: OfflineJobSnapshot = structuredClone(s);
  const leaseValid = s.status === "LEASED" && c.leaseToken === s.leaseToken &&
    s.leaseExpiresAt !== null && c.at < s.leaseExpiresAt;
  if (c.kind === "CLAIMED") {
    if (!["QUEUED", "RETRY_WAIT"].includes(s.status) ||
        s.scheduledAt > c.at || c.at >= s.expiresAt ||
        !identifier(c.leaseToken) || !Number.isSafeInteger(c.leaseSeconds) ||
        c.leaseSeconds! < 10 || c.leaseSeconds! > 3600)
      return rejected(s, "JOB_NOT_CLAIMABLE");
    n.status = "LEASED"; n.attempts++;
    n.leasedBy = c.actorId; n.leaseToken = c.leaseToken!;
    n.leaseExpiresAt = new Date(Date.parse(c.at) +
      c.leaseSeconds! * 1000).toISOString();
  } else if (c.kind === "HEARTBEAT") {
    if (!leaseValid || s.leasedBy !== c.actorId ||
        !Number.isSafeInteger(c.leaseSeconds) ||
        c.leaseSeconds! < 10 || c.leaseSeconds! > 3600)
      return rejected(s, "JOB_LEASE_FENCE_REJECTED");
    n.leaseExpiresAt = new Date(Date.parse(c.at) + c.leaseSeconds! * 1000)
      .toISOString();
  } else if (c.kind === "SUCCEEDED") {
    if (!leaseValid || s.leasedBy !== c.actorId || !c.result ||
        Array.isArray(c.result) || typeof c.result !== "object")
      return rejected(s, "JOB_RESULT_LEASE_REJECTED");
    const policy = c.policy ?? DEFAULT_OFFLINE_JOB_POLICY;
    if (validateJobPolicy(policy).length ||
        Buffer.byteLength(canonical(c.result)) > policy.maxResultBytes)
      return rejected(s, "JOB_RESULT_LIMIT_EXCEEDED");
    n.status = "SUCCEEDED"; n.result = c.result;
    n.resultDigest = jobDigest(c.result); n.completedAt = c.at;
    n.leaseToken = null; n.leasedBy = null; n.leaseExpiresAt = null;
    n.lastFailure = null; n.failureClass = null;
  } else if (c.kind === "RETRY_SCHEDULED" || c.kind === "DEAD_LETTERED") {
    if (s.status !== "LEASED" || s.leaseToken !== c.leaseToken ||
        !identifier(c.failureCode) || !c.failureClass)
      return rejected(s, "JOB_FAILURE_LEASE_REJECTED");
    const policy = c.policy ?? DEFAULT_OFFLINE_JOB_POLICY;
    if (validateJobPolicy(policy).length) return rejected(s, "JOB_POLICY_INVALID");
    const exhausted = s.attempts >= s.maxAttempts ||
      c.failureClass === "PERMANENT" || c.failureClass === "AUTHORIZATION" ||
      c.failureClass === "DATA_INTEGRITY" || c.at >= s.expiresAt;
    if (c.kind === "RETRY_SCHEDULED" && exhausted ||
        c.kind === "DEAD_LETTERED" && !exhausted)
      return rejected(s, "JOB_RETRY_CLASSIFICATION_INVALID");
    n.status = exhausted ? "DEAD_LETTER" : "RETRY_WAIT";
    n.lastFailure = c.failureCode; n.failureClass = c.failureClass;
    n.leaseToken = null; n.leasedBy = null; n.leaseExpiresAt = null;
    if (!exhausted)
      n.scheduledAt = new Date(Date.parse(c.at) +
        nextBackoffSeconds(s.attempts, policy) * 1000).toISOString();
  } else if (c.kind === "REQUEUED") {
    if (s.status !== "LEASED" || !s.leaseExpiresAt ||
        c.at < s.leaseExpiresAt || s.attempts >= s.maxAttempts ||
        c.at >= s.expiresAt)
      return rejected(s, "JOB_NOT_STALE_OR_EXHAUSTED");
    n.status = "RETRY_WAIT"; n.leaseToken = null;
    n.leasedBy = null; n.leaseExpiresAt = null;
    n.scheduledAt = c.at; n.lastFailure = "LEASE_EXPIRED";
    n.failureClass = "TIMEOUT";
  } else if (c.kind === "CANCELLED") {
    if (!["QUEUED", "RETRY_WAIT"].includes(s.status))
      return rejected(s, "JOB_CANNOT_CANCEL");
    n.status = "CANCELLED";
  } else return rejected(s, "JOB_COMMAND_UNKNOWN");
  n.revision++; n.updatedAt = c.at;
  const issues = validateJobSnapshot(n);
  if (issues.length) return rejected(s, issues[0]!);
  const event: JobEvent = { organizationId: s.organizationId, jobId: s.id,
    revision: n.revision, kind: c.kind, previous: s.status, next: n.status,
    occurredAt: c.at, actorId: c.actorId, digest: jobDigest(n),
    attempts: n.attempts, providerOperations: 0 };
  return { accepted: true, code: "ACCEPTED", previous: s,
    next: n, event, providerWrites: 0 };
}
export function admissionEvent(s: OfflineJobSnapshot): JobEvent {
  if (s.revision !== 1 || s.status !== "QUEUED" || validateJobSnapshot(s).length)
    throw Error("JOB_ADMISSION_EVENT_INVALID");
  return { organizationId: s.organizationId, jobId: s.id, revision: 1,
    kind: "ADMITTED", previous: "QUEUED", next: "QUEUED",
    occurredAt: s.createdAt, actorId: s.requestedById,
    digest: jobDigest(s), attempts: 0, providerOperations: 0 };
}
export function auditJob(s: OfflineJobSnapshot, history: JobEvent[], truncated = false) {
  const errors = validateJobSnapshot(s);
  const sorted = [...history].sort((a, b) => a.revision - b.revision);
  if (truncated || sorted.length !== s.revision ||
      sorted.some((event, index) =>
        event.organizationId !== s.organizationId || event.jobId !== s.id ||
        event.revision !== index + 1 || event.providerOperations !== 0 ||
        index > 0 && event.previous !== sorted[index - 1]!.next))
    errors.push("JOB_AUDIT_CHAIN_INCOMPLETE");
  if (sorted.at(-1)?.digest !== jobDigest(s) ||
      sorted.at(-1)?.next !== s.status)
    errors.push("JOB_AUDIT_DIGEST_MISMATCH");
  return { valid: errors.length === 0, issues: [...new Set(errors)],
    observedEvents: history.length, latestRevision: sorted.at(-1)?.revision ?? 0,
    providerChangesVerified: false as const };
}
