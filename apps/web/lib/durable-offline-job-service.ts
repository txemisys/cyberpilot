import { randomUUID } from "node:crypto";
import { evaluateClaimedIncidentEscalationJob } from "./incident-escalation-job-handler";
import { buildQueueDispatchPlan, reviewDeadLetters, analyzeJobEventChain } from "./offline-job-dispatch-assurance";
import { evaluateQueueFaultScenarios } from "./offline-job-recovery-fault-matrix";
import { buildQueueAssuranceReport, exportQueueAssuranceReport } from "./offline-job-assurance-report";
import { evaluateOfflineQueueHealth, exportOfflineQueueHealth, inspectJobReplay } from "./durable-offline-job-operations";
import { db, type Prisma } from "@cyberpilot/database";
import type { IntegratedReviewer } from "./integrated-risk-service";
import { auditPersistedCaptureHistory } from "./offline-capture-timeline-service";
import { readRecoveryFaultMatrix } from "./offline-recovery-fault-service";
import { admittedJob, admissionEvent, jobDigest, applyJobCommand,
  auditJob, validateJobSnapshot, DEFAULT_OFFLINE_JOB_POLICY,
  OFFLINE_JOB_TYPES, type OfflineJobRequest, type OfflineJobSnapshot,
  type OfflineJobType, type JobCommand, type JobEvent, type OfflineJobFailureClass }
  from "./durable-offline-job-domain";

export class DurableJobError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new DurableJobError(code); }
const ident = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
type Row = NonNullable<Awaited<ReturnType<typeof db.durableOfflineJob.findFirst>>>;
type EventRow = Awaited<ReturnType<typeof db.durableOfflineJobEvent.findMany>>[number];
function fromRow(row: Row): OfflineJobSnapshot {
  const snapshot = row.snapshot as unknown as OfflineJobSnapshot;
  if (!snapshot || typeof snapshot !== "object" ||
      validateJobSnapshot(snapshot).length ||
      snapshot.id !== row.id || snapshot.organizationId !== row.organizationId ||
      snapshot.revision !== row.revision || snapshot.type !== row.type ||
      snapshot.status !== row.status || snapshot.requestDigest !== row.requestDigest ||
      snapshot.attempts !== row.attempts ||
      snapshot.scheduledAt !== row.scheduledAt.toISOString() ||
      snapshot.leaseExpiresAt !== row.leaseExpiresAt?.toISOString() &&
        !(snapshot.leaseExpiresAt === null && row.leaseExpiresAt === null))
    fail("JOB_PERSISTENCE_INTEGRITY_INVALID");
  return snapshot;
}
function fromEvent(row: EventRow): JobEvent {
  return { organizationId: row.organizationId, jobId: row.jobId,
    revision: row.revision, kind: row.kind as JobEvent["kind"],
    actorId: row.actorId, previous: row.previousState as JobEvent["previous"],
    next: row.nextState as JobEvent["next"],
    occurredAt: row.occurredAt.toISOString(), digest: row.snapshotDigest,
    attempts: row.attempts, providerOperations: 0 };
}
async function authorize(actor: IntegratedReviewer, write: boolean) {
  if (!ident(actor.organizationId) || !ident(actor.userId))
    fail("JOB_ACTOR_INVALID");
  if (!["OWNER", "ADMIN", "AUDITOR"].includes(actor.role) ||
      write && !["OWNER", "ADMIN"].includes(actor.role))
    fail("JOB_ROLE_DENIED");
  const membership = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("JOB_CURRENT_MEMBERSHIP_REQUIRED");
}
function serializable<T>(action: (tx: Prisma.TransactionClient) => Promise<T>) {
  return db.$transaction(action, { isolationLevel: "Serializable" });
}
function snapshotColumns(s: OfflineJobSnapshot) {
  return {
    status: s.status, revision: s.revision, attempts: s.attempts,
    scheduledAt: new Date(s.scheduledAt),
    leaseExpiresAt: s.leaseExpiresAt ? new Date(s.leaseExpiresAt) : null,
    leaseToken: s.leaseToken, leasedBy: s.leasedBy,
    resultDigest: s.resultDigest, lastFailure: s.lastFailure,
    failureClass: s.failureClass, updatedAt: new Date(s.updatedAt),
    snapshot: s as unknown as Prisma.InputJsonValue,
  };
}
async function makeEvent(tx: Prisma.TransactionClient, e: JobEvent) {
  await tx.durableOfflineJobEvent.create({ data: {
    organizationId: e.organizationId, jobId: e.jobId, revision: e.revision,
    kind: e.kind, actorId: e.actorId, previousState: e.previous,
    nextState: e.next, occurredAt: new Date(e.occurredAt),
    snapshotDigest: e.digest, attempts: e.attempts,
  } });
}
export async function enqueueOfflineJob(actor: IntegratedReviewer, input: {
  type: OfflineJobType; idempotencyKey: string;
  payload: Record<string, unknown>; delaySeconds?: number;
}) {
  await authorize(actor, true);
  if (!OFFLINE_JOB_TYPES.includes(input.type) ||
      !Number.isSafeInteger(input.delaySeconds ?? 0) ||
      (input.delaySeconds ?? 0) < 0 || (input.delaySeconds ?? 0) > 86400)
    fail("JOB_ADMISSION_INPUT_INVALID");
  const now = new Date(), delay = input.delaySeconds ?? 0;
  const request: OfflineJobRequest = {
    organizationId: actor.organizationId, requestedById: actor.userId,
    type: input.type, idempotencyKey: input.idempotencyKey,
    payload: input.payload,
    scheduledAt: new Date(now.getTime() + delay * 1000).toISOString(),
    expiresAt: new Date(now.getTime() + delay * 1000 +
      DEFAULT_OFFLINE_JOB_POLICY.maxAgeHours * 3600000).toISOString(),
  };
  const requestDigest = jobDigest({ type: input.type, payload: input.payload });
  const existing = await db.durableOfflineJob.findUnique({
    where: { organizationId_idempotencyKey: {
      organizationId: actor.organizationId, idempotencyKey: input.idempotencyKey,
    } },
  });
  if (existing) {
    const s = fromRow(existing);
    if (s.requestDigest !== requestDigest)
      fail("JOB_IDEMPOTENCY_PAYLOAD_CONFLICT");
    return { created: false, job: s, providerWrites: 0 as const };
  }
  try {
    const created = await serializable(async tx => {
      const row = await tx.durableOfflineJob.create({ data: {
        organizationId: actor.organizationId, type: input.type,
        status: "QUEUED", idempotencyKey: input.idempotencyKey,
        requestDigest, revision: 1, attempts: 0,
        maxAttempts: DEFAULT_OFFLINE_JOB_POLICY.maxAttempts,
        scheduledAt: new Date(request.scheduledAt),
        expiresAt: new Date(request.expiresAt), snapshot: {},
        createdAt: now, updatedAt: now,
      }, select: { id: true } });
      const snapshot = admittedJob(request, row.id, now.toISOString());
      const event = admissionEvent(snapshot);
      await tx.durableOfflineJob.update({ where: { id: row.id },
        data: snapshotColumns(snapshot) });
      await makeEvent(tx, event);
      return snapshot;
    });
    return { created: true, job: created, providerWrites: 0 as const };
  } catch (error) {
    if (error && typeof error === "object" && "code" in error &&
        error.code === "P2002") {
      const row = await db.durableOfflineJob.findUnique({
        where: { organizationId_idempotencyKey: {
          organizationId: actor.organizationId,
          idempotencyKey: input.idempotencyKey,
        } },
      });
      if (row) {
        const snapshot = fromRow(row);
        if (snapshot.requestDigest !== requestDigest)
          fail("JOB_IDEMPOTENCY_PAYLOAD_CONFLICT");
        return { created: false, job: snapshot, providerWrites: 0 as const };
      }
    }
    throw error;
  }
}
async function transition(actor: IntegratedReviewer, input: {
  jobId: string; kind: JobEvent["kind"]; expectedRevision: number;
  leaseToken?: string; result?: Record<string, unknown>;
  failureCode?: string; failureClass?: OfflineJobFailureClass;
  leaseSeconds?: number;
}) {
  await authorize(actor, true);
  if (!ident(input.jobId) || !Number.isSafeInteger(input.expectedRevision))
    fail("JOB_COMMAND_INVALID");
  const row = await db.durableOfflineJob.findFirst({
    where: { organizationId: actor.organizationId, id: input.jobId },
  });
  if (!row) fail("JOB_NOT_IN_TENANT");
  const previous = fromRow(row);
  const command: JobCommand = {
    organizationId: actor.organizationId, jobId: row.id,
    expectedRevision: input.expectedRevision, kind: input.kind,
    actorId: actor.userId, at: new Date().toISOString(),
    ...(input.leaseToken !== undefined ? { leaseToken: input.leaseToken } : {}),
    ...(input.leaseSeconds !== undefined ? { leaseSeconds: input.leaseSeconds } : {}),
    ...(input.result !== undefined ? { result: input.result } : {}),
    ...(input.failureCode !== undefined ? { failureCode: input.failureCode } : {}),
    ...(input.failureClass !== undefined ? { failureClass: input.failureClass } : {}),
  };
  const outcome = applyJobCommand(previous, command);
  if (!outcome.accepted || !outcome.next || !outcome.event) fail(outcome.code);
  const next = outcome.next, event = outcome.event;
  await serializable(async tx => {
    const modified = await tx.durableOfflineJob.updateMany({ where: {
      id: row.id, organizationId: actor.organizationId,
      revision: previous.revision, status: previous.status,
      leaseToken: previous.leaseToken,
    }, data: snapshotColumns(next) });
    if (modified.count !== 1) fail("JOB_CONCURRENT_REVISION_CONFLICT");
    await makeEvent(tx, event);
  });
  return { job: next, event, providerWrites: 0 as const };
}
/**
 * Serialize claim admission per organization, rather than checking the active
 * count outside the claim transaction (which permitted a concurrent overshoot).
 * The organization row is the narrow transaction-wide lock shared by all claims
 * for a tenant. CAS still protects the individual job and its immutable audit.
 */
export async function claimOfflineJob(actor: IntegratedReviewer, id: string,
  expectedRevision: number) {
  await authorize(actor, true);
  if (!ident(id) || !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 1) fail("JOB_CLAIM_ARGUMENT_INVALID");
  return serializable(async tx => {
    const locked = await tx.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "Organization"
      WHERE "id" = ${actor.organizationId}
      FOR UPDATE
    `;
    if (locked.length !== 1) fail("JOB_CLAIM_TENANT_GONE");
    // Reconfirm membership while holding the tenant lock; the session
    // alone is never authority for dispatching a persisted job.
    const membership = await tx.membership.findFirst({
      where: { organizationId: actor.organizationId,
        userId: actor.userId },
      select: { role: true },
    });
    if (!membership || membership.role !== actor.role ||
        !["OWNER", "ADMIN"].includes(membership.role))
      fail("JOB_CLAIM_MEMBERSHIP_REVOKED");
    const at = new Date();
    const active = await tx.durableOfflineJob.count({
      where: { organizationId: actor.organizationId, status: "LEASED",
        leaseExpiresAt: { gt: at } },
    });
    if (active >= DEFAULT_OFFLINE_JOB_POLICY.concurrencyPerTenant)
      fail("JOB_TENANT_CONCURRENCY_REACHED");
    const row = await tx.durableOfflineJob.findFirst({
      where: { id, organizationId: actor.organizationId },
    });
    if (!row) fail("JOB_NOT_IN_TENANT");
    const snapshot = fromRow(row);
    const token = randomUUID();
    const outcome = applyJobCommand(snapshot, {
      organizationId: actor.organizationId, jobId: id,
      kind: "CLAIMED", actorId: actor.userId, at: at.toISOString(),
      expectedRevision, leaseToken: token,
      leaseSeconds: DEFAULT_OFFLINE_JOB_POLICY.leaseSeconds,
    });
    if (!outcome.accepted || !outcome.next || !outcome.event)
      fail(outcome.code);
    const modified = await tx.durableOfflineJob.updateMany({
      where: { id, organizationId: actor.organizationId,
        revision: snapshot.revision, status: snapshot.status,
        leaseToken: snapshot.leaseToken },
      data: snapshotColumns(outcome.next),
    });
    if (modified.count !== 1) fail("JOB_CONCURRENT_REVISION_CONFLICT");
    await makeEvent(tx, outcome.event);
    return { job: outcome.next, event: outcome.event, providerWrites: 0 as const };
  });
}
export async function heartbeatOfflineJob(actor: IntegratedReviewer,
  id: string, revision: number, leaseToken: string) {
  return transition(actor, { jobId: id, expectedRevision: revision,
    kind: "HEARTBEAT", leaseToken,
    leaseSeconds: DEFAULT_OFFLINE_JOB_POLICY.leaseSeconds });
}
export async function cancelOfflineJob(actor: IntegratedReviewer, id: string,
  expectedRevision: number) {
  return transition(actor, { jobId: id, expectedRevision, kind: "CANCELLED" });
}
export async function recoverExpiredOfflineJob(actor: IntegratedReviewer,
  id: string, expectedRevision: number) {
  return transition(actor, { jobId: id, expectedRevision, kind: "REQUEUED" });
}
export async function executeClaimedOfflineJob(actor: IntegratedReviewer,
  id: string, revision: number, leaseToken: string) {
  await authorize(actor, true);
  const row = await db.durableOfflineJob.findFirst({
    where: { id, organizationId: actor.organizationId, status: "LEASED" },
  });
  if (!row) fail("JOB_NOT_LEASED_IN_TENANT");
  const snapshot = fromRow(row);
  if (snapshot.revision !== revision || snapshot.leasedBy !== actor.userId ||
      snapshot.leaseToken !== leaseToken ||
      !snapshot.leaseExpiresAt || snapshot.leaseExpiresAt <= new Date().toISOString())
    fail("JOB_EXECUTOR_LEASE_FENCE_REJECTED");
  // The worker only examines already persisted local rows; it neither syncs
  // Microsoft Graph nor changes a customer's controls.
  let output: Record<string, unknown>;
  try {
    if (snapshot.type === "CAPTURE_TIMELINE_AUDIT") {
      const report = await auditPersistedCaptureHistory(actor, {
        limit: 100, offset: 0,
      });
      output = {
        schema: report.schema, auditAt: report.evaluatedAt,
        manifestDigest: report.manifestDigest,
        sourceGapCount: report.sourceGaps.length,
        schemaDriftCount: report.schemaDrift.length,
        sourceDriftCount: report.sourceDrift.length,
        duplicateCount: report.duplicateSourceIds.length,
        incompleteCount: report.incompleteIds.length,
        integrityFailureCount: report.integrityFailures.length,
        truncated: report.truncated,
        acceptedForProduction: false,
      };
    } else if (snapshot.type === "RECOVERY_FAULT_MATRIX") {
      const report = await readRecoveryFaultMatrix(actor, { latestPerKind: true });
      output = {
        schema: report.schema, captureCount: report.selectedCaptureCount,
        faultCount: report.faultCount,
        detectedFaultCount: report.faultDetectionCount,
        matrixDigest: jobDigest(report.matrix), acceptance: report.acceptance,
        sqlRestoreOperations: 0, productionRecoveryEstablished: false,
      };
    } else if (snapshot.type === "INCIDENT_ESCALATION_REVIEW") {
      output = await evaluateClaimedIncidentEscalationJob(actor,
        snapshot.payload);
    } else fail("JOB_HANDLER_NOT_RECOGNIZED");
  } catch (error) {
    const failureCode =
      error instanceof DurableJobError ? error.code : "OFFLINE_HANDLER_FAILED";
    const failureClass: OfflineJobFailureClass =
      failureCode === "JOB_HANDLER_NOT_RECOGNIZED" ? "PERMANENT" : "TRANSIENT";
    const kind = snapshot.attempts >= snapshot.maxAttempts ||
      failureClass === "PERMANENT" ? "DEAD_LETTERED" : "RETRY_SCHEDULED";
    return transition(actor, { jobId: id, expectedRevision: revision,
      leaseToken, kind, failureCode, failureClass });
  }
  return transition(actor, { jobId: id, expectedRevision: revision,
    leaseToken, kind: "SUCCEEDED", result: output });
}
export async function readOfflineJobs(actor: IntegratedReviewer, request: {
  offset?: number; limit?: number; status?: string; type?: OfflineJobType;
} = {}) {
  await authorize(actor, false);
  const limit = request.limit ?? 40, offset = request.offset ?? 0;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      request.type && !OFFLINE_JOB_TYPES.includes(request.type) ||
      request.status && !["QUEUED", "LEASED", "SUCCEEDED",
        "RETRY_WAIT", "DEAD_LETTER", "CANCELLED"].includes(request.status))
    fail("JOB_LIST_FILTER_INVALID");
  const where = { organizationId: actor.organizationId,
    ...(request.type ? { type: request.type } : {}),
    ...(request.status ? { status: request.status } : {}) };
  const [rows, total] = await Promise.all([
    db.durableOfflineJob.findMany({ where, orderBy: [
      { createdAt: "desc" }, { id: "asc" } ], skip: offset, take: limit }),
    db.durableOfflineJob.count({ where }),
  ]);
  return { schema: "cyberpilot.offline.jobs.page.v1" as const,
    organizationId: actor.organizationId,
    items: rows.map(fromRow), total, offset, limit,
    nextOffset: offset + limit < total ? offset + limit : null,
    providerOperations: 0 as const, autonomousExecution: false as const };
}
export async function readOfflineJobAudit(actor: IntegratedReviewer, jobId: string) {
  await authorize(actor, false);
  if (!ident(jobId)) fail("JOB_ID_INVALID");
  const row = await db.durableOfflineJob.findFirst({
    where: { organizationId: actor.organizationId, id: jobId },
  });
  if (!row) fail("JOB_NOT_IN_TENANT");
  const events = await db.durableOfflineJobEvent.findMany({
    where: { organizationId: actor.organizationId, jobId },
    take: 201, orderBy: { revision: "asc" },
  });
  const snapshot = fromRow(row);
  const mapped = events.slice(0, 200).map(fromEvent);
  return { snapshot, events: mapped,
    replayProblems: inspectJobReplay(mapped, actor.organizationId, jobId),
    audit: auditJob(snapshot, mapped, events.length > 200),
    providerCalls: 0 as const };
}
export async function offlineQueueMetrics(actor: IntegratedReviewer) {
  await authorize(actor, false);
  const jobs = await db.durableOfflineJob.findMany({
    where: { organizationId: actor.organizationId },
    select: { status: true, type: true, attempts: true, scheduledAt: true,
      leaseExpiresAt: true, lastFailure: true, createdAt: true },
    take: 10001, orderBy: { createdAt: "desc" },
  });
  const states = ["QUEUED", "LEASED", "SUCCEEDED", "RETRY_WAIT",
    "DEAD_LETTER", "CANCELLED"] as const;
  const now = Date.now();
  return { schema: "cyberpilot.offline.jobs.metrics.v1" as const,
    organizationId: actor.organizationId, asOf: new Date(now).toISOString(),
    truncated: jobs.length > 10000,
    observed: Math.min(jobs.length, 10000),
    status: Object.fromEntries(states.map(s => [
      s, jobs.filter(x => x.status === s).length ])),
    overdue: jobs.filter(x => ["QUEUED", "RETRY_WAIT"].includes(x.status) &&
      x.scheduledAt.getTime() < now).length,
    staleLeases: jobs.filter(x => x.status === "LEASED" &&
      x.leaseExpiresAt && x.leaseExpiresAt.getTime() < now).length,
    exhausted: jobs.filter(x => x.status === "DEAD_LETTER").length,
    retryAttemptCount: jobs.reduce((sum, x) => sum + Math.max(0, x.attempts - 1), 0),
    providerCalls: 0 as const };
}

/** Read-only queue health with bounded cross-org-safe exports. */
export async function readOfflineQueueHealth(actor: IntegratedReviewer,
  format?: "JSON" | "CSV" | "MARKDOWN") {
  await authorize(actor, false);
  const rows = await db.durableOfflineJob.findMany({
    where: { organizationId: actor.organizationId },
    orderBy: [{ createdAt: "desc" }, { id: "asc" }],
    take: 10001,
  });
  const health = evaluateOfflineQueueHealth(
    actor.organizationId, rows.slice(0, 10000).map(fromRow),
    new Date().toISOString(), rows.length > 10000);
  return { health, artifact: format ? exportOfflineQueueHealth(health, format) : null,
    providerCalls: 0 as const, unattendedExecution: false as const };
}

/** Tenant-scoped, read-only planning; no implicit claim or worker scheduling. */
export async function previewOfflineDispatch(actor: IntegratedReviewer) {
  await authorize(actor, false);
  const rows = await db.durableOfflineJob.findMany({
    where: { organizationId: actor.organizationId },
    orderBy: [{ scheduledAt: "asc" }, { id: "asc" }], take: 1001,
  });
  const truncated = rows.length > 1000;
  const jobs = rows.slice(0, 1000).map(fromRow);
  const asOf = new Date().toISOString();
  return { plan: buildQueueDispatchPlan(actor.organizationId,
      jobs.map(job => ({ job })), asOf, undefined, truncated),
    deadLetters: reviewDeadLetters(actor.organizationId, jobs, asOf,
      undefined, truncated),
    providerCalls: 0 as const, automaticClaims: 0 as const };
}
/** Actual records, but injected faults are computed on cloned memory only. */
export async function rehearseOfflineJobFaults(actor: IntegratedReviewer) {
  await authorize(actor, false);
  const rows = await db.durableOfflineJob.findMany({
    where: { organizationId: actor.organizationId },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 21,
  });
  const selected = rows.slice(0, 20).map(fromRow);
  const events = selected.length ? await db.durableOfflineJobEvent.findMany({
    where: { organizationId: actor.organizationId,
      jobId: { in: selected.map(s => s.id) } },
    take: 401, orderBy: [{ revision: "asc" }, { id: "asc" }],
  }) : [];
  if (rows.length > 20 || events.length > 400)
    return { status: "TRUNCATED_SELECT_NARROWER_SCOPE" as const,
      organizationId: actor.organizationId, faultMatrix: null,
      providerCalls: 0 as const, destructiveTestsRun: 0 as const };
  const history: Record<string, JobEvent[]> = {};
  for (const event of events) {
    (history[event.jobId] ??= []).push(fromEvent(event));
  }
  const faultMatrix = evaluateQueueFaultScenarios(
    actor.organizationId, selected, history, new Date().toISOString());
  return { status: "SIMULATED" as const,
    organizationId: actor.organizationId, faultMatrix,
    providerCalls: 0 as const, destructiveTestsRun: 0 as const };
}
/** Tenant audit timeline, with explicit integrity defects and revision caps. */
export async function inspectOfflineJobEventIntegrity(
  actor: IntegratedReviewer, jobId: string,
) {
  const read = await readOfflineJobAudit(actor, jobId);
  const diagnostic = analyzeJobEventChain(read.snapshot, read.events);
  return { schema: "cyberpilot.offline.queue.integrity.v1" as const,
    organizationId: actor.organizationId, jobId, diagnostic,
    historicalPageTruncated: read.events.length >= 200,
    combinedAccepted: read.audit.valid && diagnostic.issues.length === 0,
    providerWrites: 0 as const, liveAssuranceConfirmed: false as const };
}

/** Read-only operational evidence assembled from persisted job + event rows. */
export async function readOfflineQueueAssurance(
  actor: IntegratedReviewer,
  format?: "JSON" | "CSV" | "MARKDOWN",
) {
  await authorize(actor, false);
  const rows = await db.durableOfflineJob.findMany({
    where: { organizationId: actor.organizationId },
    orderBy: [{ createdAt: "desc" }, { id: "asc" }], take: 501,
  });
  const jobs = rows.slice(0, 500).map(fromRow);
  const events = await db.durableOfflineJobEvent.findMany({
    where: { organizationId: actor.organizationId,
      jobId: { in: jobs.map(x => x.id) } },
    take: 10001, orderBy: [{ occurredAt: "asc" }, { revision: "asc" }],
  });
  const histories: Record<string, JobEvent[]> = {};
  for (const e of events.slice(0, 10000))
    (histories[e.jobId] ??= []).push(fromEvent(e));
  const report = buildQueueAssuranceReport({
    organizationId: actor.organizationId, snapshots: jobs,
    histories, at: new Date().toISOString(),
    truncated: rows.length > 500 || events.length > 10000,
    historyTruncatedIds: events.length > 10000 ? jobs.map(x => x.id) : [],
  });
  return { report, artifact: format ? exportQueueAssuranceReport(report, format) : null,
    auditedDatabaseRows: jobs.length, providerCalls: 0 as const,
    externalSideEffects: false as const };
}
