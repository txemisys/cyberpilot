import { jobDigest, type OfflineJobSnapshot, type JobEvent,
  type OfflineJobStatus } from "./durable-offline-job-domain";
export type QueueHealth = {
  schema: "cyberpilot.jobs.health.v1"; organizationId: string; at: string;
  total: number; truncated: boolean;
  actionable: number; blocked: number; staleLeaseCount: number;
  oldestQueuedAgeSeconds: number | null;
  maxObservedAttempts: number; perType: Record<string, number>;
  deadLetters: Array<{ id: string; code: string | null; attempts: number;
    ageSeconds: number; type: string }>;
  stalled: Array<{ id: string; leaseOwner: string | null;
    expiredSeconds: number; revision: number }>;
  pending: Array<{ id: string; readyAt: string; waitSeconds: number;
    attempts: number; type: string }>;
  providerWritesVerified: false; unattendedWorkerRunning: false;
};
function ensureTime(at: string) {
  const ms = Date.parse(at);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== at)
    throw Error("JOB_HEALTH_TIME_INVALID");
  return ms;
}
export function evaluateOfflineQueueHealth(organizationId: string,
  jobs: OfflineJobSnapshot[], at: string, truncated: boolean): QueueHealth {
  const time = ensureTime(at);
  if (!organizationId || jobs.length > 10000 ||
      jobs.some(job => job.organizationId !== organizationId))
    throw Error("JOB_HEALTH_SCOPE_INVALID");
  const deadLetters: QueueHealth["deadLetters"] = [];
  const stalled: QueueHealth["stalled"] = [];
  const pending: QueueHealth["pending"] = [];
  const perType: Record<string, number> = {};
  for (const job of jobs) {
    perType[job.type] = (perType[job.type] ?? 0) + 1;
    if (job.status === "DEAD_LETTER") deadLetters.push({
      id: job.id, code: job.lastFailure, attempts: job.attempts,
      ageSeconds: Math.max(0, Math.floor((time - Date.parse(job.createdAt)) / 1000)),
      type: job.type });
    if (job.status === "LEASED" && job.leaseExpiresAt &&
        Date.parse(job.leaseExpiresAt) <= time)
      stalled.push({ id: job.id, leaseOwner: job.leasedBy,
        expiredSeconds: Math.floor((time - Date.parse(job.leaseExpiresAt)) / 1000),
        revision: job.revision });
    if (job.status === "QUEUED" || job.status === "RETRY_WAIT")
      pending.push({ id: job.id, readyAt: job.scheduledAt, attempts: job.attempts,
        type: job.type, waitSeconds: Math.max(0,
          Math.ceil((Date.parse(job.scheduledAt) - time) / 1000)) });
  }
  pending.sort((a, b) => a.readyAt.localeCompare(b.readyAt) || a.id.localeCompare(b.id));
  stalled.sort((a, b) => b.expiredSeconds - a.expiredSeconds || a.id.localeCompare(b.id));
  deadLetters.sort((a, b) => b.ageSeconds - a.ageSeconds || a.id.localeCompare(b.id));
  return {
    schema: "cyberpilot.jobs.health.v1", organizationId, at, total: jobs.length,
    truncated, actionable: pending.filter(x => x.waitSeconds === 0).length,
    blocked: jobs.filter(x => x.status === "DEAD_LETTER" ||
      x.status === "CANCELLED").length,
    staleLeaseCount: stalled.length,
    oldestQueuedAgeSeconds: pending.filter(x => x.waitSeconds === 0).length ?
      Math.max(...jobs.filter(x => (x.status === "QUEUED" ||
        x.status === "RETRY_WAIT") && Date.parse(x.scheduledAt) <= time)
        .map(x => Math.floor((time - Date.parse(x.createdAt)) / 1000))) : null,
    maxObservedAttempts: jobs.length ? Math.max(...jobs.map(x => x.attempts)) : 0,
    perType, deadLetters: deadLetters.slice(0, 100),
    stalled: stalled.slice(0, 100), pending: pending.slice(0, 100),
    providerWritesVerified: false, unattendedWorkerRunning: false,
  };
}
export type JobReplayProblem = { code: string; eventRevision: number;
  previous: string; next: string; forensicOnly: true };
const transitions: Record<string, ReadonlySet<OfflineJobStatus>> = {
  ADMITTED: new Set(["QUEUED"]),
  CLAIMED: new Set(["LEASED"]),
  HEARTBEAT: new Set(["LEASED"]),
  SUCCEEDED: new Set(["SUCCEEDED"]),
  RETRY_SCHEDULED: new Set(["RETRY_WAIT"]),
  DEAD_LETTERED: new Set(["DEAD_LETTER"]),
  CANCELLED: new Set(["CANCELLED"]),
  REQUEUED: new Set(["RETRY_WAIT"]),
};
export function inspectJobReplay(events: JobEvent[], organizationId: string,
  jobId: string): JobReplayProblem[] {
  if (events.length > 2000) throw Error("JOB_REPLAY_LIMIT_EXCEEDED");
  const sorted = [...events].sort((a, b) => a.revision - b.revision);
  const problems: JobReplayProblem[] = [];
  for (let i = 0; i < sorted.length; i++) {
    const event = sorted[i]!;
    if (event.organizationId !== organizationId || event.jobId !== jobId)
      throw Error("JOB_REPLAY_CROSS_TENANT");
    if (event.revision !== i + 1)
      problems.push({ code: "EVENT_REVISION_GAP", eventRevision: event.revision,
        previous: event.previous, next: event.next, forensicOnly: true });
    if (i > 0 && event.previous !== sorted[i - 1]!.next)
      problems.push({ code: "EVENT_STATUS_DISCONTINUITY", eventRevision: event.revision,
        previous: event.previous, next: event.next, forensicOnly: true });
    if (!transitions[event.kind]?.has(event.next))
      problems.push({ code: "EVENT_COMMAND_STATE_INVALID", eventRevision: event.revision,
        previous: event.previous, next: event.next, forensicOnly: true });
    if (event.providerOperations !== 0)
      problems.push({ code: "EXTERNAL_EXECUTION_CLAIM", eventRevision: event.revision,
        previous: event.previous, next: event.next, forensicOnly: true });
  }
  return problems;
}
function csv(value: string | number | null) {
  const raw = String(value ?? "");
  const safe = /^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""').replaceAll("\n", " ")
    .replaceAll("\r", " ") + '"';
}
export function exportOfflineQueueHealth(health: QueueHealth,
  format: "JSON" | "CSV" | "MARKDOWN") {
  const digest = jobDigest(health), filename = "offline-queue-" +
    health.at.slice(0, 10);
  if (format === "JSON") return { filename: filename + ".json",
    mime: "application/json", digest,
    content: JSON.stringify({ ...health, digest }, null, 2) };
  if (format === "CSV") {
    const rows = [
      ["kind", "jobId", "typeOrOwner", "secondsOrAge", "revisionOrAttempts"],
      ...health.deadLetters.map(x => ["dead-letter", x.id, x.type,
        String(x.ageSeconds), String(x.attempts)]),
      ...health.stalled.map(x => ["stale-lease", x.id, x.leaseOwner ?? "",
        String(x.expiredSeconds), String(x.revision)]),
      ...health.pending.map(x => ["pending", x.id, x.type,
        String(x.waitSeconds), String(x.attempts)]),
    ];
    return { filename: filename + ".csv", mime: "text/csv", digest,
      content: rows.map(row => row.map(csv).join(",")).join("\n") };
  }
  if (format === "MARKDOWN") return { filename: filename + ".md",
    mime: "text/markdown", digest,
    content: [
      "# CyberPilot offline queue health", "Organization: " + health.organizationId,
      "As of: " + health.at, "Observed jobs: " + health.total,
      "Truncated: " + health.truncated, "Ready: " + health.actionable,
      "Stale leases: " + health.staleLeaseCount,
      "Dead letters: " + health.deadLetters.length,
      "SHA-256: " + digest,
      "", "This is a manually dispatched offline job system.",
      "No provider remediation, remote sync or managed disaster restore is proven.",
    ].join("\n") };
  throw Error("JOB_HEALTH_EXPORT_UNKNOWN");
}
