import type { OfflineJobSnapshot, JobEvent, OfflineJobType } from "./durable-offline-job-domain";
import { jobDigest, validateJobSnapshot } from "./durable-offline-job-domain";
import { buildQueueDispatchPlan, analyzeJobEventChain,
  type QueueDispatchPlan, type QueueDispatchPolicy,
  DEFAULT_QUEUE_DISPATCH_POLICY } from "./offline-job-dispatch-assurance";

export type QueueAssuranceFinding = {
  key: string; jobId: string | null; severity: "INFO" | "WARNING" | "ERROR";
  source: "PERSISTED_SNAPSHOT" | "AUDIT_EVENTS" | "DISPATCH_POLICY";
  message: string; nextAction: string; blocksAutomation: boolean;
};
export type QueueAssuranceReport = {
  schema: "cyberpilot.queue.assurance.report.v1";
  organizationId: string; evaluatedAt: string;
  observedJobs: number; truncated: boolean; jobTypes: OfflineJobType[];
  dispatchPlanDigest: string; queueSnapshotDigest: string;
  findings: QueueAssuranceFinding[]; failures: number; warnings: number;
  humanReviewRequired: number; cleanAuditRecords: number;
  incompleteAuditRecords: number; repeatedIdempotencyKeys: string[];
  overdueByType: Array<{ type: OfflineJobType; count: number; oldestAgeHours: number }>;
  activeLeases: Array<{ jobId: string; worker: string | null;
    remainingSeconds: number; revision: number }>;
  recoveryCandidates: Array<{ jobId: string; reason: string;
    expectedRevision: number }>;
  acceptance: "BLOCKED" | "INCOMPLETE" | "READY_FOR_OPERATOR_REVIEW";
  provenProviderWrites: 0; productionResilienceProven: false;
};
export type QueueAssuranceInput = {
  organizationId: string; at: string;
  snapshots: OfflineJobSnapshot[];
  histories: Readonly<Record<string, JobEvent[]>>;
  truncated: boolean; historyTruncatedIds?: readonly string[];
  policy?: QueueDispatchPolicy;
};
function emit(findings: QueueAssuranceFinding[], jobId: string | null,
  severity: QueueAssuranceFinding["severity"],
  source: QueueAssuranceFinding["source"],
  key: string, message: string, nextAction: string,
  blocksAutomation = severity === "ERROR") {
  findings.push({ key, jobId, severity, source, message, nextAction,
    blocksAutomation });
}
export function buildQueueAssuranceReport(input: QueueAssuranceInput): QueueAssuranceReport {
  const policy = input.policy ?? DEFAULT_QUEUE_DISPATCH_POLICY;
  if (!input.organizationId || input.snapshots.length > 2000 ||
      !Number.isFinite(Date.parse(input.at)) ||
      input.snapshots.some(s => s.organizationId !== input.organizationId))
    throw Error("QUEUE_ASSURANCE_SCOPE_INVALID");
  const dispatch = buildQueueDispatchPlan(input.organizationId,
    input.snapshots.map(job => ({ job })), input.at,
    policy, input.truncated);
  const findings: QueueAssuranceFinding[] = [];
  const historyTruncated = new Set(input.historyTruncatedIds ?? []);
  const ids = new Set<string>(), idempotency = new Map<string, string>();
  let cleanAuditRecords = 0, incompleteAuditRecords = 0;
  const overdue = new Map<OfflineJobType, { count: number; oldest: number }>();
  const activeLeases: QueueAssuranceReport["activeLeases"] = [];
  const recoveryCandidates: QueueAssuranceReport["recoveryCandidates"] = [];
  const timestamp = Date.parse(input.at);
  for (const s of input.snapshots) {
    if (ids.has(s.id)) {
      emit(findings, s.id, "ERROR", "PERSISTED_SNAPSHOT",
        "DUPLICATE_JOB_ID", "Duplicate snapshot identity",
        "Inspect tenant SQL uniqueness constraints");
    }
    ids.add(s.id);
    const previousId = idempotency.get(s.idempotencyKey);
    if (previousId && previousId !== s.id) {
      emit(findings, s.id, "ERROR", "PERSISTED_SNAPSHOT",
        "IDEMPOTENCY_COLLISION", "Repeated organization idempotency key",
        "Inspect uniqueness constraint and source records");
    }
    idempotency.set(s.idempotencyKey, s.id);
    const errors = validateJobSnapshot(s);
    for (const error of errors) {
      emit(findings, s.id, "ERROR", "PERSISTED_SNAPSHOT",
        error, "Snapshot does not satisfy job contract",
        "Quarantine and review original persisted data");
    }
    const events = input.histories[s.id];
    if (!events || historyTruncated.has(s.id)) {
      incompleteAuditRecords++;
      emit(findings, s.id, "WARNING", "AUDIT_EVENTS",
        "HISTORY_NOT_COMPLETE", "History unavailable or explicitly truncated",
        "Read complete event history using bounded cursor");
    } else {
      const diagnostic = analyzeJobEventChain(s, events);
      if (diagnostic.issues.length === 0) cleanAuditRecords++;
      else {
        incompleteAuditRecords++;
        for (const issue of diagnostic.issues)
          emit(findings, s.id, "ERROR", "AUDIT_EVENTS",
            issue, "Audit event sequence or digest mismatch",
            "Compare exact persisted revisions before retry");
      }
    }
    const ageHours = Math.max(0, (timestamp -
      Date.parse(s.createdAt)) / 3600000);
    if (["QUEUED", "RETRY_WAIT"].includes(s.status) &&
        Date.parse(s.scheduledAt) < timestamp) {
      const entry = overdue.get(s.type) ?? { count: 0, oldest: 0 };
      entry.count++; entry.oldest = Math.max(entry.oldest, ageHours);
      overdue.set(s.type, entry);
    }
    if (s.status === "LEASED" && s.leaseExpiresAt) {
      const remainingSeconds = Math.ceil((Date.parse(s.leaseExpiresAt) -
        timestamp) / 1000);
      if (remainingSeconds > 0)
        activeLeases.push({ jobId: s.id, worker: s.leasedBy,
          remainingSeconds, revision: s.revision });
      else {
        recoveryCandidates.push({ jobId: s.id, reason: "LEASE_EXPIRED",
          expectedRevision: s.revision });
        emit(findings, s.id, "WARNING", "DISPATCH_POLICY",
          "LEASE_EXPIRED", "Lease has expired without a recorded successor",
          "Review ownership, then recover using revision CAS", true);
      }
    }
    if (s.status === "DEAD_LETTER") {
      emit(findings, s.id, "WARNING", "DISPATCH_POLICY",
        "MANUAL_DEAD_LETTER", "Job exhausted attempts or was non-retryable",
        "Open a separate resolution record; never silently replay");
    }
    if (s.status === "RETRY_WAIT" && s.failureClass === "AUTHORIZATION")
      emit(findings, s.id, "ERROR", "DISPATCH_POLICY",
        "UNSAFE_AUTHORIZATION_RETRY", "Authorization failure was scheduled for retry",
        "Stop retry and investigate membership and role controls");
    if (s.attempts > s.maxAttempts)
      emit(findings, s.id, "ERROR", "DISPATCH_POLICY",
        "ATTEMPT_LIMIT_BROKEN", "Attempt count exceeds persisted upper bound",
        "Inspect job transition writer and exact SQL revisions");
  }
  if (input.truncated)
    emit(findings, null, "WARNING", "PERSISTED_SNAPSHOT",
      "QUEUE_PAGE_TRUNCATED", "Not all tenant jobs were inspected",
      "Run bounded follow-up pages and merge findings");
  if (dispatch.selected.length === 0 && dispatch.claimCandidates.length > 0)
    emit(findings, null, "INFO", "DISPATCH_POLICY",
      "NO_CURRENT_CAPACITY", "Eligible work exists but cannot be dispatched",
      "Review tenant active lease count and scheduling");
  if (dispatch.stalledLeases.length > 0)
    emit(findings, null, "WARNING", "DISPATCH_POLICY",
      "STALE_LEASES_PRESENT", "At least one lease needs fencing recovery",
      "Inspect stale lease owners and event histories", true);
  const repeatedIdempotencyKeys = findings.filter(x =>
    x.key === "IDEMPOTENCY_COLLISION").map(x => x.jobId ?? "");
  const failures = findings.filter(x => x.severity === "ERROR").length;
  const warnings = findings.filter(x => x.severity === "WARNING").length;
  return {
    schema: "cyberpilot.queue.assurance.report.v1",
    organizationId: input.organizationId, evaluatedAt: input.at,
    observedJobs: input.snapshots.length, truncated: input.truncated,
    jobTypes: [...new Set(input.snapshots.map(s => s.type))].sort(),
    dispatchPlanDigest: jobDigest(dispatch), queueSnapshotDigest:
      jobDigest(input.snapshots),
    findings, failures, warnings,
    humanReviewRequired: findings.filter(x => x.blocksAutomation).length,
    cleanAuditRecords, incompleteAuditRecords,
    repeatedIdempotencyKeys,
    overdueByType: [...overdue.entries()].map(([type, v]) =>
      ({ type, count: v.count, oldestAgeHours: v.oldest }))
      .sort((a, b) => b.count - a.count),
    activeLeases: activeLeases.sort((a, b) =>
      a.remainingSeconds - b.remainingSeconds),
    recoveryCandidates,
    acceptance: failures > 0 ? "BLOCKED" : input.truncated ||
      incompleteAuditRecords || warnings ? "INCOMPLETE" :
      "READY_FOR_OPERATOR_REVIEW",
    provenProviderWrites: 0, productionResilienceProven: false,
  };
}
function csvField(value: unknown) {
  const raw = String(value ?? "");
  const safe = /^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""').replaceAll("\r", " ")
    .replaceAll("\n", " ") + '"';
}
export function exportQueueAssuranceReport(report: QueueAssuranceReport,
  format: "JSON" | "CSV" | "MARKDOWN") {
  const basename = "cyberpilot-queue-assurance-" +
    report.evaluatedAt.slice(0, 10);
  const digest = jobDigest(report);
  if (format === "JSON") return {
    filename: basename + ".json", mime: "application/json",
    digest, content: JSON.stringify({ ...report, digest }, null, 2),
  };
  if (format === "CSV") {
    const columns = ["jobId", "severity", "source", "code",
      "message", "nextAction", "blocksAutomation"];
    const rows = report.findings.map(x => [
      x.jobId ?? "", x.severity, x.source, x.key, x.message,
      x.nextAction, String(x.blocksAutomation),
    ]);
    return { filename: basename + ".csv", mime: "text/csv",
      digest, content: [columns, ...rows].map(row => row.map(csvField)
        .join(",")).join("\r\n") };
  }
  if (format === "MARKDOWN") {
    const safe = (s: string) => s.replaceAll("|", "\\|")
      .replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    return { filename: basename + ".md", mime: "text/markdown",
      digest, content: [
        "# Offline job assurance review",
        "Organization: " + report.organizationId,
        "Evaluated: " + report.evaluatedAt,
        "Jobs observed: " + report.observedJobs,
        "Acceptance: " + report.acceptance,
        "Evidence digest: " + digest,
        "Production resilience verified: NO", "",
        "| Severity | Job | Finding | Operator action |",
        "|---|---|---|---|",
        ...report.findings.map(f => "| " + f.severity + " | " +
          safe(f.jobId ?? "TENANT") + " | " + safe(f.key) +
          " | " + safe(f.nextAction) + " |"),
        "", "A green local diagnostic is not proof of managed production recovery.",
      ].join("\n") };
  }
  throw Error("QUEUE_ASSURANCE_FORMAT_INVALID");
}
export function compareQueueAssuranceReports(
  before: QueueAssuranceReport, after: QueueAssuranceReport,
) {
  if (before.organizationId !== after.organizationId ||
      before.evaluatedAt > after.evaluatedAt)
    throw Error("QUEUE_ASSURANCE_COMPARISON_SCOPE_INVALID");
  const beforeKeys = new Set(before.findings.map(x =>
    [x.jobId ?? "", x.key, x.source].join(":")));
  const afterKeys = new Set(after.findings.map(x =>
    [x.jobId ?? "", x.key, x.source].join(":")));
  return {
    schema: "cyberpilot.queue.assurance.compare.v1" as const,
    organizationId: before.organizationId,
    earlier: before.evaluatedAt, later: after.evaluatedAt,
    newlyReported: [...afterKeys].filter(x => !beforeKeys.has(x)),
    noLongerReported: [...beforeKeys].filter(x => !afterKeys.has(x)),
    earlierTruncated: before.truncated, laterTruncated: after.truncated,
    comparable: !before.truncated && !after.truncated &&
      before.observedJobs === after.observedJobs,
    fixedInProductionProven: false as const,
    restoredFromBackup: false as const,
  };
}
