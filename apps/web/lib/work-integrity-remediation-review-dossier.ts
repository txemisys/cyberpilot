import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityReviewReplay } from "./work-integrity-remediation-review-event-replay";
import type { IntegrityReviewGateReport } from "./work-integrity-remediation-review-gate";
import type { IntegrityReviewEvidenceReport } from "./work-integrity-remediation-review-evidence";
import type { IntegrityReviewDeadlineReport } from "./work-integrity-remediation-review-deadlines";
import type { IntegrityReviewBatchDecision } from "./work-integrity-remediation-review-batch";
import type { IntegrityReviewLineageReport } from "./work-integrity-remediation-review-lineage";

export type IntegrityReviewDossierPolicy = {
  requireReplay: boolean;
  requireGate: boolean;
  requireEvidence: boolean;
  requireDeadlines: boolean;
  requireBatch: boolean;
  requireLineage: boolean;
  rejectRejectedEvents: boolean;
  rejectUnmatchedEvidence: boolean;
  rejectTruncatedLineage: boolean;
  maximumTaskSummaries: number;
};
export type IntegrityReviewDossierTask = {
  taskId: string;
  action: string;
  severity: string;
  reviewRequired: boolean;
  disposition: string;
  ownerId: string | null;
  eventCount: number;
  rejectedEvents: number;
  evidenceReferences: number;
  activeAssociations: number;
  provenanceComplete: boolean;
  deadlineStatus: string | null;
  deadlineBreached: boolean;
  gateReady: boolean;
  blockers: string[];
  analyticallyComplete: boolean;
  independentlyVerified: false;
};
export type IntegrityReviewDossierFinding = {
  code: string;
  severity: "ERROR" | "WARNING";
  taskId: string | null;
  detail: string;
};
export type IntegrityReviewDossier = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewDossierPolicy;
  status: "INCOMPLETE" | "NEEDS_HUMAN_REVIEW" | "ANALYTICALLY_COMPLETE";
  tasks: IntegrityReviewDossierTask[];
  findings: IntegrityReviewDossierFinding[];
  sources: {
    replay: boolean;
    gate: boolean;
    evidence: boolean;
    deadlines: boolean;
    batch: boolean;
    lineage: boolean;
  };
  totals: {
    tasks: number;
    includedTasks: number;
    truncated: boolean;
    required: number;
    analyticallyComplete: number;
    outstandingRequired: number;
    gateBlocked: number;
    overdue: number;
    rejectedEvents: number;
    unmatchedEvidence: number;
    missingSources: number;
    errors: number;
    warnings: number;
    independentlyVerified: 0;
  };
  limitation: string;
};
export type IntegrityReviewDossierQuery = {
  taskIds?: string[];
  severities?: string[];
  onlyIncomplete?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityReviewDossierPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityReviewDossierTask[];
};
const defaults: IntegrityReviewDossierPolicy = {
  requireReplay: true, requireGate: true,
  requireEvidence: true, requireDeadlines: false,
  requireBatch: true, requireLineage: false,
  rejectRejectedEvents: true, rejectUnmatchedEvidence: true,
  rejectTruncatedLineage: true,
  maximumTaskSummaries: 2000,
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
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityReviewDossierPolicy(
  value: unknown,
): IntegrityReviewDossierPolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "review dossier policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown dossier policy field.");
  const policy = { ...defaults };
  for (const key of [
    "requireReplay", "requireGate", "requireEvidence",
    "requireDeadlines", "requireBatch", "requireLineage",
    "rejectRejectedEvents", "rejectUnmatchedEvidence",
    "rejectTruncatedLineage",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid dossier policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumTaskSummaries !== undefined)
    policy.maximumTaskSummaries = integer(raw.maximumTaskSummaries,
      "maximum dossier tasks", 1, 5000);
  return policy;
}
export function buildIntegrityReviewDossier(
  queue: IntegrityCapacityReviewQueue,
  replay: IntegrityReviewReplay | null,
  gate: IntegrityReviewGateReport | null,
  evidence: IntegrityReviewEvidenceReport | null,
  deadlines: IntegrityReviewDeadlineReport | null,
  batch: IntegrityReviewBatchDecision | null,
  lineage: IntegrityReviewLineageReport | null,
  policy: IntegrityReviewDossierPolicy = defaults,
): IntegrityReviewDossier {
  const captureId = queue.captureId;
  for (const source of [replay, gate, evidence, deadlines, batch, lineage])
    if (source && source.captureId !== captureId)
      throw new WorkInputError("INVALID", "Dossier source capture mismatch.");
  const sources = {
    replay: replay !== null, gate: gate !== null,
    evidence: evidence !== null, deadlines: deadlines !== null,
    batch: batch !== null, lineage: lineage !== null,
  };
  const findings: IntegrityReviewDossierFinding[] = [];
  const add = (
    code: string, severity: "ERROR" | "WARNING",
    detail: string, taskId: string | null = null,
  ) => findings.push({ code, severity, detail, taskId });
  for (const name of Object.keys(sources) as Array<keyof typeof sources>) {
    const requirement: Record<keyof typeof sources, boolean> = {
      replay: policy.requireReplay, gate: policy.requireGate,
      evidence: policy.requireEvidence,
      deadlines: policy.requireDeadlines,
      batch: policy.requireBatch, lineage: policy.requireLineage,
    };
    if (requirement[name] && !sources[name])
      add("MISSING_" + name.toUpperCase(), "ERROR",
        "The required " + name + " report is unavailable.");
  }
  if (replay && policy.rejectRejectedEvents &&
      replay.totals.rejectedEvents)
    add("REPLAY_REJECTIONS", "ERROR",
      "One or more review events failed optimistic replay.");
  if (batch && batch.status === "REJECTED")
    add("BATCH_VALIDATION_FAILED", "ERROR",
      "Review batch validation found blocking inconsistencies.");
  if (gate && gate.status === "BLOCKED")
    add("REVIEW_GATE_BLOCKED", "ERROR",
      "The conservative review gate remains blocked.");
  if (evidence && policy.rejectUnmatchedEvidence &&
      evidence.totals.errors)
    add("EVIDENCE_PROVENANCE_INCOMPLETE", "ERROR",
      "Evidence reconciliation reports errors.");
  if (lineage && policy.rejectTruncatedLineage &&
      lineage.totals.truncated)
    add("LINEAGE_TRUNCATED", "ERROR",
      "The provenance graph exceeded its configured limits.");
  if (lineage && lineage.totals.errors)
    add("LINEAGE_ERRORS", "WARNING",
      "The reconstructed provenance graph contains invalid edges or nodes.");
  const stateMap = new Map(replay?.tasks.map(x =>
    [x.taskId, x]) ?? []);
  const gateMap = new Map(gate?.tasks.map(x =>
    [x.taskId, x]) ?? []);
  const evidenceMap = new Map(evidence?.tasks.map(x =>
    [x.taskId, x]) ?? []);
  const deadlineMap = new Map(deadlines?.tasks.map(x =>
    [x.taskId, x]) ?? []);
  const allTasks: IntegrityReviewDossierTask[] = queue.tasks.map(task => {
    const state = stateMap.get(task.taskId);
    const gateTask = gateMap.get(task.taskId);
    const evidenceTask = evidenceMap.get(task.taskId);
    const deadlineTask = deadlineMap.get(task.taskId);
    const blockers: string[] = [];
    if (!state) blockers.push("NO_REPLAY_STATE");
    else if (!state.terminal) blockers.push("REVIEW_OUTSTANDING");
    if (!gateTask) blockers.push("NO_GATE_DECISION");
    else if (!gateTask.ready) blockers.push(...gateTask.blockers);
    if (!evidenceTask) blockers.push("NO_EVIDENCE_RECONCILIATION");
    else if (!evidenceTask.provenanceComplete)
      blockers.push("EVIDENCE_PROVENANCE_INCOMPLETE");
    if (deadlineTask?.resolutionBreached)
      blockers.push("RESOLUTION_DEADLINE_BREACHED");
    if (batch && batch.events.some(x =>
      x.taskId === task.taskId && !x.acceptedForAnalysis))
      blockers.push("BATCH_EVENT_REJECTED");
    const uniqueBlockers = [...new Set(blockers)].sort();
    const complete = uniqueBlockers.length === 0;
    if (task.reviewRequired && !complete)
      add("REQUIRED_REVIEW_INCOMPLETE", "WARNING",
        "The task has unresolved review or evidence blockers.",
        task.taskId);
    return {
      taskId: task.taskId, action: task.action,
      severity: task.severity,
      reviewRequired: task.reviewRequired,
      disposition: state?.disposition ?? "UNKNOWN",
      ownerId: state?.ownerId ?? null,
      eventCount: state?.history.length ?? 0,
      rejectedEvents: state?.history.filter(x =>
        !x.accepted).length ?? 0,
      evidenceReferences: evidenceTask?.submittedReferences ?? 0,
      activeAssociations: evidenceTask?.activeReferences ?? 0,
      provenanceComplete: evidenceTask?.provenanceComplete ?? false,
      deadlineStatus: deadlineTask?.status ?? null,
      deadlineBreached: deadlineTask?.resolutionBreached ?? false,
      gateReady: gateTask?.ready ?? false,
      blockers: uniqueBlockers,
      analyticallyComplete: complete,
      independentlyVerified: false,
    };
  });
  const selected = allTasks.slice(0, policy.maximumTaskSummaries);
  if (selected.length < allTasks.length)
    add("DOSSIER_TRUNCATED", "ERROR",
      "The dossier omits tasks due to the configured output limit.");
  const errors = findings.filter(x => x.severity === "ERROR").length;
  const warnings = findings.filter(x => x.severity === "WARNING").length;
  const requiredOutstanding = allTasks.filter(x =>
    x.reviewRequired && !x.analyticallyComplete).length;
  return {
    schemaVersion: 1, captureId,
    evaluatedAt: replay?.evaluatedAt ?? queue.evaluatedAt,
    policy, status: errors ? "INCOMPLETE" :
      requiredOutstanding || warnings ?
        "NEEDS_HUMAN_REVIEW" : "ANALYTICALLY_COMPLETE",
    tasks: selected, findings, sources,
    totals: {
      tasks: allTasks.length, includedTasks: selected.length,
      truncated: selected.length < allTasks.length,
      required: allTasks.filter(x => x.reviewRequired).length,
      analyticallyComplete: allTasks.filter(x =>
        x.analyticallyComplete).length,
      outstandingRequired: requiredOutstanding,
      gateBlocked: allTasks.filter(x => !x.gateReady).length,
      overdue: allTasks.filter(x => x.deadlineBreached).length,
      rejectedEvents: replay?.totals.rejectedEvents ?? 0,
      unmatchedEvidence: evidence?.totals.errors ?? 0,
      missingSources: Object.entries(sources).filter(([name, present]) => {
        const required: Record<string, boolean> = {
          replay: policy.requireReplay, gate: policy.requireGate,
          evidence: policy.requireEvidence,
          deadlines: policy.requireDeadlines,
          batch: policy.requireBatch, lineage: policy.requireLineage,
        };
        return required[name] && !present;
      }).length,
      errors, warnings, independentlyVerified: 0,
    },
    limitation: "Dossier completion is an analytical synthesis of caller-supplied events and associations. It is not an authenticated approval, persistent case record, independent security verification or permission to execute changes.",
  };
}
export function parseIntegrityReviewDossierQuery(
  value: unknown,
): IntegrityReviewDossierQuery {
  const raw = record(value, "review dossier query");
  if (Object.keys(raw).some(x => ![
    "taskIds", "severities", "onlyIncomplete", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown dossier query field.");
  if (raw.onlyIncomplete !== undefined &&
      typeof raw.onlyIncomplete !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dossier filter.");
  const selectedSeverities = raw.severities === undefined ? undefined :
    identifiers(raw.severities, "dossier severities", 3);
  if (selectedSeverities?.some(x =>
    !["ERROR", "WARNING", "INFO"].includes(x)))
    throw new WorkInputError("INVALID", "Unknown dossier severity.");
  return {
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "dossier task IDs", 500),
    }),
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities,
    }),
    onlyIncomplete: raw.onlyIncomplete === true,
    offset: integer(raw.offset ?? 0, "dossier offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "dossier limit", 1, 500),
  };
}
export function queryIntegrityReviewDossier(
  report: IntegrityReviewDossier,
  query: IntegrityReviewDossierQuery,
): IntegrityReviewDossierPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.tasks.filter(x =>
    (!query.taskIds || query.taskIds.includes(x.taskId)) &&
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.onlyIncomplete || !x.analyticallyComplete));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    tasks: selected.slice(offset, offset + limit),
  };
}
