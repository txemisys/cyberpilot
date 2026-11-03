import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityReviewEvent, IntegrityReviewReplay } from "./work-integrity-remediation-review-event-replay";

export type IntegrityReviewEvidenceAssociation = {
  associationId: string;
  captureId: string;
  taskId: string;
  reference: string;
  workItemId: string | null;
  caseKey: string | null;
  recordedAt: string;
  withdrawnAt: string | null;
  source: "LINK_AUDIT" | "IMPORTED_MANIFEST";
};
export type IntegrityReviewEvidenceFindingCode =
  | "REFERENCE_NOT_REGISTERED" | "REFERENCE_WITHDRAWN"
  | "REFERENCE_REGISTERED_AFTER_REVIEW" | "REFERENCE_WRONG_TASK"
  | "REFERENCE_WRONG_CAPTURE" | "DUPLICATE_ASSOCIATION"
  | "CONFLICTING_ASSOCIATION" | "MISSING_RESOLUTION_REFERENCE"
  | "UNACCEPTED_RESOLUTION_EVENT" | "REFERENCE_REUSED_ACROSS_TASKS"
  | "ASSOCIATION_WITHOUT_REVIEW" | "WITHDRAWAL_BEFORE_LINK";
export type IntegrityReviewEvidenceFinding = {
  code: IntegrityReviewEvidenceFindingCode;
  severity: "ERROR" | "WARNING";
  taskId: string | null;
  reference: string | null;
  associationId: string | null;
  eventId: string | null;
  detail: string;
};
export type IntegrityReviewEvidenceReference = {
  taskId: string;
  reference: string;
  eventId: string;
  associationId: string | null;
  status: "ACTIVE" | "WITHDRAWN" | "UNKNOWN" |
    "CROSS_TASK" | "CROSS_CAPTURE" | "FUTURE" | "AMBIGUOUS";
  recordedAt: string | null;
  withdrawnAt: string | null;
  associatedCaseKey: string | null;
  associatedWorkItemId: string | null;
  submittedAt: string;
  evidenceAssociated: boolean;
  independentlyVerified: false;
};
export type IntegrityReviewEvidenceTask = {
  taskId: string;
  disposition: string;
  submittedReferences: number;
  activeReferences: number;
  withdrawnReferences: number;
  unknownReferences: number;
  crossTaskReferences: number;
  crossCaptureReferences: number;
  findings: IntegrityReviewEvidenceFinding[];
  provenanceComplete: boolean;
  independentlyVerified: false;
};
export type IntegrityReviewEvidenceReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  references: IntegrityReviewEvidenceReference[];
  tasks: IntegrityReviewEvidenceTask[];
  findings: IntegrityReviewEvidenceFinding[];
  totals: {
    registeredAssociations: number;
    resolutionEvents: number;
    submittedReferences: number;
    activeReferences: number;
    withdrawnReferences: number;
    unknownReferences: number;
    crossTaskReferences: number;
    crossCaptureReferences: number;
    findings: number;
    errors: number;
    warnings: number;
    completeTasks: number;
    independentlyVerifiedTasks: 0;
  };
  limitation: string;
};
export type IntegrityReviewEvidenceQuery = {
  taskIds?: string[];
  statuses?: IntegrityReviewEvidenceReference["status"][];
  onlyMismatches?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityReviewEvidencePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  references: IntegrityReviewEvidenceReference[];
};
const statuses: IntegrityReviewEvidenceReference["status"][] = [
  "ACTIVE", "WITHDRAWN", "UNKNOWN", "CROSS_TASK",
  "CROSS_CAPTURE", "FUTURE", "AMBIGUOUS",
];
function record(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function identifier(value: unknown, label: string) {
  if (typeof value !== "string" || !value.trim() || value.length > 300 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function optionalId(value: unknown, label: string) {
  return value === undefined || value === null ? null : identifier(value, label);
}
function timestamp(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
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
export function parseIntegrityReviewEvidenceAssociations(
  value: unknown,
): IntegrityReviewEvidenceAssociation[] {
  if (!Array.isArray(value) || value.length > 5000)
    throw new WorkInputError("INVALID", "Invalid review evidence associations.");
  return value.map(item => {
    const raw = record(item, "review evidence association");
    if (Object.keys(raw).some(x => ![
      "associationId", "captureId", "taskId", "reference",
      "workItemId", "caseKey", "recordedAt", "withdrawnAt", "source",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown evidence association field.");
    if (raw.source !== "LINK_AUDIT" && raw.source !== "IMPORTED_MANIFEST")
      throw new WorkInputError("INVALID", "Invalid association source.");
    return {
      associationId: identifier(raw.associationId, "association ID"),
      captureId: identifier(raw.captureId, "association capture ID"),
      taskId: identifier(raw.taskId, "association task ID"),
      reference: identifier(raw.reference, "association reference"),
      workItemId: optionalId(raw.workItemId, "work item ID"),
      caseKey: optionalId(raw.caseKey, "case key"),
      recordedAt: timestamp(raw.recordedAt, "association timestamp"),
      withdrawnAt: raw.withdrawnAt === undefined ||
        raw.withdrawnAt === null ? null :
        timestamp(raw.withdrawnAt, "withdrawal timestamp"),
      source: raw.source,
    };
  });
}
export function reconcileIntegrityReviewEvidence(
  queue: IntegrityCapacityReviewQueue,
  replay: IntegrityReviewReplay,
  events: readonly IntegrityReviewEvent[],
  associations: readonly IntegrityReviewEvidenceAssociation[],
): IntegrityReviewEvidenceReport {
  if (queue.captureId !== replay.captureId)
    throw new WorkInputError("INVALID", "Review evidence capture mismatch.");
  const tasks = new Set(queue.tasks.map(x => x.taskId));
  const accepted = new Set(replay.results.filter(x =>
    x.accepted).map(x => x.eventId));
  const findings: IntegrityReviewEvidenceFinding[] = [];
  const add = (
    code: IntegrityReviewEvidenceFindingCode,
    severity: "ERROR" | "WARNING",
    taskId: string | null,
    reference: string | null,
    associationId: string | null,
    eventId: string | null,
    detail: string,
  ) => findings.push({
    code, severity, taskId, reference, associationId, eventId, detail,
  });
  const byReference = new Map<string, IntegrityReviewEvidenceAssociation[]>();
  const seenAssociations = new Set<string>();
  for (const association of associations) {
    if (seenAssociations.has(association.associationId))
      add("DUPLICATE_ASSOCIATION", "ERROR", association.taskId,
        association.reference, association.associationId, null,
        "An association identifier appears more than once.");
    seenAssociations.add(association.associationId);
    if (association.withdrawnAt !== null &&
        Date.parse(association.withdrawnAt) <
          Date.parse(association.recordedAt))
      add("WITHDRAWAL_BEFORE_LINK", "ERROR", association.taskId,
        association.reference, association.associationId, null,
        "Withdrawal precedes the association.");
    const entries = byReference.get(association.reference) ?? [];
    entries.push(association);
    byReference.set(association.reference, entries);
  }
  for (const [reference, entries] of byReference) {
    const identities = new Set(entries.map(x =>
      x.captureId + "\u0000" + x.taskId));
    if (identities.size > 1)
      add("CONFLICTING_ASSOCIATION", "ERROR", null, reference,
        null, null, "The reference has associations with different tasks or captures.");
  }
  const references: IntegrityReviewEvidenceReference[] = [];
  const resolutionEvents = events.filter(x =>
    x.kind === "RESOLVE" || x.kind === "WAIVE");
  const referencedAssociations = new Set<string>();
  const usage = new Map<string, Set<string>>();
  for (const event of resolutionEvents) {
    if (!accepted.has(event.eventId)) {
      add("UNACCEPTED_RESOLUTION_EVENT", "WARNING", event.taskId,
        null, null, event.eventId,
        "A rejected resolution or waiver event cannot establish review completion.");
      continue;
    }
    if (event.kind === "RESOLVE" && !event.evidenceRefs.length)
      add("MISSING_RESOLUTION_REFERENCE", "ERROR", event.taskId,
        null, null, event.eventId, "Resolution has no evidence references.");
    for (const reference of event.evidenceRefs) {
      const entries = byReference.get(reference) ?? [];
      const own = entries.filter(x =>
        x.captureId === queue.captureId && x.taskId === event.taskId);
      const crossCapture = entries.some(x =>
        x.captureId !== queue.captureId);
      const crossTask = entries.some(x =>
        x.captureId === queue.captureId && x.taskId !== event.taskId);
      const matching = own.filter(x =>
        Date.parse(x.recordedAt) <= Date.parse(event.occurredAt));
      const active = matching.filter(x => x.withdrawnAt === null ||
        Date.parse(x.withdrawnAt) > Date.parse(event.occurredAt));
      let status: IntegrityReviewEvidenceReference["status"];
      let selected: IntegrityReviewEvidenceAssociation | null = null;
      if (own.length > 1 || active.length > 1)
        status = "AMBIGUOUS";
      else if (active.length === 1) {
        status = "ACTIVE";
        selected = active[0]!;
      } else if (matching.length) {
        status = "WITHDRAWN";
        selected = matching[0]!;
      } else if (own.length)
        status = "FUTURE";
      else if (crossCapture)
        status = "CROSS_CAPTURE";
      else if (crossTask)
        status = "CROSS_TASK";
      else
        status = "UNKNOWN";
      if (selected) referencedAssociations.add(selected.associationId);
      if (status !== "ACTIVE") {
        const code: IntegrityReviewEvidenceFindingCode =
          status === "WITHDRAWN" ? "REFERENCE_WITHDRAWN" :
          status === "FUTURE" ? "REFERENCE_REGISTERED_AFTER_REVIEW" :
          status === "CROSS_CAPTURE" ? "REFERENCE_WRONG_CAPTURE" :
          status === "CROSS_TASK" ? "REFERENCE_WRONG_TASK" :
          status === "AMBIGUOUS" ? "CONFLICTING_ASSOCIATION" :
          "REFERENCE_NOT_REGISTERED";
        add(code, "ERROR", event.taskId, reference,
          selected?.associationId ?? null, event.eventId,
          "The submitted reference has no unambiguous active association for this task at review time.");
      }
      const used = usage.get(reference) ?? new Set<string>();
      used.add(event.taskId);
      usage.set(reference, used);
      references.push({
        taskId: event.taskId, reference, eventId: event.eventId,
        associationId: selected?.associationId ?? null,
        status, recordedAt: selected?.recordedAt ?? null,
        withdrawnAt: selected?.withdrawnAt ?? null,
        associatedCaseKey: selected?.caseKey ?? null,
        associatedWorkItemId: selected?.workItemId ?? null,
        submittedAt: event.occurredAt,
        evidenceAssociated: status === "ACTIVE",
        independentlyVerified: false,
      });
    }
  }
  for (const [reference, used] of usage)
    if (used.size > 1)
      add("REFERENCE_REUSED_ACROSS_TASKS", "WARNING", null,
        reference, null, null,
        "The same evidence reference was submitted for multiple review tasks.");
  for (const association of associations)
    if (tasks.has(association.taskId) &&
        !referencedAssociations.has(association.associationId))
      add("ASSOCIATION_WITHOUT_REVIEW", "WARNING",
        association.taskId, association.reference,
        association.associationId, null,
        "The registered association was not used in an accepted review event.");
  const taskReports: IntegrityReviewEvidenceTask[] = queue.tasks.map(task => {
    const relevant = references.filter(x => x.taskId === task.taskId);
    const taskFindings = findings.filter(x =>
      x.taskId === task.taskId);
    const state = replay.tasks.find(x => x.taskId === task.taskId);
    return {
      taskId: task.taskId,
      disposition: state?.disposition ?? "UNKNOWN",
      submittedReferences: relevant.length,
      activeReferences: relevant.filter(x =>
        x.status === "ACTIVE").length,
      withdrawnReferences: relevant.filter(x =>
        x.status === "WITHDRAWN").length,
      unknownReferences: relevant.filter(x =>
        x.status === "UNKNOWN").length,
      crossTaskReferences: relevant.filter(x =>
        x.status === "CROSS_TASK").length,
      crossCaptureReferences: relevant.filter(x =>
        x.status === "CROSS_CAPTURE").length,
      findings: taskFindings,
      provenanceComplete: state?.disposition === "RESOLVED" &&
        relevant.length > 0 &&
        relevant.every(x => x.status === "ACTIVE") &&
        !taskFindings.some(x => x.severity === "ERROR"),
      independentlyVerified: false,
    };
  });
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: queue.evaluatedAt,
    references, tasks: taskReports, findings,
    totals: {
      registeredAssociations: associations.length,
      resolutionEvents: resolutionEvents.length,
      submittedReferences: references.length,
      activeReferences: references.filter(x =>
        x.status === "ACTIVE").length,
      withdrawnReferences: references.filter(x =>
        x.status === "WITHDRAWN").length,
      unknownReferences: references.filter(x =>
        x.status === "UNKNOWN").length,
      crossTaskReferences: references.filter(x =>
        x.status === "CROSS_TASK").length,
      crossCaptureReferences: references.filter(x =>
        x.status === "CROSS_CAPTURE").length,
      findings: findings.length,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
      completeTasks: taskReports.filter(x =>
        x.provenanceComplete).length,
      independentlyVerifiedTasks: 0,
    },
    limitation: "Associations and review events are caller-supplied; matching an active association does not authenticate its source, establish evidence integrity, or verify security remediation.",
  };
}
export function parseIntegrityReviewEvidenceQuery(
  value: unknown,
): IntegrityReviewEvidenceQuery {
  const raw = record(value, "review evidence query");
  if (Object.keys(raw).some(x => ![
    "taskIds", "statuses", "onlyMismatches", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown evidence query field.");
  const selected = raw.statuses === undefined ? undefined :
    identifiers(raw.statuses, "evidence statuses", statuses.length);
  if (selected?.some(x => !statuses.includes(
    x as IntegrityReviewEvidenceReference["status"])))
    throw new WorkInputError("INVALID", "Unknown evidence status.");
  if (raw.onlyMismatches !== undefined &&
      typeof raw.onlyMismatches !== "boolean")
    throw new WorkInputError("INVALID", "Invalid evidence mismatch filter.");
  return {
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "evidence task IDs", 500),
    }),
    ...(selected === undefined ? {} : {
      statuses: selected as IntegrityReviewEvidenceReference["status"][],
    }),
    onlyMismatches: raw.onlyMismatches === true,
    offset: integer(raw.offset ?? 0, "evidence offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "evidence limit", 1, 500),
  };
}
export function queryIntegrityReviewEvidence(
  report: IntegrityReviewEvidenceReport,
  query: IntegrityReviewEvidenceQuery,
): IntegrityReviewEvidencePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.references.filter(x =>
    (!query.taskIds || query.taskIds.includes(x.taskId)) &&
    (!query.statuses || query.statuses.includes(x.status)) &&
    (!query.onlyMismatches || x.status !== "ACTIVE"));
  return {
    captureId: report.captureId,
    total: selected.length,
    offset, limit,
    hasMore: offset + limit < selected.length,
    references: selected.slice(offset, offset + limit),
  };
}
