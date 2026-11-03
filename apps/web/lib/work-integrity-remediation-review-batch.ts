import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type {
  IntegrityReviewEvent, IntegrityReviewReplay,
} from "./work-integrity-remediation-review-event-replay";
import type { IntegrityReviewEvidenceReport } from "./work-integrity-remediation-review-evidence";

export type IntegrityReviewBatchFindingCode =
  | "DUPLICATE_EVENT_ID" | "EVENT_TIME_REGRESSION"
  | "EVENT_AFTER_EVALUATION" | "EVENT_BEFORE_CAPTURE"
  | "UNKNOWN_TASK" | "ACTOR_CHANGED_WITHOUT_HANDOFF"
  | "UNEXPECTED_VERSION" | "RESOLUTION_REFERENCE_NOT_ASSOCIATED"
  | "RESOLUTION_REFERENCE_WITHDRAWN" | "UNVERIFIED_RESOLUTION"
  | "TASK_NOT_REQUIRED" | "BATCH_LIMIT" | "REPLAY_REJECTION"
  | "CROSS_TASK_REFERENCE" | "MISSING_REVIEW_OWNER"
  | "COMPLETION_WITHOUT_ACKNOWLEDGMENT";
export type IntegrityReviewBatchFinding = {
  code: IntegrityReviewBatchFindingCode;
  severity: "ERROR" | "WARNING" | "INFO";
  eventId: string | null;
  taskId: string | null;
  detail: string;
  relatedReferences: string[];
};
export type IntegrityReviewBatchPolicy = {
  maximumBatchEvents: number;
  maximumDistinctTasks: number;
  rejectTimeRegression: boolean;
  rejectFutureEvents: boolean;
  rejectActorHandoff: boolean;
  requireEvidenceAssociation: boolean;
  requireIndependentVerification: boolean;
  rejectUnrequiredTaskChanges: boolean;
  rejectDuplicateReferencesAcrossTasks: boolean;
  rejectAnyReplayFailure: boolean;
};
export type IntegrityReviewBatchDecision = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewBatchPolicy;
  status: "REJECTED" | "REQUIRES_REVIEW" | "ANALYTICALLY_CONSISTENT";
  events: Array<{
    eventId: string;
    taskId: string;
    kind: string;
    replayAccepted: boolean;
    acceptedForAnalysis: boolean;
    findings: IntegrityReviewBatchFindingCode[];
  }>;
  findings: IntegrityReviewBatchFinding[];
  totals: {
    submitted: number;
    replayAccepted: number;
    analyticallyAccepted: number;
    rejected: number;
    affectedTasks: number;
    errors: number;
    warnings: number;
    info: number;
    unverifiedResolutions: number;
    referencesWithoutAssociation: number;
  };
  limitation: string;
};
export type IntegrityReviewBatchQuery = {
  severities?: IntegrityReviewBatchFinding["severity"][];
  codes?: IntegrityReviewBatchFindingCode[];
  taskIds?: string[];
  onlyErrors?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityReviewBatchPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  findings: IntegrityReviewBatchFinding[];
};
const defaults: IntegrityReviewBatchPolicy = {
  maximumBatchEvents: 2000,
  maximumDistinctTasks: 500,
  rejectTimeRegression: true,
  rejectFutureEvents: true,
  rejectActorHandoff: true,
  requireEvidenceAssociation: true,
  requireIndependentVerification: false,
  rejectUnrequiredTaskChanges: false,
  rejectDuplicateReferencesAcrossTasks: true,
  rejectAnyReplayFailure: true,
};
const codes: IntegrityReviewBatchFindingCode[] = [
  "DUPLICATE_EVENT_ID", "EVENT_TIME_REGRESSION",
  "EVENT_AFTER_EVALUATION", "EVENT_BEFORE_CAPTURE",
  "UNKNOWN_TASK", "ACTOR_CHANGED_WITHOUT_HANDOFF",
  "UNEXPECTED_VERSION", "RESOLUTION_REFERENCE_NOT_ASSOCIATED",
  "RESOLUTION_REFERENCE_WITHDRAWN", "UNVERIFIED_RESOLUTION",
  "TASK_NOT_REQUIRED", "BATCH_LIMIT", "REPLAY_REJECTION",
  "CROSS_TASK_REFERENCE", "MISSING_REVIEW_OWNER",
  "COMPLETION_WITHOUT_ACKNOWLEDGMENT",
];
const severities: IntegrityReviewBatchFinding["severity"][] = [
  "ERROR", "WARNING", "INFO",
];
function object(value: unknown, label: string) {
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
export function parseIntegrityReviewBatchPolicy(
  value: unknown,
): IntegrityReviewBatchPolicy {
  if (value === undefined) return { ...defaults };
  const raw = object(value, "review batch policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown review batch policy field.");
  const policy = { ...defaults };
  for (const key of [
    "rejectTimeRegression", "rejectFutureEvents", "rejectActorHandoff",
    "requireEvidenceAssociation", "requireIndependentVerification",
    "rejectUnrequiredTaskChanges", "rejectDuplicateReferencesAcrossTasks",
    "rejectAnyReplayFailure",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid batch policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumBatchEvents !== undefined)
    policy.maximumBatchEvents = integer(raw.maximumBatchEvents,
      "maximum batch events", 1, 5000);
  if (raw.maximumDistinctTasks !== undefined)
    policy.maximumDistinctTasks = integer(raw.maximumDistinctTasks,
      "maximum batch tasks", 1, 5000);
  return policy;
}
export function evaluateIntegrityReviewBatch(
  queue: IntegrityCapacityReviewQueue,
  events: readonly IntegrityReviewEvent[],
  replay: IntegrityReviewReplay,
  evidence: IntegrityReviewEvidenceReport | null,
  policy: IntegrityReviewBatchPolicy = defaults,
  evaluatedAt: string = replay.evaluatedAt,
): IntegrityReviewBatchDecision {
  if (queue.captureId !== replay.captureId ||
      (evidence && evidence.captureId !== queue.captureId))
    throw new WorkInputError("INVALID", "Review batch capture mismatch.");
  if (!Number.isFinite(Date.parse(evaluatedAt)))
    throw new WorkInputError("INVALID", "Invalid batch evaluation time.");
  const tasks = new Map(queue.tasks.map(x => [x.taskId, x]));
  const states = new Map(replay.tasks.map(x => [x.taskId, x]));
  const replayResults = new Map(replay.results.map(x => [x.eventId, x]));
  const evidenceRefs = new Map((evidence?.references ?? []).map(x =>
    [x.eventId + "\u0000" + x.reference, x]));
  const seen = new Set<string>();
  const actors = new Map<string, string>();
  const owners = new Map<string, string>();
  const referenceTasks = new Map<string, string>();
  const findings: IntegrityReviewBatchFinding[] = [];
  const eventFindings = new Map<string, IntegrityReviewBatchFindingCode[]>();
  const add = (
    code: IntegrityReviewBatchFindingCode,
    severity: IntegrityReviewBatchFinding["severity"],
    event: IntegrityReviewEvent | null,
    detail: string,
    relatedReferences: string[] = [],
  ) => {
    findings.push({
      code, severity, eventId: event?.eventId ?? null,
      taskId: event?.taskId ?? null, detail, relatedReferences,
    });
    if (event) {
      const existing = eventFindings.get(event.eventId) ?? [];
      existing.push(code);
      eventFindings.set(event.eventId, existing);
    }
  };
  if (events.length > policy.maximumBatchEvents)
    add("BATCH_LIMIT", "ERROR", null,
      "The event batch exceeds the configured limit.");
  if (new Set(events.map(x => x.taskId)).size >
      policy.maximumDistinctTasks)
    add("BATCH_LIMIT", "ERROR", null,
      "The batch spans too many distinct review tasks.");
  let lastTime = -Infinity;
  const captureTime = Date.parse(queue.evaluatedAt);
  const evaluationTime = Date.parse(evaluatedAt);
  for (const event of events) {
    const time = Date.parse(event.occurredAt);
    const task = tasks.get(event.taskId);
    const replayResult = replayResults.get(event.eventId);
    if (seen.has(event.eventId))
      add("DUPLICATE_EVENT_ID", "ERROR", event,
        "An event identifier occurs multiple times.");
    seen.add(event.eventId);
    if (!task)
      add("UNKNOWN_TASK", "ERROR", event,
        "The event references a task outside the review queue.");
    if (policy.rejectTimeRegression && time < lastTime)
      add("EVENT_TIME_REGRESSION", "ERROR", event,
        "Event timestamps must be nondecreasing.");
    if (policy.rejectFutureEvents && time > evaluationTime)
      add("EVENT_AFTER_EVALUATION", "ERROR", event,
        "The event was recorded after the evaluation time.");
    if (time < captureTime)
      add("EVENT_BEFORE_CAPTURE", "ERROR", event,
        "The event predates the capture being reviewed.");
    lastTime = Math.max(lastTime, time);
    if (!replayResult?.accepted && policy.rejectAnyReplayFailure)
      add("REPLAY_REJECTION", "ERROR", event,
        "The event was rejected by optimistic state replay.");
    if (replayResult && replayResult.versionBefore !==
        event.expectedVersion)
      add("UNEXPECTED_VERSION", "ERROR", event,
        "The expected version differs from the replayed task version.");
    if (task && !task.reviewRequired &&
        policy.rejectUnrequiredTaskChanges)
      add("TASK_NOT_REQUIRED", "WARNING", event,
        "The event modifies a task that was not required for review.");
    const owner = owners.get(event.taskId);
    if (event.kind === "ACKNOWLEDGE" && replayResult?.accepted)
      owners.set(event.taskId, event.actorId);
    const actor = actors.get(event.taskId);
    if (policy.rejectActorHandoff && actor &&
        actor !== event.actorId && replayResult?.accepted)
      add("ACTOR_CHANGED_WITHOUT_HANDOFF", "ERROR", event,
        "The actor changes without a modeled handoff authorization.");
    if (replayResult?.accepted)
      actors.set(event.taskId, event.actorId);
    if (event.kind === "RESOLVE" && replayResult?.accepted) {
      if (!owner && !states.get(event.taskId)?.ownerId)
        add("MISSING_REVIEW_OWNER", "ERROR", event,
          "The resolution has no acknowledged review owner.");
      if (!events.some(x => x.taskId === event.taskId &&
          x.kind === "ACKNOWLEDGE" && replayResults.get(x.eventId)?.accepted))
        add("COMPLETION_WITHOUT_ACKNOWLEDGMENT", "ERROR", event,
          "The resolution has no accepted acknowledgment.");
      for (const reference of event.evidenceRefs) {
        const associated = evidenceRefs.get(event.eventId +
          "\u0000" + reference);
        if (policy.requireEvidenceAssociation &&
            (!associated || associated.status !== "ACTIVE")) {
          add(associated?.status === "WITHDRAWN" ?
            "RESOLUTION_REFERENCE_WITHDRAWN" :
            "RESOLUTION_REFERENCE_NOT_ASSOCIATED", "ERROR", event,
            "The resolution reference has no active task-scoped association.",
            [reference]);
        }
        if (policy.requireIndependentVerification)
          add("UNVERIFIED_RESOLUTION", "ERROR", event,
            "Caller-supplied associations cannot independently verify remediation.",
            [reference]);
        const previousTask = referenceTasks.get(reference);
        if (policy.rejectDuplicateReferencesAcrossTasks &&
            previousTask && previousTask !== event.taskId)
          add("CROSS_TASK_REFERENCE", "ERROR", event,
            "The reference is reused for multiple review tasks.",
            [reference]);
        referenceTasks.set(reference, event.taskId);
      }
    }
  }
  const eventRows = events.map(event => {
    const related = eventFindings.get(event.eventId) ?? [];
    const accepted = replayResults.get(event.eventId)?.accepted === true;
    return {
      eventId: event.eventId, taskId: event.taskId,
      kind: event.kind, replayAccepted: accepted,
      acceptedForAnalysis: accepted && !related.some(code =>
        findings.some(x => x.eventId === event.eventId &&
          x.code === code && x.severity === "ERROR")),
      findings: related,
    };
  });
  const errors = findings.filter(x => x.severity === "ERROR").length;
  const warnings = findings.filter(x => x.severity === "WARNING").length;
  return {
    schemaVersion: 1, captureId: queue.captureId, evaluatedAt,
    policy,
    status: errors ? "REJECTED" : warnings ?
      "REQUIRES_REVIEW" : "ANALYTICALLY_CONSISTENT",
    events: eventRows, findings,
    totals: {
      submitted: events.length,
      replayAccepted: eventRows.filter(x => x.replayAccepted).length,
      analyticallyAccepted: eventRows.filter(x =>
        x.acceptedForAnalysis).length,
      rejected: eventRows.filter(x => !x.acceptedForAnalysis).length,
      affectedTasks: new Set(events.map(x => x.taskId)).size,
      errors, warnings,
      info: findings.filter(x => x.severity === "INFO").length,
      unverifiedResolutions: findings.filter(x =>
        x.code === "UNVERIFIED_RESOLUTION").length,
      referencesWithoutAssociation: findings.filter(x =>
        x.code === "RESOLUTION_REFERENCE_NOT_ASSOCIATED").length,
    },
    limitation: "Batch consistency validates caller-supplied events and associations only. It does not authenticate actors, persist decisions, or establish independently verified remediation.",
  };
}
export function parseIntegrityReviewBatchQuery(
  value: unknown,
): IntegrityReviewBatchQuery {
  const raw = object(value, "review batch query");
  if (Object.keys(raw).some(x => ![
    "severities", "codes", "taskIds", "onlyErrors",
    "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown review batch query field.");
  const selectedSeverities = raw.severities === undefined ? undefined :
    identifiers(raw.severities, "batch severities", severities.length);
  const selectedCodes = raw.codes === undefined ? undefined :
    identifiers(raw.codes, "batch codes", codes.length);
  if (selectedSeverities?.some(x => !severities.includes(
    x as IntegrityReviewBatchFinding["severity"])) ||
      selectedCodes?.some(x => !codes.includes(
        x as IntegrityReviewBatchFindingCode)))
    throw new WorkInputError("INVALID", "Unknown batch query filter.");
  if (raw.onlyErrors !== undefined &&
      typeof raw.onlyErrors !== "boolean")
    throw new WorkInputError("INVALID", "Invalid batch error filter.");
  return {
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities as IntegrityReviewBatchFinding["severity"][],
    }),
    ...(selectedCodes === undefined ? {} : {
      codes: selectedCodes as IntegrityReviewBatchFindingCode[],
    }),
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "batch task IDs", 500),
    }),
    onlyErrors: raw.onlyErrors === true,
    offset: integer(raw.offset ?? 0, "batch offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "batch limit", 1, 500),
  };
}
export function queryIntegrityReviewBatch(
  report: IntegrityReviewBatchDecision,
  query: IntegrityReviewBatchQuery,
): IntegrityReviewBatchPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.findings.filter(x =>
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.codes || query.codes.includes(x.code)) &&
    (!query.taskIds || (x.taskId !== null &&
      query.taskIds.includes(x.taskId))) &&
    (!query.onlyErrors || x.severity === "ERROR"));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    findings: selected.slice(offset, offset + limit),
  };
}
