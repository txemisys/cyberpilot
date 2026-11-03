import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityReviewQueue,
  IntegrityCapacityReviewTask,
} from "./work-integrity-remediation-capacity-review-queue";

export type IntegrityReviewDisposition = "OPEN" | "ACKNOWLEDGED" |
  "IN_REVIEW" | "RESOLVED" | "WAIVED" | "REOPENED";
export type IntegrityReviewEventKind = "ACKNOWLEDGE" | "START_REVIEW" |
  "RESOLVE" | "WAIVE" | "REOPEN" | "ADD_NOTE";
export type IntegrityReviewEvent = {
  eventId: string;
  taskId: string;
  kind: IntegrityReviewEventKind;
  occurredAt: string;
  actorId: string;
  reason: string | null;
  evidenceRefs: string[];
  expectedVersion: number;
};
export type IntegrityReviewEventResult = {
  eventId: string;
  taskId: string;
  kind: IntegrityReviewEventKind;
  accepted: boolean;
  rejection: string | null;
  versionBefore: number;
  versionAfter: number;
  dispositionBefore: IntegrityReviewDisposition;
  dispositionAfter: IntegrityReviewDisposition;
};
export type IntegrityReviewTaskState = {
  taskId: string;
  disposition: IntegrityReviewDisposition;
  version: number;
  ownerId: string | null;
  lastActorId: string | null;
  lastChangedAt: string | null;
  resolutionReason: string | null;
  resolutionEvidenceRefs: string[];
  eventIds: string[];
  history: IntegrityReviewEventResult[];
  open: boolean;
  terminal: boolean;
  reviewRequired: boolean;
};
export type IntegrityReviewReplayPolicy = {
  rejectUnknownTasks: boolean;
  rejectDuplicateEvents: boolean;
  requireEvidenceForResolution: boolean;
  requireReasonForWaiver: boolean;
  allowWaiverOfErrors: boolean;
  maximumEvents: number;
  maximumEventsPerTask: number;
};
export type IntegrityReviewReplay = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewReplayPolicy;
  tasks: IntegrityReviewTaskState[];
  results: IntegrityReviewEventResult[];
  totals: {
    suppliedEvents: number;
    acceptedEvents: number;
    rejectedEvents: number;
    open: number;
    acknowledged: number;
    inReview: number;
    resolved: number;
    waived: number;
    reopened: number;
    requiredOutstanding: number;
    evidenceLinked: number;
    byRejection: Record<string, number>;
  };
  limitation: string;
};
export type IntegrityReviewReplayQuery = {
  dispositions?: IntegrityReviewDisposition[];
  onlyOutstanding?: boolean;
  taskIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityReviewReplayPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityReviewTaskState[];
};
const defaults: IntegrityReviewReplayPolicy = {
  rejectUnknownTasks: true,
  rejectDuplicateEvents: true,
  requireEvidenceForResolution: true,
  requireReasonForWaiver: true,
  allowWaiverOfErrors: false,
  maximumEvents: 2000,
  maximumEventsPerTask: 100,
};
const dispositions: IntegrityReviewDisposition[] = [
  "OPEN", "ACKNOWLEDGED", "IN_REVIEW",
  "RESOLVED", "WAIVED", "REOPENED",
];
const kinds: IntegrityReviewEventKind[] = [
  "ACKNOWLEDGE", "START_REVIEW", "RESOLVE",
  "WAIVE", "REOPEN", "ADD_NOTE",
];
function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim() || value.length > 300 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifiers(value: unknown, label: string, max: number): string[] {
  if (!Array.isArray(value) || value.length > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  const ids = value.map(x => identifier(x, label));
  if (new Set(ids).size !== ids.length)
    throw new WorkInputError("INVALID", "Duplicate " + label);
  return ids;
}
function date(value: unknown): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    throw new WorkInputError("INVALID", "Invalid review event timestamp.");
  return value;
}
export function parseIntegrityReviewReplayPolicy(value: unknown): IntegrityReviewReplayPolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "review replay policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown replay policy field.");
  const policy = { ...defaults };
  for (const key of [
    "rejectUnknownTasks", "rejectDuplicateEvents",
    "requireEvidenceForResolution", "requireReasonForWaiver",
    "allowWaiverOfErrors",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid replay policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumEvents !== undefined)
    policy.maximumEvents = integer(raw.maximumEvents, "maximum events", 1, 5000);
  if (raw.maximumEventsPerTask !== undefined)
    policy.maximumEventsPerTask = integer(raw.maximumEventsPerTask,
      "maximum events per task", 1, 500);
  return policy;
}
export function parseIntegrityReviewEvents(value: unknown): IntegrityReviewEvent[] {
  if (!Array.isArray(value) || value.length > 5000)
    throw new WorkInputError("INVALID", "Invalid review event list.");
  return value.map(entry => {
    const raw = record(entry, "review event");
    if (Object.keys(raw).some(x => ![
      "eventId", "taskId", "kind", "occurredAt",
      "actorId", "reason", "evidenceRefs", "expectedVersion",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown review event field.");
    if (!kinds.includes(raw.kind as IntegrityReviewEventKind))
      throw new WorkInputError("INVALID", "Unknown review event kind.");
    if (raw.reason !== undefined && raw.reason !== null &&
        (typeof raw.reason !== "string" || raw.reason.length > 2000 ||
          /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(raw.reason)))
      throw new WorkInputError("INVALID", "Invalid review event reason.");
    return {
      eventId: identifier(raw.eventId, "event ID"),
      taskId: identifier(raw.taskId, "task ID"),
      kind: raw.kind as IntegrityReviewEventKind,
      occurredAt: date(raw.occurredAt),
      actorId: identifier(raw.actorId, "actor ID"),
      reason: raw.reason === undefined ? null : raw.reason as string | null,
      evidenceRefs: identifiers(raw.evidenceRefs ?? [],
        "review evidence refs", 100),
      expectedVersion: integer(raw.expectedVersion,
        "expected event version", 0, 1000000),
    };
  });
}
function initial(task: IntegrityCapacityReviewTask): IntegrityReviewTaskState {
  return {
    taskId: task.taskId,
    disposition: "OPEN",
    version: 0,
    ownerId: null,
    lastActorId: null,
    lastChangedAt: null,
    resolutionReason: null,
    resolutionEvidenceRefs: [],
    eventIds: [],
    history: [],
    open: true,
    terminal: false,
    reviewRequired: task.reviewRequired,
  };
}
function transition(
  state: IntegrityReviewTaskState,
  task: IntegrityCapacityReviewTask,
  event: IntegrityReviewEvent,
  policy: IntegrityReviewReplayPolicy,
): string | null {
  const current = state.disposition;
  if (event.expectedVersion !== state.version) return "VERSION_CONFLICT";
  if (event.kind === "ACKNOWLEDGE" &&
      !["OPEN", "REOPENED"].includes(current)) return "INVALID_TRANSITION";
  if (event.kind === "START_REVIEW" &&
      !["ACKNOWLEDGED", "REOPENED"].includes(current))
    return "INVALID_TRANSITION";
  if (event.kind === "RESOLVE" && current !== "IN_REVIEW")
    return "INVALID_TRANSITION";
  if (event.kind === "WAIVE" &&
      !["ACKNOWLEDGED", "IN_REVIEW"].includes(current))
    return "INVALID_TRANSITION";
  if (event.kind === "REOPEN" &&
      !["RESOLVED", "WAIVED"].includes(current))
    return "INVALID_TRANSITION";
  if (event.kind === "ADD_NOTE" &&
      ["RESOLVED", "WAIVED"].includes(current))
    return "INVALID_TRANSITION";
  if (event.kind === "RESOLVE" &&
      policy.requireEvidenceForResolution && !event.evidenceRefs.length)
    return "MISSING_RESOLUTION_EVIDENCE";
  if (event.kind === "WAIVE" &&
      policy.requireReasonForWaiver && !event.reason?.trim())
    return "MISSING_WAIVER_REASON";
  if (event.kind === "WAIVE" && task.severity === "ERROR" &&
      !policy.allowWaiverOfErrors)
    return "ERROR_WAIVER_FORBIDDEN";
  if (["RESOLVE", "WAIVE", "REOPEN"].includes(event.kind) &&
      !event.reason?.trim())
    return "MISSING_TRANSITION_REASON";
  return null;
}
function dispositionAfter(
  before: IntegrityReviewDisposition,
  kind: IntegrityReviewEventKind,
): IntegrityReviewDisposition {
  switch (kind) {
    case "ACKNOWLEDGE": return "ACKNOWLEDGED";
    case "START_REVIEW": return "IN_REVIEW";
    case "RESOLVE": return "RESOLVED";
    case "WAIVE": return "WAIVED";
    case "REOPEN": return "REOPENED";
    case "ADD_NOTE": return before;
  }
}
export function replayIntegrityReviewEvents(
  queue: IntegrityCapacityReviewQueue,
  events: readonly IntegrityReviewEvent[],
  policy: IntegrityReviewReplayPolicy = defaults,
): IntegrityReviewReplay {
  if (events.length > policy.maximumEvents)
    throw new WorkInputError("INVALID", "Review event replay limit exceeded.");
  const tasks = new Map(queue.tasks.map(x => [x.taskId, x]));
  if (tasks.size !== queue.tasks.length)
    throw new WorkInputError("INVALID", "Duplicate review queue task.");
  const states = new Map(queue.tasks.map(x => [x.taskId, initial(x)]));
  const seen = new Set<string>();
  const results: IntegrityReviewEventResult[] = [];
  const perTask = new Map<string, number>();
  let lastTime = -Infinity;
  for (const event of events) {
    const task = tasks.get(event.taskId);
    const state = states.get(event.taskId);
    const before = state?.disposition ?? "OPEN";
    const versionBefore = state?.version ?? 0;
    let rejection: string | null = null;
    if (seen.has(event.eventId))
      rejection = "DUPLICATE_EVENT";
    else if (!task || !state)
      rejection = "UNKNOWN_TASK";
    else if ((perTask.get(event.taskId) ?? 0) >=
        policy.maximumEventsPerTask)
      rejection = "TASK_EVENT_LIMIT";
    else if (Date.parse(event.occurredAt) < lastTime)
      rejection = "EVENT_TIME_REGRESSION";
    else
      rejection = transition(state, task, event, policy);
    seen.add(event.eventId);
    const accepted = rejection === null;
    if (accepted && state) {
      state.disposition = dispositionAfter(state.disposition, event.kind);
      state.version++;
      state.lastActorId = event.actorId;
      state.lastChangedAt = event.occurredAt;
      state.eventIds.push(event.eventId);
      if (event.kind === "ACKNOWLEDGE") state.ownerId = event.actorId;
      if (event.kind === "REOPEN") {
        state.resolutionReason = null;
        state.resolutionEvidenceRefs = [];
      }
      if (event.kind === "RESOLVE" || event.kind === "WAIVE") {
        state.resolutionReason = event.reason;
        state.resolutionEvidenceRefs = [...event.evidenceRefs];
      }
      state.terminal = ["RESOLVED", "WAIVED"].includes(state.disposition);
      state.open = !state.terminal;
      perTask.set(event.taskId, (perTask.get(event.taskId) ?? 0) + 1);
      lastTime = Date.parse(event.occurredAt);
    }
    const result: IntegrityReviewEventResult = {
      eventId: event.eventId, taskId: event.taskId,
      kind: event.kind, accepted, rejection,
      versionBefore,
      versionAfter: state?.version ?? 0,
      dispositionBefore: before,
      dispositionAfter: state?.disposition ?? before,
    };
    results.push(result);
    if (state) state.history.push(result);
  }
  const all = [...states.values()];
  const count = (disposition: IntegrityReviewDisposition) =>
    all.filter(x => x.disposition === disposition).length;
  const byRejection: Record<string, number> = {};
  for (const result of results) {
    if (result.rejection)
      byRejection[result.rejection] =
        (byRejection[result.rejection] ?? 0) + 1;
  }
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: queue.evaluatedAt,
    policy, tasks: all, results,
    totals: {
      suppliedEvents: events.length,
      acceptedEvents: results.filter(x => x.accepted).length,
      rejectedEvents: results.filter(x => !x.accepted).length,
      open: count("OPEN"),
      acknowledged: count("ACKNOWLEDGED"),
      inReview: count("IN_REVIEW"),
      resolved: count("RESOLVED"),
      waived: count("WAIVED"),
      reopened: count("REOPENED"),
      requiredOutstanding: all.filter(x =>
        x.reviewRequired && !x.terminal).length,
      evidenceLinked: new Set(all.flatMap(x =>
        x.resolutionEvidenceRefs)).size,
      byRejection,
    },
    limitation: "This is a deterministic replay of caller-supplied events. Actor identities and evidence references are not independently authenticated; no state is persisted or authorization granted.",
  };
}
export function parseIntegrityReviewReplayQuery(
  value: unknown,
): IntegrityReviewReplayQuery {
  const raw = record(value, "review replay query");
  if (Object.keys(raw).some(x => ![
    "dispositions", "onlyOutstanding", "taskIds", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown replay query field.");
  const selected = raw.dispositions === undefined ? undefined :
    identifiers(raw.dispositions, "review dispositions", dispositions.length);
  if (selected?.some(x => !dispositions.includes(
    x as IntegrityReviewDisposition)))
    throw new WorkInputError("INVALID", "Unknown review disposition.");
  if (raw.onlyOutstanding !== undefined &&
      typeof raw.onlyOutstanding !== "boolean")
    throw new WorkInputError("INVALID", "Invalid outstanding flag.");
  return {
    ...(selected === undefined ? {} : {
      dispositions: selected as IntegrityReviewDisposition[],
    }),
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "review task IDs", 500),
    }),
    onlyOutstanding: raw.onlyOutstanding === true,
    offset: integer(raw.offset ?? 0, "review replay offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "review replay limit", 1, 500),
  };
}
export function queryIntegrityReviewReplay(
  report: IntegrityReviewReplay,
  query: IntegrityReviewReplayQuery,
): IntegrityReviewReplayPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const tasks = report.tasks.filter(x =>
    (!query.dispositions || query.dispositions.includes(x.disposition)) &&
    (!query.onlyOutstanding || !x.terminal) &&
    (!query.taskIds || query.taskIds.includes(x.taskId)));
  return {
    captureId: report.captureId,
    total: tasks.length,
    offset, limit,
    hasMore: offset + limit < tasks.length,
    tasks: tasks.slice(offset, offset + limit),
  };
}
