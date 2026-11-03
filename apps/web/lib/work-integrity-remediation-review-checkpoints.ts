import { WorkInputError } from "./remediation-work-input";
import {
  replayIntegrityReviewEvents,
  type IntegrityReviewEvent,
  type IntegrityReviewReplayPolicy,
  type IntegrityReviewTaskState,
} from "./work-integrity-remediation-review-event-replay";
import type {
  IntegrityCapacityReviewQueue,
} from "./work-integrity-remediation-capacity-review-queue";

export type IntegrityReviewCheckpoint = {
  checkpointId: string;
  eventCount: number;
  evaluatedAt: string;
};
export type IntegrityReviewCheckpointSnapshot = {
  checkpointId: string;
  eventCount: number;
  evaluatedAt: string;
  accepted: number;
  rejected: number;
  requiredOutstanding: number;
  resolved: number;
  waived: number;
  open: number;
  completionPercent: number;
  rejectedEventIds: string[];
  outstandingTaskIds: string[];
  completedTaskIds: string[];
};
export type IntegrityReviewCheckpointChange = {
  fromCheckpointId: string;
  toCheckpointId: string;
  acceptedDelta: number;
  rejectedDelta: number;
  requiredOutstandingDelta: number;
  resolvedDelta: number;
  waivedDelta: number;
  newlyCompletedTaskIds: string[];
  newlyOutstandingTaskIds: string[];
  regressed: boolean;
  regressionReasons: string[];
};
export type IntegrityReviewCheckpointReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  checkpoints: IntegrityReviewCheckpointSnapshot[];
  changes: IntegrityReviewCheckpointChange[];
  totals: {
    checkpoints: number;
    changes: number;
    regressions: number;
    maximumRequiredOutstanding: number;
    minimumRequiredOutstanding: number;
    finalRequiredOutstanding: number;
    finalCompletionPercent: number;
    newlyCompletedAcrossHistory: number;
    distinctRejectedEventIds: number;
  };
  limitation: string;
};
export type IntegrityReviewCheckpointQuery = {
  checkpointIds?: string[];
  onlyRegressions?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityReviewCheckpointPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  changes: IntegrityReviewCheckpointChange[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid review checkpoint query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function ids(value: unknown, label: string, max: number): string[] {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityReviewCheckpoints(
  value: unknown,
): IntegrityReviewCheckpoint[] {
  if (!Array.isArray(value) || !value.length || value.length > 100)
    throw new WorkInputError("INVALID", "Invalid review checkpoints.");
  const checkpoints = value.map(entry => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new WorkInputError("INVALID", "Invalid review checkpoint.");
    const raw = entry as Record<string, unknown>;
    if (Object.keys(raw).some(x => ![
      "checkpointId", "eventCount", "evaluatedAt",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown checkpoint field.");
    if (typeof raw.checkpointId !== "string" ||
        !raw.checkpointId || raw.checkpointId.length > 150 ||
        /[\u0000-\u001f\u007f]/.test(raw.checkpointId))
      throw new WorkInputError("INVALID", "Invalid checkpoint ID.");
    if (typeof raw.evaluatedAt !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(raw.evaluatedAt) ||
        !Number.isFinite(Date.parse(raw.evaluatedAt)))
      throw new WorkInputError("INVALID", "Invalid checkpoint time.");
    return {
      checkpointId: raw.checkpointId,
      eventCount: integer(raw.eventCount, "checkpoint event count", 0, 5000),
      evaluatedAt: raw.evaluatedAt,
    };
  });
  if (new Set(checkpoints.map(x => x.checkpointId)).size !==
      checkpoints.length)
    throw new WorkInputError("INVALID", "Duplicate checkpoint ID.");
  for (let index = 1; index < checkpoints.length; index++) {
    if (checkpoints[index]!.eventCount <
        checkpoints[index - 1]!.eventCount ||
        Date.parse(checkpoints[index]!.evaluatedAt) <
        Date.parse(checkpoints[index - 1]!.evaluatedAt))
      throw new WorkInputError("INVALID", "Checkpoints must be chronological.");
  }
  return checkpoints;
}
function complete(state: IntegrityReviewTaskState) {
  return state.terminal;
}
export function buildIntegrityReviewCheckpointHistory(
  queue: IntegrityCapacityReviewQueue,
  events: readonly IntegrityReviewEvent[],
  checkpoints: readonly IntegrityReviewCheckpoint[],
  policy: IntegrityReviewReplayPolicy,
): IntegrityReviewCheckpointReport {
  if (!checkpoints.length || checkpoints.length > 100)
    throw new WorkInputError("INVALID", "Invalid checkpoint count.");
  const seen = new Set<string>();
  const snapshots: IntegrityReviewCheckpointSnapshot[] = [];
  const completed = new Set<string>();
  for (const checkpoint of checkpoints) {
    if (seen.has(checkpoint.checkpointId))
      throw new WorkInputError("INVALID", "Duplicate checkpoint ID.");
    seen.add(checkpoint.checkpointId);
    if (checkpoint.eventCount > events.length)
      throw new WorkInputError("INVALID", "Checkpoint exceeds event count.");
    if (snapshots.length && checkpoint.eventCount <
        snapshots[snapshots.length - 1]!.eventCount)
      throw new WorkInputError("INVALID", "Checkpoint event count regression.");
    const replay = replayIntegrityReviewEvents(queue,
      events.slice(0, checkpoint.eventCount), policy);
    const outstandingTaskIds = replay.tasks.filter(x =>
      x.reviewRequired && !complete(x)).map(x => x.taskId).sort();
    const completedTaskIds = replay.tasks.filter(x =>
      x.reviewRequired && complete(x)).map(x => x.taskId).sort();
    for (const id of completedTaskIds) completed.add(id);
    const required = replay.tasks.filter(x => x.reviewRequired).length;
    snapshots.push({
      checkpointId: checkpoint.checkpointId,
      eventCount: checkpoint.eventCount,
      evaluatedAt: checkpoint.evaluatedAt,
      accepted: replay.totals.acceptedEvents,
      rejected: replay.totals.rejectedEvents,
      requiredOutstanding: outstandingTaskIds.length,
      resolved: replay.totals.resolved,
      waived: replay.totals.waived,
      open: replay.totals.open,
      completionPercent: required ?
        Math.round(100 * completedTaskIds.length / required) : 100,
      rejectedEventIds: replay.results.filter(x =>
        !x.accepted).map(x => x.eventId),
      outstandingTaskIds, completedTaskIds,
    });
  }
  const changes: IntegrityReviewCheckpointChange[] = [];
  for (let index = 1; index < snapshots.length; index++) {
    const before = snapshots[index - 1]!;
    const after = snapshots[index]!;
    const newlyCompletedTaskIds = after.completedTaskIds.filter(x =>
      !before.completedTaskIds.includes(x));
    const newlyOutstandingTaskIds = after.outstandingTaskIds.filter(x =>
      !before.outstandingTaskIds.includes(x));
    const reasons: string[] = [];
    if (newlyOutstandingTaskIds.length)
      reasons.push("PREVIOUSLY_COMPLETED_REVIEW_REOPENED");
    if (after.rejected > before.rejected)
      reasons.push("NEW_REJECTED_EVENTS");
    if (after.requiredOutstanding > before.requiredOutstanding)
      reasons.push("OUTSTANDING_REQUIRED_REVIEWS_INCREASED");
    changes.push({
      fromCheckpointId: before.checkpointId,
      toCheckpointId: after.checkpointId,
      acceptedDelta: after.accepted - before.accepted,
      rejectedDelta: after.rejected - before.rejected,
      requiredOutstandingDelta: after.requiredOutstanding -
        before.requiredOutstanding,
      resolvedDelta: after.resolved - before.resolved,
      waivedDelta: after.waived - before.waived,
      newlyCompletedTaskIds,
      newlyOutstandingTaskIds,
      regressed: reasons.length > 0,
      regressionReasons: reasons,
    });
  }
  const final = snapshots[snapshots.length - 1]!;
  return {
    schemaVersion: 1,
    captureId: queue.captureId,
    evaluatedAt: final.evaluatedAt,
    checkpoints: snapshots, changes,
    totals: {
      checkpoints: snapshots.length,
      changes: changes.length,
      regressions: changes.filter(x => x.regressed).length,
      maximumRequiredOutstanding: Math.max(...snapshots.map(x =>
        x.requiredOutstanding)),
      minimumRequiredOutstanding: Math.min(...snapshots.map(x =>
        x.requiredOutstanding)),
      finalRequiredOutstanding: final.requiredOutstanding,
      finalCompletionPercent: final.completionPercent,
      newlyCompletedAcrossHistory: completed.size,
      distinctRejectedEventIds: new Set(snapshots.flatMap(x =>
        x.rejectedEventIds)).size,
    },
    limitation: "Checkpoint history is a retrospective replay of unverified caller events, not a persisted audit log or proof of human action.",
  };
}
export function parseIntegrityReviewCheckpointQuery(
  value: unknown,
): IntegrityReviewCheckpointQuery {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "checkpointIds", "onlyRegressions", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown checkpoint query field.");
  if (raw.onlyRegressions !== undefined &&
      typeof raw.onlyRegressions !== "boolean")
    throw new WorkInputError("INVALID", "Invalid regression filter.");
  return {
    ...(raw.checkpointIds === undefined ? {} : {
      checkpointIds: ids(raw.checkpointIds, "checkpoint IDs", 100),
    }),
    onlyRegressions: raw.onlyRegressions === true,
    offset: integer(raw.offset ?? 0, "checkpoint offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "checkpoint limit", 1, 100),
  };
}
export function queryIntegrityReviewCheckpointHistory(
  report: IntegrityReviewCheckpointReport,
  query: IntegrityReviewCheckpointQuery,
): IntegrityReviewCheckpointPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const changes = report.changes.filter(x =>
    (!query.onlyRegressions || x.regressed) &&
    (!query.checkpointIds ||
      query.checkpointIds.includes(x.fromCheckpointId) ||
      query.checkpointIds.includes(x.toCheckpointId)));
  return {
    captureId: report.captureId,
    total: changes.length,
    offset, limit,
    hasMore: offset + limit < changes.length,
    changes: changes.slice(offset, offset + limit),
  };
}
