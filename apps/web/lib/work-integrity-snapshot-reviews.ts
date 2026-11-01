import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

export type SnapshotReviewStatus = "PENDING" | "ACCEPTED" | "REJECTED" | "NEEDS_RECAPTURE";
export type SnapshotReviewEvent = {
  id: string;
  organizationId: string;
  source: string;
  capturedAt: string;
  reviewerId: string;
  reviewedAt: string;
  status: SnapshotReviewStatus;
  rationale: string;
  reference: string | null;
  expectedPreviousEventId: string | null;
};
export type SnapshotReviewState = {
  source: string;
  capturedAt: string;
  status: SnapshotReviewStatus;
  latestEventId: string | null;
  reviewerId: string | null;
  reviewedAt: string | null;
  rationale: string | null;
  history: SnapshotReviewEvent[];
  warnings: string[];
};
export type SnapshotReviewLedger = {
  organizationId: string;
  states: SnapshotReviewState[];
  eventCount: number;
  rejectedEvents: number;
  warnings: string[];
};
function text(value: string, label: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
    /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value.trim();
}
function timestamp(value: string, label: string): number {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error(`Invalid ${label}.`);
  return time;
}
function identity(source: string, capturedAt: string): string {
  return JSON.stringify([source, timestamp(capturedAt, "capture timestamp")]);
}
export function validateSnapshotReviewEvent(
  event: SnapshotReviewEvent, organizationId: string,
): SnapshotReviewEvent {
  if (event.organizationId !== organizationId)
    throw new Error("Cross-organization review event is forbidden.");
  const id = text(event.id, "event ID", 256);
  const source = text(event.source, "source", 1000);
  const reviewerId = text(event.reviewerId, "reviewer", 256);
  const rationale = text(event.rationale, "rationale", 4000);
  if (!["ACCEPTED", "REJECTED", "NEEDS_RECAPTURE"].includes(event.status))
    throw new Error("Review events must contain an explicit decision.");
  const reviewedAt = timestamp(event.reviewedAt, "review timestamp");
  const capturedAt = timestamp(event.capturedAt, "capture timestamp");
  if (reviewedAt < capturedAt) throw new Error("Review precedes capture.");
  if (event.reference !== null) text(event.reference, "reference", 1000);
  if (event.expectedPreviousEventId !== null)
    text(event.expectedPreviousEventId, "previous event ID", 256);
  return { ...event, id, source, reviewerId, rationale };
}
export function buildSnapshotReviewLedger(
  input: readonly unknown[], events: readonly SnapshotReviewEvent[],
  organizationId: string,
): SnapshotReviewLedger {
  if (input.length > 10000 || events.length > 50000)
    throw new Error("Snapshot review ledger cardinality exceeded.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const captureByKey = new Map<string, CaseSnapshot>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization review capture is forbidden.");
    const key = identity(capture.source, capture.capturedAt);
    if (captureByKey.has(key)) throw new Error("Duplicate review capture identity.");
    captureByKey.set(key, capture);
  }
  const eventIds = new Set<string>();
  const grouped = new Map<string, SnapshotReviewEvent[]>();
  for (const raw of events) {
    const event = validateSnapshotReviewEvent(raw, organizationId);
    if (eventIds.has(event.id)) throw new Error("Duplicate review event ID.");
    eventIds.add(event.id);
    const key = identity(event.source, event.capturedAt);
    if (!captureByKey.has(key)) throw new Error("Review references an unknown capture.");
    const group = grouped.get(key) ?? [];
    group.push(event);
    grouped.set(key, group);
  }
  let rejectedEvents = 0;
  const states: SnapshotReviewState[] = [];
  for (const [key, capture] of captureByKey) {
    const history = (grouped.get(key) ?? []).sort((a, b) =>
      timestamp(a.reviewedAt, "review timestamp") -
      timestamp(b.reviewedAt, "review timestamp") || a.id.localeCompare(b.id));
    let previousId: string | null = null;
    for (const event of history) {
      if (event.expectedPreviousEventId !== previousId)
        throw new Error("Review history optimistic concurrency conflict.");
      previousId = event.id;
      if (event.status === "REJECTED") rejectedEvents++;
    }
    const latest = history.at(-1);
    const quality = inspectCaptureQuality(capture);
    const warnings: string[] = [];
    if (latest?.status === "ACCEPTED" && !quality.safeToTreatAsComplete)
      warnings.push("Accepted capture has unresolved quality or coverage limitations.");
    if (latest?.status === "ACCEPTED" && !capture.complete)
      warnings.push("Acceptance does not change the capture's incomplete coverage.");
    states.push({
      source: capture.source, capturedAt: capture.capturedAt,
      status: latest?.status ?? "PENDING",
      latestEventId: latest?.id ?? null,
      reviewerId: latest?.reviewerId ?? null,
      reviewedAt: latest?.reviewedAt ?? null,
      rationale: latest?.rationale ?? null, history, warnings,
    });
  }
  states.sort((a, b) => a.source.localeCompare(b.source) ||
    b.capturedAt.localeCompare(a.capturedAt));
  return {
    organizationId, states, eventCount: events.length, rejectedEvents,
    warnings: [
      "The review ledger is reconstructed from supplied events; persistence and event authenticity must be enforced by the caller.",
      "Review acceptance is not a security-control verification or finding closure.",
    ],
  };
}
export function appendSnapshotReviewEvent(
  ledger: SnapshotReviewLedger, event: SnapshotReviewEvent,
): SnapshotReviewLedger {
  validateSnapshotReviewEvent(event, ledger.organizationId);
  const state = ledger.states.find(item => item.source === event.source &&
    Date.parse(item.capturedAt) === Date.parse(event.capturedAt));
  if (!state) throw new Error("Unknown capture for review event.");
  if (state.latestEventId !== event.expectedPreviousEventId)
    throw new Error("Stale snapshot review revision.");
  if (ledger.states.some(item => item.history.some(previous => previous.id === event.id)))
    throw new Error("Duplicate snapshot review event.");
  const nextHistory = [...state.history, event];
  const nextState: SnapshotReviewState = {
    ...state, status: event.status, latestEventId: event.id,
    reviewerId: event.reviewerId, reviewedAt: event.reviewedAt,
    rationale: event.rationale, history: nextHistory,
    warnings: event.status === "ACCEPTED" ? state.warnings : [],
  };
  return {
    ...ledger, eventCount: ledger.eventCount + 1,
    rejectedEvents: ledger.rejectedEvents + (event.status === "REJECTED" ? 1 : 0),
    states: ledger.states.map(item => item === state ? nextState : item),
  };
}
