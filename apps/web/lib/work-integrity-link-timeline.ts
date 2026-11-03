import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, buildIntegrityReviewMatrix,
  type LinkReviewAssociation, type LinkReviewFinding,
} from "./work-integrity-link-review";

export type IntegrityReviewSnapshot = {
  schemaVersion: 1;
  captureId: string;
  asOf: string;
  totalEvents: number;
  active: number;
  withdrawn: number;
  findings: LinkReviewFinding[];
  associations: LinkReviewAssociation[];
};
export type IntegrityReviewInterval = {
  from: string;
  to: string;
  openingActive: number;
  closingActive: number;
  linksCreated: number;
  linksWithdrawn: number;
  netChange: number;
  casesChanged: string[];
  workItemsChanged: string[];
};
export type IntegrityReviewTimeline = {
  captureId: string;
  intervals: IntegrityReviewInterval[];
  finalActive: number;
};
const timestamp = (value: string): string => {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid review timestamp.");
  return value;
};
function ordered(values: readonly string[]) {
  return [...new Set(values)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}
export function snapshotIntegrityReview(
  captureId: string, events: readonly IntegrityLinkHistoryEvent[], asOf: string,
): IntegrityReviewSnapshot {
  timestamp(asOf);
  const visible = events.filter(x => x.occurredAt <= asOf);
  const report = reviewIntegrityLinks(captureId, visible);
  return {
    schemaVersion: 1, captureId, asOf, totalEvents: report.totalEvents,
    active: report.counts.active, withdrawn: report.counts.withdrawn,
    findings: report.findings, associations: report.associations,
  };
}
export function compareIntegritySnapshots(
  before: IntegrityReviewSnapshot, after: IntegrityReviewSnapshot,
): IntegrityReviewInterval {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare different captures.");
  if (before.asOf > after.asOf)
    throw new WorkInputError("INVALID", "Snapshot dates must be ascending.");
  const old = new Map(before.associations.map(x => [x.auditId, x]));
  const current = new Map(after.associations.map(x => [x.auditId, x]));
  const created: LinkReviewAssociation[] = [];
  const withdrawn: LinkReviewAssociation[] = [];
  for (const [id, item] of current) {
    const previous = old.get(id);
    if (!previous) {
      created.push(item);
      if (item.state === "WITHDRAWN") withdrawn.push(item);
    } else if (previous.state === "ACTIVE" && item.state === "WITHDRAWN") {
      withdrawn.push(item);
    } else if (previous.state === "WITHDRAWN" && item.state === "ACTIVE") {
      throw new WorkInputError("CONFLICT", "Withdrawal cannot be reversed.");
    }
  }
  for (const [id, item] of old) {
    const next = current.get(id);
    if (!next || next.caseKey !== item.caseKey ||
        next.workItemId !== item.workItemId || next.createdAt !== item.createdAt)
      throw new WorkInputError("CONFLICT", "Immutable history changed.");
  }
  const changed = [...created, ...withdrawn];
  return {
    from: before.asOf, to: after.asOf,
    openingActive: before.active, closingActive: after.active,
    linksCreated: created.length, linksWithdrawn: withdrawn.length,
    netChange: created.length - withdrawn.length,
    casesChanged: ordered(changed.map(x => x.caseKey)),
    workItemsChanged: ordered(changed.map(x => x.workItemId)),
  };
}
export function buildIntegrityReviewTimeline(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  checkpoints: readonly string[],
): IntegrityReviewTimeline {
  if (!checkpoints.length || checkpoints.length > 366)
    throw new WorkInputError("INVALID", "Timeline requires 1–366 checkpoints.");
  const sorted = ordered(checkpoints.map(timestamp));
  if (sorted.length !== checkpoints.length)
    throw new WorkInputError("INVALID", "Duplicate timeline checkpoint.");
  const snapshots = sorted.map(at => snapshotIntegrityReview(captureId, events, at));
  const empty: IntegrityReviewSnapshot = {
    schemaVersion: 1, captureId, asOf: "1970-01-01T00:00:00.000Z",
    totalEvents: 0, active: 0, withdrawn: 0, findings: [], associations: [],
  };
  const intervals: IntegrityReviewInterval[] = [];
  let previous = empty;
  for (const snapshot of snapshots) {
    intervals.push(compareIntegritySnapshots(previous, snapshot));
    previous = snapshot;
  }
  return { captureId, intervals, finalActive: previous.active };
}
export function summarizeIntegrityReviewAt(
  captureId: string, events: readonly IntegrityLinkHistoryEvent[], asOf: string,
) {
  const snapshot = snapshotIntegrityReview(captureId, events, asOf);
  const report = reviewIntegrityLinks(captureId,
    events.filter(x => x.occurredAt <= asOf));
  const matrix = buildIntegrityReviewMatrix(report);
  return {
    captureId, asOf, totalEvents: snapshot.totalEvents,
    active: snapshot.active, withdrawn: snapshot.withdrawn,
    errors: snapshot.findings.filter(x => x.severity === "ERROR").length,
    warnings: snapshot.findings.filter(x => x.severity === "WARNING").length,
    cases: matrix.cases.length, workItems: matrix.workItems.length,
    actors: matrix.actors.length,
    firstActivityAt: matrix.trends[0]?.day ?? null,
    lastActivityAt: matrix.trends.at(-1)?.day ?? null,
  };
}
