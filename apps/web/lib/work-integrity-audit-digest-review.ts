import type {
  AuditDigest, AuditDigestActor, AuditDigestBucket, AuditDigestCase,
} from "./work-integrity-audit-digest";

/**
 * Transform bounded, factual audit activity into an investigation workload.
 * No task is created automatically: owners must use their audited workflow.
 */
export type ReviewWorkloadKind =
  | "AUDIT_SOURCE_TRUNCATED"
  | "MALFORMED_AUDIT_EVENTS"
  | "ACTOR_REFERENCE_MISSING"
  | "HISTORICAL_REVIEW_REVISION"
  | "REOPENED_DIAGNOSTIC"
  | "UNAVAILABLE_WORK_ITEM"
  | "RECENT_REVIEW_WITHOUT_CURRENT_REVISION"
  | "MULTIPLE_HUMAN_DECISIONS"
  | "HIGH_REVIEW_ACTIVITY"
  | "UNATTRIBUTED_DECISION_VOLUME";
export type ReviewWorkloadItem = {
  id: string;
  kind: ReviewWorkloadKind;
  priority: "P0" | "P1" | "P2" | "P3";
  workItemId: string | null;
  caseKey: string | null;
  actorUserId: string | null;
  day: string | null;
  occurrences: number;
  explanation: string;
  recommendedAction: string;
  requiresHumanReview: boolean;
  cannotBeAutoClosed: true;
};
export type ReviewWorkloadReport = {
  organizationId: string;
  from: string;
  to: string;
  sourceTruncated: boolean;
  sourceRecordsInspected: number;
  itemCount: number;
  casesNeedingReview: number;
  sourceQualityItems: number;
  priority: { P0: number; P1: number; P2: number; P3: number };
  byKind: Partial<Record<ReviewWorkloadKind, number>>;
  items: ReviewWorkloadItem[];
  omittedItems: number;
  limitations: string[];
};
export type ReviewWorkloadOptions = {
  limit?: number;
  dailyActivityThreshold?: number;
  repeatedCaseReviewThreshold?: number;
  missingActorThreshold?: number;
};
const precedence = { P0: 0, P1: 1, P2: 2, P3: 3 };
function assertLimit(value: number, label: string, max: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > max)
    throw new Error(`Invalid ${label} for audit review workload.`);
}
function caseAction(
  row: AuditDigestCase,
  kind: ReviewWorkloadKind,
  priority: ReviewWorkloadItem["priority"],
  explanation: string,
  recommendedAction: string,
  occurrences = 1,
): ReviewWorkloadItem {
  return {
    id: JSON.stringify([kind, row.caseKey]),
    kind, priority,
    workItemId: row.workItemId, caseKey: row.caseKey,
    actorUserId: null, day: row.lastAt.slice(0, 10),
    occurrences, explanation, recommendedAction,
    requiresHumanReview: true, cannotBeAutoClosed: true,
  };
}
function dailyAction(
  row: AuditDigestBucket,
  kind: ReviewWorkloadKind,
  priority: ReviewWorkloadItem["priority"],
  occurrences: number,
  explanation: string,
  recommendedAction: string,
): ReviewWorkloadItem {
  return {
    id: JSON.stringify([kind, row.day]),
    kind, priority,
    workItemId: null, caseKey: null,
    actorUserId: null, day: row.day,
    occurrences, explanation, recommendedAction,
    requiresHumanReview: true, cannotBeAutoClosed: true,
  };
}
function actorAction(
  row: AuditDigestActor,
  kind: ReviewWorkloadKind,
  occurrences: number,
): ReviewWorkloadItem {
  return {
    id: JSON.stringify([kind, row.actorUserId]),
    kind, priority: "P2",
    workItemId: null, caseKey: null,
    actorUserId: row.actorUserId, day: null,
    occurrences,
    explanation: "Recorded human review activity has no retained user reference.",
    recommendedAction: "Inspect the event's original actor, service context and account retention.",
    requiresHumanReview: true, cannotBeAutoClosed: true,
  };
}
export function planAuditReviewWorkload(
  digest: AuditDigest,
  options: ReviewWorkloadOptions = {},
): ReviewWorkloadReport {
  const limit = options.limit ?? 250;
  const dailyActivityThreshold = options.dailyActivityThreshold ?? 100;
  const repeatedCaseReviewThreshold = options.repeatedCaseReviewThreshold ?? 5;
  const missingActorThreshold = options.missingActorThreshold ?? 2;
  assertLimit(limit, "workload result limit", 1000);
  assertLimit(dailyActivityThreshold, "activity threshold", 5000);
  assertLimit(repeatedCaseReviewThreshold, "repeated review threshold", 100);
  assertLimit(missingActorThreshold, "actor threshold", 1000);
  const items: ReviewWorkloadItem[] = [];
  if (digest.historyTruncated) items.push({
    id: JSON.stringify(["AUDIT_SOURCE_TRUNCATED", digest.from, digest.to]),
    kind: "AUDIT_SOURCE_TRUNCATED", priority: "P1",
    workItemId: null, caseKey: null, actorUserId: null, day: null,
    occurrences: digest.rawRecordsRead,
    explanation: "Audit-event query reached the configured bounded source limit.",
    recommendedAction: "Split the requested period into smaller windows or increase the permitted history cap.",
    requiresHumanReview: true, cannotBeAutoClosed: true,
  });
  if (digest.malformed > 0) items.push({
    id: JSON.stringify(["MALFORMED_AUDIT_EVENTS", digest.from, digest.to]),
    kind: "MALFORMED_AUDIT_EVENTS", priority: "P1",
    workItemId: null, caseKey: null, actorUserId: null, day: null,
    occurrences: digest.malformed,
    explanation: "Some stored audit records cannot be interpreted as human integrity decisions.",
    recommendedAction: "Inspect original event metadata with authorized audit access.",
    requiresHumanReview: true, cannotBeAutoClosed: true,
  });
  for (const row of digest.cases) {
    if (row.currentWorkRevision === null) items.push(caseAction(
      row, "UNAVAILABLE_WORK_ITEM", "P1",
      "A recorded diagnostic review references work that is not present in the current work lookup.",
      "Investigate archival or deletion history without discarding the original audit event.",
    ));
    else if (row.currentlyReviewed === false) items.push(caseAction(
      row, "HISTORICAL_REVIEW_REVISION", "P1",
      "The latest recorded case decision refers to an outdated work revision.",
      "Request review of the latest work revision; preserve historical decisions.",
    ));
    if (row.lastDecision === "REOPEN") items.push(caseAction(
      row, "REOPENED_DIAGNOSTIC", "P2",
      "The latest recorded decision reopens an earlier review.",
      "Confirm current case ownership, next investigation steps and linked evidence.",
    ));
    if (row.events >= repeatedCaseReviewThreshold) items.push(caseAction(
      row, "MULTIPLE_HUMAN_DECISIONS", "P2",
      "Repeated review activity occurred for the same diagnostic within the selected window.",
      "Review whether the case is awaiting evidence or experiencing unproductive decision churn.",
      row.events,
    ));
    if (row.currentlyReviewed === false &&
        row.lastAt >= digest.to.slice(0, 10) && row.events > 0)
      items.push(caseAction(
        row, "RECENT_REVIEW_WITHOUT_CURRENT_REVISION", "P2",
        "A recent review still does not match the current work revision.",
        "Verify the current work-item revision and determine whether further human review is required.",
      ));
  }
  for (const day of digest.daily) {
    if (day.recorded >= dailyActivityThreshold) items.push(dailyAction(
      day, "HIGH_REVIEW_ACTIVITY", "P3", day.recorded,
      "Recorded review activity on this day reached the configured threshold.",
      "Check staffing and queue throughput; volume alone is not a security incident.",
    ));
    if (day.unknownActors >= missingActorThreshold) items.push(dailyAction(
      day, "ACTOR_REFERENCE_MISSING", "P2", day.unknownActors,
      "Multiple decisions lack a retained actor reference on this day.",
      "Inspect audit actor retention and source event metadata.",
    ));
  }
  for (const actor of digest.actors) {
    if (actor.actorUserId === null && actor.recorded >= missingActorThreshold)
      items.push(actorAction(actor, "UNATTRIBUTED_DECISION_VOLUME", actor.recorded));
  }
  const deduplicated = new Map<string, ReviewWorkloadItem>();
  for (const item of items) {
    const existing = deduplicated.get(item.id);
    if (!existing || precedence[item.priority] < precedence[existing.priority])
      deduplicated.set(item.id, item);
  }
  const ordered = [...deduplicated.values()].sort((a, b) =>
    precedence[a.priority] - precedence[b.priority] ||
    b.occurrences - a.occurrences || a.id.localeCompare(b.id));
  const priority = { P0: 0, P1: 0, P2: 0, P3: 0 };
  const byKind: ReviewWorkloadReport["byKind"] = {};
  for (const item of ordered) {
    priority[item.priority]++;
    byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
  }
  return {
    organizationId: digest.organizationId, from: digest.from, to: digest.to,
    sourceTruncated: digest.historyTruncated,
    sourceRecordsInspected: digest.rawRecordsRead,
    itemCount: ordered.length,
    casesNeedingReview: new Set(ordered.filter(item => item.caseKey !== null)
      .map(item => item.caseKey)).size,
    sourceQualityItems: ordered.filter(item =>
      item.kind === "AUDIT_SOURCE_TRUNCATED" || item.kind === "MALFORMED_AUDIT_EVENTS").length,
    priority, byKind, items: ordered.slice(0, limit),
    omittedItems: Math.max(0, ordered.length - limit),
    limitations: [
      "Recommended actions are advisory and are never written into the task database.",
      "Human decisions must be recorded through the authorized audited workflow.",
      "Truncated audit windows cannot establish complete review activity.",
      "Unusual decision volume is operational context, not proof of a cyber incident.",
      "No audit activity measure certifies remediation, compliance or security effectiveness.",
    ],
  };
}
export function reviewWorkloadCsv(report: ReviewWorkloadReport): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const columns = [
    "kind", "priority", "workItemId", "caseKey", "actorUserId", "day",
    "occurrences", "explanation", "recommendedAction", "requiresHumanReview",
    "cannotBeAutoClosed",
  ];
  const output = [columns.map(quote).join(",")];
  for (const item of report.items) output.push([
    item.kind, item.priority, item.workItemId, item.caseKey,
    item.actorUserId, item.day, item.occurrences, item.explanation,
    item.recommendedAction, item.requiresHumanReview,
    item.cannotBeAutoClosed,
  ].map(quote).join(","));
  return output.join("\r\n") + "\r\n";
}
