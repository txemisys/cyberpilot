import type { CaseSnapshot } from "./work-integrity-snapshots";
import type { CaseRow } from "./work-integrity-cases";

/**
 * Read-only, evidence-conscious review continuity across successive captures.
 * Review events identify recorded human actions, not proof that a control works.
 */
export type ContinuityFindingKind =
  | "REVIEW_EVENT_REUSED_FOR_DIFFERENT_CASE"
  | "REVIEW_EVENT_CONTENT_CHANGED"
  | "REVIEW_EVENT_DISAPPEARED"
  | "REVIEW_REVISION_REWOUND"
  | "WORK_REVISION_REWOUND"
  | "REVIEW_EVENT_CHANGED_WITHOUT_REVISION"
  | "DECISION_CHANGED_WITHOUT_EVENT"
  | "REVIEW_TIME_REWOUND"
  | "REVIEW_TIME_AFTER_CAPTURE"
  | "REVIEW_REVISION_AHEAD"
  | "REVIEW_STALE"
  | "REVIEW_UNATTRIBUTED"
  | "REVIEW_WITHOUT_RATIONALE"
  | "REVIEW_ABSENT_ON_NEW_REVISION"
  | "SOURCE_SCOPE_INCOMPLETE";
export type ContinuitySeverity = "CRITICAL" | "HIGH" | "REVIEW" | "INFO";
export type ContinuityFinding = {
  caseKey: string | null;
  kind: ContinuityFindingKind;
  severity: ContinuitySeverity;
  beforeTime: string;
  afterTime: string;
  beforeRevision: number | null;
  afterRevision: number | null;
  eventId: string | null;
  message: string;
  followup: string;
};
export type ContinuityTransition = {
  from: string;
  to: string;
  casesBefore: number;
  casesAfter: number;
  inspectedCases: number;
  findings: ContinuityFinding[];
  incompleteScope: boolean;
};
export type ContinuityReport = {
  organizationId: string;
  source: string;
  captures: number;
  from: string;
  to: string;
  caseIdentities: number;
  eventIdentities: number;
  transitions: ContinuityTransition[];
  totals: Record<ContinuitySeverity, number>;
  byKind: Partial<Record<ContinuityFindingKind, number>>;
  affectedCaseKeys: string[];
  limitations: string[];
};
const severityOrder: ContinuitySeverity[] = ["CRITICAL", "HIGH", "REVIEW", "INFO"];
function eventFingerprint(row: CaseRow): string {
  return JSON.stringify([
    row.workItemId, row.code, row.resourceId, row.reviewEventId,
    row.reviewedRevision, row.reviewedAt, row.reviewerUserId,
    row.reviewRationale, row.reviewReference,
  ]);
}
function validateCaptures(captures: readonly CaseSnapshot[]): void {
  if (captures.length < 2 || captures.length > 24)
    throw new Error("Review continuity requires between two and 24 captures.");
  const first = captures[0]!;
  if (!first.organizationId || !first.source)
    throw new Error("Capture identity and source are required.");
  let previous = -Infinity;
  for (const capture of captures) {
    if (capture.organizationId !== first.organizationId)
      throw new Error("Cross-organization review continuity is forbidden.");
    if (capture.source !== first.source)
      throw new Error("Capture scopes differ: review continuity cannot be inferred.");
    const time = Date.parse(capture.capturedAt);
    if (!Number.isFinite(time) || time <= previous)
      throw new Error("Review continuity requires ordered, unique capture timestamps.");
    previous = time;
    if (capture.cases.length > 10000)
      throw new Error("A capture exceeds the bounded continuity limit.");
    const keys = new Set(capture.cases.map(row => row.key));
    if (keys.size !== capture.cases.length)
      throw new Error("Duplicate identities in a continuity capture.");
  }
}
function eventIndex(cases: readonly CaseRow[]): Map<string, CaseRow> {
  const index = new Map<string, CaseRow>();
  for (const row of cases) {
    if (row.reviewEventId === null) continue;
    const existing = index.get(row.reviewEventId);
    if (existing && existing.key !== row.key)
      throw new Error("One review event is associated with multiple case identities.");
    index.set(row.reviewEventId, row);
  }
  return index;
}
export function analyzeReviewContinuity(
  captures: readonly CaseSnapshot[],
): ContinuityReport {
  validateCaptures(captures);
  const transitions: ContinuityTransition[] = [];
  const kinds: Partial<Record<ContinuityFindingKind, number>> = {};
  const totals: Record<ContinuitySeverity, number> = {
    CRITICAL: 0, HIGH: 0, REVIEW: 0, INFO: 0,
  };
  const affected = new Set<string>();
  const identities = new Set<string>();
  const events = new Set<string>();
  for (const capture of captures) {
    for (const row of capture.cases) {
      identities.add(row.key);
      if (row.reviewEventId) events.add(row.reviewEventId);
    }
  }
  for (let index = 1; index < captures.length; index++) {
    const before = captures[index - 1]!;
    const after = captures[index]!;
    const oldByKey = new Map(before.cases.map(row => [row.key, row]));
    const newByKey = new Map(after.cases.map(row => [row.key, row]));
    const oldEvents = eventIndex(before.cases);
    const newEvents = eventIndex(after.cases);
    const findings: ContinuityFinding[] = [];
    const incompleteScope = !before.complete || !after.complete;
    const emit = (
      key: string | null, kind: ContinuityFindingKind,
      severity: ContinuitySeverity, message: string,
      followup: string, oldRow: CaseRow | null = null,
      newRow: CaseRow | null = null,
    ) => {
      totals[severity]++;
      kinds[kind] = (kinds[kind] ?? 0) + 1;
      if (key !== null) affected.add(key);
      findings.push({
        caseKey: key, kind, severity,
        beforeTime: before.capturedAt, afterTime: after.capturedAt,
        beforeRevision: oldRow?.taskRevision ?? null,
        afterRevision: newRow?.taskRevision ?? null,
        eventId: newRow?.reviewEventId ?? oldRow?.reviewEventId ?? null,
        message, followup,
      });
    };
    if (incompleteScope) emit(
      null, "SOURCE_SCOPE_INCOMPLETE", "HIGH",
      "One or both captures lack complete declared coverage.",
      "Recollect the same complete source scope before inferring case disappearance.",
    );
    for (const [eventId, oldRow] of oldEvents) {
      const newRow = newEvents.get(eventId);
      if (!newRow) {
        if (!incompleteScope && newByKey.has(oldRow.key)) emit(
          oldRow.key, "REVIEW_EVENT_DISAPPEARED", "HIGH",
          "A previously recorded review event vanished while its case is still present.",
          "Inspect audit event retention, triage reconciliation and snapshot consistency.",
          oldRow, newByKey.get(oldRow.key) ?? null,
        );
        continue;
      }
      if (eventFingerprint(oldRow) !== eventFingerprint(newRow)) emit(
        oldRow.key, "REVIEW_EVENT_CONTENT_CHANGED", "CRITICAL",
        "The same event ID has different review metadata in sequential captures.",
        "Investigate audit provenance before treating either record as authoritative.",
        oldRow, newRow,
      );
    }
    for (const [key, next] of newByKey) {
      const previous = oldByKey.get(key);
      if (!previous) continue;
      if (next.taskRevision < previous.taskRevision) emit(
        key, "WORK_REVISION_REWOUND", "CRITICAL",
        "Work-item revision moved backward between captures.",
        "Inspect concurrent writes and confirm the authoritative revision chain.",
        previous, next,
      );
      if (previous.reviewedRevision !== null && next.reviewedRevision !== null &&
          next.reviewedRevision < previous.reviewedRevision) emit(
        key, "REVIEW_REVISION_REWOUND", "HIGH",
        "Reviewed work revision moved backward between captures.",
        "Confirm which audit event supersedes the earlier review.",
        previous, next,
      );
      if (previous.reviewEventId !== null && next.reviewEventId !== null &&
          previous.reviewEventId !== next.reviewEventId &&
          previous.taskRevision === next.taskRevision &&
          previous.state === next.state) emit(
        key, "REVIEW_EVENT_CHANGED_WITHOUT_REVISION", "REVIEW",
        "A new triage event was recorded with no work revision or state change.",
        "Review the audit trail for an explanatory follow-up action.",
        previous, next,
      );
      if (previous.state !== next.state && next.reviewEventId === previous.reviewEventId &&
          next.reviewEventId !== null) emit(
        key, "DECISION_CHANGED_WITHOUT_EVENT", "CRITICAL",
        "Human review status changed without a new review event.",
        "Rebuild case status from the immutable decision history.",
        previous, next,
      );
      const beforeReview = previous.reviewedAt ? Date.parse(previous.reviewedAt) : null;
      const afterReview = next.reviewedAt ? Date.parse(next.reviewedAt) : null;
      if (beforeReview !== null && afterReview !== null &&
          Number.isFinite(beforeReview) && Number.isFinite(afterReview) &&
          afterReview < beforeReview) emit(
        key, "REVIEW_TIME_REWOUND", "HIGH",
        "The most recent review timestamp moved backward.",
        "Verify the event sequence and the source clock.",
        previous, next,
      );
      if (next.reviewedAt && Date.parse(next.reviewedAt) > Date.parse(after.capturedAt)) emit(
        key, "REVIEW_TIME_AFTER_CAPTURE", "HIGH",
        "The review timestamp is later than the capture timestamp.",
        "Confirm synchronization and regenerate the capture.",
        previous, next,
      );
      if (next.reviewedRevision !== null &&
          next.reviewedRevision > next.taskRevision) emit(
        key, "REVIEW_REVISION_AHEAD", "CRITICAL",
        "The reviewed revision is newer than the captured work revision.",
        "Reconcile work and audit revision history before accepting the review.",
        previous, next,
      );
      if (next.reviewEventId !== null &&
          next.reviewedRevision !== next.taskRevision) emit(
        key, "REVIEW_STALE", "REVIEW",
        "A recorded review refers to a different work-item revision.",
        "Repeat the human review against the current work revision.",
        previous, next,
      );
      if (next.reviewEventId !== null && next.reviewerUserId === null) emit(
        key, "REVIEW_UNATTRIBUTED", "REVIEW",
        "The review event lacks a current user reference.",
        "Inspect the recorded audit actor and any user deletion history.",
        previous, next,
      );
      if (next.reviewEventId !== null && !next.reviewRationale?.trim()) emit(
        key, "REVIEW_WITHOUT_RATIONALE", "REVIEW",
        "The review event has no explanatory rationale.",
        "Request an auditable explanatory note for this review.",
        previous, next,
      );
      if (next.taskRevision > previous.taskRevision &&
          next.reviewEventId === null && previous.reviewEventId !== null) emit(
        key, "REVIEW_ABSENT_ON_NEW_REVISION", "REVIEW",
        "Work was revised but the previously recorded review is no longer linked.",
        "Check whether reassessment is required and preserve prior review history.",
        previous, next,
      );
    }
    for (const [eventId, row] of newEvents) {
      const historical = oldEvents.get(eventId);
      if (historical && historical.key !== row.key) emit(
        row.key, "REVIEW_EVENT_REUSED_FOR_DIFFERENT_CASE", "CRITICAL",
        "A review event identifier changed case ownership.",
        "Quarantine the conflicting capture data and inspect audit source identity.",
        historical, row,
      );
    }
    transitions.push({
      from: before.capturedAt, to: after.capturedAt,
      casesBefore: before.cases.length, casesAfter: after.cases.length,
      inspectedCases: [...new Set([...oldByKey.keys(), ...newByKey.keys()])].length,
      findings: findings.sort((a, b) =>
        severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) ||
        (a.caseKey ?? "").localeCompare(b.caseKey ?? "") ||
        a.kind.localeCompare(b.kind)),
      incompleteScope,
    });
  }
  return {
    organizationId: captures[0]!.organizationId,
    source: captures[0]!.source,
    captures: captures.length,
    from: captures[0]!.capturedAt,
    to: captures[captures.length - 1]!.capturedAt,
    caseIdentities: identities.size,
    eventIdentities: events.size,
    transitions, totals, byKind: kinds,
    affectedCaseKeys: [...affected].sort(),
    limitations: [
      "Snapshots are caller-provided; this analysis does not authenticate source records.",
      "Audit-event IDs are consistency keys, not cryptographic integrity proofs.",
      "Reviews do not resolve findings or attest to security-control effectiveness.",
      "Cases missing from partial snapshots are not treated as cleared.",
      "This diagnostic analysis never writes operational or audit state.",
    ],
  };
}
export function reviewContinuityCsv(report: ContinuityReport): string {
  const escape = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const header = [
    "from", "to", "caseKey", "kind", "severity",
    "beforeRevision", "afterRevision", "eventId", "message", "followup",
  ];
  const lines = [header.map(escape).join(",")];
  for (const transition of report.transitions) {
    for (const issue of transition.findings) {
      lines.push([
        issue.beforeTime, issue.afterTime, issue.caseKey, issue.kind,
        issue.severity, issue.beforeRevision, issue.afterRevision,
        issue.eventId, issue.message, issue.followup,
      ].map(escape).join(","));
    }
  }
  return lines.join("\r\n") + "\r\n";
}
