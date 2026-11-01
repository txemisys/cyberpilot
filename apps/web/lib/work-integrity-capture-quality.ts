import type { CaseSnapshot } from "./work-integrity-snapshots";
import type { CaseRow } from "./work-integrity-cases";

/**
 * Independently inspect an imported case capture for internal contradictions.
 * This is a consistency review of supplied records, never attestation of
 * their origin, factual accuracy, or the operation of a security control.
 */
export type CaptureQualityCode =
  | "PARTIAL_CASE_COVERAGE"
  | "HISTORICAL_WITH_DIAGNOSTIC"
  | "HISTORICAL_WITHOUT_REVIEW"
  | "ACTIVE_WITHOUT_DIAGNOSTIC"
  | "REVIEW_WITHOUT_EVENT"
  | "EVENT_WITHOUT_REVIEW_TIME"
  | "REVIEW_WITHOUT_ACTOR"
  | "REVIEW_REVISION_IN_FUTURE"
  | "STALE_REVIEW_REVISION_MATCHES"
  | "CURRENT_REVIEW_REVISION_DIFFERS"
  | "NO_LONGER_DETECTED_WITH_DIAGNOSTIC"
  | "CLOSED_REVIEW_WITHOUT_RATIONALE"
  | "FUTURE_REVIEW_TIME"
  | "REVIEW_AFTER_CAPTURE"
  | "CAPTURE_WITHOUT_CASES"
  | "DECLARED_COMPLETE_WITH_PARTIAL_CASES";
export type CaptureQualityIssue = {
  code: CaptureQualityCode;
  caseKey: string | null;
  severity: "BLOCKER" | "WARNING" | "INFO";
  explanation: string;
  nextAction: string;
};
export type CaptureQualityReport = {
  organizationId: string;
  capturedAt: string;
  declaredComplete: boolean;
  structurallyConsistent: boolean;
  safeToTreatAsComplete: boolean;
  caseCount: number;
  affectedCases: number;
  blockers: number;
  warnings: number;
  information: number;
  byCode: Partial<Record<CaptureQualityCode, number>>;
  issues: CaptureQualityIssue[];
  limitations: string[];
};

const HOUR_MS = 60 * 60 * 1000;
function validTimestamp(value: string | null): number | null {
  if (value === null) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
export function inspectCaptureQuality(
  capture: CaseSnapshot,
  options: { maximumIssues?: number; futureToleranceMs?: number } = {},
): CaptureQualityReport {
  const maximumIssues = options.maximumIssues ?? 10000;
  const futureToleranceMs = options.futureToleranceMs ?? 5 * 60 * 1000;
  if (!Number.isSafeInteger(maximumIssues) || maximumIssues < 1 || maximumIssues > 10000)
    throw new Error("Invalid capture issue limit.");
  if (!Number.isSafeInteger(futureToleranceMs) ||
      futureToleranceMs < 0 || futureToleranceMs > HOUR_MS)
    throw new Error("Invalid time tolerance.");
  const captureTime = validTimestamp(capture.capturedAt);
  if (captureTime === null) throw new Error("Invalid capture timestamp.");
  const issues: CaptureQualityIssue[] = [];
  const byCode: Partial<Record<CaptureQualityCode, number>> = {};
  const affected = new Set<string>();
  let blockers = 0;
  let warnings = 0;
  let information = 0;
  let suppressed = 0;
  function add(
    code: CaptureQualityCode, row: CaseRow | null,
    severity: CaptureQualityIssue["severity"],
    explanation: string, nextAction: string,
  ): void {
    byCode[code] = (byCode[code] ?? 0) + 1;
    if (severity === "BLOCKER") blockers++;
    else if (severity === "WARNING") warnings++;
    else information++;
    if (row) affected.add(row.key);
    if (issues.length === maximumIssues) {
      suppressed++;
      return;
    }
    issues.push({ code, caseKey: row?.key ?? null, severity, explanation, nextAction });
  }
  if (capture.cases.length === 0) {
    add("CAPTURE_WITHOUT_CASES", null, "INFO",
      "No integrity cases are contained in this snapshot.",
      "Check the capture scope and work-item pagination before concluding there are no issues.");
  }
  for (const row of capture.cases) {
    if (!row.completeCoverage) {
      add("PARTIAL_CASE_COVERAGE", row, "WARNING",
        "Linked records were not fully collected for this work item.",
        "Collect the missing linked records and repeat the diagnostic.");
    }
    if (row.historicalOnly && row.diagnostic !== null) {
      add("HISTORICAL_WITH_DIAGNOSTIC", row, "BLOCKER",
        "Historical-only case unexpectedly includes a current diagnostic.",
        "Recreate this case using an unmodified authenticated capture.");
    }
    if (row.historicalOnly && row.reviewEventId === null) {
      add("HISTORICAL_WITHOUT_REVIEW", row, "BLOCKER",
        "Historical-only case lacks the review event that establishes its history.",
        "Retrieve the associated audit event or discard the inconsistent case.");
    }
    if (!row.historicalOnly && row.diagnostic === null) {
      add("ACTIVE_WITHOUT_DIAGNOSTIC", row, "WARNING",
        "Active case has no recorded diagnostic explanation.",
        "Inspect the diagnostic source and reload this case.");
    }
    if (row.state !== "UNREVIEWED" && row.state !== "NO_LONGER_DETECTED" &&
        row.reviewEventId === null) {
      add("REVIEW_WITHOUT_EVENT", row, "BLOCKER",
        "Reviewed state is not associated with an audit event.",
        "Obtain the original immutable triage event before relying on this state.");
    }
    if (row.reviewEventId !== null && row.reviewedAt === null) {
      add("EVENT_WITHOUT_REVIEW_TIME", row, "BLOCKER",
        "A review event lacks its occurrence timestamp.",
        "Retrieve the event's server-recorded occurrence time.");
    }
    if (row.reviewEventId !== null && row.reviewerUserId === null) {
      add("REVIEW_WITHOUT_ACTOR", row, "WARNING",
        "Review event has no linked user actor.",
        "Confirm whether the actor was removed or this was a system event.");
    }
    if (row.reviewedRevision !== null && row.reviewedRevision > row.taskRevision) {
      add("REVIEW_REVISION_IN_FUTURE", row, "BLOCKER",
        "The recorded review references a revision newer than the work item.",
        "Inspect the source history for reordered or inconsistent revisions.");
    }
    if (row.state === "STALE" && row.reviewedRevision === row.taskRevision) {
      add("STALE_REVIEW_REVISION_MATCHES", row, "BLOCKER",
        "Stale review has the same revision as the current work item.",
        "Recompute case state from the current work revision and review event.");
    }
    if (row.reviewedRevision !== null && row.reviewedRevision !== row.taskRevision &&
        !["STALE", "NO_LONGER_DETECTED"].includes(row.state)) {
      add("CURRENT_REVIEW_REVISION_DIFFERS", row, "BLOCKER",
        "Case is treated as currently reviewed despite an outdated review revision.",
        "Reassess the case against the updated work item before accepting the decision.");
    }
    if (row.state === "NO_LONGER_DETECTED" && !row.historicalOnly) {
      add("NO_LONGER_DETECTED_WITH_DIAGNOSTIC", row, "BLOCKER",
        "A case marked no longer detected is still represented as an active diagnostic.",
        "Reconcile the finding detection and historical review records.");
    }
    if (["ACKNOWLEDGED", "DISMISSED"].includes(row.state) &&
        !row.reviewRationale?.trim()) {
      add("CLOSED_REVIEW_WITHOUT_RATIONALE", row, "WARNING",
        "Acknowledgement or dismissal lacks an explanatory rationale.",
        "Ask the reviewer to document the reason in the audited triage workflow.");
    }
    if (row.reviewedAt !== null) {
      const reviewedTime = validTimestamp(row.reviewedAt);
      if (reviewedTime === null) {
        add("FUTURE_REVIEW_TIME", row, "BLOCKER",
          "Review timestamp is not a valid date.",
          "Re-export the review from the audit-event source.");
      } else if (reviewedTime > captureTime + futureToleranceMs) {
        add("REVIEW_AFTER_CAPTURE", row, "BLOCKER",
          "Review is recorded after this capture was created.",
          "Verify the event clock and capture time; regenerate if necessary.");
      }
    }
  }
  if (capture.complete && capture.cases.some(row => !row.completeCoverage)) {
    add("DECLARED_COMPLETE_WITH_PARTIAL_CASES", null, "BLOCKER",
      "Snapshot claims completeness despite incomplete linked records.",
      "Mark this capture incomplete or recollect its linked evidence.");
  }
  return {
    organizationId: capture.organizationId,
    capturedAt: capture.capturedAt,
    declaredComplete: capture.complete,
    structurallyConsistent: blockers === 0,
    safeToTreatAsComplete: capture.complete && blockers === 0 && warnings === 0,
    caseCount: capture.cases.length,
    affectedCases: affected.size,
    blockers, warnings, information, byCode, issues,
    limitations: [
      "The capture is caller-supplied; this check cannot authenticate its provenance.",
      "A structurally consistent snapshot is not proof of full organizational coverage.",
      "A diagnostic disappearing is not evidence that the underlying security control works.",
      ...(suppressed ? [`${suppressed} additional quality issues omitted from the bounded response.`] : []),
    ],
  };
}
