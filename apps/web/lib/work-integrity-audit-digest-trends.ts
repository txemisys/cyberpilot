import type { AuditDigest, AuditDigestBucket } from "./work-integrity-audit-digest";

/**
 * Interpret activity direction within an already bounded audit window.
 * Trend comparisons measure recorded human actions, not security outcomes.
 */
export type AuditTrendSignal =
  | "RISING_REVIEW_LOAD"
  | "FALLING_REVIEW_LOAD"
  | "REOPENING_ACTIVITY"
  | "UNATTRIBUTED_REVIEWS"
  | "OUTDATED_REVISION_ACTIVITY"
  | "MALFORMED_SOURCE_ROWS"
  | "INCOMPLETE_HISTORY"
  | "NO_RECORDED_ACTIVITY"
  | "STABLE_REVIEW_LOAD";
export type AuditTrendPeriod = {
  days: number;
  recorded: number;
  investigations: number;
  acknowledgements: number;
  dismissals: number;
  reopenings: number;
  unknownActors: number;
  outdatedReviews: number;
  malformed: number;
  activityPerDay: number;
};
export type AuditTrendFinding = {
  signal: AuditTrendSignal;
  priority: "REVIEW" | "CONTEXT" | "UNKNOWN";
  explanation: string;
  nextStep: string;
  currentCount: number;
  priorCount: number | null;
};
export type AuditTrendReport = {
  organizationId: string;
  from: string;
  to: string;
  days: number;
  sourceTruncated: boolean;
  prior: AuditTrendPeriod;
  current: AuditTrendPeriod;
  recordedDelta: number;
  dailyRateRatio: number | null;
  findings: AuditTrendFinding[];
  limitations: string[];
};
function aggregate(days: readonly AuditDigestBucket[]): AuditTrendPeriod {
  const total = (key: keyof AuditDigestBucket) =>
    days.reduce((sum, day) => sum + Number(day[key] ?? 0), 0);
  const recorded = total("recorded");
  return {
    days: days.length, recorded,
    investigations: total("investigations"),
    acknowledgements: total("acknowledgements"),
    dismissals: total("dismissals"),
    reopenings: total("reopenings"),
    unknownActors: total("unknownActors"),
    outdatedReviews: total("staleReviews"),
    malformed: total("malformed"),
    activityPerDay: days.length ? recorded / days.length : 0,
  };
}
export function analyzeAuditDigestTrends(digest: AuditDigest): AuditTrendReport {
  if (!digest.organizationId) throw new Error("Invalid audit trend organization.");
  const sorted = [...digest.daily].sort((a, b) => a.day.localeCompare(b.day));
  if (new Set(sorted.map(row => row.day)).size !== sorted.length)
    throw new Error("Duplicate daily audit trend bucket.");
  if (sorted.some(row => row.recorded < 0 || !Number.isSafeInteger(row.recorded)))
    throw new Error("Invalid recorded daily audit counts.");
  const midpoint = Math.floor(sorted.length / 2);
  const prior = aggregate(sorted.slice(0, midpoint));
  const current = aggregate(sorted.slice(midpoint));
  const recordedDelta = current.recorded - prior.recorded;
  const dailyRateRatio = prior.activityPerDay > 0 ?
    current.activityPerDay / prior.activityPerDay : null;
  const findings: AuditTrendFinding[] = [];
  const emit = (
    signal: AuditTrendSignal,
    priority: AuditTrendFinding["priority"],
    explanation: string,
    nextStep: string,
    currentCount: number,
    priorCount: number | null = null,
  ) => findings.push({
    signal, priority, explanation, nextStep, currentCount, priorCount,
  });
  if (digest.historyTruncated) emit(
    "INCOMPLETE_HISTORY", "UNKNOWN",
    "The recorded audit source exceeded the configured history cap.",
    "Split the requested time range into smaller windows before comparing periods.",
    digest.rawRecordsRead,
  );
  if (digest.malformed > 0) emit(
    "MALFORMED_SOURCE_ROWS", "REVIEW",
    "Some source audit records could not be decoded as human decisions.",
    "Inspect malformed event metadata before relying on exact actor or decision totals.",
    digest.malformed,
  );
  if (digest.recorded === 0) emit(
    "NO_RECORDED_ACTIVITY", "CONTEXT",
    "No readable human integrity decisions were recorded in the selected window.",
    "Check the work queue and source event coverage; absence alone is not an error.",
    0,
  );
  if (prior.days > 0 && current.days > 0 && !digest.historyTruncated) {
    if (dailyRateRatio !== null && dailyRateRatio >= 1.5 &&
        current.recorded >= prior.recorded + 3) emit(
      "RISING_REVIEW_LOAD", "CONTEXT",
      "Daily recorded review actions increased between the two halves of the selected window.",
      "Check staff workload and whether investigations have appropriate owners.",
      current.recorded, prior.recorded,
    );
    else if (dailyRateRatio !== null && dailyRateRatio <= 0.5 &&
        prior.recorded >= current.recorded + 3) emit(
      "FALLING_REVIEW_LOAD", "CONTEXT",
      "Daily recorded review actions decreased between the two halves.",
      "Check source ingestion, work availability and review queue age.",
      current.recorded, prior.recorded,
    );
    else emit(
      "STABLE_REVIEW_LOAD", "CONTEXT",
      "No material workload trend crossed the configured comparison thresholds.",
      "Continue normal review monitoring without inferring improved security.",
      current.recorded, prior.recorded,
    );
  }
  if (current.reopenings > 0) emit(
    "REOPENING_ACTIVITY", "REVIEW",
    "Cases were reopened by recorded human decisions in the later period.",
    "Review current case ownership and investigate why earlier dispositions were reopened.",
    current.reopenings, prior.reopenings,
  );
  if (current.unknownActors > 0) emit(
    "UNATTRIBUTED_REVIEWS", "REVIEW",
    "Some decisions in the later period lack current user references.",
    "Check audit source actor retention and account lifecycle.",
    current.unknownActors, prior.unknownActors,
  );
  if (current.outdatedReviews > 0) emit(
    "OUTDATED_REVISION_ACTIVITY", "REVIEW",
    "Some recorded reviews refer to revisions different from currently stored work.",
    "Confirm whether new human reviews are required after changes to work.",
    current.outdatedReviews, prior.outdatedReviews,
  );
  findings.sort((a, b) => {
    const rank = { REVIEW: 0, UNKNOWN: 1, CONTEXT: 2 };
    return rank[a.priority] - rank[b.priority] ||
      a.signal.localeCompare(b.signal);
  });
  return {
    organizationId: digest.organizationId,
    from: digest.from, to: digest.to,
    days: sorted.length, sourceTruncated: digest.historyTruncated,
    prior, current, recordedDelta, dailyRateRatio,
    findings,
    limitations: [
      "The chosen audit window is split into chronological halves of calendar-day buckets.",
      "Different numbers of days are normalized by activity per day when comparing trends.",
      "Only recorded review actions are measured; no control status or remediation is verified.",
      "Historical-review revision counts describe current source context, not necessarily status at review time.",
      "Source event truncation blocks trend direction claims.",
    ],
  };
}
export function auditTrendCsv(report: AuditTrendReport): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const columns = [
    "signal", "priority", "priorCount", "currentCount",
    "explanation", "nextStep", "from", "to",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const row of report.findings) lines.push([
    row.signal, row.priority, row.priorCount, row.currentCount,
    row.explanation, row.nextStep, report.from, report.to,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
