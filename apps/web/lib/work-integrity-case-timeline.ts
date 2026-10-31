import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";
import type { CaseRow } from "./work-integrity-cases";

/**
 * A bounded offline longitudinal analysis for operational integrity cases.
 * All captures must describe the same authenticated organization and source.
 * It never interprets disappearance as verified remediation.
 */
export type TimelineTrend =
  | "NEVER_PRESENT"
  | "NEW_IN_LAST_CAPTURE"
  | "PERSISTENT"
  | "FLAPPING"
  | "DISAPPEARED"
  | "UNCERTAIN";
export type TimelinePoint = {
  capturedAt: string;
  present: boolean;
  state: string | null;
  severity: string | null;
  revision: number | null;
  reviewed: boolean | null;
  completeCoverage: boolean | null;
};
export type TimelineCase = {
  key: string;
  workItemId: string;
  code: string;
  resourceId: string;
  trend: TimelineTrend;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  observations: number;
  transitions: number;
  reviewRevisions: number;
  lastKnownState: string | null;
  lastKnownSeverity: string | null;
  reviewIsCurrent: boolean | null;
  gaps: string[];
  points: TimelinePoint[];
};
export type IntegrityTimeline = {
  organizationId: string;
  source: string;
  captures: number;
  from: string;
  through: string;
  comparable: boolean;
  completeCaptures: number;
  incompleteCaptures: number;
  counts: Record<TimelineTrend, number>;
  cases: TimelineCase[];
  warnings: string[];
};
export type TimelineInput = {
  captures: unknown[];
};
export type TimelinePolicy = {
  maxCaptures?: number;
  maxCasesPerCapture?: number;
  maxTimelineCases?: number;
};
const TRENDS: TimelineTrend[] = [
  "NEVER_PRESENT", "NEW_IN_LAST_CAPTURE", "PERSISTENT",
  "FLAPPING", "DISAPPEARED", "UNCERTAIN",
];
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Timeline body must be an object.");
  return value as Record<string, unknown>;
}
function bounded(value: number | undefined, fallback: number, max: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > max)
    throw new Error("Timeline limit is outside permitted bounds.");
  return result;
}
function sourceDefinition(value: string): { kind: string | null; parameters: string } {
  try {
    const parsed: unknown = JSON.parse(value);
    const data = object(parsed);
    return {
      kind: typeof data.kind === "string" ? data.kind : null,
      parameters: JSON.stringify(data),
    };
  } catch {
    return { kind: null, parameters: value };
  }
}
export function parseTimelineInput(
  value: unknown,
  organizationId: string,
  policy: TimelinePolicy = {},
): CaseSnapshot[] {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization ID is required.");
  const maxCaptures = bounded(policy.maxCaptures, 12, 24);
  const maxCases = bounded(policy.maxCasesPerCapture, 2000, 10000);
  const maxTimelineCases = bounded(policy.maxTimelineCases, 5000, 10000);
  const raw = object(value);
  if (Object.keys(raw).some(key => key !== "captures"))
    throw new Error("Unsupported timeline input field.");
  if (!Array.isArray(raw.captures) ||
      raw.captures.length < 2 || raw.captures.length > maxCaptures)
    throw new Error("A timeline requires 2 to the permitted number of captures.");
  const captures = raw.captures.map(capture => parseCaseSnapshot(capture, maxCases));
  const source = captures[0]!.source;
  let previous = -Infinity;
  const keys = new Set<string>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization timeline is forbidden.");
    if (capture.source !== source)
      throw new Error("Timeline captures must describe the identical source and query scope.");
    const at = Date.parse(capture.capturedAt);
    if (at <= previous)
      throw new Error("Timeline captures must be strictly chronologically ordered.");
    previous = at;
    for (const row of capture.cases) {
      keys.add(row.key);
      if (keys.size > maxTimelineCases)
        throw new Error("Timeline exceeds distinct-case safety limit.");
    }
  }
  return captures;
}
function stateTransitions(points: TimelinePoint[]): number {
  let transitions = 0;
  for (let i = 1; i < points.length; i++) {
    if (points[i]!.present !== points[i - 1]!.present) transitions++;
  }
  return transitions;
}
function rankTrend(
  points: TimelinePoint[],
  captures: readonly CaseSnapshot[],
): TimelineTrend {
  const first = points[0]!;
  const last = points[points.length - 1]!;
  if (captures.some(capture => !capture.complete))
    return "UNCERTAIN";
  if (points.some(point => point.present && point.completeCoverage === false))
    return "UNCERTAIN";
  const occurrences = points.filter(point => point.present).length;
  if (occurrences === 0) return "NEVER_PRESENT";
  if (last.present && occurrences === 1) return "NEW_IN_LAST_CAPTURE";
  const transitions = stateTransitions(points);
  if (transitions >= 2) return "FLAPPING";
  if (!last.present) return "DISAPPEARED";
  if (first.present && occurrences === points.length) return "PERSISTENT";
  return "PERSISTENT";
}
function buildCase(
  key: string,
  captures: CaseSnapshot[],
  maps: Array<Map<string, CaseRow>>,
): TimelineCase {
  const rows = maps.map(map => map.get(key) ?? null);
  const present = rows.filter((row): row is CaseRow => row !== null);
  const newest = present[present.length - 1] ?? null;
  if (!newest) throw new Error("Timeline contains an impossible empty case key.");
  const points: TimelinePoint[] = rows.map((row, index) => ({
    capturedAt: captures[index]!.capturedAt,
    present: row !== null,
    state: row?.state ?? null,
    severity: row?.severity ?? null,
    revision: row?.taskRevision ?? null,
    reviewed: row ? row.reviewEventId !== null : null,
    completeCoverage: row?.completeCoverage ?? null,
  }));
  const trend = rankTrend(points, captures);
  const gaps: string[] = [];
  if (captures.some(capture => !capture.complete))
    gaps.push("One or more captures were not declared complete.");
  if (present.some(row => !row.completeCoverage))
    gaps.push("At least one case has incomplete linked-record coverage.");
  if (trend === "DISAPPEARED")
    gaps.push("Disappearance is a diagnostic observation, not validated remediation.");
  const revisionChanges = new Set(present.map(row => row.taskRevision));
  const reviewRevisions = new Set(
    present.map(row => row.reviewedRevision).filter((value): value is number => value !== null),
  );
  if (revisionChanges.size > 1 && reviewRevisions.size === 1)
    gaps.push("Work revisions changed while the recorded review revision did not.");
  const last = rows[rows.length - 1];
  const lastReviewIsCurrent = last?.reviewEventId !== null &&
    last?.reviewedRevision === last?.taskRevision;
  return {
    key,
    workItemId: newest.workItemId,
    code: newest.code,
    resourceId: newest.resourceId,
    trend,
    firstSeenAt: points.find(point => point.present)?.capturedAt ?? null,
    lastSeenAt: [...points].reverse().find(point => point.present)?.capturedAt ?? null,
    observations: present.length,
    transitions: stateTransitions(points),
    reviewRevisions: reviewRevisions.size,
    lastKnownState: newest.state,
    lastKnownSeverity: newest.severity,
    reviewIsCurrent: last ? Boolean(lastReviewIsCurrent) : null,
    gaps,
    points,
  };
}
export function buildIntegrityTimeline(
  captures: CaseSnapshot[],
): IntegrityTimeline {
  if (captures.length < 2)
    throw new Error("A timeline needs at least two validated captures.");
  const organizationId = captures[0]!.organizationId;
  // Validate even when callers bypass the JSON entry point.
  const parsed = parseTimelineInput({ captures }, organizationId, {
    maxCaptures: 24,
    maxCasesPerCapture: 10000,
    maxTimelineCases: 10000,
  });
  const maps = parsed.map(capture =>
    new Map(capture.cases.map(row => [row.key, row])));
  const keys = [...new Set(parsed.flatMap(capture =>
    capture.cases.map(row => row.key)))].sort();
  const quality = parsed.map(inspectCaptureQuality);
  const cases = keys.map(key => buildCase(key, parsed, maps));
  const counts = Object.fromEntries(TRENDS.map(trend => [trend, 0])) as
    Record<TimelineTrend, number>;
  for (const row of cases) counts[row.trend]++;
  const completeCaptures = quality.filter(q =>
    q.safeToTreatAsComplete).length;
  return {
    organizationId,
    source: parsed[0]!.source,
    captures: parsed.length,
    from: parsed[0]!.capturedAt,
    through: parsed[parsed.length - 1]!.capturedAt,
    comparable: completeCaptures === parsed.length,
    completeCaptures,
    incompleteCaptures: parsed.length - completeCaptures,
    counts, cases,
    warnings: [
      "Timeline inputs are submitted captures; their provenance is not authenticated.",
      "The analysis is read-only and does not change reviews or remediation records.",
      "A case disappearing does not establish that a control works or a finding is resolved.",
      ...quality.some(q => q.blockers > 0) ? [
        "At least one capture has contradictory review or coverage metadata.",
      ] : [],
      ...quality.some(q => q.warnings > 0) ? [
        "At least one capture has quality warnings; interpret chronology conservatively.",
      ] : [],
    ],
  };
}
export function integrityTimelineCsv(report: IntegrityTimeline): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const names = ["caseKey", "workItemId", "code", "resourceId", "trend",
    "observations", "transitions", "reviewRevisions", "firstSeenAt",
    "lastSeenAt", "lastKnownState", "lastKnownSeverity", "reviewIsCurrent",
    "gaps"];
  const lines = [names.map(quote).join(",")];
  for (const row of report.cases) {
    lines.push([
      row.key, row.workItemId, row.code, row.resourceId, row.trend,
      row.observations, row.transitions, row.reviewRevisions,
      row.firstSeenAt, row.lastSeenAt, row.lastKnownState,
      row.lastKnownSeverity, row.reviewIsCurrent, row.gaps.join("; "),
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
