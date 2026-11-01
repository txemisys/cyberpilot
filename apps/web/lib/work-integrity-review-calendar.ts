import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/**
 * Deterministic offline review calendar. No notifications are sent and no
 * external calendar entries are created. All deadlines are UTC instants.
 */
export type ReviewCadence = {
  priority: "P0" | "P1" | "P2" | "P3" | "P4";
  dueWithinHours: number;
  escalationAfterHours: number;
};
export type ReviewCalendarPolicy = {
  cadences: ReviewCadence[];
  maxItems: number;
  excludeHistorical: boolean;
  excludeReviewed: boolean;
  requireCompleteSnapshot: boolean;
};
export type ReviewCalendarEntry = {
  caseKey: string;
  workItemId: string;
  code: string;
  priority: ReviewCadence["priority"];
  capturedAt: string;
  dueAt: string;
  escalationAt: string;
  reviewEventId: string | null;
  revision: number;
  coverageComplete: boolean;
};
export type ReviewCalendar = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  entries: ReviewCalendarEntry[];
  omitted: number;
  warnings: string[];
};
export type ReviewCalendarStatus = "UPCOMING" | "DUE" | "ESCALATED" | "UNKNOWN";
export type ReviewCalendarAssessment = {
  assessedAt: string;
  total: number;
  byStatus: Record<ReviewCalendarStatus, number>;
  overdue: ReviewCalendarEntry[];
  escalated: ReviewCalendarEntry[];
  upcoming: ReviewCalendarEntry[];
  unknown: ReviewCalendarEntry[];
};
export const DEFAULT_REVIEW_CADENCES: ReviewCadence[] = [
  { priority: "P0", dueWithinHours: 4, escalationAfterHours: 8 },
  { priority: "P1", dueWithinHours: 24, escalationAfterHours: 48 },
  { priority: "P2", dueWithinHours: 72, escalationAfterHours: 120 },
  { priority: "P3", dueWithinHours: 168, escalationAfterHours: 240 },
  { priority: "P4", dueWithinHours: 336, escalationAfterHours: 504 },
];
function parseUtcInstant(value: string, label: string): number {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw new Error(`Invalid ${label}: expected millisecond-precision UTC timestamp.`);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis) || new Date(millis).toISOString() !== value)
    throw new Error(`Invalid ${label}: noncanonical UTC timestamp.`);
  return millis;
}
function utcAfter(start: number, hours: number): string {
  const timestamp = start + hours * 3_600_000;
  if (!Number.isFinite(timestamp) || timestamp > 8_640_000_000_000_000)
    throw new Error("Review deadline is outside the supported timestamp range.");
  return new Date(timestamp).toISOString();
}
export function validateReviewCalendarPolicy(policy: ReviewCalendarPolicy): ReviewCalendarPolicy {
  if (!policy || !Array.isArray(policy.cadences) || policy.cadences.length !== 5)
    throw new Error("Review calendar requires five priority cadences.");
  const priorities = new Set<string>();
  const cadences = policy.cadences.map(cadence => {
    if (!["P0", "P1", "P2", "P3", "P4"].includes(cadence.priority))
      throw new Error("Invalid review priority.");
    if (priorities.has(cadence.priority)) throw new Error("Duplicate review priority.");
    priorities.add(cadence.priority);
    if (!Number.isSafeInteger(cadence.dueWithinHours) ||
        !Number.isSafeInteger(cadence.escalationAfterHours) ||
        cadence.dueWithinHours < 1 ||
        cadence.escalationAfterHours < cadence.dueWithinHours ||
        cadence.escalationAfterHours > 24 * 365 * 5)
      throw new Error("Invalid review cadence deadlines.");
    return { ...cadence };
  });
  if (!Number.isSafeInteger(policy.maxItems) || policy.maxItems < 1 || policy.maxItems > 100000)
    throw new Error("Invalid calendar item limit.");
  if (typeof policy.excludeHistorical !== "boolean" ||
      typeof policy.excludeReviewed !== "boolean" ||
      typeof policy.requireCompleteSnapshot !== "boolean")
    throw new Error("Invalid calendar policy flags.");
  return { ...policy, cadences: cadences.sort((a, b) => a.priority.localeCompare(b.priority)) };
}
export function createReviewCalendar(
  snapshot: CaseSnapshot,
  input: ReviewCalendarPolicy = {
    cadences: DEFAULT_REVIEW_CADENCES, maxItems: 10000,
    excludeHistorical: true, excludeReviewed: false,
    requireCompleteSnapshot: true,
  },
): ReviewCalendar {
  const policy = validateReviewCalendarPolicy(input);
  if (policy.requireCompleteSnapshot && !snapshot.complete)
    throw new Error("Cannot schedule a complete review calendar from partial capture.");
  const start = parseUtcInstant(snapshot.capturedAt, "capture timestamp");
  const cadence = new Map(policy.cadences.map(item => [item.priority, item]));
  const entries = buildReviewWorklist(snapshot).entries.filter(item =>
    (!policy.excludeHistorical || !item.historicalOnly) &&
    (!policy.excludeReviewed || !item.reviewEventId));
  if (entries.length > policy.maxItems)
    throw new Error("Calendar exceeds configured item bound.");
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, complete: snapshot.complete,
    entries: entries.map(item => {
      const schedule = cadence.get(item.priority)!;
      return {
        caseKey: item.caseKey, workItemId: item.workItemId, code: item.code,
        priority: item.priority, capturedAt: snapshot.capturedAt,
        dueAt: utcAfter(start, schedule.dueWithinHours),
        escalationAt: utcAfter(start, schedule.escalationAfterHours),
        reviewEventId: item.reviewEventId, revision: item.currentRevision,
        coverageComplete: item.completeCoverage,
      };
    }),
    omitted: snapshot.cases.length - entries.length,
    warnings: [
      "Deadlines are planning targets, not guarantees of review or remediation.",
      "Calendar generation does not send notifications or alter review records.",
      ...(!snapshot.complete ? ["Incomplete capture may omit other cases."] : []),
    ],
  };
}
export function reviewCalendarStatus(
  item: ReviewCalendarEntry, assessedAt: string,
): ReviewCalendarStatus {
  const now = parseUtcInstant(assessedAt, "assessment time");
  const due = parseUtcInstant(item.dueAt, "due time");
  const escalation = parseUtcInstant(item.escalationAt, "escalation time");
  if (escalation < due) throw new Error("Escalation precedes due time.");
  if (!item.coverageComplete) return "UNKNOWN";
  if (now >= escalation) return "ESCALATED";
  if (now >= due) return "DUE";
  return "UPCOMING";
}
export function assessReviewCalendar(
  calendar: ReviewCalendar, assessedAt: string,
): ReviewCalendarAssessment {
  parseUtcInstant(assessedAt, "assessment time");
  const byStatus: Record<ReviewCalendarStatus, number> = {
    UPCOMING: 0, DUE: 0, ESCALATED: 0, UNKNOWN: 0,
  };
  const overdue: ReviewCalendarEntry[] = [];
  const escalated: ReviewCalendarEntry[] = [];
  const upcoming: ReviewCalendarEntry[] = [];
  const unknown: ReviewCalendarEntry[] = [];
  for (const item of calendar.entries) {
    const status = !calendar.complete ? "UNKNOWN" : reviewCalendarStatus(item, assessedAt);
    byStatus[status]++;
    if (status === "DUE") overdue.push(item);
    else if (status === "ESCALATED") escalated.push(item);
    else if (status === "UPCOMING") upcoming.push(item);
    else unknown.push(item);
  }
  return {
    assessedAt, total: calendar.entries.length, byStatus,
    overdue, escalated, upcoming, unknown,
  };
}
export type ReviewCalendarChange = {
  caseKey: string;
  kind: "ADDED" | "REMOVED" | "RESCHEDULED" | "UNCHANGED" | "UNCERTAIN";
  previousDueAt: string | null;
  currentDueAt: string | null;
};
export function compareReviewCalendars(
  before: ReviewCalendar, after: ReviewCalendar,
): ReviewCalendarChange[] {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare calendars across organizations.");
  const old = new Map(before.entries.map(item => [item.caseKey, item]));
  const current = new Map(after.entries.map(item => [item.caseKey, item]));
  const result: ReviewCalendarChange[] = [];
  for (const key of [...new Set([...old.keys(), ...current.keys()])].sort()) {
    const previous = old.get(key);
    const next = current.get(key);
    const kind = !previous || !next
      ? (!before.complete || !after.complete ? "UNCERTAIN" : previous ? "REMOVED" : "ADDED")
      : previous.dueAt !== next.dueAt || previous.escalationAt !== next.escalationAt ||
        previous.revision !== next.revision ? "RESCHEDULED" : "UNCHANGED";
    result.push({
      caseKey: key, kind,
      previousDueAt: previous?.dueAt ?? null,
      currentDueAt: next?.dueAt ?? null,
    });
  }
  return result;
}
export function reviewCalendarCsv(calendar: ReviewCalendar): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const escaped = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + escaped.replace(/"/g, '""') + '"';
  };
  const lines = [[
    "caseKey", "workItemId", "code", "priority", "dueAt",
    "escalationAt", "revision", "reviewEventId", "coverageComplete",
  ].map(safe).join(",")];
  for (const item of calendar.entries)
    lines.push([item.caseKey, item.workItemId, item.code, item.priority,
      item.dueAt, item.escalationAt, item.revision, item.reviewEventId,
      item.coverageComplete].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function reviewCalendarJson(calendar: ReviewCalendar): string {
  return JSON.stringify(calendar, null, 2) + "\n";
}
