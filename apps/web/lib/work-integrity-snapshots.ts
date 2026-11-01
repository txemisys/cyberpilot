/** Pure, tenant-agnostic snapshot comparison for integrity case queues. */
import type { CaseRow, CaseState, CaseSeverity } from "./work-integrity-cases";

export type CaseSnapshot = {
  capturedAt: string;
  organizationId: string;
  source: string;
  complete: boolean;
  cases: CaseRow[];
};
export type CaseDeltaKind = "NEW" | "CLEARED" | "CHANGED" | "UNCHANGED" | "INDETERMINATE";
export type CaseDelta = {
  key: string;
  kind: CaseDeltaKind;
  before: CaseRow | null;
  after: CaseRow | null;
  changes: string[];
};
export type SnapshotComparison = {
  organizationId: string;
  beforeCapturedAt: string;
  afterCapturedAt: string;
  complete: boolean;
  counts: Record<CaseDeltaKind, number>;
  deltas: CaseDelta[];
  warnings: string[];
};
const states: CaseState[] = [
  "UNREVIEWED", "INVESTIGATING", "ACKNOWLEDGED", "DISMISSED",
  "REOPENED", "STALE", "NO_LONGER_DETECTED",
];
const severities: (CaseSeverity | null)[] = ["critical", "attention", "info", null];
const comparedFields = [
  "taskStatus", "taskRevision", "severity", "diagnostic",
  "recommendation", "state", "reviewEventId", "reviewedRevision",
  "completeCoverage", "historicalOnly",
] as const;
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Expected an object.");
  return value as Record<string, unknown>;
}
function requiredString(value: unknown, field: string, max = 256): string {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new Error(`Invalid ${field}.`);
  return value;
}
function optionalString(value: unknown, field: string, max = 4000): string | null {
  if (value === null) return null;
  return requiredString(value, field, max);
}
function caseRow(value: unknown): CaseRow {
  const row = record(value);
  const workItemId = requiredString(row.workItemId, "workItemId");
  const code = requiredString(row.code, "code");
  const resourceId = requiredString(row.resourceId, "resourceId");
  const key = JSON.stringify([workItemId, code, resourceId]);
  if (row.key !== key) throw new Error("Case key does not match identity.");
  if (!states.includes(row.state as CaseState)) throw new Error("Invalid case state.");
  if (!severities.includes(row.severity as CaseSeverity | null))
    throw new Error("Invalid severity.");
  if (!Number.isSafeInteger(row.taskRevision) || (row.taskRevision as number) < 1)
    throw new Error("Invalid revision.");
  if (typeof row.completeCoverage !== "boolean" || typeof row.historicalOnly !== "boolean")
    throw new Error("Invalid coverage.");
  if (row.reviewedRevision !== null &&
      (!Number.isSafeInteger(row.reviewedRevision) || (row.reviewedRevision as number) < 1))
    throw new Error("Invalid reviewed revision.");
  return {
    key, workItemId, code: code as CaseRow["code"], resourceId,
    taskStatus: requiredString(row.taskStatus, "taskStatus"),
    taskRevision: row.taskRevision as number,
    severity: row.severity as CaseSeverity | null,
    diagnostic: optionalString(row.diagnostic, "diagnostic"),
    recommendation: optionalString(row.recommendation, "recommendation"),
    state: row.state as CaseState,
    reviewEventId: optionalString(row.reviewEventId, "reviewEventId"),
    reviewedAt: optionalString(row.reviewedAt, "reviewedAt"),
    reviewedRevision: row.reviewedRevision as number | null,
    reviewerUserId: optionalString(row.reviewerUserId, "reviewerUserId"),
    reviewRationale: optionalString(row.reviewRationale, "reviewRationale"),
    reviewReference: optionalString(row.reviewReference, "reviewReference"),
    completeCoverage: row.completeCoverage as boolean,
    historicalOnly: row.historicalOnly as boolean,
  };
}
export function parseCaseSnapshot(value: unknown, maxCases = 10000): CaseSnapshot {
  const raw = record(value);
  const organizationId = requiredString(raw.organizationId, "organizationId");
  const source = requiredString(raw.source, "source", 1000);
  const capturedAt = requiredString(raw.capturedAt, "capturedAt");
  if (!Number.isFinite(Date.parse(capturedAt))) throw new Error("Invalid capture time.");
  if (typeof raw.complete !== "boolean") throw new Error("Invalid completeness.");
  if (!Array.isArray(raw.cases) || raw.cases.length > maxCases)
    throw new Error("Snapshot exceeds bounded case limit.");
  const cases = raw.cases.map(caseRow);
  const keys = new Set(cases.map(row => row.key));
  if (keys.size !== cases.length) throw new Error("Duplicate case identities.");
  return { organizationId, source, capturedAt, complete: raw.complete, cases };
}
export function compareCaseSnapshots(before: CaseSnapshot, after: CaseSnapshot): SnapshotComparison {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cross-organization comparison is forbidden.");
  const oldCases = new Map(before.cases.map(row => [row.key, row]));
  const newCases = new Map(after.cases.map(row => [row.key, row]));
  const keys = [...new Set([...oldCases.keys(), ...newCases.keys()])].sort();
  const complete = before.complete && after.complete;
  const counts: Record<CaseDeltaKind, number> = {
    NEW: 0, CLEARED: 0, CHANGED: 0, UNCHANGED: 0, INDETERMINATE: 0,
  };
  const deltas = keys.map(key => {
    const oldRow = oldCases.get(key) ?? null;
    const newRow = newCases.get(key) ?? null;
    const changes: string[] = [];
    if (oldRow && newRow) {
      for (const field of comparedFields) {
        if (oldRow[field] !== newRow[field]) changes.push(field);
      }
    }
    let kind: CaseDeltaKind;
    if (!oldRow || !newRow) {
      kind = !complete ? "INDETERMINATE" : !oldRow ? "NEW" : "CLEARED";
    } else {
      kind = changes.length ? "CHANGED" : "UNCHANGED";
    }
    counts[kind]++;
    return { key, kind, before: oldRow, after: newRow, changes };
  });
  return {
    organizationId: before.organizationId,
    beforeCapturedAt: before.capturedAt,
    afterCapturedAt: after.capturedAt,
    complete,
    counts,
    deltas,
    warnings: [
      "Changes describe recorded diagnostic case snapshots, not validated security outcomes.",
      ...(!complete ? ["Incomplete snapshots cannot establish newly detected or cleared cases."] : []),
      "A cleared case does not establish that a security control is effective.",
    ],
  };
}
