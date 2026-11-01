import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { parseCaseSnapshot } from "./work-integrity-snapshots";

/** Safe bounded offline interchange for operational case snapshots. */
export type SnapshotEnvelope = {
  schemaVersion: 1;
  exportType: "CYBERPILOT_CASE_SNAPSHOT";
  organizationId: string;
  generatedAt: string;
  complete: boolean;
  source: string;
  cases: CaseRow[];
  metadata: {
    scannedWorkItems: number;
    returnedCases: number;
    nextCursor: string | null;
    limitations: string[];
  };
};
export type SnapshotImportResult = {
  snapshot: CaseSnapshot;
  metadata: SnapshotEnvelope["metadata"];
  warnings: string[];
};
export type SnapshotBatch = {
  organizationId: string;
  exports: SnapshotEnvelope[];
  complete: boolean;
  firstCapturedAt: string | null;
  lastCapturedAt: string | null;
  totalCases: number;
};
const MAX_CASES = 10000;
const MAX_TEXT = 4000;
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Expected an object.");
  return value as Record<string, unknown>;
}
function string(value: unknown, label: string, max = MAX_TEXT): string {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function integer(value: unknown, label: string, max = 100000000): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new Error(`Invalid ${label}.`);
  return value as number;
}
function limitations(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100 ||
      value.some(item => typeof item !== "string" || item.length > MAX_TEXT))
    throw new Error("Invalid limitations.");
  return value as string[];
}
export function parseSnapshotEnvelope(value: unknown): SnapshotEnvelope {
  const input = object(value);
  if (input.schemaVersion !== 1 || input.exportType !== "CYBERPILOT_CASE_SNAPSHOT")
    throw new Error("Unsupported snapshot envelope.");
  const organizationId = string(input.organizationId, "organization");
  const generatedAt = string(input.generatedAt, "capture time", 100);
  const source = string(input.source, "source", 1000);
  if (typeof input.complete !== "boolean")
    throw new Error("Invalid completeness.");
  const metadata = object(input.metadata);
  const scannedWorkItems = integer(metadata.scannedWorkItems, "scanned work items");
  const returnedCases = integer(metadata.returnedCases, "returned cases", MAX_CASES);
  const nextCursor = metadata.nextCursor === null ? null :
    string(metadata.nextCursor, "cursor", 300);
  const notes = limitations(metadata.limitations);
  const snapshot = parseCaseSnapshot({
    organizationId, source, capturedAt: generatedAt,
    complete: input.complete, cases: input.cases,
  }, MAX_CASES);
  if (returnedCases !== snapshot.cases.length)
    throw new Error("Returned case count does not match the envelope.");
  return {
    schemaVersion: 1, exportType: "CYBERPILOT_CASE_SNAPSHOT",
    organizationId, generatedAt, complete: input.complete,
    source, cases: snapshot.cases,
    metadata: {
      scannedWorkItems, returnedCases, nextCursor, limitations: notes,
    },
  };
}
export function importSnapshotEnvelope(
  value: unknown, expectedOrganizationId: string,
): SnapshotImportResult {
  const envelope = parseSnapshotEnvelope(value);
  if (!expectedOrganizationId || envelope.organizationId !== expectedOrganizationId)
    throw new Error("Snapshot does not belong to the selected organization.");
  return {
    snapshot: {
      organizationId: envelope.organizationId,
      source: envelope.source,
      capturedAt: envelope.generatedAt,
      complete: envelope.complete,
      cases: envelope.cases,
    },
    metadata: envelope.metadata,
    warnings: [
      "Imported data is an offline diagnostic snapshot, not a verified security assessment.",
      ...(!envelope.complete ? ["Snapshot coverage is incomplete."] : []),
      ...(envelope.metadata.nextCursor !== null
        ? ["The export contains a continuation cursor and is not a complete inventory."] : []),
      ...envelope.metadata.limitations,
    ],
  };
}
export function exportSnapshotEnvelope(
  snapshot: CaseSnapshot,
  metadata: SnapshotEnvelope["metadata"],
): SnapshotEnvelope {
  const normalized = parseCaseSnapshot(snapshot);
  return parseSnapshotEnvelope({
    schemaVersion: 1,
    exportType: "CYBERPILOT_CASE_SNAPSHOT",
    organizationId: normalized.organizationId,
    generatedAt: normalized.capturedAt,
    complete: normalized.complete,
    source: normalized.source,
    cases: normalized.cases,
    metadata,
  });
}
export function snapshotEnvelopeJson(envelope: SnapshotEnvelope): string {
  return JSON.stringify(parseSnapshotEnvelope(envelope), null, 2) + "\n";
}
export function parseSnapshotJson(text: string, expectedOrganizationId: string): SnapshotImportResult {
  if (typeof text !== "string" || text.length > 10_000_000)
    throw new Error("Snapshot JSON exceeds the input limit.");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Snapshot JSON is invalid."); }
  return importSnapshotEnvelope(parsed, expectedOrganizationId);
}
export function buildSnapshotBatch(envelopes: readonly SnapshotEnvelope[]): SnapshotBatch {
  if (envelopes.length > 100) throw new Error("Snapshot batch exceeds 100 captures.");
  const normalized = envelopes.map(parseSnapshotEnvelope);
  const organizationId = normalized[0]?.organizationId ?? "";
  if (normalized.some(item => item.organizationId !== organizationId))
    throw new Error("Cannot combine captures from different organizations.");
  const exports = normalized.sort((a, b) =>
    a.generatedAt.localeCompare(b.generatedAt));
  const dates = exports.map(item => item.generatedAt);
  if (new Set(dates).size !== dates.length)
    throw new Error("Duplicate capture timestamps.");
  return {
    organizationId, exports,
    complete: exports.every(item => item.complete && item.metadata.nextCursor === null),
    firstCapturedAt: dates[0] ?? null,
    lastCapturedAt: dates.at(-1) ?? null,
    totalCases: exports.reduce((sum, item) => sum + item.cases.length, 0),
  };
}
export function batchToSnapshots(batch: SnapshotBatch): CaseSnapshot[] {
  return batch.exports.map(envelope => importSnapshotEnvelope(
    envelope, batch.organizationId,
  ).snapshot);
}
export type SnapshotCoverage = {
  complete: boolean;
  scannedWorkItems: number;
  returnedCases: number;
  continuationPending: boolean;
  incompleteCaseRows: number;
  reasons: string[];
};
export function envelopeCoverage(envelope: SnapshotEnvelope): SnapshotCoverage {
  const item = parseSnapshotEnvelope(envelope);
  const incompleteCaseRows = item.cases.filter(row => !row.completeCoverage).length;
  const continuationPending = item.metadata.nextCursor !== null;
  const complete = item.complete && !continuationPending && incompleteCaseRows === 0;
  return {
    complete,
    scannedWorkItems: item.metadata.scannedWorkItems,
    returnedCases: item.metadata.returnedCases,
    continuationPending,
    incompleteCaseRows,
    reasons: [
      ...(!item.complete ? ["Capture marked incomplete."] : []),
      ...(continuationPending ? ["More work-item pages remain."] : []),
      ...(incompleteCaseRows ? ["Linked records are incomplete for some cases."] : []),
    ],
  };
}
export function snapshotCaseIndex(snapshot: CaseSnapshot): Map<string, CaseRow> {
  const index = new Map<string, CaseRow>();
  for (const row of snapshot.cases) {
    if (index.has(row.key)) throw new Error("Duplicate case key.");
    index.set(row.key, row);
  }
  return index;
}
export function mergeSnapshotPages(pages: readonly SnapshotEnvelope[]): SnapshotEnvelope {
  if (!pages.length) throw new Error("At least one page is required.");
  const normalized = pages.map(parseSnapshotEnvelope);
  const first = normalized[0]!;
  if (normalized.some(item =>
    item.organizationId !== first.organizationId ||
    item.generatedAt !== first.generatedAt ||
    item.source !== first.source))
    throw new Error("Snapshot pages must share capture identity.");
  const cases = normalized.flatMap(item => item.cases);
  if (cases.length > MAX_CASES) throw new Error("Merged snapshot exceeds case limit.");
  const keys = new Set(cases.map(row => row.key));
  if (keys.size !== cases.length)
    throw new Error("Overlapping snapshot pages contain duplicate cases.");
  const last = normalized.at(-1)!;
  return exportSnapshotEnvelope({
    organizationId: first.organizationId,
    capturedAt: first.generatedAt,
    source: first.source,
    complete: normalized.every(item => item.complete) && last.metadata.nextCursor === null,
    cases,
  }, {
    scannedWorkItems: normalized.reduce((sum, item) => sum + item.metadata.scannedWorkItems, 0),
    returnedCases: cases.length,
    nextCursor: last.metadata.nextCursor,
    limitations: [...new Set(normalized.flatMap(item => item.metadata.limitations))].slice(0, 100),
  });
}
