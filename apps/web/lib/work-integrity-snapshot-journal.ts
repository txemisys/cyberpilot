import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

/**
 * An append-only logical capture journal with optimistic concurrency.
 * Callers may persist the resulting journal atomically; this pure reducer
 * never writes to storage or trusts a caller-supplied organization identity.
 */
export type JournalOperation =
  | "CAPTURE_ADDED" | "CAPTURE_DUPLICATE" | "CAPTURE_REJECTED"
  | "CAPTURE_QUARANTINED" | "CAPTURE_RELEASED" | "CAPTURE_ARCHIVED";
export type JournalEntry = {
  sequence: number;
  id: string;
  organizationId: string;
  source: string;
  capturedAt: string;
  recordedAt: string;
  actorId: string;
  operation: JournalOperation;
  captureDigest: string;
  reason: string;
  previousEntryDigest: string | null;
  entryDigest: string;
};
export type JournalCaptureStatus =
  | "ACTIVE" | "QUARANTINED" | "ARCHIVED" | "REJECTED";
export type JournalCaptureState = {
  source: string;
  capturedAt: string;
  digest: string;
  status: JournalCaptureStatus;
  lastOperation: JournalOperation;
  lastRecordedAt: string;
  lastActorId: string;
  journalSequence: number;
};
export type SnapshotJournal = {
  version: 1;
  organizationId: string;
  entries: JournalEntry[];
  captures: JournalCaptureState[];
  headDigest: string | null;
  nextSequence: number;
  warnings: string[];
};
export type JournalAppendInput = {
  id: string;
  source: string;
  capturedAt: string;
  recordedAt: string;
  actorId: string;
  operation: JournalOperation;
  captureDigest: string;
  reason: string;
  expectedHeadDigest: string | null;
};
export type JournalAppendResult = {
  journal: SnapshotJournal;
  appended: JournalEntry;
  previousStatus: JournalCaptureStatus | null;
  currentStatus: JournalCaptureStatus;
};
export type JournalValidation = {
  valid: boolean;
  checkedEntries: number;
  firstInvalidSequence: number | null;
  errors: string[];
  rebuilt: SnapshotJournal | null;
};
import { createHash } from "node:crypto";
function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}
function required(value: unknown, label: string, max = 1000): string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value;
}
function iso(value: unknown, label: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    throw new Error(`Invalid ${label}.`);
  return new Date(value).toISOString();
}
function identity(source: string, capturedAt: string): string {
  return JSON.stringify([source, Date.parse(capturedAt)]);
}
function entryHash(entry: Omit<JournalEntry, "entryDigest">): string {
  return digest([
    entry.sequence, entry.id, entry.organizationId,
    entry.source, entry.capturedAt, entry.recordedAt,
    entry.actorId, entry.operation, entry.captureDigest,
    entry.reason, entry.previousEntryDigest,
  ]);
}
function transition(previous: JournalCaptureStatus | null,
  operation: JournalOperation): JournalCaptureStatus {
  if (operation === "CAPTURE_ADDED") {
    if (previous !== null) throw new Error("Capture already exists in the journal.");
    return "ACTIVE";
  }
  if (operation === "CAPTURE_DUPLICATE") {
    if (previous === null) throw new Error("Cannot mark unknown capture as duplicate.");
    return previous;
  }
  if (operation === "CAPTURE_REJECTED") {
    if (previous !== null) throw new Error("Cannot reject an already registered capture.");
    return "REJECTED";
  }
  if (operation === "CAPTURE_QUARANTINED") {
    if (previous !== "ACTIVE") throw new Error("Only active captures can be quarantined.");
    return "QUARANTINED";
  }
  if (operation === "CAPTURE_RELEASED") {
    if (previous !== "QUARANTINED")
      throw new Error("Only quarantined captures can be released.");
    return "ACTIVE";
  }
  if (operation === "CAPTURE_ARCHIVED") {
    if (previous !== "ACTIVE")
      throw new Error("Only active captures can be archived.");
    return "ARCHIVED";
  }
  throw new Error("Unsupported journal operation.");
}
export function emptySnapshotJournal(organizationId: string): SnapshotJournal {
  required(organizationId, "organization ID", 256);
  return {
    version: 1, organizationId, entries: [], captures: [],
    headDigest: null, nextSequence: 1,
    warnings: [
      "Journal integrity hashes are not signatures and do not authenticate the writer.",
      "Journal state is a logical record, not proof that a snapshot exists in durable storage.",
      "Capture state transitions do not imply security control effectiveness.",
    ],
  };
}
export function appendSnapshotJournalEntry(
  journal: SnapshotJournal, input: JournalAppendInput,
  organizationId: string,
): JournalAppendResult {
  if (journal.organizationId !== organizationId)
    throw new Error("Cross-organization journal mutation forbidden.");
  if (journal.entries.length !== journal.nextSequence - 1 ||
      journal.headDigest !== (journal.entries.at(-1)?.entryDigest ?? null))
    throw new Error("Journal head or sequence is inconsistent.");
  if (journal.version !== 1 || journal.entries.length > 50000 ||
      journal.captures.length > 10000)
    throw new Error("Unsupported or oversized capture journal.");
  if (input.expectedHeadDigest !== journal.headDigest)
    throw new Error("Capture journal optimistic concurrency conflict.");
  required(input.id, "journal entry ID", 256);
  required(input.actorId, "journal actor", 256);
  required(input.source, "capture source");
  required(input.reason, "journal reason", 4000);
  const capturedAt = iso(input.capturedAt, "capture timestamp");
  const recordedAt = iso(input.recordedAt, "recording timestamp");
  if (Date.parse(recordedAt) < Date.parse(capturedAt))
    throw new Error("Journal entry cannot precede the capture.");
  if (!/^[a-f0-9]{64}$/.test(input.captureDigest))
    throw new Error("Invalid capture content digest.");
  if (journal.entries.some(entry => entry.id === input.id))
    throw new Error("Duplicate journal entry ID.");
  const key = identity(input.source, capturedAt);
  const previous = journal.captures.find(capture =>
    identity(capture.source, capture.capturedAt) === key);
  if (previous && previous.digest !== input.captureDigest)
    throw new Error("Journal capture digest conflict.");
  const status = transition(previous?.status ?? null, input.operation);
  const entryWithoutDigest: Omit<JournalEntry, "entryDigest"> = {
    sequence: journal.nextSequence, id: input.id,
    organizationId, source: input.source, capturedAt,
    recordedAt, actorId: input.actorId, operation: input.operation,
    captureDigest: input.captureDigest, reason: input.reason,
    previousEntryDigest: journal.headDigest,
  };
  const entry: JournalEntry = {
    ...entryWithoutDigest, entryDigest: entryHash(entryWithoutDigest),
  };
  const captures = journal.captures.filter(capture =>
    identity(capture.source, capture.capturedAt) !== key);
  captures.push({
    source: input.source, capturedAt, digest: input.captureDigest,
    status, lastOperation: input.operation, lastRecordedAt: recordedAt,
    lastActorId: input.actorId, journalSequence: entry.sequence,
  });
  captures.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
  return {
    journal: {
      ...journal, entries: [...journal.entries, entry], captures,
      headDigest: entry.entryDigest, nextSequence: entry.sequence + 1,
    },
    appended: entry, previousStatus: previous?.status ?? null,
    currentStatus: status,
  };
}
export function verifySnapshotJournal(
  input: SnapshotJournal, organizationId: string,
): JournalValidation {
  if (!input || input.organizationId !== organizationId)
    throw new Error("Cross-organization journal verification forbidden.");
  const errors: string[] = [];
  let rebuilt = emptySnapshotJournal(organizationId);
  let firstInvalidSequence: number | null = null;
  if (input.version !== 1 || !Array.isArray(input.entries) ||
      !Array.isArray(input.captures) || input.entries.length > 50000 ||
      input.captures.length > 10000)
    return {
      valid: false, checkedEntries: 0, firstInvalidSequence: null,
      errors: ["Invalid journal version or entry cardinality."], rebuilt: null,
    };
  for (let index = 0; index < input.entries.length; index++) {
    const entry = input.entries[index]!;
    try {
      if (entry.sequence !== index + 1)
        throw new Error("Journal sequence is not contiguous.");
      if (entry.organizationId !== organizationId)
        throw new Error("Cross-organization journal entry.");
      const expected = entryHash({
        sequence: entry.sequence, id: entry.id,
        organizationId: entry.organizationId, source: entry.source,
        capturedAt: entry.capturedAt, recordedAt: entry.recordedAt,
        actorId: entry.actorId, operation: entry.operation,
        captureDigest: entry.captureDigest, reason: entry.reason,
        previousEntryDigest: entry.previousEntryDigest,
      });
      if (expected !== entry.entryDigest)
        throw new Error("Journal entry digest mismatch.");
      rebuilt = appendSnapshotJournalEntry(rebuilt, {
        id: entry.id, source: entry.source,
        capturedAt: entry.capturedAt, recordedAt: entry.recordedAt,
        actorId: entry.actorId, operation: entry.operation,
        captureDigest: entry.captureDigest, reason: entry.reason,
        expectedHeadDigest: rebuilt.headDigest,
      }, organizationId).journal;
    } catch (error) {
      firstInvalidSequence = index + 1;
      errors.push(error instanceof Error ? error.message : "Invalid journal entry.");
      break;
    }
  }
  if (errors.length === 0) {
    if (rebuilt.headDigest !== input.headDigest)
      errors.push("Journal head digest differs from replayed entries.");
    if (rebuilt.nextSequence !== input.nextSequence)
      errors.push("Journal next sequence differs from replayed entries.");
    if (JSON.stringify(rebuilt.captures) !== JSON.stringify(input.captures))
      errors.push("Journal materialized capture states differ from replayed entries.");
  }
  return {
    valid: errors.length === 0,
    checkedEntries: rebuilt.entries.length,
    firstInvalidSequence, errors,
    rebuilt: errors.length ? null : rebuilt,
  };
}
export type JournalReconciliation = {
  organizationId: string;
  journalCaptures: number;
  suppliedCaptures: number;
  missingFromSupply: string[];
  unexpectedInSupply: string[];
  contentConflicts: string[];
  quarantinedInSupply: string[];
  rejectedInSupply: string[];
  archivedInSupply: string[];
  warnings: string[];
};
export function reconcileSnapshotJournal(
  journal: SnapshotJournal, input: readonly unknown[],
  organizationId: string, evaluatedAt: string,
): JournalReconciliation {
  const validation = verifySnapshotJournal(journal, organizationId);
  if (!validation.valid) throw new Error("Cannot reconcile an invalid capture journal.");
  if (input.length > 10000) throw new Error("Journal reconciliation capture limit exceeded.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const manifest = buildSnapshotManifest(captures, organizationId, evaluatedAt);
  const actual = new Map(manifest.entries.map(entry =>
    [identity(entry.source, entry.capturedAt), entry.sha256]));
  const expected = new Map(journal.captures.map(capture =>
    [identity(capture.source, capture.capturedAt), capture]));
  const missingFromSupply: string[] = [];
  const unexpectedInSupply: string[] = [];
  const contentConflicts: string[] = [];
  const quarantinedInSupply: string[] = [];
  const rejectedInSupply: string[] = [];
  const archivedInSupply: string[] = [];
  for (const [key, capture] of expected) {
    const supplied = actual.get(key);
    if (supplied === undefined) {
      if (capture.status === "ACTIVE") missingFromSupply.push(key);
      continue;
    }
    if (supplied !== capture.digest) contentConflicts.push(key);
    if (capture.status === "QUARANTINED") quarantinedInSupply.push(key);
    if (capture.status === "REJECTED") rejectedInSupply.push(key);
    if (capture.status === "ARCHIVED") archivedInSupply.push(key);
  }
  for (const key of actual.keys())
    if (!expected.has(key)) unexpectedInSupply.push(key);
  return {
    organizationId, journalCaptures: expected.size,
    suppliedCaptures: actual.size,
    missingFromSupply, unexpectedInSupply, contentConflicts,
    quarantinedInSupply, rejectedInSupply, archivedInSupply,
    warnings: [
      "The journal is supplied by the caller and is not an independently trusted audit log.",
      "A matching content hash is not proof of diagnostic truth or remediation success.",
      "Quarantined, rejected and archived captures must not be silently treated as active evidence.",
    ],
  };
}
export function planJournalAppendFromCaptures(
  input: readonly unknown[], journal: SnapshotJournal,
  organizationId: string, recordedAt: string, actorId: string,
): SnapshotJournal {
  const valid = verifySnapshotJournal(journal, organizationId);
  if (!valid.valid) throw new Error("Invalid starting journal.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const manifest = buildSnapshotManifest(captures, organizationId, recordedAt);
  const digests = new Map(manifest.entries.map(entry =>
    [identity(entry.source, entry.capturedAt), entry.sha256]));
  let next = journal;
  for (const capture of captures) {
    const key = identity(capture.source, capture.capturedAt);
    const existing = next.captures.find(item =>
      identity(item.source, item.capturedAt) === key);
    const operation: JournalOperation = existing ?
      "CAPTURE_DUPLICATE" : inspectCaptureQuality(capture).safeToTreatAsComplete ?
        "CAPTURE_ADDED" : "CAPTURE_REJECTED";
    next = appendSnapshotJournalEntry(next, {
      id: digest([actorId, recordedAt, key, next.nextSequence]),
      source: capture.source, capturedAt: capture.capturedAt,
      recordedAt, actorId, operation, captureDigest: digests.get(key)!,
      reason: existing ? "Identical capture already registered." :
        operation === "CAPTURE_ADDED" ?
          "Capture passed structural quality inspection." :
          "Capture did not pass structural quality inspection.",
      expectedHeadDigest: next.headDigest,
    }, organizationId).journal;
  }
  return next;
}
