import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import { type SnapshotJournal, verifySnapshotJournal } from "./work-integrity-snapshot-journal";

/**
 * Validate a candidate archive against the journal's logical active inventory.
 * This is a dry-run plan. No storage mutation is performed.
 */
export type JournalArchivePolicy = {
  minimumAgeDays: number;
  preserveLatestPerSource: number;
  maximumArchiveCaptures: number;
  requireComplete: boolean;
  requireJournalValidation: boolean;
  allowQuarantined: boolean;
};
export type JournalArchiveReason =
  | "TOO_RECENT" | "SOURCE_FLOOR" | "INCOMPLETE" | "NOT_IN_JOURNAL"
  | "CONTENT_CONFLICT" | "QUARANTINED" | "REJECTED"
  | "ALREADY_ARCHIVED" | "FUTURE_CAPTURE" | "ELIGIBLE";
export type JournalArchiveCandidate = {
  source: string;
  capturedAt: string;
  digest: string;
  journalStatus: string | null;
  ageDays: number;
  eligible: boolean;
  reasons: JournalArchiveReason[];
};
export type JournalArchivePlan = {
  organizationId: string;
  evaluatedAt: string;
  eligible: number;
  blocked: number;
  eligibleBytes: number;
  candidates: JournalArchiveCandidate[];
  warnings: string[];
};
function identity(source: string, capturedAt: string): string {
  return JSON.stringify([source, Date.parse(capturedAt)]);
}
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
export function planJournalArchive(
  input: readonly unknown[], journal: SnapshotJournal,
  organizationId: string, evaluatedAt: string,
  policy: JournalArchivePolicy,
): JournalArchivePlan {
  if (journal.organizationId !== organizationId)
    throw new Error("Cross-organization archive journal forbidden.");
  if (policy.requireJournalValidation &&
      !verifySnapshotJournal(journal, organizationId).valid)
    throw new Error("Archive journal fails integrity verification.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid archive evaluation time.");
  if (input.length > 10000) throw new Error("Archive capture limit exceeded.");
  const minimumAgeDays = integer(policy.minimumAgeDays, 0, 3650, "archive age");
  const preserveLatestPerSource = integer(policy.preserveLatestPerSource, 0, 1000,
    "archive source floor");
  const maximumArchiveCaptures = integer(policy.maximumArchiveCaptures, 1, 10000,
    "archive cardinality");
  const captures = input.map(value => parseCaseSnapshot(value));
  const manifest = buildSnapshotManifest(captures, organizationId, evaluatedAt);
  const hashes = new Map(manifest.entries.map(entry =>
    [identity(entry.source, entry.capturedAt), entry.sha256]));
  const journalEntries = new Map(journal.captures.map(entry =>
    [identity(entry.source, entry.capturedAt), entry]));
  const groups = new Map<string, CaseSnapshot[]>();
  for (const capture of captures) {
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const protectedKeys = new Set<string>();
  for (const group of groups.values()) {
    group.sort((a, b) => Date.parse(b.capturedAt) - Date.parse(a.capturedAt));
    for (const capture of group.slice(0, preserveLatestPerSource))
      protectedKeys.add(identity(capture.source, capture.capturedAt));
  }
  const candidates: JournalArchiveCandidate[] = [];
  let eligibleBytes = 0;
  let eligible = 0;
  for (const capture of captures) {
    const key = identity(capture.source, capture.capturedAt);
    const entry = journalEntries.get(key);
    const digest = hashes.get(key)!;
    const ageDays = (now - Date.parse(capture.capturedAt)) / 86400000;
    const reasons: JournalArchiveReason[] = [];
    if (ageDays < 0) reasons.push("FUTURE_CAPTURE");
    if (ageDays < minimumAgeDays) reasons.push("TOO_RECENT");
    if (protectedKeys.has(key)) reasons.push("SOURCE_FLOOR");
    if (policy.requireComplete && !capture.complete) reasons.push("INCOMPLETE");
    if (!entry) reasons.push("NOT_IN_JOURNAL");
    if (entry && entry.digest !== digest) reasons.push("CONTENT_CONFLICT");
    if (entry?.status === "QUARANTINED" && !policy.allowQuarantined)
      reasons.push("QUARANTINED");
    if (entry?.status === "REJECTED") reasons.push("REJECTED");
    if (entry?.status === "ARCHIVED") reasons.push("ALREADY_ARCHIVED");
    const canArchive = reasons.length === 0 && eligible < maximumArchiveCaptures;
    if (canArchive) {
      eligible++;
      eligibleBytes += Buffer.byteLength(JSON.stringify(capture), "utf8");
    }
    candidates.push({
      source: capture.source, capturedAt: capture.capturedAt,
      digest, journalStatus: entry?.status ?? null, ageDays,
      eligible: canArchive,
      reasons: canArchive ? ["ELIGIBLE"] :
        reasons.length ? reasons : ["SOURCE_FLOOR"],
    });
  }
  candidates.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    eligible, blocked: candidates.length - eligible,
    eligibleBytes, candidates,
    warnings: [
      "This is a dry-run archive plan and does not move or delete any captures.",
      "Journal status is supplied by the caller and is not independent evidence of durable storage.",
      "Archive eligibility does not establish that the original capture is authentic.",
    ],
  };
}
