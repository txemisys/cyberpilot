import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import {
  type SnapshotJournal, verifySnapshotJournal, type JournalCaptureState,
} from "./work-integrity-snapshot-journal";

/**
 * Evidence custody reconciliation across an independently supplied snapshot
 * inventory and the logical journal. This does not claim that the journal is
 * independently trustworthy or that snapshots prove a control is effective.
 */
export type CustodyIssueKind =
  | "JOURNAL_INVALID" | "CAPTURE_UNREGISTERED" | "CAPTURE_MISSING"
  | "CONTENT_MODIFIED" | "CAPTURE_QUARANTINED" | "CAPTURE_REJECTED"
  | "CAPTURE_ARCHIVED" | "DUPLICATE_CAPTURE" | "FUTURE_CAPTURE"
  | "SOURCE_OUT_OF_SCOPE" | "STALE_ACTIVE_CAPTURE"
  | "INCOMPLETE_ACTIVE_CAPTURE";
export type CustodyIssueSeverity = "BLOCKER" | "WARNING" | "INFO";
export type CustodyIssue = {
  kind: CustodyIssueKind;
  severity: CustodyIssueSeverity;
  source: string;
  capturedAt: string | null;
  expectedDigest: string | null;
  actualDigest: string | null;
  explanation: string;
  recommendedAction: string;
};
export type CustodyPolicy = {
  maxCaptures: number;
  maxAgeDays: number;
  maxFutureSkewMinutes: number;
  requireCompleteActiveCaptures: boolean;
  allowedSources: readonly string[] | null;
  includeArchived: boolean;
  includeRejected: boolean;
};
export type CustodySourceSummary = {
  source: string;
  activeJournalCaptures: number;
  suppliedCaptures: number;
  matchedActiveCaptures: number;
  blockers: number;
  warnings: number;
  latestActiveAt: string | null;
  latestSuppliedAt: string | null;
};
export type CustodyReport = {
  organizationId: string;
  evaluatedAt: string;
  journalValid: boolean;
  journalHead: string | null;
  journalEntries: number;
  suppliedCaptures: number;
  matchedActiveCaptures: number;
  blockers: number;
  warnings: number;
  issues: CustodyIssue[];
  sources: CustodySourceSummary[];
  operationallyReconciled: boolean;
  limitations: string[];
};
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function identity(source: string, capturedAt: string): string {
  return JSON.stringify([source, Date.parse(capturedAt)]);
}
function issue(
  kind: CustodyIssueKind, severity: CustodyIssueSeverity, source: string,
  capturedAt: string | null, expectedDigest: string | null,
  actualDigest: string | null, explanation: string, recommendedAction: string,
): CustodyIssue {
  return {
    kind, severity, source, capturedAt, expectedDigest, actualDigest,
    explanation, recommendedAction,
  };
}
export function auditSnapshotCustody(
  rawCaptures: readonly unknown[], journal: SnapshotJournal,
  organizationId: string, evaluatedAt: string, policy: CustodyPolicy,
): CustodyReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  const maxCaptures = integer(policy.maxCaptures, 1, 10000, "custody capture limit");
  const maxAgeDays = integer(policy.maxAgeDays, 1, 3650, "custody age");
  const maxFutureSkewMinutes = integer(policy.maxFutureSkewMinutes, 0, 1440,
    "custody clock skew");
  if (typeof policy.requireCompleteActiveCaptures !== "boolean" ||
      typeof policy.includeArchived !== "boolean" ||
      typeof policy.includeRejected !== "boolean")
    throw new Error("Invalid custody policy flags.");
  if (rawCaptures.length > maxCaptures)
    throw new Error("Custody capture cardinality exceeded.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid custody evaluation time.");
  if (!journal || journal.organizationId !== organizationId)
    throw new Error("Cross-organization custody journal forbidden.");
  const allowed = policy.allowedSources === null ? null :
    new Set(policy.allowedSources);
  if (allowed && (allowed.size !== policy.allowedSources!.length ||
      [...allowed].some(source => typeof source !== "string" || !source.trim())))
    throw new Error("Invalid custody source allowlist.");
  const validation = verifySnapshotJournal(journal, organizationId);
  const captures = rawCaptures.map(value => parseCaseSnapshot(value));
  for (const capture of captures)
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization custody capture forbidden.");
  const issues: CustodyIssue[] = [];
  if (!validation.valid)
    issues.push(issue("JOURNAL_INVALID", "BLOCKER", "*", null, null, null,
      "Journal hash chain or materialized state failed replay validation.",
      "Restore the journal from a trusted checkpoint before reconciling custody."));
  const uniqueCaptures: CaseSnapshot[] = [];
  const manifestIdentities = new Set<string>();
  for (const capture of captures) {
    const key = identity(capture.source, capture.capturedAt);
    if (!manifestIdentities.has(key)) {
      uniqueCaptures.push(capture);
      manifestIdentities.add(key);
    }
  }
  const manifest = buildSnapshotManifest(uniqueCaptures, organizationId, evaluatedAt);
  const digests = new Map(manifest.entries.map(entry =>
    [identity(entry.source, entry.capturedAt), entry.sha256]));
  const journalByIdentity = new Map<string, JournalCaptureState>();
  if (validation.valid)
    for (const entry of journal.captures)
      journalByIdentity.set(identity(entry.source, entry.capturedAt), entry);
  const seen = new Set<string>();
  let matchedActiveCaptures = 0;
  for (const capture of captures) {
    const key = identity(capture.source, capture.capturedAt);
    const actualDigest = digests.get(key) ?? null;
    if (seen.has(key)) {
      issues.push(issue("DUPLICATE_CAPTURE", "BLOCKER", capture.source,
        capture.capturedAt, null, actualDigest,
        "A source and capture timestamp appears more than once.",
        "Deduplicate the inventory using a trusted source identity."));
      continue;
    }
    seen.add(key);
    if (allowed && !allowed.has(capture.source))
      issues.push(issue("SOURCE_OUT_OF_SCOPE", "BLOCKER", capture.source,
        capture.capturedAt, null, actualDigest,
        "The capture source is outside the allowed custody scope.",
        "Review the expected source schedule and remove unauthorized inputs."));
    const timestamp = Date.parse(capture.capturedAt);
    if (timestamp > now + maxFutureSkewMinutes * 60000)
      issues.push(issue("FUTURE_CAPTURE", "BLOCKER", capture.source,
        capture.capturedAt, null, actualDigest,
        "Capture timestamp exceeds permitted clock skew.",
        "Check source clock synchronization and recollect the capture."));
    const registered = journalByIdentity.get(key);
    if (!validation.valid) continue;
    if (!registered) {
      issues.push(issue("CAPTURE_UNREGISTERED", "BLOCKER", capture.source,
        capture.capturedAt, null, actualDigest,
        "The supplied capture is absent from the verified journal.",
        "Investigate provenance and register it through an authorized workflow."));
      continue;
    }
    if (registered.digest !== actualDigest) {
      issues.push(issue("CONTENT_MODIFIED", "BLOCKER", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "Capture content differs from the digest registered in the journal.",
        "Quarantine the capture and investigate the integrity discrepancy."));
      continue;
    }
    if (registered.status === "QUARANTINED")
      issues.push(issue("CAPTURE_QUARANTINED", "BLOCKER", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "A quarantined capture was included in the supplied inventory.",
        "Exclude it from active evidence until an authorized release."));
    else if (registered.status === "REJECTED" && policy.includeRejected)
      issues.push(issue("CAPTURE_REJECTED", "WARNING", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "A rejected capture remains present in the inventory.",
        "Preserve rejection history but exclude it from operational conclusions."));
    else if (registered.status === "ARCHIVED" && policy.includeArchived)
      issues.push(issue("CAPTURE_ARCHIVED", "INFO", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "An archived capture was supplied for custody reconciliation.",
        "Verify that archival storage and retention obligations are satisfied."));
    if (registered.status !== "ACTIVE") continue;
    matchedActiveCaptures++;
    if (now - timestamp > maxAgeDays * 86400000)
      issues.push(issue("STALE_ACTIVE_CAPTURE", "WARNING", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "The latest supplied active evidence exceeds the age threshold.",
        "Schedule a fresh collection before using the snapshot for current decisions."));
    if (policy.requireCompleteActiveCaptures && !capture.complete)
      issues.push(issue("INCOMPLETE_ACTIVE_CAPTURE", "WARNING", capture.source,
        capture.capturedAt, registered.digest, actualDigest,
        "An active capture does not claim complete source coverage.",
        "Recollect the source before interpreting missing cases as resolved."));
  }
  if (validation.valid)
    for (const entry of journal.captures) {
      if (entry.status !== "ACTIVE") continue;
      const key = identity(entry.source, entry.capturedAt);
      if (!seen.has(key))
        issues.push(issue("CAPTURE_MISSING", "BLOCKER", entry.source,
          entry.capturedAt, entry.digest, null,
          "An active journal capture is absent from the supplied inventory.",
          "Recover the original content from trusted storage or investigate its loss."));
    }
  const sourceNames = new Set([
    ...captures.map(capture => capture.source),
    ...(validation.valid ? journal.captures.map(entry => entry.source) : []),
  ]);
  const sources = [...sourceNames].sort().map(source => {
    const supplied = captures.filter(capture => capture.source === source);
    const active = validation.valid ? journal.captures.filter(entry =>
      entry.source === source && entry.status === "ACTIVE") : [];
    const sourceIssues = issues.filter(item => item.source === source);
    const matched = supplied.filter(capture => {
      const entry = journalByIdentity.get(identity(capture.source, capture.capturedAt));
      return entry?.status === "ACTIVE" &&
        entry.digest === digests.get(identity(capture.source, capture.capturedAt));
    });
    return {
      source, activeJournalCaptures: active.length,
      suppliedCaptures: supplied.length,
      matchedActiveCaptures: matched.length,
      blockers: sourceIssues.filter(item => item.severity === "BLOCKER").length,
      warnings: sourceIssues.filter(item => item.severity === "WARNING").length,
      latestActiveAt: active.length ? active.map(entry => entry.capturedAt).sort().at(-1)! : null,
      latestSuppliedAt: supplied.length ?
        supplied.map(capture => capture.capturedAt).sort().at(-1)! : null,
    };
  });
  issues.sort((a, b) => a.source.localeCompare(b.source) ||
    (a.capturedAt ?? "").localeCompare(b.capturedAt ?? "") ||
    a.kind.localeCompare(b.kind));
  const blockers = issues.filter(item => item.severity === "BLOCKER").length;
  const warnings = issues.filter(item => item.severity === "WARNING").length;
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    journalValid: validation.valid,
    journalHead: journal.headDigest, journalEntries: journal.entries.length,
    suppliedCaptures: captures.length, matchedActiveCaptures,
    blockers, warnings, issues, sources,
    operationallyReconciled: validation.valid && blockers === 0,
    limitations: [
      "Custody reconciliation compares caller-supplied snapshots and a caller-supplied journal.",
      "A hash-chain match does not independently authenticate journal authors or storage.",
      "Operational reconciliation does not establish that security controls are effective.",
    ],
  };
}
