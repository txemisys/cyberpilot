import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";

/**
 * Offline capture ingestion preflight. This never persists snapshots:
 * it computes a complete, bounded, tenant-scoped acceptance plan.
 */
export type IngestionRejectionCode =
  | "DUPLICATE_BATCH_IDENTITY" | "EXISTING_IDENTICAL"
  | "EXISTING_CONFLICT" | "FUTURE_CAPTURE" | "STALE_CAPTURE"
  | "INCOMPLETE_COVERAGE" | "QUALITY_BLOCKERS"
  | "QUALITY_WARNINGS" | "SOURCE_NOT_ALLOWED"
  | "SOURCE_QUOTA" | "CASE_QUOTA";
export type IngestionDisposition = "ACCEPT" | "SKIP_IDENTICAL" | "REJECT";
export type IngestionPolicy = {
  maxAgeDays: number;
  maxFutureSkewMinutes: number;
  maxCasesPerCapture: number;
  maxCapturesPerSource: number;
  requireComplete: boolean;
  rejectQualityBlockers: boolean;
  rejectQualityWarnings: boolean;
  allowedSources: string[] | null;
};
export type IngestionCandidate = {
  source: string;
  capturedAt: string;
  complete: boolean;
  caseCount: number;
  digest: string;
  disposition: IngestionDisposition;
  reasons: IngestionRejectionCode[];
  qualityBlockers: number;
  qualityWarnings: number;
  conflictsWithExisting: boolean;
};
export type IngestionPlan = {
  organizationId: string;
  evaluatedAt: string;
  candidates: IngestionCandidate[];
  accepted: number;
  skippedIdentical: number;
  rejected: number;
  acceptedSources: string[];
  resultingSourceCounts: Array<{ source: string; count: number }>;
  warnings: string[];
};
function bounded(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function identity(capture: { source: string; capturedAt: string }): string {
  return JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
}
function digestMap(captures: CaseSnapshot[], organizationId: string, at: string): Map<string, string> {
  const manifest = buildSnapshotManifest(captures, organizationId, at);
  return new Map(manifest.entries.map(entry => [identity(entry), entry.sha256]));
}
export function planSnapshotIngestion(
  incomingInput: readonly unknown[], existingInput: readonly unknown[],
  organizationId: string, evaluatedAt: string, policy: IngestionPolicy,
): IngestionPlan {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (incomingInput.length > 10000 || existingInput.length > 10000)
    throw new Error("Ingestion capture limit exceeded.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid ingestion evaluation time.");
  const maxAgeDays = bounded(policy.maxAgeDays, 1, 3650, "ingestion age");
  const maxFutureSkewMinutes = bounded(policy.maxFutureSkewMinutes, 0, 1440,
    "ingestion future skew");
  const maxCasesPerCapture = bounded(policy.maxCasesPerCapture, 0, 10000,
    "ingestion case limit");
  const maxCapturesPerSource = bounded(policy.maxCapturesPerSource, 1, 10000,
    "ingestion source quota");
  const allowed = policy.allowedSources === null ? null : new Set(policy.allowedSources);
  if (allowed && (allowed.size !== policy.allowedSources!.length ||
      [...allowed].some(source => typeof source !== "string" ||
        !source.trim() || source.length > 1000)))
    throw new Error("Invalid allowed source list.");
  const incoming = incomingInput.map(value => parseCaseSnapshot(value));
  const existing = existingInput.map(value => parseCaseSnapshot(value));
  for (const capture of [...incoming, ...existing])
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization ingestion capture is forbidden.");
  const existingHashes = digestMap(existing, organizationId, evaluatedAt);
  const sourceCounts = new Map<string, number>();
  for (const capture of existing)
    sourceCounts.set(capture.source, (sourceCounts.get(capture.source) ?? 0) + 1);
  const incomingHashes = new Map<string, string>();
  const manifest = buildSnapshotManifest(
    incoming.filter((capture, index) =>
      incoming.findIndex(other => identity(other) === identity(capture)) === index),
    organizationId, evaluatedAt);
  const hashByKey = new Map(manifest.entries.map(entry => [identity(entry), entry.sha256]));
  const candidates: IngestionCandidate[] = [];
  for (const capture of incoming) {
    const key = identity(capture);
    const digest = hashByKey.get(key)!;
    const reasons: IngestionRejectionCode[] = [];
    const existingDigest = existingHashes.get(key);
    const quality = inspectCaptureQuality(capture);
    if (incomingHashes.has(key)) reasons.push("DUPLICATE_BATCH_IDENTITY");
    incomingHashes.set(key, digest);
    if (existingDigest !== undefined)
      reasons.push(existingDigest === digest ? "EXISTING_IDENTICAL" : "EXISTING_CONFLICT");
    if (Date.parse(capture.capturedAt) > now + maxFutureSkewMinutes * 60000)
      reasons.push("FUTURE_CAPTURE");
    if (now - Date.parse(capture.capturedAt) > maxAgeDays * 86400000)
      reasons.push("STALE_CAPTURE");
    if (policy.requireComplete && !capture.complete)
      reasons.push("INCOMPLETE_COVERAGE");
    if (policy.rejectQualityBlockers && quality.blockers > 0)
      reasons.push("QUALITY_BLOCKERS");
    if (policy.rejectQualityWarnings && quality.warnings > 0)
      reasons.push("QUALITY_WARNINGS");
    if (allowed && !allowed.has(capture.source))
      reasons.push("SOURCE_NOT_ALLOWED");
    if (capture.cases.length > maxCasesPerCapture)
      reasons.push("CASE_QUOTA");
    if ((sourceCounts.get(capture.source) ?? 0) >= maxCapturesPerSource &&
        existingDigest === undefined)
      reasons.push("SOURCE_QUOTA");
    const disposition: IngestionDisposition =
      reasons.length === 1 && reasons[0] === "EXISTING_IDENTICAL" ?
        "SKIP_IDENTICAL" : reasons.length ? "REJECT" : "ACCEPT";
    if (disposition === "ACCEPT")
      sourceCounts.set(capture.source, (sourceCounts.get(capture.source) ?? 0) + 1);
    candidates.push({
      source: capture.source, capturedAt: capture.capturedAt,
      complete: capture.complete, caseCount: capture.cases.length,
      digest, disposition, reasons,
      qualityBlockers: quality.blockers, qualityWarnings: quality.warnings,
      conflictsWithExisting: existingDigest !== undefined && existingDigest !== digest,
    });
  }
  candidates.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(), candidates,
    accepted: candidates.filter(item => item.disposition === "ACCEPT").length,
    skippedIdentical: candidates.filter(item => item.disposition === "SKIP_IDENTICAL").length,
    rejected: candidates.filter(item => item.disposition === "REJECT").length,
    acceptedSources: [...new Set(candidates.filter(item =>
      item.disposition === "ACCEPT").map(item => item.source))].sort(),
    resultingSourceCounts: [...sourceCounts].map(([source, count]) =>
      ({ source, count })).sort((a, b) => a.source.localeCompare(b.source)),
    warnings: [
      "Ingestion is a dry-run plan; no snapshots have been written to storage.",
      "Capture completeness and diagnostic accuracy cannot be independently verified from supplied records.",
      "Accepted captures require a separate authorized, atomic persistence operation.",
    ],
  };
}
export type IngestionExecutionBatch = {
  organizationId: string;
  accepted: CaseSnapshot[];
  rejectedIdentities: string[];
  skippedIdentities: string[];
  expectedDigestByIdentity: Record<string, string>;
  warnings: string[];
};
export function materializeAcceptedSnapshotBatch(
  plan: IngestionPlan, incomingInput: readonly unknown[],
): IngestionExecutionBatch {
  if (incomingInput.length > 10000) throw new Error("Ingestion materialization limit exceeded.");
  const captures = incomingInput.map(value => parseCaseSnapshot(value));
  const acceptedByKey = new Map(plan.candidates.filter(candidate =>
    candidate.disposition === "ACCEPT").map(candidate =>
      [identity(candidate), candidate.digest]));
  // A materialization request must contain precisely the preflight identities,
  // including rejected and skipped candidates. Otherwise a stale or forged
  // plan could be replayed against a different batch without detection.
  const plannedKeys = new Set(plan.candidates.map(identity));
  if (plannedKeys.size !== plan.candidates.length)
    throw new Error("Ingestion batch differs from its preflight plan.");
  const seen = new Set<string>();
  const accepted: CaseSnapshot[] = [];
  for (const capture of captures) {
    if (capture.organizationId !== plan.organizationId)
      throw new Error("Cross-organization ingestion materialization forbidden.");
    const key = identity(capture);
    if (seen.has(key)) throw new Error("Duplicate ingestion materialization identity.");
    seen.add(key);
    if (!plannedKeys.has(key))
      throw new Error("Unplanned ingestion capture identity.");
    if (acceptedByKey.has(key)) accepted.push(capture);
  }
  if (accepted.length !== acceptedByKey.size ||
      seen.size !== plannedKeys.size)
    throw new Error("Ingestion plan references missing captures.");
  const hashes = digestMap(accepted, plan.organizationId, plan.evaluatedAt);
  for (const [key, digest] of acceptedByKey)
    if (hashes.get(key) !== digest)
      throw new Error("Accepted capture was modified after ingestion preflight.");
  return {
    organizationId: plan.organizationId, accepted,
    rejectedIdentities: plan.candidates.filter(item =>
      item.disposition === "REJECT").map(identity),
    skippedIdentities: plan.candidates.filter(item =>
      item.disposition === "SKIP_IDENTICAL").map(identity),
    expectedDigestByIdentity: Object.fromEntries(acceptedByKey),
    warnings: [
      "Materialization verifies content against the plan but does not persist it.",
      "The caller must re-check authorization and concurrency before committing captures.",
    ],
  };
}
