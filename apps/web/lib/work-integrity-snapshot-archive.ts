import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import { planSnapshotRetention, type RetentionPolicy } from "./work-integrity-snapshot-retention";

export type SnapshotArchivePolicy = {
  retention: RetentionPolicy;
  requireQualityClearance: boolean;
  rejectFutureCaptures: boolean;
  maxArchiveBytes: number;
  maxCaptures: number;
};
export type SnapshotArchiveItem = {
  source: string;
  capturedAt: string;
  caseCount: number;
  complete: boolean;
  qualityBlockers: number;
  qualityWarnings: number;
  retention: "KEEP" | "ELIGIBLE_FOR_DELETION";
  retentionReasons: string[];
  eligibleForArchive: boolean;
  archiveReasons: string[];
};
export type SnapshotArchivePlan = {
  organizationId: string;
  evaluatedAt: string;
  manifestRoot: string;
  estimatedBytes: number;
  withinByteLimit: boolean;
  items: SnapshotArchiveItem[];
  archiveCandidates: number;
  blockedCandidates: number;
  warnings: string[];
};
export function planSnapshotArchive(
  input: readonly unknown[], organizationId: string,
  evaluatedAt: string, policy: SnapshotArchivePolicy,
): SnapshotArchivePlan {
  if (!Number.isSafeInteger(policy.maxArchiveBytes) || policy.maxArchiveBytes < 1 ||
    policy.maxArchiveBytes > 1_000_000_000)
    throw new Error("Invalid archive byte budget.");
  if (!Number.isSafeInteger(policy.maxCaptures) || policy.maxCaptures < 1 ||
    policy.maxCaptures > 10000)
    throw new Error("Invalid archive capture limit.");
  if (input.length > policy.maxCaptures)
    throw new Error("Archive capture count exceeds configured limit.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const manifest = buildSnapshotManifest(captures, organizationId, evaluatedAt);
  const retention = planSnapshotRetention(captures, organizationId, evaluatedAt, policy.retention);
  const retentionByIdentity = new Map(retention.decisions.map(decision => [
    JSON.stringify([decision.source, Date.parse(decision.capturedAt)]), decision,
  ]));
  const now = Date.parse(evaluatedAt);
  const items = captures.map(capture => {
    const quality = inspectCaptureQuality(capture);
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    const decision = retentionByIdentity.get(identity);
    if (!decision) throw new Error("Missing retention decision.");
    const archiveReasons: string[] = [];
    if (decision.action !== "ELIGIBLE_FOR_DELETION")
      archiveReasons.push("protected-by-retention");
    if (policy.requireQualityClearance && !quality.safeToTreatAsComplete)
      archiveReasons.push("quality-not-cleared");
    if (policy.rejectFutureCaptures && Date.parse(capture.capturedAt) > now)
      archiveReasons.push("future-capture");
    return {
      source: capture.source, capturedAt: capture.capturedAt,
      caseCount: capture.cases.length, complete: capture.complete,
      qualityBlockers: quality.blockers, qualityWarnings: quality.warnings,
      retention: decision.action, retentionReasons: decision.reasons,
      eligibleForArchive: archiveReasons.length === 0, archiveReasons,
    };
  }).sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
  const estimatedBytes = Buffer.byteLength(JSON.stringify({
    version: 1, organizationId, captures,
  }), "utf8");
  const withinByteLimit = estimatedBytes <= policy.maxArchiveBytes;
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    manifestRoot: manifest.rootSha256, estimatedBytes, withinByteLimit, items,
    archiveCandidates: items.filter(item => item.eligibleForArchive).length,
    blockedCandidates: items.filter(item => !item.eligibleForArchive).length,
    warnings: [
      ...retention.warnings,
      ...(!withinByteLimit ? ["Archive payload exceeds the configured byte budget."] : []),
      "Archive eligibility is a proposal only; this function does not delete or move captures.",
      "Archival does not validate security outcomes or authenticate capture provenance.",
    ],
  };
}
export type ArchivePartition = {
  source: string;
  yearMonth: string;
  captures: CaseSnapshot[];
  bytes: number;
};
export function partitionSnapshotArchive(
  input: readonly unknown[], organizationId: string,
  maxPartitionBytes = 5_000_000,
): ArchivePartition[] {
  if (!Number.isSafeInteger(maxPartitionBytes) || maxPartitionBytes < 1024 ||
    maxPartitionBytes > 100_000_000)
    throw new Error("Invalid archive partition byte limit.");
  if (input.length > 10000) throw new Error("Archive partition count exceeded.");
  const groups = new Map<string, CaseSnapshot[]>();
  for (const value of input) {
    const capture = parseCaseSnapshot(value);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization archive partition is forbidden.");
    const month = new Date(capture.capturedAt).toISOString().slice(0, 7);
    const key = JSON.stringify([capture.source, month]);
    const group = groups.get(key) ?? [];
    group.push(capture);
    groups.set(key, group);
  }
  const partitions: ArchivePartition[] = [];
  for (const [key, captures] of groups) {
    const [source, yearMonth] = JSON.parse(key) as [string, string];
    captures.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt));
    let chunk: CaseSnapshot[] = [];
    let bytes = 0;
    const flush = () => {
      if (!chunk.length) return;
      partitions.push({ source, yearMonth, captures: chunk, bytes });
      chunk = [];
      bytes = 0;
    };
    for (const capture of captures) {
      const size = Buffer.byteLength(JSON.stringify(capture), "utf8");
      if (size > maxPartitionBytes)
        throw new Error("Individual capture exceeds archive partition byte limit.");
      if (bytes + size > maxPartitionBytes) flush();
      chunk.push(capture);
      bytes += size;
    }
    flush();
  }
  return partitions.sort((a, b) => a.source.localeCompare(b.source) ||
    a.yearMonth.localeCompare(b.yearMonth));
}
