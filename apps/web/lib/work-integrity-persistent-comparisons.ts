import { compareCaseSnapshots, type SnapshotComparison } from "./work-integrity-snapshots";
import {
  pageStoredIntegrityCaptures, readStoredIntegrityCapture,
  type StoredCaptureSummary,
} from "./work-integrity-persistent-captures";

export type StoredCaptureComparison = {
  organizationId: string;
  source: string;
  before: StoredCaptureSummary;
  after: StoredCaptureSummary;
  comparison: SnapshotComparison;
  limitations: string[];
};

export async function compareStoredIntegrityCaptureIds(
  organizationId: string, beforeId: string, afterId: string,
): Promise<SnapshotComparison> {
  if (!organizationId || !beforeId || !afterId || beforeId === afterId)
    throw new Error("Two distinct captures in an authenticated organization are required.");
  const [before, after] = await Promise.all([
    readStoredIntegrityCapture(organizationId, beforeId),
    readStoredIntegrityCapture(organizationId, afterId),
  ]);
  if (!before || !after) throw new Error("Stored capture not found.");
  if (before.source !== after.source)
    throw new Error("Cross-source comparison is forbidden.");
  if (Date.parse(before.capturedAt) >= Date.parse(after.capturedAt))
    throw new Error("Comparison must progress chronologically.");
  return compareCaseSnapshots(before, after);
}

/**
 * Compare the latest two stored captures for a source. This intentionally
 * does not infer a cleared control from a missing case in partial evidence.
 */
export async function compareLatestStoredIntegrityCaptures(
  organizationId: string, source: string,
): Promise<StoredCaptureComparison | null> {
  if (!organizationId || !source.trim())
    throw new Error("Authenticated organization and source are required.");
  const page = await pageStoredIntegrityCaptures(organizationId, 2, undefined, source);
  if (page.captures.length < 2) return null;
  const [after, before] = page.captures;
  if (!after || !before) return null;
  const comparison = await compareStoredIntegrityCaptureIds(
    organizationId, before.id, after.id,
  );
  return {
    organizationId, source, before, after, comparison,
    limitations: [
      "Stored diagnostics are historical observations, not proof of control effectiveness.",
      "Missing cases in incomplete captures must not be interpreted as remediation.",
      "Stored content hashes establish consistency, not independent provenance.",
    ],
  };
}
