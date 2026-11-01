import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";

/**
 * Deterministic retention planning for imported integrity snapshots.
 * This module makes no database changes: callers must explicitly approve deletions.
 * Incomplete captures are never silently substituted for complete baselines.
 */
export type RetentionPolicy = {
  maxAgeDays: number;
  minRecentCaptures: number;
  maxRetainedCaptures: number;
  preserveMonthlyBaselines: boolean;
  preserveFirstComplete: boolean;
};
export type RetentionDecision = {
  capturedAt: string;
  source: string;
  complete: boolean;
  caseCount: number;
  action: "KEEP" | "ELIGIBLE_FOR_DELETION";
  reasons: string[];
};
export type RetentionPlan = {
  organizationId: string;
  evaluatedAt: string;
  decisions: RetentionDecision[];
  retained: number;
  eligibleForDeletion: number;
  warnings: string[];
};
const DAY = 86_400_000;
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
export function validateRetentionPolicy(policy: RetentionPolicy): RetentionPolicy {
  return {
    maxAgeDays: integer(policy.maxAgeDays, 1, 3650, "retention age"),
    minRecentCaptures: integer(policy.minRecentCaptures, 1, 1000, "minimum recent captures"),
    maxRetainedCaptures: integer(policy.maxRetainedCaptures, 1, 10000, "maximum retained captures"),
    preserveMonthlyBaselines: policy.preserveMonthlyBaselines === true,
    preserveFirstComplete: policy.preserveFirstComplete === true,
  };
}
export function planSnapshotRetention(
  input: readonly unknown[],
  organizationId: string,
  now: string,
  policy: RetentionPolicy,
): RetentionPlan {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  const validated = validateRetentionPolicy(policy);
  const timestamp = Date.parse(now);
  if (!Number.isFinite(timestamp)) throw new Error("Invalid evaluation time.");
  if (input.length > 10000) throw new Error("Too many snapshots.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const identities = new Set<string>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization retention is forbidden.");
    const at = Date.parse(capture.capturedAt);
    if (at > timestamp) throw new Error("Future captures cannot be evaluated.");
    const identity = JSON.stringify([capture.source, at]);
    if (identities.has(identity)) throw new Error("Duplicate source capture timestamps.");
    identities.add(identity);
  }
  const bySource = new Map<string, CaseSnapshot[]>();
  for (const capture of captures) {
    const group = bySource.get(capture.source) ?? [];
    group.push(capture);
    bySource.set(capture.source, group);
  }
  const reasons = new Map<CaseSnapshot, Set<string>>();
  const mark = (capture: CaseSnapshot, reason: string) => {
    const set = reasons.get(capture) ?? new Set<string>();
    set.add(reason);
    reasons.set(capture, set);
  };
  const warnings: string[] = [];
  for (const [source, group] of bySource) {
    const sorted = [...group].sort((a, b) =>
      Date.parse(b.capturedAt) - Date.parse(a.capturedAt));
    for (const capture of sorted.slice(0, validated.minRecentCaptures))
      mark(capture, "recent-capture-floor");
    for (const capture of sorted) {
      if (timestamp - Date.parse(capture.capturedAt) <= validated.maxAgeDays * DAY)
        mark(capture, "within-retention-window");
    }
    if (validated.preserveFirstComplete) {
      const firstComplete = [...sorted].reverse().find(capture => capture.complete);
      if (firstComplete) mark(firstComplete, "first-complete-baseline");
      else warnings.push(`No complete baseline exists for source ${source}.`);
    }
    if (validated.preserveMonthlyBaselines) {
      const months = new Map<string, CaseSnapshot[]>();
      for (const capture of sorted) {
        const month = new Date(capture.capturedAt).toISOString().slice(0, 7);
        const bucket = months.get(month) ?? [];
        bucket.push(capture);
        months.set(month, bucket);
      }
      for (const bucket of months.values()) {
        const preferred = bucket.find(capture => capture.complete) ?? bucket[0]!;
        mark(preferred, "monthly-baseline");
      }
    }
    const protectedCount = sorted.filter(capture => reasons.has(capture)).length;
    if (protectedCount > validated.maxRetainedCaptures)
      warnings.push(`Source ${source} has ${protectedCount} protected captures, exceeding the requested cap of ${validated.maxRetainedCaptures}; no protected capture will be deleted.`);
    // Keep the most recent unprotected captures until the soft cap is reached.
    let remaining = Math.max(0, validated.maxRetainedCaptures - protectedCount);
    for (const capture of sorted) {
      if (reasons.has(capture)) continue;
      if (remaining > 0) {
        mark(capture, "soft-cap-recent");
        remaining--;
      }
    }
  }
  const decisions = captures.map(capture => {
    const keepReasons = [...(reasons.get(capture) ?? [])].sort();
    return {
      capturedAt: capture.capturedAt,
      source: capture.source,
      complete: capture.complete,
      caseCount: capture.cases.length,
      action: keepReasons.length ? "KEEP" as const : "ELIGIBLE_FOR_DELETION" as const,
      reasons: keepReasons.length ? keepReasons : ["outside-retention-policy"],
    };
  }).sort((a, b) => a.source.localeCompare(b.source) ||
    b.capturedAt.localeCompare(a.capturedAt));
  return {
    organizationId, evaluatedAt: new Date(timestamp).toISOString(), decisions,
    retained: decisions.filter(d => d.action === "KEEP").length,
    eligibleForDeletion: decisions.filter(d => d.action === "ELIGIBLE_FOR_DELETION").length,
    warnings,
  };
}
