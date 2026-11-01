import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest, verifySnapshotManifest, type SnapshotManifest } from "./work-integrity-snapshot-integrity";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

/**
 * Prepare a bounded recovery transaction from a trusted manifest.
 * No storage writes occur here. Callers must enforce authorization,
 * atomic persistence and independent manifest provenance.
 */
export type RecoveryAction =
  | { kind: "RESTORE"; source: string; capturedAt: string; snapshot: CaseSnapshot }
  | { kind: "REMOVE_UNEXPECTED"; source: string; capturedAt: string }
  | { kind: "RETAIN"; source: string; capturedAt: string };
export type RecoveryPolicy = {
  allowRemoval: boolean;
  requireComplete: boolean;
  rejectQualityBlockers: boolean;
  maxRestores: number;
  maxRemovals: number;
};
export type RecoveryPlan = {
  organizationId: string;
  manifestRoot: string;
  actions: RecoveryAction[];
  restores: number;
  removals: number;
  retained: number;
  executable: boolean;
  blockers: string[];
  warnings: string[];
};
function identity(value: { source: string; capturedAt: string }): string {
  return JSON.stringify([value.source, Date.parse(value.capturedAt)]);
}
function validateLimit(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 10000)
    throw new Error(`Invalid ${label}.`);
  return value;
}
export function planSnapshotRecovery(
  manifest: SnapshotManifest,
  trustedSnapshots: readonly unknown[],
  currentSnapshots: readonly unknown[],
  organizationId: string,
  policy: RecoveryPolicy,
): RecoveryPlan {
  const maxRestores = validateLimit(policy.maxRestores, "restore limit");
  const maxRemovals = validateLimit(policy.maxRemovals, "removal limit");
  if (manifest.organizationId !== organizationId)
    throw new Error("Cross-organization recovery manifest is forbidden.");
  if (trustedSnapshots.length > 10000 || currentSnapshots.length > 10000)
    throw new Error("Recovery capture limit exceeded.");
  const trusted = trustedSnapshots.map(value => parseCaseSnapshot(value));
  const current = currentSnapshots.map(value => parseCaseSnapshot(value));
  for (const capture of [...trusted, ...current]) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization recovery capture is forbidden.");
  }
  const verification = verifySnapshotManifest(manifest, trusted);
  const blockers: string[] = [];
  if (!verification.verified)
    blockers.push("Trusted recovery material does not match the supplied manifest.");
  const expected = new Map<string, CaseSnapshot>();
  const actual = new Map<string, CaseSnapshot>();
  for (const capture of trusted) {
    const key = identity(capture);
    if (expected.has(key)) throw new Error("Duplicate trusted capture identity.");
    expected.set(key, capture);
  }
  for (const capture of current) {
    const key = identity(capture);
    if (actual.has(key)) throw new Error("Duplicate current capture identity.");
    actual.set(key, capture);
  }
  const trustedDigest = buildSnapshotManifest(trusted, organizationId, manifest.generatedAt);
  const currentDigest = buildSnapshotManifest(current, organizationId, manifest.generatedAt);
  const trustedEntries = new Map(trustedDigest.entries.map(entry => [identity(entry), entry]));
  const currentEntries = new Map(currentDigest.entries.map(entry => [identity(entry), entry]));
  const actions: RecoveryAction[] = [];
  for (const [key, capture] of expected) {
    const found = actual.get(key);
    const referenceDigest = trustedEntries.get(key);
    const observedDigest = currentEntries.get(key);
    if (found && referenceDigest?.sha256 === observedDigest?.sha256) {
      actions.push({ kind: "RETAIN", source: capture.source, capturedAt: capture.capturedAt });
      continue;
    }
    if (policy.requireComplete && !capture.complete)
      blockers.push(`Recovery candidate ${key} lacks complete coverage.`);
    if (policy.rejectQualityBlockers && inspectCaptureQuality(capture).blockers > 0)
      blockers.push(`Recovery candidate ${key} has structural quality blockers.`);
    actions.push({ kind: "RESTORE", source: capture.source,
      capturedAt: capture.capturedAt, snapshot: capture });
  }
  for (const [key, capture] of actual) {
    if (expected.has(key)) continue;
    if (!policy.allowRemoval) {
      blockers.push(`Unexpected capture ${key} cannot be removed by policy.`);
      continue;
    }
    actions.push({ kind: "REMOVE_UNEXPECTED", source: capture.source,
      capturedAt: capture.capturedAt });
  }
  actions.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt) || a.kind.localeCompare(b.kind));
  const restores = actions.filter(action => action.kind === "RESTORE").length;
  const removals = actions.filter(action => action.kind === "REMOVE_UNEXPECTED").length;
  const retained = actions.filter(action => action.kind === "RETAIN").length;
  if (restores > maxRestores) blockers.push("Restore operation exceeds configured limit.");
  if (removals > maxRemovals) blockers.push("Removal operation exceeds configured limit.");
  return {
    organizationId, manifestRoot: manifest.rootSha256, actions, restores, removals, retained,
    executable: blockers.length === 0, blockers,
    warnings: [
      "Recovery planning never writes, deletes or authenticates records.",
      "The caller must establish trusted manifest provenance before authorizing recovery.",
      "Restored diagnostics are historical records, not proof of security-control effectiveness.",
    ],
  };
}
export type RecoverySimulation = {
  organizationId: string;
  resultingManifestRoot: string;
  matchesExpectedManifest: boolean;
  resultingCaptureCount: number;
  warnings: string[];
};
export function simulateSnapshotRecovery(
  plan: RecoveryPlan, currentSnapshots: readonly unknown[],
  expectedManifest: SnapshotManifest,
): RecoverySimulation {
  if (!plan.executable) throw new Error("Recovery plan contains blocking issues.");
  if (plan.organizationId !== expectedManifest.organizationId)
    throw new Error("Cross-organization recovery simulation is forbidden.");
  if (plan.manifestRoot !== expectedManifest.rootSha256)
    throw new Error("Recovery plan manifest does not match expected manifest.");
  if (plan.restores !== plan.actions.filter(action => action.kind === "RESTORE").length ||
      plan.removals !== plan.actions.filter(action => action.kind === "REMOVE_UNEXPECTED").length ||
      plan.retained !== plan.actions.filter(action => action.kind === "RETAIN").length)
    throw new Error("Recovery plan action counts are inconsistent.");
  const plannedIdentities = new Set<string>();
  for (const action of plan.actions) {
    if (action.kind !== "RESTORE" && action.kind !== "REMOVE_UNEXPECTED" &&
        action.kind !== "RETAIN")
      throw new Error("Unsupported recovery action.");
    const key = identity(action);
    if (plannedIdentities.has(key))
      throw new Error("Duplicate recovery action identity.");
    plannedIdentities.add(key);
    if (action.kind === "RESTORE") {
      const snapshot = parseCaseSnapshot(action.snapshot);
      if (snapshot.organizationId !== plan.organizationId ||
          identity(snapshot) !== key)
        throw new Error("Recovery action snapshot identity mismatch.");
    }
  }
  const result = new Map<string, CaseSnapshot>();
  for (const value of currentSnapshots) {
    const capture = parseCaseSnapshot(value);
    if (capture.organizationId !== plan.organizationId)
      throw new Error("Cross-organization simulation capture is forbidden.");
    const key = identity(capture);
    if (result.has(key)) throw new Error("Duplicate simulation capture.");
    result.set(key, capture);
  }
  for (const action of plan.actions) {
    const key = identity(action);
    if (action.kind === "REMOVE_UNEXPECTED") result.delete(key);
    else if (action.kind === "RESTORE") result.set(key, action.snapshot);
  }
  const captures = [...result.values()];
  const manifest = buildSnapshotManifest(captures, plan.organizationId, expectedManifest.generatedAt);
  return {
    organizationId: plan.organizationId,
    resultingManifestRoot: manifest.rootSha256,
    matchesExpectedManifest: verifySnapshotManifest(expectedManifest, captures).verified,
    resultingCaptureCount: captures.length,
    warnings: ["This is a pure in-memory simulation; no recovery has been applied to persistent storage."],
  };
}
