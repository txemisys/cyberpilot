import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";

export type SnapshotReleaseGate =
  | "IDENTITY" | "COVERAGE" | "QUALITY" | "FRESHNESS"
  | "REVIEW" | "BASELINE" | "MANIFEST";
export type ReleaseGateResult = {
  gate: SnapshotReleaseGate;
  passed: boolean;
  explanation: string;
  requiredAction: string | null;
};
export type SnapshotReleasePolicy = {
  maxAgeDays: number;
  requireComplete: boolean;
  requireQualityClearance: boolean;
  requireReview: boolean;
  requireBaseline: boolean;
  minCases: number;
};
export type SnapshotReleaseAssessment = {
  organizationId: string;
  source: string;
  capturedAt: string;
  evaluatedAt: string;
  eligible: boolean;
  gates: ReleaseGateResult[];
  manifestDigest: string;
  limitations: string[];
};
export type SnapshotReleaseReview = {
  status: "PENDING" | "ACCEPTED" | "REJECTED" | "NEEDS_RECAPTURE";
  reviewerId: string | null;
  reviewedAt: string | null;
};
const DAY = 86400000;
export function assessSnapshotRelease(
  snapshotInput: unknown, organizationId: string, evaluatedAt: string,
  policy: SnapshotReleasePolicy,
  review: SnapshotReleaseReview | null,
  baselineInput: unknown | null,
): SnapshotReleaseAssessment {
  const snapshot = parseCaseSnapshot(snapshotInput);
  if (snapshot.organizationId !== organizationId)
    throw new Error("Cross-organization release assessment is forbidden.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid release evaluation time.");
  if (!Number.isSafeInteger(policy.maxAgeDays) || policy.maxAgeDays < 1 ||
    policy.maxAgeDays > 3650) throw new Error("Invalid release age limit.");
  if (!Number.isSafeInteger(policy.minCases) || policy.minCases < 0 ||
    policy.minCases > 10000) throw new Error("Invalid minimum case count.");
  const quality = inspectCaptureQuality(snapshot);
  const baseline = baselineInput === null ? null : parseCaseSnapshot(baselineInput);
  if (baseline && baseline.organizationId !== organizationId)
    throw new Error("Cross-organization release baseline is forbidden.");
  const gates: ReleaseGateResult[] = [];
  const add = (gate: SnapshotReleaseGate, passed: boolean,
    explanation: string, requiredAction: string | null) =>
    gates.push({ gate, passed, explanation, requiredAction: passed ? null : requiredAction });
  add("IDENTITY", snapshot.source.length > 0,
    "Capture source and tenant identity have been validated against the request.",
    "Provide a valid capture source and organization.");
  add("COVERAGE", (!policy.requireComplete || snapshot.complete) &&
    snapshot.cases.length >= policy.minCases,
    "Capture coverage and minimum case cardinality meet the configured policy.",
    "Recollect complete case coverage and verify the expected case count.");
  add("QUALITY", !policy.requireQualityClearance || quality.safeToTreatAsComplete,
    "Structural capture quality satisfies the configured release requirement.",
    "Resolve capture quality blockers and warnings before release.");
  const age = (now - Date.parse(snapshot.capturedAt)) / DAY;
  add("FRESHNESS", age >= 0 && age <= policy.maxAgeDays,
    "Capture age is within the configured freshness window.",
    "Acquire a fresh capture and verify its collection time.");
  const reviewAccepted = review?.status === "ACCEPTED" &&
    review.reviewerId !== null && review.reviewedAt !== null &&
    Number.isFinite(Date.parse(review.reviewedAt)) &&
    Date.parse(review.reviewedAt) >= Date.parse(snapshot.capturedAt) &&
    Date.parse(review.reviewedAt) <= now;
  add("REVIEW", !policy.requireReview || reviewAccepted,
    "An explicit review decision is recorded for the capture.",
    "Obtain an authorized, timestamped capture review.");
  const baselineComparable = baseline !== null &&
    baseline.source === snapshot.source &&
    Date.parse(baseline.capturedAt) < Date.parse(snapshot.capturedAt);
  add("BASELINE", !policy.requireBaseline || baselineComparable,
    "An earlier capture of the same source is available for comparison.",
    "Provide an earlier same-source capture to establish a comparison baseline.");
  const manifest = buildSnapshotManifest([snapshot], organizationId, evaluatedAt);
  add("MANIFEST", manifest.entries.length === 1,
    "A deterministic content manifest was generated for this capture.",
    "Regenerate the capture manifest.");
  return {
    organizationId, source: snapshot.source, capturedAt: snapshot.capturedAt,
    evaluatedAt: new Date(now).toISOString(),
    eligible: gates.every(gate => gate.passed), gates,
    manifestDigest: manifest.rootSha256,
    limitations: [
      "Release eligibility is an operational policy decision, not proof of security compliance.",
      "A generated manifest does not authenticate the provenance of a capture.",
      "This assessment does not persist review decisions or change remediation states.",
    ],
  };
}
export type SnapshotReleaseBatch = {
  organizationId: string;
  assessed: number;
  eligible: number;
  blocked: number;
  results: SnapshotReleaseAssessment[];
  failedByGate: Record<SnapshotReleaseGate, number>;
};
export function assessSnapshotReleaseBatch(
  input: readonly unknown[], organizationId: string, evaluatedAt: string,
  policy: SnapshotReleasePolicy,
  reviews: ReadonlyMap<string, SnapshotReleaseReview> = new Map(),
): SnapshotReleaseBatch {
  if (input.length > 10000) throw new Error("Release batch capture limit exceeded.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const groups = new Map<string, CaseSnapshot[]>();
  const identities = new Set<string>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization release batch is forbidden.");
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (identities.has(identity)) throw new Error("Duplicate release capture identity.");
    identities.add(identity);
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const results: SnapshotReleaseAssessment[] = [];
  for (const group of groups.values()) {
    group.sort((a, b) => Date.parse(a.capturedAt) - Date.parse(b.capturedAt));
    for (let index = 0; index < group.length; index++) {
      const capture = group[index]!;
      const key = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
      results.push(assessSnapshotRelease(capture, organizationId, evaluatedAt, policy,
        reviews.get(key) ?? null, index > 0 ? group[index - 1]! : null));
    }
  }
  const gateNames: SnapshotReleaseGate[] = [
    "IDENTITY", "COVERAGE", "QUALITY", "FRESHNESS", "REVIEW", "BASELINE", "MANIFEST",
  ];
  const failedByGate = Object.fromEntries(gateNames.map(gate => [
    gate, results.filter(result => result.gates.some(item =>
      item.gate === gate && !item.passed)).length,
  ])) as Record<SnapshotReleaseGate, number>;
  return {
    organizationId, assessed: results.length,
    eligible: results.filter(result => result.eligible).length,
    blocked: results.filter(result => !result.eligible).length,
    results: results.sort((a, b) => a.source.localeCompare(b.source) ||
      b.capturedAt.localeCompare(a.capturedAt)),
    failedByGate,
  };
}
