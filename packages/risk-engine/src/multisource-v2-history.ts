import {
  type V2Manifest, type V2Score,
  type V2Coverage, type V2Domain,
  canonicalV2, validV2Id, validV2Time,
  validateV2Manifest,
} from "./multisource-v2-contract";
import {
  computeV2Coverage, compareV2Coverage,
} from "./multisource-v2-coverage";
import {
  calculateMultiSourceCyberScoreV2,
  compareV2Scores,
  explainV2Score,
} from "./multisource-v2-score";

/**
 * Immutable opt-in score history. The v1 algorithm and persisted v1
 * table are never read, migrated, rewritten or backfilled. Snapshots
 * can be compared only with the exact model revision and org scope.
 */
export type V2HistoryEntry = {
  schema: "cyberpilot.multisource.history.entry.v2";
  organizationId: string;
  snapshotId: string;
  modelId: "cyberpilot.multisource.v2";
  modelRevision: 1;
  evaluatedAt: string;
  manifest: V2Manifest;
  coverage: V2Coverage;
  score: V2Score;
  manifestFingerprint: string;
  coverageFingerprint: string;
  scoreFingerprint: string;
  previousDigest: string | null;
  chainDigest: string;
  legacyCyberScoreUnchanged: true;
  externalConsentAttested: false;
  customerSecurityCertified: false;
};
export type V2HistoricalTimeline = {
  schema: "cyberpilot.multisource.timeline.v2";
  organizationId: string;
  modelId: "cyberpilot.multisource.v2";
  modelRevision: 1;
  entries: V2HistoryEntry[];
  revisions: number;
  earliest: string | null;
  latest: string | null;
  numericScores: number;
  unscorableSnapshots: number;
  trend: Array<{
    previousSnapshotId: string;
    currentSnapshotId: string;
    numericDelta: number | null;
    comparable: boolean;
    coverageDelta: number;
    newRiskIds: string[];
    disappearedRisks: string[];
    newlyVerifiedControls: string[];
    newlyUncoveredControls: string[];
    remediationConfirmed: false;
  }>;
  sourceDigest: string;
  noV1Migration: true;
  noCustomerCertification: true;
  noAutomaticResolution: true;
};
export type V2HistoricalIssue = {
  code: "INVALID_ENTRY_DIGEST" |
    "CROSS_TENANT" | "CHAIN_PARENT" |
    "OUT_OF_ORDER" | "DUPLICATE_SNAPSHOT" |
    "MODEL_INCOMPATIBLE" | "SOURCE_CHANGED" |
    "INVALID_RESULT" | "FALSE_LEGACY_MIGRATION";
  entry: string;
  explanation: string;
  blocksHistory: boolean;
  requiresOperatorReview: boolean;
  automaticallyResolved: false;
};
export type V2HistoryReconciliation = {
  schema: "cyberpilot.multisource.history.audit.v2";
  organizationId: string;
  entriesChecked: number;
  valid: boolean;
  latestDigest: string | null;
  issues: V2HistoricalIssue[];
  canTrustLocalIntegrity: boolean;
  signedByCustomer: false;
  signedByProvider: false;
  legacyV1Recomputed: false;
};
export type V2ModelRegistryEntry = {
  id: "cyberpilot.multisource.v2";
  revision: 1;
  enabledByDefault: false;
  experimental: true;
  legacyModelId: "cyberpilot.v1";
  writesLegacyScores: false;
  sourceNeutral: true;
  supportsM365lessOrgs: true;
  supportsPartialCoverage: true;
  allowsHealthCertification: false;
  requiresLIVEForFullSecurityClaim: true;
  migrationStrategy: "SIDE_BY_SIDE_ONLY";
  sourceDomains: V2Domain[];
};
export type V2VersionCompatibility = {
  previousModel: string;
  currentModel: string;
  comparable: boolean;
  requiredAction: "NO_ACTION" | "SEPARATE_BASELINE" |
    "MANUAL_MIGRATION_DESIGN";
  previousScoreRetained: boolean;
  riskNormalizationEquivalent: boolean;
  evidenceCoverageComparable: boolean;
  mayRewriteHistoricalRecords: false;
  explanation: string[];
};
const model: V2ModelRegistryEntry = {
  id: "cyberpilot.multisource.v2", revision: 1,
  enabledByDefault: false, experimental: true,
  legacyModelId: "cyberpilot.v1",
  writesLegacyScores: false,
  sourceNeutral: true,
  supportsM365lessOrgs: true,
  supportsPartialCoverage: true,
  allowsHealthCertification: false,
  requiresLIVEForFullSecurityClaim: true,
  migrationStrategy: "SIDE_BY_SIDE_ONLY",
  sourceDomains: [
    "IDENTITY", "EMAIL", "WEB", "ENDPOINT",
    "BACKUP", "GOVERNANCE", "EXPOSURE",
  ],
};
function hash(value: unknown) {
  return sha256V2(canonicalV2(value));
}
/**
 * Pure TypeScript SHA-256, avoiding a Node-only dependency so v2
 * history can be independently verified in browser and server builds.
 */
export function sha256V2(message: string) {
  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const encode = (input: string) => {
    const bytes: number[] = [];
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;
      if (cp > 0xffff) i++;
      if (cp <= 0x7f) bytes.push(cp);
      else if (cp <= 0x7ff)
        bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
      else if (cp <= 0xffff)
        bytes.push(0xe0 | (cp >> 12),
          0x80 | (cp >> 6 & 0x3f), 0x80 | (cp & 0x3f));
      else bytes.push(0xf0 | (cp >> 18),
        0x80 | (cp >> 12 & 0x3f),
        0x80 | (cp >> 6 & 0x3f), 0x80 | (cp & 0x3f));
    }
    return bytes;
  };
  const bytes = encode(message);
  const bitLength = BigInt(bytes.length) * 8n;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--)
    bytes.push(Number(bitLength >> BigInt(i * 8) & 255n));
  let h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const rotr = (n: number, count: number) =>
    n >>> count | n << 32 - count;
  for (let offset = 0; offset < bytes.length; offset += 64) {
    const w = new Array<number>(64).fill(0);
    for (let i = 0; i < 16; i++) {
      const pos = offset + i * 4;
      w[i] = (bytes[pos]! << 24 | bytes[pos + 1]! << 16 |
        bytes[pos + 2]! << 8 | bytes[pos + 3]!) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!, b = w[i - 2]!;
      const s0 = rotr(a, 7) ^ rotr(a, 18) ^ a >>> 3;
      const s1 = rotr(b, 17) ^ rotr(b, 19) ^ b >>> 10;
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, x] = h as [
      number, number, number, number, number, number, number, number,
    ];
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = e & f ^ ~e & g;
      const temp1 = (x + s1 + ch + constants[i]! + w[i]!) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = a & b ^ a & c ^ b & c;
      const temp2 = (s0 + maj) >>> 0;
      x = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h = h.map((old, i) =>
      (old + [a, b, c, d, e, f, g, x][i]!) >>> 0);
  }
  return h.map(n => n.toString(16).padStart(8, "0")).join("");
}
export function v2ModelRegistry(): V2ModelRegistryEntry {
  return { ...model, sourceDomains: [...model.sourceDomains] };
}
export function compareV2ModelVersions(
  previousModel: string, currentModel: string,
): V2VersionCompatibility {
  const same = previousModel === currentModel;
  return {
    previousModel, currentModel, comparable: same,
    requiredAction: same ? "NO_ACTION" :
      previousModel === "cyberpilot.v1" ?
        "SEPARATE_BASELINE" : "MANUAL_MIGRATION_DESIGN",
    previousScoreRetained: true,
    riskNormalizationEquivalent: same,
    evidenceCoverageComparable: same,
    mayRewriteHistoricalRecords: false,
    explanation: same ? [
      "Models are identical, but evidence coverage must be checked before interpreting deltas.",
    ] : [
      "Historical CyberScore v1 is a different model and cannot be silently converted.",
      "Keep v1 scores and introduce a separate baseline for v2.",
      "No migration or backfill is automatically authorized.",
    ],
  };
}
function assertEntryParts(
  manifest: V2Manifest, score: V2Score,
  coverage: V2Coverage,
) {
  if (!validateV2Manifest(manifest).valid)
    throw new Error("Invalid source manifest in historical snapshot.");
  if (manifest.organizationId !== score.organizationId ||
      manifest.organizationId !== coverage.organizationId ||
      manifest.evaluatedAt !== score.evaluatedAt ||
      manifest.evaluatedAt !== coverage.evaluatedAt ||
      manifest.modelId !== score.modelId ||
      manifest.modelId !== coverage.modelId)
    throw new Error("Historical score, coverage and manifest mismatch.");
  if (score.legacyCyberScoreRecomputed ||
      score.modelMigrationCompleted ||
      coverage.canonicalV1ScoreChanged ||
      coverage.healthClaimPermitted)
    throw new Error("Historical entry makes unsupported legacy or health claim.");
}
export function createV2HistoryEntry(
  manifest: V2Manifest, previous: V2HistoryEntry | null = null,
): V2HistoryEntry {
  if (previous && (previous.organizationId !== manifest.organizationId ||
      previous.modelId !== manifest.modelId ||
      previous.modelRevision !== manifest.modelRevision ||
      previous.evaluatedAt >= manifest.evaluatedAt ||
      previous.snapshotId === manifest.snapshotId))
    throw new Error("History append requires same tenant/model and increasing time.");
  const coverage = computeV2Coverage(manifest);
  const score = calculateMultiSourceCyberScoreV2(manifest);
  assertEntryParts(manifest, score, coverage);
  const canonical = {
    schema: "cyberpilot.multisource.history.entry.v2" as const,
    organizationId: manifest.organizationId,
    snapshotId: manifest.snapshotId,
    modelId: "cyberpilot.multisource.v2" as const,
    modelRevision: 1 as const,
    evaluatedAt: manifest.evaluatedAt,
    manifest, coverage, score,
    manifestFingerprint: hash(manifest),
    coverageFingerprint: hash(coverage),
    scoreFingerprint: hash(score),
    previousDigest: previous?.chainDigest ?? null,
    legacyCyberScoreUnchanged: true as const,
    externalConsentAttested: false as const,
    customerSecurityCertified: false as const,
  };
  return { ...canonical, chainDigest: hash(canonical) };
}
export function inspectV2HistoryEntry(
  entry: V2HistoryEntry,
): V2HistoricalIssue[] {
  const issues: V2HistoricalIssue[] = [];
  const report = (code: V2HistoricalIssue["code"],
    explanation: string) => issues.push({
    code, entry: entry.snapshotId,
    explanation, blocksHistory: true,
    requiresOperatorReview: true,
    automaticallyResolved: false,
  });
  const { chainDigest, ...canonical } = entry;
  if (hash(canonical) !== chainDigest)
    report("INVALID_ENTRY_DIGEST",
      "History payload differs from deterministic local fingerprint.");
  if (hash(entry.manifest) !== entry.manifestFingerprint ||
      hash(entry.coverage) !== entry.coverageFingerprint ||
      hash(entry.score) !== entry.scoreFingerprint)
    report("SOURCE_CHANGED",
      "Snapshot evidence, coverage or scoring changed.");
  if (entry.organizationId !== entry.manifest.organizationId ||
      entry.organizationId !== entry.coverage.organizationId ||
      entry.organizationId !== entry.score.organizationId)
    report("CROSS_TENANT",
      "History entry crosses organization boundary.");
  if (entry.modelId !== "cyberpilot.multisource.v2" ||
      entry.modelRevision !== 1 ||
      entry.score.modelId !== entry.modelId)
    report("MODEL_INCOMPATIBLE",
      "History model revision differs.");
  if (!entry.legacyCyberScoreUnchanged ||
      entry.externalConsentAttested ||
      entry.customerSecurityCertified)
    report("FALSE_LEGACY_MIGRATION",
      "History falsely claims legacy or customer approval.");
  try {
    const recalculated = calculateMultiSourceCyberScoreV2(entry.manifest);
    const coverage = computeV2Coverage(entry.manifest);
    if (canonicalV2(recalculated) !== canonicalV2(entry.score) ||
        canonicalV2(coverage) !== canonicalV2(entry.coverage))
      report("INVALID_RESULT",
        "Derived result differs from the verified immutable source.");
  } catch {
    report("INVALID_RESULT",
      "Historical manifest cannot be independently recomputed.");
  }
  return issues;
}
export function reconcileV2History(
  organizationId: string, entries: readonly V2HistoryEntry[],
): V2HistoryReconciliation {
  if (!validV2Id(organizationId) ||
      entries.length > 1000)
    throw new Error("Invalid v2 history scope or capacity.");
  const issues: V2HistoricalIssue[] = [];
  const seen = new Set<string>();
  let parent: string | null = null;
  let time: string | null = null;
  for (const entry of entries) {
    issues.push(...inspectV2HistoryEntry(entry));
    const report = (code: V2HistoricalIssue["code"],
      explanation: string) => issues.push({
      code, entry: entry.snapshotId, explanation,
      blocksHistory: true, requiresOperatorReview: true,
      automaticallyResolved: false,
    });
    if (entry.organizationId !== organizationId)
      report("CROSS_TENANT", "Foreign history entry.");
    if (seen.has(entry.snapshotId))
      report("DUPLICATE_SNAPSHOT", "Repeated snapshot ID.");
    seen.add(entry.snapshotId);
    if (entry.previousDigest !== parent)
      report("CHAIN_PARENT", "History digest parent does not match.");
    if (time !== null && time >= entry.evaluatedAt)
      report("OUT_OF_ORDER", "History timestamps do not increase.");
    if (entry.modelId !== model.id ||
        entry.modelRevision !== model.revision)
      report("MODEL_INCOMPATIBLE", "Incompatible history revision.");
    parent = entry.chainDigest;
    time = entry.evaluatedAt;
  }
  return {
    schema: "cyberpilot.multisource.history.audit.v2",
    organizationId, entriesChecked: entries.length,
    valid: issues.length === 0,
    latestDigest: parent, issues,
    canTrustLocalIntegrity: issues.length === 0,
    signedByCustomer: false, signedByProvider: false,
    legacyV1Recomputed: false,
  };
}
export function createV2HistoricalTimeline(
  organizationId: string,
  entries: readonly V2HistoryEntry[],
): V2HistoricalTimeline {
  const checked = reconcileV2History(organizationId, entries);
  if (!checked.valid)
    throw new Error("Cannot create score history from invalid audit chain.");
  const trends: V2HistoricalTimeline["trend"] = [];
  for (let index = 1; index < entries.length; index++) {
    const before = entries[index - 1]!;
    const after = entries[index]!;
    const scores = compareV2Scores(before.score, after.score);
    const coverage = compareV2Coverage(
      before.coverage, after.coverage);
    trends.push({
      previousSnapshotId: before.snapshotId,
      currentSnapshotId: after.snapshotId,
      numericDelta: scores.numericDelta,
      comparable: scores.deltaIsComparable,
      coverageDelta: scores.coverageDelta,
      newRiskIds: [...scores.newPotentialRisks],
      disappearedRisks: [...scores.absentFromCurrentAssessment],
      newlyVerifiedControls: coverage.changes
        .filter(c => !c.oldVerified && c.newVerified)
        .map(c => c.controlId),
      newlyUncoveredControls: coverage.changes
        .filter(c => c.oldVerified && !c.newVerified)
        .map(c => c.controlId),
      remediationConfirmed: false,
    });
  }
  return {
    schema: "cyberpilot.multisource.timeline.v2",
    organizationId, modelId: model.id,
    modelRevision: model.revision,
    entries: [...entries], revisions: entries.length,
    earliest: entries[0]?.evaluatedAt ?? null,
    latest: entries.at(-1)?.evaluatedAt ?? null,
    numericScores: entries.filter(x =>
      x.score.score !== null).length,
    unscorableSnapshots: entries.filter(x =>
      x.score.score === null).length,
    trend: trends, sourceDigest: hash(entries.map(x =>
      x.chainDigest)),
    noV1Migration: true, noCustomerCertification: true,
    noAutomaticResolution: true,
  };
}
export function compareV2TimelineToV1(
  timeline: V2HistoricalTimeline,
  legacy: readonly {
    id: string; score: number; modelVersion: string;
    calculatedAt: string;
  }[],
) {
  if (timeline.modelId !== model.id ||
      legacy.some(x => !validV2Id(x.id) ||
        !validV2Time(x.calculatedAt) ||
        !Number.isSafeInteger(x.score) ||
        x.score < 0 || x.score > 100))
    throw new Error("Invalid historical comparison source.");
  return {
    organizationId: timeline.organizationId,
    v2SnapshotCount: timeline.entries.length,
    legacySnapshotCount: legacy.length,
    legacyModels: [...new Set(legacy.map(x =>
      x.modelVersion))],
    legacyScoresRetainedExactly: legacy.map(x => ({
      id: x.id, score: x.score,
      modelVersion: x.modelVersion,
      calculatedAt: x.calculatedAt,
    })),
    v2ScoreRange: timeline.entries.map(x => ({
      id: x.snapshotId,
      score: x.score.score,
      lower: x.score.scoreRange.min,
      upper: x.score.scoreRange.max,
      coverage: x.coverage.coveragePercent,
    })),
    statisticallyComparable: false as const,
    automaticRecalculationAllowed: false as const,
    legacyDatabaseWriteCount: 0 as const,
    proposedMigrationApproved: false as const,
    warnings: [
      "Different score models are not numerically interchangeable.",
      "Historical v1 scores must not be overwritten to match v2.",
      "A new v2 baseline must be identified explicitly.",
    ],
  };
}
export function scoreV2HistorySignals(
  timeline: V2HistoricalTimeline,
) {
  const results = timeline.trend.map((trend, index) => {
    const current = timeline.entries[index + 1]!;
    const previous = timeline.entries[index]!;
    const missing = current.coverage.missingControls;
    return {
      snapshotId: current.snapshotId,
      checkedAt: current.evaluatedAt,
      model: current.modelId,
      score: current.score.score,
      coverage: current.coverage.coveragePercent,
      newlyUncovered: [...trend.newlyUncoveredControls],
      newFindings: [...trend.newRiskIds],
      absentFindings: [...trend.disappearedRisks],
      lowConfidence: current.score.confidence === "LOW" ||
        current.score.confidence === "UNKNOWN",
      sourceGapWidened: missing >
        previous.coverage.missingControls,
      scoreDelta: trend.numericDelta,
      confirmedImprovement: false as const,
      realProviderVerifiedOnEveryEntry: false as const,
      nextAction: trend.newlyUncoveredControls.length ?
        "Reevaluate source coverage before interpreting score changes." :
        trend.newRiskIds.length ?
          "Review new evidence-backed potential risks." :
          "Retain cautious assessment and monitor missing sources.",
    };
  });
  return {
    organizationId: timeline.organizationId,
    trendCount: results.length,
    results, historyDigest: timeline.sourceDigest,
    supportsLegacyModelRewrite: false as const,
    customerDeploymentApproved: false as const,
  };
}
export function historyV2EvidenceManifest(
  timeline: V2HistoricalTimeline,
) {
  const audit = reconcileV2History(
    timeline.organizationId, timeline.entries);
  if (!audit.valid)
    throw new Error("Cannot attest invalid v2 historical chain.");
  return {
    schema: "cyberpilot.multisource.history.manifest.v2" as const,
    organizationId: timeline.organizationId,
    model: timeline.modelId,
    modelRevision: timeline.modelRevision,
    entryDigests: timeline.entries.map(x => ({
      snapshotId: x.snapshotId,
      manifestDigest: x.manifestFingerprint,
      scoreDigest: x.scoreFingerprint,
      coverageDigest: x.coverageFingerprint,
      chainDigest: x.chainDigest,
    })),
    latest: audit.latestDigest,
    entryCount: timeline.entries.length,
    localIntegrityValid: true,
    providerCryptographicSignature: false as const,
    operatorLegalApproval: false as const,
    oldCyberScoreV1Changed: false as const,
    customerComplianceCertified: false as const,
    manifestDigest: hash({
      organizationId: timeline.organizationId,
      entries: timeline.entries.map(x => x.chainDigest),
    }),
  };
}
