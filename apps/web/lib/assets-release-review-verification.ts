import { createHash, timingSafeEqual } from "node:crypto";
import { verifyOfflineAcceptanceReport } from "./assets-offline-acceptance-verification";
import type { AcceptanceReport } from "./assets-offline-acceptance";
import type { PrivacyReadinessReport } from "./assets-privacy-readiness";

/**
 * Verify an already persisted release record independently of its authoring
 * service. This checks integrity, not a digital signature or external origin.
 * The caller must separately enforce tenant authorization and freshness.
 */
export type ReleaseVerificationSubject = {
  organizationId: string;
  importId: string;
  inspectionId: string;
  inventoryDigest: string;
  inspectionDigest: string;
  acceptanceDigest: string;
  privacyDigest: string;
  scenarioDigest: string;
  evidenceBundleDigest: string;
  policyDigest: string;
  state: string;
  revision: number;
  operatorAcknowledgements: unknown;
  exclusions: unknown;
  acceptanceSnapshot: unknown;
  privacySnapshot: unknown;
  scenarioSummary: unknown;
  decidedAt: Date | string | null;
  decidedByUserId: string | null;
  decisionReason: string | null;
};
export type ReleaseVerificationResult = {
  schema: "cyberpilot.assets.release.verification.v1";
  verified: boolean;
  snapshotDigestsValid: boolean;
  bundleDigestValid: boolean;
  policyDigestValid: boolean;
  organizationConsistent: boolean;
  sourceConsistent: boolean;
  scenarioConsistent: boolean;
  stateConsistent: boolean;
  privacyCaveatsPreserved: boolean;
  acceptanceCaveatsPreserved: boolean;
  reasons: string[];
  sha256IsSignature: false;
  externalProviderVerified: false;
  legalSignoffVerified: false;
};
function object(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return null;
  return value as Record<string, unknown>;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function eq(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string" ||
      !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b))
    return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
/**
 * PostgreSQL JSONB normalizes object key ordering. SHA-256 reports in the
 * existing engines hash JSON.stringify insertion order; the original bytes
 * must therefore be retained as an immutable JSON string inside JSONB.
 * Do not validate the decoded JSONB object by re-stringifying its keys.
 */
export function decodeReleaseSnapshot(value: unknown): unknown {
  const envelope = object(value);
  if (!envelope || typeof envelope.canonical !== "string" ||
      envelope.canonical.length > 2_000_000)
    return null;
  try {
    const result: unknown = JSON.parse(envelope.canonical);
    return object(result) ? result : null;
  } catch {
    return null;
  }
}
function privacyDigestValid(value: unknown): boolean {
  const v = object(value);
  if (!v) return false;
  const { digest, warnings, ...canonical } = v;
  return eq(digest, sha(canonical)) &&
    Array.isArray(warnings) && warnings.length > 0;
}
function acceptanceDigestValid(value: unknown): boolean {
  const v = object(value);
  if (!v) return false;
  try {
    return verifyOfflineAcceptanceReport(
      value as AcceptanceReport).valid;
  } catch {
    return false;
  }
}
function acknowledged(value: unknown) {
  const expected = [
    "OFFLINE_ONLY", "SOURCE_LIMITATIONS", "HUMAN_REVIEW",
    "PRIVACY_AND_RETENTION", "NO_VERIFIED_REMEDIATION",
    "BACKUPS_NOT_ERASED",
  ];
  return Array.isArray(value) &&
    value.length === expected.length &&
    new Set(value).size === expected.length &&
    expected.every(id => value.includes(id));
}
function stateValid(row: ReleaseVerificationSubject) {
  const states = ["PENDING", "IN_REVIEW", "ACCEPTED_OFFLINE",
    "REJECTED", "REOPENED"];
  if (!states.includes(row.state) ||
      !Number.isSafeInteger(row.revision) || row.revision < 1)
    return false;
  const decided = row.state === "ACCEPTED_OFFLINE" ||
    row.state === "REJECTED";
  if (decided !== (row.decidedAt !== null) ||
      decided !== (row.decidedByUserId !== null))
    return false;
  // In-progress and reopened reviews retain the latest human transition
  // reason, even though those transitions are not terminal decisions.
  if (row.decisionReason !== null &&
      row.decisionReason.length < 20)
    return false;
  if (decided && (!row.decidedByUserId || !row.decisionReason))
    return false;
  if (row.state === "ACCEPTED_OFFLINE" &&
      !acknowledged(row.operatorAcknowledgements))
    return false;
  return true;
}
export function verifyPersistedAssetReleaseReview(
  row: ReleaseVerificationSubject,
): ReleaseVerificationResult {
  const decodedAcceptance = decodeReleaseSnapshot(row.acceptanceSnapshot);
  const decodedPrivacy = decodeReleaseSnapshot(row.privacySnapshot);
  const acceptance = object(decodedAcceptance);
  const privacy = object(decodedPrivacy);
  const scenario = object(row.scenarioSummary);
  const source = object(acceptance?.source);
  const acceptancePolicy = object(acceptance?.policy);
  const privacyPolicy = object(privacy?.policy);
  const acceptanceCaveatsPreserved =
    acceptance?.manualAcceptanceStillRequired === true &&
    acceptance?.noExternalTenantsRequired === true &&
    acceptance?.findingsModified === false &&
    acceptance?.cyberScoreModified === false &&
    acceptance?.providerRequests === 0 &&
    acceptance?.databaseWrites === 0;
  const privacyCaveatsPreserved =
    privacy?.databasesMutated === false &&
    privacy?.personalDataErased === false &&
    privacy?.backupDeletionVerified === false &&
    privacy?.userConsentInferred === false &&
    object(privacy?.readiness)?.pendingOperatorApproval === true;
  const organizationConsistent =
    acceptance?.organizationId === row.organizationId &&
    privacy?.organizationId === row.organizationId;
  const sourceConsistent =
    acceptance?.importId === row.importId &&
    acceptance?.inspectionId === row.inspectionId &&
    source?.inventoryDigest === row.inventoryDigest &&
    source?.inspectionDigest === row.inspectionDigest;
  const scenarioConsistent =
    scenario?.schema === "cyberpilot.assets.offline.scenario.matrix.v1" &&
    scenario?.source === "BUILT_IN_SYNTHETIC_FIXTURES" &&
    scenario?.synthetic === true &&
    scenario?.resultsDigest === row.scenarioDigest &&
    scenario?.totalExecuted === 13 &&
    scenario?.passed === 13 &&
    scenario?.failed === 0 &&
    scenario?.verdict === "COMPLETE_REFERENCE_SET" &&
    Array.isArray(scenario?.missingGates) &&
    scenario.missingGates.length === 0;
  const snapshotDigestsValid =
    acceptanceDigestValid(decodedAcceptance) &&
    privacyDigestValid(decodedPrivacy) &&
    eq(acceptance?.reportDigest, row.acceptanceDigest) &&
    eq(privacy?.digest, row.privacyDigest);
  const policyDigestValid = !!acceptancePolicy && !!privacyPolicy &&
    eq(row.policyDigest, sha({
      acceptance: acceptancePolicy, privacy: privacyPolicy,
    }));
  const bundleDigestValid = eq(row.evidenceBundleDigest, sha({
    schema: "cyberpilot.assets.release.evidence.v1",
    organizationId: row.organizationId,
    importId: row.importId, inspectionId: row.inspectionId,
    inventoryDigest: row.inventoryDigest,
    inspectionDigest: row.inspectionDigest,
    acceptanceDigest: row.acceptanceDigest,
    privacyDigest: row.privacyDigest,
    scenarioDigest: row.scenarioDigest,
    policyDigest: row.policyDigest,
  }));
  const stateConsistent = stateValid(row);
  const reasons = [
    ...(!snapshotDigestsValid ?
      ["Persisted acceptance or privacy source digest is invalid."] : []),
    ...(!bundleDigestValid ?
      ["Release evidence bundle digest is invalid."] : []),
    ...(!policyDigestValid ?
      ["Release assessment policy digest is invalid."] : []),
    ...(!organizationConsistent ?
      ["Release snapshots do not match the scoped organization."] : []),
    ...(!sourceConsistent ?
      ["Release source references do not match stored digests."] : []),
    ...(!scenarioConsistent ?
      ["Synthetic matrix coverage or digest reference is incomplete."] : []),
    ...(!stateConsistent ?
      ["Human release decision state or acknowledgement is inconsistent."] : []),
    ...(!privacyCaveatsPreserved ?
      ["Privacy review limitations have been removed."] : []),
    ...(!acceptanceCaveatsPreserved ?
      ["Offline release scope limitations have been removed."] : []),
  ];
  return {
    schema: "cyberpilot.assets.release.verification.v1",
    verified: reasons.length === 0,
    snapshotDigestsValid, bundleDigestValid,
    policyDigestValid, organizationConsistent, sourceConsistent,
    scenarioConsistent, stateConsistent,
    privacyCaveatsPreserved, acceptanceCaveatsPreserved,
    reasons, sha256IsSignature: false,
    externalProviderVerified: false,
    legalSignoffVerified: false,
  };
}
export function compareReleaseEvidenceHistory(
  current: ReleaseVerificationSubject,
  previous: ReleaseVerificationSubject,
) {
  const identityStable =
    current.organizationId === previous.organizationId &&
    current.importId === previous.importId &&
    current.inspectionId === previous.inspectionId;
  const unchanged =
    identityStable &&
    eq(current.evidenceBundleDigest, previous.evidenceBundleDigest);
  const differences: string[] = [];
  if (!identityStable) differences.push("SOURCE_IDENTITY");
  for (const key of [
    "inventoryDigest", "inspectionDigest", "acceptanceDigest",
    "privacyDigest", "scenarioDigest", "policyDigest",
  ] as const) {
    if (!eq(current[key], previous[key])) differences.push(key);
  }
  return {
    unchanged,
    differences,
    requiresNewHumanDecision: !unchanged,
    noExternalSignatureInferred: true as const,
  };
}
