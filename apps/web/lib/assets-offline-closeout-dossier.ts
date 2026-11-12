import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { AssetScope } from "./assets-inventory-service";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { inspectAssetOfflineAcceptance } from "./assets-offline-acceptance-service";
import { verifyOfflineAcceptanceReport } from "./assets-offline-acceptance-verification";
import { inspectAssetPrivacyReadiness } from "./assets-privacy-readiness-service";
import { parseScenarioMatrixOptions, runOfflineScenarioMatrix,
  inspectScenarioMatrixCoverage, verifyOfflineScenarioMatrix,
} from "./assets-offline-scenario-matrix";
import { inspectReleaseAuditDossier,
  verifyReleaseAuditDossier } from "./assets-release-audit-dossier";
import { verifyPersistedAssetReleaseReview } from
  "./assets-release-review-verification";
import { verifyRetentionReview } from "./assets-retention-review-service";
import type { AcceptanceReport } from "./assets-offline-acceptance";
import type { PrivacyReadinessReport } from "./assets-privacy-readiness";

export type CloseoutGateCode =
  "TENANT_BOUND" | "INVENTORY_COMPLETE" | "STORED_OSV_INSPECTION" |
  "EXACT_MAPPING" | "ACCEPTANCE_REPORT_INTEGRITY" | "ACCEPTANCE_ELIGIBILITY" |
  "CASES_AND_AUDIT" | "SYNTHETIC_REFERENCE_SUITE" |
  "PRIVACY_COVERAGE" | "PRIVACY_REVIEW_BLOCKERS" |
  "PRIVACY_POLICY_DOCUMENTED" | "RETENTION_EXCEPTION_REVIEW" |
  "BACKUP_HANDLING" | "EXPORT_HANDLING" | "RELEASE_REVIEW_PRESENT" |
  "RELEASE_HUMAN_DECISION" | "RELEASE_AUDIT_COMPLETE" |
  "EVIDENCE_FRESHNESS" | "MANUAL_END_TO_END" |
  "EXTERNAL_PRIVACY_SIGNOFF" | "BACKUP_DELETION_ATTESTATION" |
  "LIVE_PROVIDER_VALIDATION";
export type CloseoutGate = {
  code: CloseoutGateCode;
  severity: "BLOCK" | "REVIEW" | "EXCLUDED";
  status: "PASS" | "BLOCK" | "REVIEW" | "EXCLUDED";
  observed: number | null;
  expected: number | null;
  affectedIds: string[];
  explanation: string;
  nextAction: string;
  evidence: string[];
  evidenceKind: "PERSISTED_TENANT" | "SYNTHETIC_REFERENCE" |
    "MANUAL_UNVERIFIED" | "OUT_OF_SCOPE";
};
export type CloseoutCommand = {
  importId: string;
  inspectionId: string;
  bindings: unknown;
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
  maxAuditEvents: number;
  includeHumanReasons: boolean;
};
export type CloseoutInventoryEvidence = {
  importId: string;
  inspectionId: string;
  inventoryDigest: string;
  inspectionDigest: string;
  source: "CUSTOMER_DECLARED_CSV";
  inspectionSource: "STORED_OSV_LEDGER";
  deviceCount: number;
  queryCount: number;
  mappedPercent: number;
  possibleCandidates: number;
  unknownEvidence: number;
  casesEvaluated: number;
  auditsObserved: number;
  positiveWithoutReview: number;
  completeWithinSnapshot: boolean;
};
export type CloseoutPrivacyEvidence = {
  digest: string;
  fullyExamined: boolean;
  blocked: number;
  reviewNeeded: number;
  pendingOperatorApproval: boolean;
  hostnameSignals: number;
  ownerHashSignals: number;
  openCasesBeyondPolicy: number;
  importCount: number;
  backupsErased: false;
  personalDataErased: false;
  consentInferred: false;
  gates: Array<{
    id: string; severity: string; explanation: string;
    affectedImportIds: string[];
  }>;
};
export type CloseoutReleaseEvidence = {
  present: boolean;
  reviewId: string | null;
  revision: number | null;
  state: string;
  digest: string | null;
  verified: boolean;
  independentIssues: string[];
  recordedBy: string | null;
  decidedBy: string | null;
  decidedAt: string | null;
  exclusions: unknown;
  humanDecisionRecorded: boolean;
  acceptedOffline: boolean;
  auditEvents: number;
  auditConsistent: boolean;
  auditDigest: string | null;
  auditIssues: string[];
};
export type CloseoutRetentionEvidence = {
  present: boolean;
  reviewId: string | null;
  state: string;
  revision: number | null;
  verified: boolean;
  reviewedBy: string | null;
  nextReviewAt: string | null;
  backupDisposition: string;
  personalDataDisposition: string;
  outstandingExceptions: number;
  exceptions: Array<{
    gateId: string;
    owner: string | null;
    reviewBy: string | null;
    ticket: string | null;
  }>;
  legalApproved: false;
  erasureVerified: false;
  independentIssues: string[];
};
export type OfflineCloseoutDossier = {
  schema: "cyberpilot.assets.offline.closeout.dossier.v1";
  organizationId: string;
  importId: string;
  inspectionId: string;
  evaluatedAt: string;
  source: "TENANT_SCOPED_PERSISTED_RECORDS";
  inventory: CloseoutInventoryEvidence;
  acceptance: {
    digest: string;
    reportValid: boolean;
    eligible: boolean;
    policy: AcceptanceReport["policy"];
    scorecard: AcceptanceReport["scorecard"];
    blockedGates: string[];
    advisoryGates: string[];
  };
  privacy: CloseoutPrivacyEvidence;
  scenario: {
    digest: string;
    source: "BUILT_IN_SYNTHETIC_FIXTURES";
    passed: number;
    executed: number;
    failed: number;
    complete: boolean;
    mismatches: string[];
    notTenantAcceptance: true;
  };
  release: CloseoutReleaseEvidence;
  retention: CloseoutRetentionEvidence;
  gates: CloseoutGate[];
  counts: {
    passed: number;
    blocked: number;
    manualReview: number;
    excluded: number;
    completedAutomated: number;
    total: number;
  };
  missingHumanActions: string[];
  reproducibleAutomatedEvaluation: boolean;
  readyForManualCloseout: boolean;
  offlineProductAccepted: false;
  mergeAuthorized: false;
  liveProviderValidated: false;
  externalTenantRequiredForThisScope: false;
  legalSignoffConfirmed: false;
  backupErasureConfirmed: false;
  destructiveWrites: 0;
  sourceDigest: string;
  digest: string;
  caveats: string[];
};
const caveats = [
  "An automated read-only dossier cannot itself confirm a human end-to-end acceptance.",
  "A synthetic 13-case suite validates reference logic, not the customer's observed asset security.",
  "Customer-declared CSV is not exhaustive endpoint discovery or vulnerability scanning.",
  "Stored OSV records are not evidence of provider availability at the time of evaluation.",
  "Local SHA-256 is an internal tamper indication, not an external digital signature.",
  "Legal/privacy signoff and actual backup/export deletion require independently verified approvals.",
  "ACCEPTED_OFFLINE records a scoped human decision, not live provider or remediation success.",
  "No SecurityFinding, CyberScore, scheduler or OSV provider request is modified.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function obj(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Closeout request must be a JSON object.");
  return value as Record<string, unknown>;
}
function str(value: unknown, name: string) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid " + name + " identifier.");
  return value;
}
function integer(value: unknown, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    fail("INVALID", "Invalid closeout audit event limit.");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function eq(a: string, b: string) {
  return /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
export function parseCloseoutCommand(input: unknown): CloseoutCommand {
  const raw = obj(input);
  const allowed = ["importId", "inspectionId", "bindings",
    "acceptancePolicy", "privacyPolicy", "maxAuditEvents",
    "includeHumanReasons"];
  if (Object.keys(raw).some(key => !allowed.includes(key)))
    fail("INVALID", "Unexpected closeout request property.");
  if (!Array.isArray(raw.bindings) || raw.bindings.length > 2000)
    fail("INVALID", "Explicit bounded package bindings required.");
  if (raw.includeHumanReasons !== undefined &&
      typeof raw.includeHumanReasons !== "boolean")
    fail("INVALID", "Human-reason disclosure must be boolean.");
  return {
    importId: str(raw.importId, "inventory"),
    inspectionId: str(raw.inspectionId, "inspection"),
    bindings: raw.bindings,
    acceptancePolicy: raw.acceptancePolicy ?? {},
    privacyPolicy: raw.privacyPolicy ?? {},
    maxAuditEvents: integer(raw.maxAuditEvents ?? 250, 1, 1000),
    includeHumanReasons: raw.includeHumanReasons === true,
  };
}
function gate(code: CloseoutGateCode, result: "PASS" | "BLOCK" |
  "REVIEW" | "EXCLUDED", explanation: string, nextAction: string,
  evidence: string[], observed: number | null = null,
  expected: number | null = null, affectedIds: string[] = [],
  kind: CloseoutGate["evidenceKind"] = "PERSISTED_TENANT",
): CloseoutGate {
  return {
    code,
    severity: result === "PASS" || result === "BLOCK" ?
      "BLOCK" : result === "EXCLUDED" ? "EXCLUDED" : "REVIEW",
    status: result, observed, expected,
    affectedIds, explanation, nextAction,
    evidence, evidenceKind: kind,
  };
}
function good(flag: boolean): "PASS" | "BLOCK" {
  return flag ? "PASS" : "BLOCK";
}
function detailsForRelease(row: {
  id: string; revision: number; state: string;
  evidenceBundleDigest: string; operatorUserId: string;
  decidedByUserId: string | null; decidedAt: Date | null;
  exclusions: unknown;
} | null, verification: { verified: boolean; reasons: string[] } | null,
  audit: { auditConsistent: boolean; totalEvents: number;
    digest: string; issues: Array<{ code: string }> } | null,
): CloseoutReleaseEvidence {
  return {
    present: !!row, reviewId: row?.id ?? null,
    revision: row?.revision ?? null,
    state: row?.state ?? "MISSING",
    digest: row?.evidenceBundleDigest ?? null,
    verified: verification?.verified ?? false,
    independentIssues: verification?.reasons ?? [],
    recordedBy: row?.operatorUserId ?? null,
    decidedBy: row?.decidedByUserId ?? null,
    decidedAt: row?.decidedAt?.toISOString() ?? null,
    exclusions: row?.exclusions ?? [],
    humanDecisionRecorded: !!row?.decidedAt && !!row?.decidedByUserId,
    acceptedOffline: row?.state === "ACCEPTED_OFFLINE" &&
      !!verification?.verified && !!audit?.auditConsistent,
    auditEvents: audit?.totalEvents ?? 0,
    auditConsistent: audit?.auditConsistent ?? false,
    auditDigest: audit?.digest ?? null,
    auditIssues: audit?.issues.map(item => item.code) ?? [],
  };
}
function detailsForRetention(row: {
  id: string; state: string; revision: number;
  reviewedByUserId: string | null; nextReviewAt: Date | null;
  backupDisposition: string; personalDataDisposition: string;
  exceptions: unknown;
} | null, verified: { valid: boolean; reasons: string[] } | null,
): CloseoutRetentionEvidence {
  const exceptions = Array.isArray(row?.exceptions) ?
    row.exceptions as unknown[] : [];
  return {
    present: !!row, reviewId: row?.id ?? null,
    state: row?.state ?? "MISSING", revision: row?.revision ?? null,
    verified: verified?.valid ?? false,
    reviewedBy: row?.reviewedByUserId ?? null,
    nextReviewAt: row?.nextReviewAt?.toISOString() ?? null,
    backupDisposition: row?.backupDisposition ?? "UNVERIFIED",
    personalDataDisposition: row?.personalDataDisposition ?? "REQUIRES_REVIEW",
    outstandingExceptions: exceptions.length,
    exceptions: exceptions.map(entry => {
      const e = entry && typeof entry === "object" && !Array.isArray(entry)
        ? entry as Record<string, unknown> : {};
      return {
        gateId: typeof e.gateId === "string" ? e.gateId : "INVALID",
        owner: typeof e.owner === "string" ? e.owner : null,
        reviewBy: typeof e.reviewBy === "string" ? e.reviewBy : null,
        ticket: typeof e.externalTicket === "string"
          ? e.externalTicket : null,
      };
    }),
    legalApproved: false, erasureVerified: false,
    independentIssues: verified?.reasons ?? [],
  };
}
export function buildCloseoutGates(input: {
  inventory: CloseoutInventoryEvidence;
  acceptance: AcceptanceReport;
  acceptanceValid: boolean;
  privacy: PrivacyReadinessReport;
  scenarioPassed: number;
  scenarioComplete: boolean;
  release: CloseoutReleaseEvidence;
  retention: CloseoutRetentionEvidence;
  checkedAt: Date;
}): CloseoutGate[] {
  const { inventory: inv, acceptance: a, privacy: p,
    release: r, retention: t } = input;
  const gates: CloseoutGate[] = [];
  const push = (...args: Parameters<typeof gate>) =>
    gates.push(gate(...args));
  push("TENANT_BOUND", "PASS",
    "All input reports use the authenticated tenant and source IDs.",
    "Keep tenant checks active on every API and database query.",
    [inv.importId, inv.inspectionId]);
  push("INVENTORY_COMPLETE", good(inv.completeWithinSnapshot &&
    inv.deviceCount > 0),
    "Inventory completeness is bounded by the customer-declared CSV.",
    "Correct incomplete import snapshots and re-run evidence.",
    [inv.inventoryDigest], inv.deviceCount, 1);
  push("STORED_OSV_INSPECTION", good(inv.queryCount > 0 &&
    /^[a-f0-9]{64}$/.test(inv.inspectionDigest)),
    "A stored OSV inspection is evaluated; there is no live provider request.",
    "Save an authorized, complete inspection and re-evaluate.",
    [inv.inspectionDigest], inv.queryCount, 1);
  push("EXACT_MAPPING", good(inv.mappedPercent >= a.policy.minimumMappedPercent),
    "Software mapping coverage is compared to the selected acceptance policy.",
    "Review ambiguous package versions and incomplete package bindings.",
    [a.reportDigest], inv.mappedPercent,
    a.policy.minimumMappedPercent);
  push("ACCEPTANCE_REPORT_INTEGRITY", good(input.acceptanceValid),
    "The full acceptance report passed independent digest and gate verification.",
    "Recompute the stored evidence using an authorized tenant.",
    [a.reportDigest]);
  push("ACCEPTANCE_ELIGIBILITY", good(a.acceptanceEligible),
    "All mandatory acceptance gates must pass; advisory items remain visible.",
    "Resolve each blocked acceptance gate and rerun.",
    a.gates.filter(g => g.level === "BLOCK").map(g => g.id),
    a.scorecard.blocked, 0);
  push("CASES_AND_AUDIT", good(
    a.scorecard.possibleCandidatesWithoutReview === 0 &&
    a.gates.find(g => g.id === "AUDIT_COVERAGE")?.level === "PASS"),
    "Positive candidates must have correctly scoped human review and audit.",
    "Open missing review cases with documented provenance and audit.",
    a.cases.filter(c => c.issues.length > 0).map(c => c.caseId),
    a.scorecard.possibleCandidatesWithoutReview, 0);
  push("SYNTHETIC_REFERENCE_SUITE", good(input.scenarioComplete &&
    input.scenarioPassed === 13),
    "The 13 synthetic reference cases test conservative rules only.",
    "Fix reference matrix failures before relying on offline acceptance.",
    [], input.scenarioPassed, 13, [], "SYNTHETIC_REFERENCE");
  push("PRIVACY_COVERAGE", good(p.fullyExamined),
    "Privacy readiness must examine every declared tenant import.",
    "Resolve partial source reads or policy query caps.",
    [p.digest], p.imports.length, p.importedCount);
  push("PRIVACY_REVIEW_BLOCKERS", good(p.readiness.blocked === 0 &&
    p.readiness.reviewNeeded === 0),
    "Unresolved privacy and retention gates remain explicit blockers.",
    "Review PII, historical evidence, retention and backup/export obligations.",
    p.gates.filter(g => g.severity !== "PASS").map(g => g.id),
    p.readiness.blocked + p.readiness.reviewNeeded, 0);
  push("PRIVACY_POLICY_DOCUMENTED",
    t.verified ? "REVIEW" : "BLOCK",
    "A privacy policy snapshot is recorded; it cannot grant legal approval.",
    "Obtain the responsible person's policy review and preserve its record.",
    [p.digest, t.reviewId ?? "MISSING"], t.verified ? 1 : 0, 1);
  push("RETENTION_EXCEPTION_REVIEW",
    t.present && t.verified &&
    t.state === "DOCUMENTED_WITH_EXCEPTIONS" ? "REVIEW" : "BLOCK",
    "Retention exceptions require owner, deadline and independent resolution.",
    "Record a human decision and review each exception before closeout.",
    [t.reviewId ?? "MISSING"], t.outstandingExceptions, 0);
  push("BACKUP_HANDLING",
    t.backupDisposition === "UNVERIFIED" ? "BLOCK" : "REVIEW",
    "Documented procedure is not proof of erasure from backups or exports.",
    "Obtain owner approval and verify recoverability and expiration policies.",
    [t.backupDisposition], null, null, [],
    "MANUAL_UNVERIFIED");
  push("EXPORT_HANDLING", "REVIEW",
    "Cross-system exports and temporary files have not been inventoried here.",
    "Identify data recipients, storage copies and documented disposal owners.",
    [], null, null, [], "MANUAL_UNVERIFIED");
  push("RELEASE_REVIEW_PRESENT", good(r.present && r.verified),
    "The release record must exist, match source digests and verify independently.",
    "Create a source-bound pending review and inspect its proof.",
    [r.reviewId ?? "MISSING"]);
  push("RELEASE_HUMAN_DECISION",
    r.acceptedOffline ? "REVIEW" : "BLOCK",
    "Even an ACCEPTED_OFFLINE state is a scoped manual decision, not LIVE.",
    "Obtain an actual signed-off operator decision with explicit exclusions.",
    [r.reviewId ?? "MISSING"], r.acceptedOffline ? 1 : 0, 1,
    [], "MANUAL_UNVERIFIED");
  push("RELEASE_AUDIT_COMPLETE", good(r.auditConsistent && r.auditEvents > 0),
    "All human decision CAS revisions must reconstruct without gaps.",
    "Investigate missing, conflicting or altered audit events.",
    r.auditIssues, r.auditEvents, r.revision);
  const validAt = Number.isFinite(input.checkedAt.getTime()) &&
    Number.isFinite(Date.parse(a.evaluatedAt)) &&
    Number.isFinite(Date.parse(p.evaluatedAt)) &&
    input.checkedAt.getTime() >= Date.parse(a.evaluatedAt) &&
    input.checkedAt.getTime() >= Date.parse(p.evaluatedAt);
  push("EVIDENCE_FRESHNESS", good(validAt &&
    a.gates.find(g => g.id === "AGE_POLICY")?.level === "PASS"),
    "The current evaluation clock and freshness gate must be coherent.",
    "Re-evaluate at the intended operational signoff time.",
    [a.evaluatedAt, p.evaluatedAt]);
  push("MANUAL_END_TO_END", "REVIEW",
    "CI and static dossiers cannot confirm a representative human walkthrough.",
    "Run and retain a witnessed CSV-to-review acceptance checklist.",
    [], null, null, [], "MANUAL_UNVERIFIED");
  push("EXTERNAL_PRIVACY_SIGNOFF", "REVIEW",
    "Privacy readiness cannot identify or approve a legally accountable officer.",
    "Collect the real responsible party's independent privacy approval.",
    [], null, null, [], "MANUAL_UNVERIFIED");
  push("BACKUP_DELETION_ATTESTATION", "EXCLUDED",
    "Actual backup deletion attestation is out of scope of this offline run.",
    "Track any mandated backup disposition independently before production use.",
    [], null, null, [], "OUT_OF_SCOPE");
  push("LIVE_PROVIDER_VALIDATION", "EXCLUDED",
    "No external tenant or OSV LIVE provider verification is requested.",
    "Retain a distinct future LIVE acceptance gate.",
    [], null, null, [], "OUT_OF_SCOPE");
  return gates;
}
export function assembleCloseoutDossier(input: {
  organizationId: string;
  acceptance: AcceptanceReport;
  acceptanceValid: boolean;
  privacy: PrivacyReadinessReport;
  scenario: {
    digest: string; passed: number; executed: number;
    failed: number; complete: boolean; mismatches: string[];
  };
  release: CloseoutReleaseEvidence;
  retention: CloseoutRetentionEvidence;
  now: Date;
}): OfflineCloseoutDossier {
  if (!Number.isFinite(input.now.getTime()))
    fail("INVALID", "Closeout clock is invalid.");
  const a = input.acceptance;
  const p = input.privacy;
  if (a.organizationId !== input.organizationId ||
      p.organizationId !== input.organizationId)
    fail("CONFLICT", "Closeout source report belongs to a different tenant.");
  const inventory: CloseoutInventoryEvidence = {
    importId: a.importId, inspectionId: a.inspectionId,
    inventoryDigest: a.source.inventoryDigest,
    inspectionDigest: a.source.inspectionDigest,
    source: a.source.origin,
    inspectionSource: a.source.inspectionOrigin,
    deviceCount: a.source.deviceCount,
    queryCount: a.source.queryCount,
    mappedPercent: a.scorecard.mappedPercent,
    possibleCandidates: a.source.positiveCandidateCount,
    unknownEvidence: a.source.unknownEvidenceCount,
    casesEvaluated: a.scorecard.casesEvaluated,
    auditsObserved: a.source.auditCount,
    positiveWithoutReview: a.scorecard.possibleCandidatesWithoutReview,
    completeWithinSnapshot: a.source.completeWithinSnapshot,
  };
  const privacy: CloseoutPrivacyEvidence = {
    digest: p.digest, fullyExamined: p.fullyExamined,
    blocked: p.readiness.blocked,
    reviewNeeded: p.readiness.reviewNeeded,
    pendingOperatorApproval: p.readiness.pendingOperatorApproval,
    hostnameSignals: p.totalPotentialHostnames,
    ownerHashSignals: p.totalOwnerHashes,
    openCasesBeyondPolicy: p.openCasesBeyondPolicy,
    importCount: p.importedCount, backupsErased: false,
    personalDataErased: false, consentInferred: false,
    gates: p.gates.map(g => ({
      id: g.id, severity: g.severity, explanation: g.rationale,
      affectedImportIds: g.affectedImportIds,
    })),
  };
  const gates = buildCloseoutGates({
    inventory, acceptance: a,
    acceptanceValid: input.acceptanceValid,
    privacy: p, scenarioPassed: input.scenario.passed,
    scenarioComplete: input.scenario.complete,
    release: input.release, retention: input.retention,
    checkedAt: input.now,
  });
  const blocked = gates.filter(g => g.status === "BLOCK").length;
  const manualReview = gates.filter(g => g.status === "REVIEW").length;
  const excluded = gates.filter(g => g.status === "EXCLUDED").length;
  const passed = gates.filter(g => g.status === "PASS").length;
  const sourceDigest = sha({
    schema: "cyberpilot.assets.offline.closeout.sources.v1",
    organizationId: input.organizationId,
    inventoryDigest: inventory.inventoryDigest,
    inspectionDigest: inventory.inspectionDigest,
    acceptanceDigest: a.reportDigest,
    privacyDigest: p.digest,
    scenarioDigest: input.scenario.digest,
    releaseDigest: input.release.digest,
    auditDigest: input.release.auditDigest,
    retentionDigest: input.retention.reviewId,
  });
  const canonical = {
    schema: "cyberpilot.assets.offline.closeout.dossier.v1" as const,
    organizationId: input.organizationId,
    importId: a.importId, inspectionId: a.inspectionId,
    evaluatedAt: input.now.toISOString(),
    source: "TENANT_SCOPED_PERSISTED_RECORDS" as const,
    inventory,
    acceptance: {
      digest: a.reportDigest,
      reportValid: input.acceptanceValid,
      eligible: a.acceptanceEligible,
      policy: a.policy, scorecard: a.scorecard,
      blockedGates: a.gates.filter(g => g.level === "BLOCK").map(g => g.id),
      advisoryGates: a.gates.filter(g => g.level === "ADVISORY").map(g => g.id),
    },
    privacy,
    scenario: {
      digest: input.scenario.digest,
      source: "BUILT_IN_SYNTHETIC_FIXTURES" as const,
      passed: input.scenario.passed,
      executed: input.scenario.executed,
      failed: input.scenario.failed,
      complete: input.scenario.complete,
      mismatches: input.scenario.mismatches,
      notTenantAcceptance: true as const,
    },
    release: input.release, retention: input.retention,
    gates,
    counts: {
      passed, blocked, manualReview, excluded,
      completedAutomated: passed,
      total: gates.length,
    },
    missingHumanActions: gates.filter(g => g.status === "REVIEW" ||
      g.status === "BLOCK").map(g => g.nextAction),
    reproducibleAutomatedEvaluation:
      input.acceptanceValid && input.scenario.complete &&
      p.fullyExamined,
    readyForManualCloseout: blocked === 0,
    offlineProductAccepted: false as const,
    mergeAuthorized: false as const,
    liveProviderValidated: false as const,
    externalTenantRequiredForThisScope: false as const,
    legalSignoffConfirmed: false as const,
    backupErasureConfirmed: false as const,
    destructiveWrites: 0 as const,
    sourceDigest,
  };
  return { ...canonical, digest: sha(canonical), caveats };
}
export function verifyCloseoutDossier(
  report: OfflineCloseoutDossier,
): { valid: boolean; issues: string[] } {
  const { digest, caveats: notes, ...canonical } = report;
  const issues: string[] = [];
  if (!eq(digest, sha(canonical)))
    issues.push("Closeout dossier canonical digest has been altered.");
  if (report.counts.total !== report.gates.length ||
      report.counts.blocked !== report.gates.filter(g =>
        g.status === "BLOCK").length ||
      report.counts.manualReview !== report.gates.filter(g =>
        g.status === "REVIEW").length ||
      report.counts.passed !== report.gates.filter(g =>
        g.status === "PASS").length ||
      report.counts.excluded !== report.gates.filter(g =>
        g.status === "EXCLUDED").length)
    issues.push("Dossier summary does not match its gate list.");
  if (new Set(report.gates.map(g => g.code)).size !== report.gates.length)
    issues.push("Duplicate acceptance gate identifiers.");
  if (report.privacy.backupsErased || report.privacy.personalDataErased ||
      report.offlineProductAccepted || report.mergeAuthorized ||
      report.liveProviderValidated || report.legalSignoffConfirmed ||
      report.backupErasureConfirmed || report.destructiveWrites !== 0 ||
      report.scenario.notTenantAcceptance !== true ||
      report.externalTenantRequiredForThisScope !== false)
    issues.push("Unsupported acceptance, erasure or LIVE claim.");
  if (report.readyForManualCloseout !==
      (report.counts.blocked === 0))
    issues.push("Ready-for-manual status contradicts blockers.");
  if (!Array.isArray(notes) || notes.length < 6)
    issues.push("Operational and privacy disclaimers are incomplete.");
  return { valid: issues.length === 0, issues };
}
export function closeoutIssuePlaybook(report: OfflineCloseoutDossier) {
  return report.gates.filter(g => g.status !== "PASS").map(g => ({
    gate: g.code,
    status: g.status,
    nextAction: g.nextAction,
    explanation: g.explanation,
    evidence: g.evidence,
    cannotSelfApprove: g.evidenceKind === "MANUAL_UNVERIFIED",
  }));
}
export function closeoutEvidenceManifest(report: OfflineCloseoutDossier) {
  if (!verifyCloseoutDossier(report).valid)
    fail("CONFLICT", "Cannot export an altered closeout dossier.");
  const sources = [
    { type: "INVENTORY", digest: report.inventory.inventoryDigest,
      identifier: report.importId },
    { type: "INSPECTION", digest: report.inventory.inspectionDigest,
      identifier: report.inspectionId },
    { type: "ACCEPTANCE", digest: report.acceptance.digest,
      identifier: report.inspectionId },
    { type: "PRIVACY", digest: report.privacy.digest,
      identifier: report.organizationId },
    { type: "SCENARIOS_SYNTHETIC", digest: report.scenario.digest,
      identifier: "BUILT_IN_FIXTURES" },
    { type: "RELEASE", digest: report.release.digest,
      identifier: report.release.reviewId },
    { type: "RELEASE_AUDIT", digest: report.release.auditDigest,
      identifier: report.release.reviewId },
  ].filter(row => row.digest !== null);
  return {
    schema: "cyberpilot.assets.offline.closeout.manifest.v1" as const,
    organizationId: report.organizationId,
    generatedAt: report.evaluatedAt,
    sources, dossierDigest: report.digest,
    missingEvidence: report.gates.filter(g => g.status === "BLOCK")
      .map(g => g.code),
    outstandingManualSignoffs: report.gates.filter(g =>
      g.evidenceKind === "MANUAL_UNVERIFIED").map(g => g.code),
    noExternalSignatures: true as const,
    productAcceptanceNotGranted: true as const,
    liveProviderNotContacted: true as const,
  };
}
export async function inspectOfflineCloseoutDossier(
  scope: AssetScope, raw: unknown, now = new Date(),
): Promise<OfflineCloseoutDossier> {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Closeout dossiers require ADMIN or OWNER.");
  const command = parseCloseoutCommand(raw);
  const [a, p, release, retention] = await Promise.all([
    inspectAssetOfflineAcceptance(scope, {
      importId: command.importId, inspectionId: command.inspectionId,
      bindings: command.bindings, policy: command.acceptancePolicy,
    }, now),
    inspectAssetPrivacyReadiness(scope, {
      policy: command.privacyPolicy,
    }, now),
    db.assetReleaseReview.findFirst({
      where: { organizationId: scope.organizationId,
        importId: command.importId, inspectionId: command.inspectionId },
    }),
    db.assetRetentionReview.findFirst({
      where: { organizationId: scope.organizationId,
        importId: command.importId },
    }),
  ]);
  const verification = verifyOfflineAcceptanceReport(a);
  if (!verification.valid)
    fail("CONFLICT", "Acceptance source report failed independent verification.");
  const suite = runOfflineScenarioMatrix(parseScenarioMatrixOptions(), now);
  const coverage = inspectScenarioMatrixCoverage(suite);
  const suiteCheck = verifyOfflineScenarioMatrix(suite);
  const audit = release ? await inspectReleaseAuditDossier(scope, {
    reviewId: release.id,
    maximumEvents: command.maxAuditEvents,
    includeDecisionReasons: command.includeHumanReasons,
    includeMetadata: false,
  }, now) : null;
  if (audit && !verifyReleaseAuditDossier(audit).valid)
    fail("CONFLICT", "Release audit dossier integrity invalid.");
  const relCheck = release ?
    verifyPersistedAssetReleaseReview(release) : null;
  const retCheck = retention ? verifyRetentionReview(retention) : null;
  const report = assembleCloseoutDossier({
    organizationId: scope.organizationId,
    acceptance: a, acceptanceValid: verification.valid,
    privacy: p,
    scenario: {
      digest: suite.resultsDigest, passed: suite.passed,
      executed: suite.totalExecuted, failed: suite.failed,
      complete: suiteCheck.valid &&
        coverage.verdict === "COMPLETE_REFERENCE_SET" &&
        suite.passed === 13 && suite.totalExecuted === 13,
      mismatches: suite.results.filter(r => !r.passed)
        .map(r => r.id),
    },
    release: detailsForRelease(release, relCheck, audit),
    retention: detailsForRetention(retention, retCheck),
    now,
  });
  if (!verifyCloseoutDossier(report).valid)
    fail("CONFLICT", "Generated closeout dossier failed verification.");
  return report;
}
