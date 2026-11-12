import { createHash, timingSafeEqual } from "node:crypto";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  inspectOperationalCloseout, verifyOperationalCloseout,
  operationalCloseoutActionPlan,
} from "./assets-phase4-operational-closeout";
import {
  inspectAcceptanceAuditReconciliation,
  verifyAuditReconciliation,
} from "./assets-acceptance-audit-reconciliation";
import {
  inspectOfflineCloseoutDossier, verifyCloseoutDossier,
  closeoutEvidenceManifest,
} from "./assets-offline-closeout-dossier";
import {
  listIndependentEvidenceReviews,
} from "./assets-evidence-independent-review";
import { OPERATOR_STEP_CODES } from
  "./assets-offline-acceptance-run-service";

export type HandoffConcernCode =
  "TENANT_MISMATCH" | "SOURCE_MISMATCH" | "RUN_MISMATCH" |
  "DOSSIER_INVALID" | "OPERATIONS_INVALID" | "AUDIT_INVALID" |
  "CLOCK_INCONSISTENT" | "SOURCE_DIGEST_MISSING" |
  "OUTSTANDING_AUTOMATED_BLOCKERS" | "PRIVACY_EXCEPTIONS" |
  "BACKUP_PROCESS_UNAPPROVED" | "OPERATOR_STEPS_INCOMPLETE" |
  "INDEPENDENT_REFERENCES_INCOMPLETE" | "INDEPENDENT_AUDIT_MISSING" |
  "UNVERIFIED_HUMAN_OPERATOR" | "RELEASE_REVIEW_PENDING" |
  "MANUAL_PRODUCT_APPROVAL_REQUIRED" | "CI_HEAD_CHECK_REQUIRED" |
  "EXTERNAL_PROVIDER_LIVE_EXCLUDED" |
  "EXTERNAL_SIGNATURE_UNVERIFIED" | "EVIDENCE_AGE_REVIEW" |
  "AUDIT_VERSION_INCOMPLETE" | "DEPENDENCY_NOT_SATISFIED" |
  "EXPORT_DISTRIBUTION_NOT_TRACKED";
export type HandoffConcern = {
  code: HandoffConcernCode;
  level: "BLOCK" | "HUMAN" | "EXCLUDED";
  owner: "OPERATOR" | "INDEPENDENT_REVIEWER" |
    "PRIVACY_OWNER" | "BACKUP_OWNER" |
    "PRODUCT_OWNER" | "CI_MAINTAINER";
  description: string;
  nextAction: string;
  linkedDigests: string[];
  relatedRunId: string | null;
  requiresExternalEvidence: boolean;
  automaticallyResolved: false;
};
export type HandoffEvidenceItem = {
  kind: "INVENTORY" | "OSV_INSPECTION" |
    "ACCEPTANCE_REPORT" | "PRIVACY_REPORT" |
    "SCENARIO_MATRIX_SYNTHETIC" | "RELEASE_REVIEW" |
    "RELEASE_AUDIT" | "RETENTION_REVIEW" |
    "OPERATOR_RUN" | "INDEPENDENT_REVIEW" |
    "CAS_RECONCILIATION" | "OPERATIONAL_CLOSEOUT";
  sourceId: string | null;
  digest: string | null;
  available: boolean;
  independentlyAuthenticated: false;
  sourceClass: "TENANT_LOCAL" | "SYNTHETIC" |
    "HUMAN_DECLARATION";
  ownerRole: string;
  caveat: string;
};
export type HandoffMilestone = {
  sequence: number;
  title: string;
  owner: HandoffConcern["owner"];
  prerequisiteCodes: string[];
  expectedDeliverable: string;
  evidencePresent: boolean;
  humanCompletionVerified: false;
  phaseClosedByMilestone: false;
  externallyRecorded: false;
};
export type HandoffSection = {
  id: "PROVENANCE" | "RISK_SCOPE" | "OPERATOR_RECORD" |
    "INDEPENDENCE" | "DATA_GOVERNANCE" | "BACKUP_EXPORTS" |
    "OFFLINE_RELEASE" | "SECURITY_TESTS" | "FINAL_DECISION";
  title: string;
  status: "LOCAL_PASS" | "BLOCK" | "HUMAN" | "EXCLUDED";
  sourceNames: string[];
  concerns: HandoffConcernCode[];
  summary: string;
  accountableRole: HandoffConcern["owner"];
  nextStep: string;
};
export type Phase4HandoffInput = {
  organizationId: string;
  importId: string;
  inspectionId: string;
  operatorRunId: string | null;
  evaluatedAt: string;
  minimumReferenceCount: 9;
  base: {
    digest: string;
    importDigest: string;
    inspectionDigest: string;
    privacyDigest: string;
    scenarioDigest: string;
    scenarioPassed: number;
    scenarioComplete: boolean;
    releaseId: string | null;
    releaseDigest: string | null;
    releaseAuditDigest: string | null;
    releaseAccepted: boolean;
    retentionId: string | null;
    retentionVerified: boolean;
    retentionState: string;
    privacyBlocked: number;
    privacyReviewNeeded: number;
    offlineBlocked: number;
  };
  operations: {
    digest: string;
    blocked: number;
    human: number;
    excluded: number;
    technicalReady: boolean;
    humanReady: boolean;
    operatorSteps: number;
    reviewerChecks: number;
    sourceOperatorDigest: string | null;
    auditDigest: string | null;
    pendingDependencies: number;
    stages: Array<{
      area: string;
      state: string;
      ownerRole: string;
      nextAction: string;
      evidenceIds: string[];
    }>;
  };
  audits: {
    present: boolean;
    digest: string | null;
    runId: string | null;
    runEvents: number;
    reviewEvents: number;
    runComplete: boolean;
    reviewComplete: boolean;
    blockers: number;
    integrity: boolean;
    independentlyReviewedSteps: number;
  };
  independent: {
    present: boolean;
    totalSteps: number;
    independentMatches: number;
    missing: number;
    stale: number;
    disputed: number;
    readyForHumanSignoff: boolean;
    digest: string | null;
  };
  generatedWithoutExternalCall: true;
};
export type Phase4HandoffPackage = {
  schema: "cyberpilot.assets.phase4.handoff.package.v1";
  organizationId: string;
  importId: string;
  inspectionId: string;
  operatorRunId: string | null;
  evaluatedAt: string;
  source: "READ_ONLY_PERSISTED_TENANT_AND_SYNTHETIC_REFERENCE";
  scope: {
    acceptance: "OFFLINE";
    includesExternalTenants: false;
    includesLiveProviderCheck: false;
    syntheticMatrixDoesNotProveCustomerAcceptance: true;
    requiresRealHumanWitness: true;
    requiresIndependentPrivacyApproval: true;
    requiresBackupExportReview: true;
  };
  evidence: HandoffEvidenceItem[];
  sections: HandoffSection[];
  concerns: HandoffConcern[];
  milestones: HandoffMilestone[];
  dependencies: Array<{
    from: string;
    to: string;
    satisfiedByLocalEvidence: boolean;
    requiresHuman: boolean;
  }>;
  summary: {
    sourcesListed: number;
    sourcesAvailable: number;
    sections: number;
    localPass: number;
    blocked: number;
    humanReview: number;
    excluded: number;
    operatorStepsRecorded: number;
    independentMatches: number;
    auditRevisionsObserved: number;
    concernsBlocking: number;
    concernsHuman: number;
    requiresExplicitSignoff: true;
    preparedForIndependentHumanReview: boolean;
    phaseAccepted: false;
    mergeAuthorized: false;
  };
  provenance: {
    inventoryDigest: string;
    inspectionDigest: string;
    offlineAcceptanceDigest: string;
    privacyDigest: string;
    referenceMatrixDigest: string;
    operationalDigest: string;
    reconciliationDigest: string | null;
    independentReviewDigest: string | null;
    dossierDigest: string;
    releaseDigest: string | null;
    noExternalSignature: true;
  };
  nextActionPlan: Array<{
    priority: number;
    owner: HandoffConcern["owner"];
    title: string;
    concernCodes: HandoffConcernCode[];
    references: string[];
    mustBeManuallyRecorded: true;
    automaticallyExecuted: false;
  }>;
  digest: string;
  limitations: string[];
  databaseWrites: 0;
  providerRequests: 0;
  legalApproved: false;
  backupDeletionVerified: false;
  productAccepted: false;
  githubMergeAuthorized: false;
  thirdPartySignaturesVerified: false;
};
export type HandoffCommand = {
  importId: string;
  inspectionId: string;
  runId: string | null;
  bindings: unknown[];
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
  maxAuditEvents: number;
  maxEvidenceAgeDays: number;
};
const caveats = [
  "This is a preparation package for real accountable humans, never a product signoff.",
  "Every local digest detects only internal content changes; it is not a digital signature.",
  "No external live provider, tenant, scanner, OSV API or GitHub workflow is invoked.",
  "The application cannot attest legal policies, actual backup deletion or data export disposal.",
  "The operator and reviewer may have declared false or incomplete source references.",
  "The reference suite is synthetic and separate from representative customer CSV acceptance.",
  "No item in this report grants authorization to merge a Draft pull request.",
  "Manual approvals must be stored independently and reviewed by competent responsible people.",
];
const actions: Record<HandoffConcernCode, string> = {
  TENANT_MISMATCH: "Rebind all source reports to the authenticated organization.",
  SOURCE_MISMATCH: "Regenerate evidence from current source snapshots and identifiers.",
  RUN_MISMATCH: "Select the operator run associated with the exact import and inspection.",
  DOSSIER_INVALID: "Recompute the source dossier and investigate invalid local digest.",
  OPERATIONS_INVALID: "Repair the operational evidence report by rerunning read-only checks.",
  AUDIT_INVALID: "Investigate inconsistent CAS audit chain; do not fabricate missing events.",
  CLOCK_INCONSISTENT: "Use a coherent evaluation timestamp and rerun checks.",
  SOURCE_DIGEST_MISSING: "Recover the source digest and inspect its provenance.",
  OUTSTANDING_AUTOMATED_BLOCKERS: "Resolve blocked local acceptance and source gates.",
  PRIVACY_EXCEPTIONS: "Obtain responsible review of each outstanding PII/retention exception.",
  BACKUP_PROCESS_UNAPPROVED: "Obtain independently documented backup and export lifecycle approval.",
  OPERATOR_STEPS_INCOMPLETE: "Execute the missing witnessed operator acceptance steps.",
  INDEPENDENT_REFERENCES_INCOMPLETE: "Cross-check all nine operator evidence references with a different person.",
  INDEPENDENT_AUDIT_MISSING: "Reconcile reviewer and operator CAS events without silent corrections.",
  UNVERIFIED_HUMAN_OPERATOR: "Confirm actual identity, scope, role and provenance of the operator.",
  RELEASE_REVIEW_PENDING: "Record a source-bound human offline release decision with exclusions.",
  MANUAL_PRODUCT_APPROVAL_REQUIRED: "Obtain a real responsible product owner decision outside this tool.",
  CI_HEAD_CHECK_REQUIRED: "Verify all five GitHub workflows SUCCESS on the exact current HEAD.",
  EXTERNAL_PROVIDER_LIVE_EXCLUDED: "Plan external LIVE approval as a separate, later scope.",
  EXTERNAL_SIGNATURE_UNVERIFIED: "Do not treat local SHA-256 as an externally authenticated signature.",
  EVIDENCE_AGE_REVIEW: "Recheck source and recorded decisions against current age policy.",
  AUDIT_VERSION_INCOMPLETE: "Investigate missing or duplicate audit revisions before signoff.",
  DEPENDENCY_NOT_SATISFIED: "Resolve prerequisites to the relevant human acceptance stage.",
  EXPORT_DISTRIBUTION_NOT_TRACKED: "Agree where sensitive exported evidence is stored and deleted.",
};
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Handoff request must be a JSON object.");
  return value as Record<string, unknown>;
}
function identifier(value: unknown, optional = false): string | null {
  if (optional && (value === null || value === undefined || value === ""))
    return null;
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid handoff source identifier.");
  return value;
}
function bound(value: unknown, name: string, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > max)
    fail("INVALID", "Invalid handoff " + name + ".");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function same(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
export function parseHandoffCommand(raw: unknown): HandoffCommand {
  const v = object(raw);
  const allowed = ["importId", "inspectionId", "runId",
    "bindings", "acceptancePolicy", "privacyPolicy",
    "maxAuditEvents", "maxEvidenceAgeDays"];
  if (Object.keys(v).some(k => !allowed.includes(k)))
    fail("INVALID", "Unexpected handoff request field.");
  if (!Array.isArray(v.bindings) || v.bindings.length > 2000)
    fail("INVALID", "Handoff needs bounded explicit package mappings.");
  return {
    importId: identifier(v.importId)!,
    inspectionId: identifier(v.inspectionId)!,
    runId: identifier(v.runId, true),
    bindings: v.bindings,
    acceptancePolicy: v.acceptancePolicy ?? {},
    privacyPolicy: v.privacyPolicy ?? {},
    maxAuditEvents: bound(v.maxAuditEvents ?? 250, "audit bound", 1000),
    maxEvidenceAgeDays: bound(v.maxEvidenceAgeDays ?? 30,
      "age policy", 3650),
  };
}
function concern(code: HandoffConcernCode, level: HandoffConcern["level"],
  owner: HandoffConcern["owner"], description: string,
  runId: string | null, digests: string[] = []): HandoffConcern {
  return {
    code, level, owner, description, nextAction: actions[code],
    linkedDigests: digests,
    relatedRunId: runId, requiresExternalEvidence:
      level === "HUMAN" && [
        "PRIVACY_EXCEPTIONS", "BACKUP_PROCESS_UNAPPROVED",
        "UNVERIFIED_HUMAN_OPERATOR", "MANUAL_PRODUCT_APPROVAL_REQUIRED",
        "EXTERNAL_SIGNATURE_UNVERIFIED", "EXPORT_DISTRIBUTION_NOT_TRACKED",
      ].includes(code),
    automaticallyResolved: false,
  };
}
function sourceItem(kind: HandoffEvidenceItem["kind"],
  id: string | null, digest: string | null, ownerRole: string,
  caveat: string, sourceClass: HandoffEvidenceItem["sourceClass"] =
    "TENANT_LOCAL"): HandoffEvidenceItem {
  return {
    kind, sourceId: id, digest,
    available: id !== null && digest !== null,
    independentlyAuthenticated: false, sourceClass, ownerRole, caveat,
  };
}
export function assemblePhase4Handoff(
  input: Phase4HandoffInput,
  ageLimit = 30,
): Phase4HandoffPackage {
  if (!Number.isFinite(Date.parse(input.evaluatedAt)) ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(input.organizationId))
    fail("INVALID", "Invalid handoff tenant or evaluation clock.");
  const base = input.base;
  const ops = input.operations;
  const audits = input.audits;
  const independent = input.independent;
  const concerns: HandoffConcern[] = [];
  const add = (code: HandoffConcernCode, level: HandoffConcern["level"],
    owner: HandoffConcern["owner"], description: string,
    digests: string[] = []) =>
    concerns.push(concern(code, level, owner, description,
      input.operatorRunId, digests));
  if (!same(base.digest, base.digest) ||
      !same(ops.digest, ops.digest))
    add("DOSSIER_INVALID", "BLOCK", "OPERATOR",
      "Local source or operational digest is malformed.");
  if (!same(base.importDigest, base.importDigest) ||
      !same(base.inspectionDigest, base.inspectionDigest))
    add("SOURCE_DIGEST_MISSING", "BLOCK", "OPERATOR",
      "An inventory or inspection digest is absent.");
  if (base.offlineBlocked > 0 || ops.blocked > 0)
    add("OUTSTANDING_AUTOMATED_BLOCKERS", "BLOCK", "OPERATOR",
      base.offlineBlocked + " source and " + ops.blocked +
      " operational blockers require investigation.", [base.digest, ops.digest]);
  if (base.privacyBlocked + base.privacyReviewNeeded > 0 ||
      !base.retentionVerified)
    add("PRIVACY_EXCEPTIONS", "HUMAN", "PRIVACY_OWNER",
      "PII/retention requires independently accountable review.",
      [base.privacyDigest]);
  add("BACKUP_PROCESS_UNAPPROVED", "HUMAN", "BACKUP_OWNER",
    "No actual backup/exports lifecycle approval can be inferred.");
  if (ops.operatorSteps < input.minimumReferenceCount)
    add("OPERATOR_STEPS_INCOMPLETE", "BLOCK", "OPERATOR",
      ops.operatorSteps + " of nine witnessed references recorded.");
  if (independent.independentMatches !== input.minimumReferenceCount ||
      !independent.readyForHumanSignoff)
    add("INDEPENDENT_REFERENCES_INCOMPLETE", "BLOCK",
      "INDEPENDENT_REVIEWER",
      "Only " + independent.independentMatches +
      " of nine operator references were independently corroborated.",
      independent.digest ? [independent.digest] : []);
  if (!audits.present || !audits.runComplete ||
      !audits.reviewComplete || audits.blockers > 0)
    add("INDEPENDENT_AUDIT_MISSING", "BLOCK",
      "INDEPENDENT_REVIEWER",
      "Operator/reviewer CAS audit history remains incomplete.",
      audits.digest ? [audits.digest] : []);
  if (!audits.integrity)
    add("AUDIT_INVALID", "BLOCK", "INDEPENDENT_REVIEWER",
      "Forensic audit integrity cannot be confirmed.");
  if (base.releaseId === null || !base.releaseAccepted)
    add("RELEASE_REVIEW_PENDING", "HUMAN", "PRODUCT_OWNER",
      "No accepted and audited offline release decision is verified.");
  if (input.operatorRunId === null)
    add("UNVERIFIED_HUMAN_OPERATOR", "HUMAN", "OPERATOR",
      "No actual operator acceptance run was supplied.");
  if (ops.pendingDependencies > 0)
    add("DEPENDENCY_NOT_SATISFIED", "BLOCK", "OPERATOR",
      ops.pendingDependencies + " prerequisites remain unsatisfied.");
  add("MANUAL_PRODUCT_APPROVAL_REQUIRED", "HUMAN", "PRODUCT_OWNER",
    "A competent product owner must decide final offline acceptance.");
  add("CI_HEAD_CHECK_REQUIRED", "HUMAN", "CI_MAINTAINER",
    "Read-only database reports do not verify current GitHub CI.");
  add("EXTERNAL_PROVIDER_LIVE_EXCLUDED", "EXCLUDED", "PRODUCT_OWNER",
    "External tenants and LIVE providers are outside this offline scope.");
  add("EXTERNAL_SIGNATURE_UNVERIFIED", "HUMAN", "PRODUCT_OWNER",
    "No digital signature of source material was independently checked.");
  add("EXPORT_DISTRIBUTION_NOT_TRACKED", "HUMAN", "PRIVACY_OWNER",
    "A downloaded handoff document may require access and retention controls.");
  const since = Date.parse(input.evaluatedAt);
  if (!Number.isFinite(since) || ageLimit < 1)
    fail("INVALID", "Invalid handoff evidence age policy.");
  const evidence: HandoffEvidenceItem[] = [
    sourceItem("INVENTORY", input.importId, base.importDigest,
      "OPERATOR", "Source is customer-declared, not endpoint-discovered."),
    sourceItem("OSV_INSPECTION", input.inspectionId, base.inspectionDigest,
      "OPERATOR", "Historical stored provider result, not a current LIVE check."),
    sourceItem("ACCEPTANCE_REPORT", input.importId, base.digest,
      "OPERATOR", "Source package contains locally evaluated gates."),
    sourceItem("PRIVACY_REPORT", input.organizationId, base.privacyDigest,
      "PRIVACY_OWNER", "Readiness cannot authenticate legal approval."),
    sourceItem("SCENARIO_MATRIX_SYNTHETIC", "BUILT_IN_FIXTURES",
      base.scenarioDigest, "CI_MAINTAINER",
      "A synthetic regression suite never represents customer acceptance.",
      "SYNTHETIC"),
    sourceItem("RELEASE_REVIEW", base.releaseId, base.releaseDigest,
      "PRODUCT_OWNER", "A recorded offline release decision is scoped."),
    sourceItem("RELEASE_AUDIT", base.releaseId, base.releaseAuditDigest,
      "INDEPENDENT_REVIEWER", "Local event history lacks an external signature."),
    sourceItem("RETENTION_REVIEW", base.retentionId,
      base.retentionId ? base.privacyDigest : null,
      "PRIVACY_OWNER", "Review of exceptions is not proof of disposal."),
    sourceItem("OPERATOR_RUN", input.operatorRunId,
      ops.sourceOperatorDigest, "OPERATOR",
      "Operator references require independent corroboration.",
      "HUMAN_DECLARATION"),
    sourceItem("INDEPENDENT_REVIEW", input.operatorRunId,
      independent.digest, "INDEPENDENT_REVIEWER",
      "Verified local references do not authenticate external origin.",
      "HUMAN_DECLARATION"),
    sourceItem("CAS_RECONCILIATION", input.operatorRunId,
      audits.digest, "INDEPENDENT_REVIEWER",
      "Detects local CAS consistency only."),
    sourceItem("OPERATIONAL_CLOSEOUT", input.importId,
      ops.digest, "PRODUCT_OWNER",
      "Local readiness is not acceptance."),
  ];
  const section = (
    id: HandoffSection["id"], title: string,
    status: HandoffSection["status"],
    owner: HandoffSection["accountableRole"],
    sourceNames: string[],
    summary: string, nextStep: string,
  ): HandoffSection => ({
    id, title, status, accountableRole: owner,
    sourceNames, summary, nextStep,
    concerns: concerns.filter(c => sourceNames.length === 0 ||
      c.owner === owner).map(c => c.code),
  });
  const sections: HandoffSection[] = [
    section("PROVENANCE", "Source inventory and stored OSV provenance",
      same(base.importDigest, base.importDigest) &&
      same(base.inspectionDigest, base.inspectionDigest) ?
        "LOCAL_PASS" : "BLOCK",
      "OPERATOR", ["INVENTORY", "OSV_INSPECTION"],
      "Customer-declared inventory and historical stored OSV inspection.",
      "Reconcile exact product versions and declared coverage."),
    section("RISK_SCOPE", "Conservative advisories and reference regressions",
      base.scenarioComplete && base.scenarioPassed === 13 ?
        "LOCAL_PASS" : "BLOCK", "OPERATOR",
      ["ACCEPTANCE_REPORT", "SCENARIO_MATRIX_SYNTHETIC"],
      "Reference suite proves local decision rules only.",
      "Review unknown software, missing mappings and provider-only advisories."),
    section("OPERATOR_RECORD", "Witnessed operator checklist",
      ops.operatorSteps === 9 ? "HUMAN" : "BLOCK", "OPERATOR",
      ["OPERATOR_RUN"], "Actual source references may require verification.",
      "Complete all nine steps with real evidence and witness."),
    section("INDEPENDENCE", "Independent reference corroboration",
      independent.independentMatches === 9 &&
      audits.reviewComplete ? "HUMAN" : "BLOCK",
      "INDEPENDENT_REVIEWER",
      ["INDEPENDENT_REVIEW", "CAS_RECONCILIATION"],
      "A distinct authenticated reviewer should check each current step.",
      "Investigate missing, disputed or stale reviews."),
    section("DATA_GOVERNANCE", "Privacy and retention",
      base.privacyBlocked + base.privacyReviewNeeded === 0 &&
      base.retentionVerified ? "HUMAN" : "BLOCK",
      "PRIVACY_OWNER", ["PRIVACY_REPORT", "RETENTION_REVIEW"],
      "Legally accountable approval cannot be inferred from locally stored checks.",
      "Obtain applicable privacy and retention decisions."),
    section("BACKUP_EXPORTS", "Backup, exported copies and disposal",
      "HUMAN", "BACKUP_OWNER", ["RETENTION_REVIEW"],
      "Backups, exports and copies require independent lifecycle verification.",
      "Agree retention, recovery and disposal responsibilities."),
    section("OFFLINE_RELEASE", "Manual offline release review",
      base.releaseAccepted ? "HUMAN" : "BLOCK",
      "PRODUCT_OWNER", ["RELEASE_REVIEW", "RELEASE_AUDIT"],
      "An accepted offline decision remains scoped and excludes LIVE.",
      "Review signed-off exclusions and release evidence."),
    section("SECURITY_TESTS", "CI HEAD and test verification",
      "HUMAN", "CI_MAINTAINER", ["CAS_RECONCILIATION"],
      "This package does not query GitHub and cannot attest CI state.",
      "Verify migration, typecheck, tests, build and five workflows at HEAD."),
    section("FINAL_DECISION", "Product owner final authorization",
      "HUMAN", "PRODUCT_OWNER", ["OPERATIONAL_CLOSEOUT"],
      "No code path can automatically authorize merge or legal approval.",
      "Record actual accountable acceptance outside this preparation package."),
  ];
  const dependencies = [
    ["PROVENANCE", "RISK_SCOPE"],
    ["PROVENANCE", "OPERATOR_RECORD"],
    ["RISK_SCOPE", "OFFLINE_RELEASE"],
    ["OPERATOR_RECORD", "INDEPENDENCE"],
    ["INDEPENDENCE", "FINAL_DECISION"],
    ["DATA_GOVERNANCE", "BACKUP_EXPORTS"],
    ["DATA_GOVERNANCE", "FINAL_DECISION"],
    ["BACKUP_EXPORTS", "FINAL_DECISION"],
    ["OFFLINE_RELEASE", "FINAL_DECISION"],
    ["SECURITY_TESTS", "FINAL_DECISION"],
  ].map(([from, to]) => ({
    from: from!, to: to!,
    satisfiedByLocalEvidence:
      sections.find(s => s.id === from)?.status === "LOCAL_PASS",
    requiresHuman: sections.find(s => s.id === from)?.status === "HUMAN",
  }));
  const milestones: HandoffMilestone[] = [
    {
      title: "Record representative CSV and scope",
      owner: "OPERATOR", prerequisiteCodes: [],
      expectedDeliverable: "Verified inventory source and boundaries",
      evidencePresent: !!base.importDigest,
    },
    {
      title: "Inspect stored OSV and decisions",
      owner: "OPERATOR", prerequisiteCodes: ["PROVENANCE"],
      expectedDeliverable: "Versioned inspection and decision report",
      evidencePresent: base.scenarioComplete,
    },
    {
      title: "Witness human operator walkthrough",
      owner: "OPERATOR", prerequisiteCodes: ["RISK_SCOPE"],
      expectedDeliverable: "Nine referenced human-observed steps",
      evidencePresent: ops.operatorSteps === 9,
    },
    {
      title: "Corroborate every step independently",
      owner: "INDEPENDENT_REVIEWER",
      prerequisiteCodes: ["OPERATOR_RECORD"],
      expectedDeliverable: "Nine actor-distinct local reference checks",
      evidencePresent: independent.independentMatches === 9,
    },
    {
      title: "Reconstruct and inspect CAS history",
      owner: "INDEPENDENT_REVIEWER",
      prerequisiteCodes: ["INDEPENDENCE"],
      expectedDeliverable: "Unbroken audit history and issue register",
      evidencePresent: audits.integrity,
    },
    {
      title: "Approve privacy and retention handling",
      owner: "PRIVACY_OWNER",
      prerequisiteCodes: ["DATA_GOVERNANCE"],
      expectedDeliverable: "Documented responsible privacy decision",
      evidencePresent: base.retentionVerified,
    },
    {
      title: "Validate backups, exports and disposal",
      owner: "BACKUP_OWNER",
      prerequisiteCodes: ["DATA_GOVERNANCE"],
      expectedDeliverable: "Backups/export lifecycle and approved exceptions",
      evidencePresent: false,
    },
    {
      title: "Confirm HEAD CI and all acceptance workflows",
      owner: "CI_MAINTAINER",
      prerequisiteCodes: ["SECURITY_TESTS"],
      expectedDeliverable: "GitHub five-workflow success on exact HEAD",
      evidencePresent: false,
    },
    {
      title: "Record actual product acceptance and merge decision",
      owner: "PRODUCT_OWNER",
      prerequisiteCodes: ["INDEPENDENCE", "OFFLINE_RELEASE",
        "BACKUP_EXPORTS", "SECURITY_TESTS"],
      expectedDeliverable: "Authorized signed-off human decision",
      evidencePresent: false,
    },
  ].map((row, index) => ({
    ...row, sequence: index + 1,
    humanCompletionVerified: false as const,
    phaseClosedByMilestone: false as const,
    externallyRecorded: false as const,
  }));
  const nextActionPlan = concerns.filter(c =>
    c.level !== "EXCLUDED").map((c, index) => ({
    priority: index + 1,
    owner: c.owner, title: actions[c.code],
    concernCodes: [c.code],
    references: c.linkedDigests,
    mustBeManuallyRecorded: true as const,
    automaticallyExecuted: false as const,
  }));
  const localPass = sections.filter(s => s.status === "LOCAL_PASS").length;
  const blocked = sections.filter(s => s.status === "BLOCK").length;
  const humanReview = sections.filter(s => s.status === "HUMAN").length;
  const excluded = sections.filter(s => s.status === "EXCLUDED").length;
  const canonical = {
    schema: "cyberpilot.assets.phase4.handoff.package.v1" as const,
    organizationId: input.organizationId,
    importId: input.importId,
    inspectionId: input.inspectionId,
    operatorRunId: input.operatorRunId,
    evaluatedAt: input.evaluatedAt,
    source: "READ_ONLY_PERSISTED_TENANT_AND_SYNTHETIC_REFERENCE" as const,
    scope: {
      acceptance: "OFFLINE" as const,
      includesExternalTenants: false as const,
      includesLiveProviderCheck: false as const,
      syntheticMatrixDoesNotProveCustomerAcceptance: true as const,
      requiresRealHumanWitness: true as const,
      requiresIndependentPrivacyApproval: true as const,
      requiresBackupExportReview: true as const,
    },
    evidence, sections, concerns, milestones, dependencies,
    summary: {
      sourcesListed: evidence.length,
      sourcesAvailable: evidence.filter(e => e.available).length,
      sections: sections.length, localPass, blocked, humanReview,
      excluded,
      operatorStepsRecorded: ops.operatorSteps,
      independentMatches: independent.independentMatches,
      auditRevisionsObserved: audits.runEvents + audits.reviewEvents,
      concernsBlocking: concerns.filter(c => c.level === "BLOCK").length,
      concernsHuman: concerns.filter(c => c.level === "HUMAN").length,
      requiresExplicitSignoff: true as const,
      preparedForIndependentHumanReview:
        blocked === 0 && audits.integrity &&
        independent.readyForHumanSignoff &&
        ops.technicalReady,
      phaseAccepted: false as const,
      mergeAuthorized: false as const,
    },
    provenance: {
      inventoryDigest: base.importDigest,
      inspectionDigest: base.inspectionDigest,
      offlineAcceptanceDigest: base.digest,
      privacyDigest: base.privacyDigest,
      referenceMatrixDigest: base.scenarioDigest,
      operationalDigest: ops.digest,
      reconciliationDigest: audits.digest,
      independentReviewDigest: independent.digest,
      dossierDigest: base.digest,
      releaseDigest: base.releaseDigest,
      noExternalSignature: true as const,
    },
    nextActionPlan,
    databaseWrites: 0 as const,
    providerRequests: 0 as const,
    legalApproved: false as const,
    backupDeletionVerified: false as const,
    productAccepted: false as const,
    githubMergeAuthorized: false as const,
    thirdPartySignaturesVerified: false as const,
  };
  return { ...canonical, digest: hash(canonical), limitations: caveats };
}
export function verifyPhase4Handoff(report: Phase4HandoffPackage) {
  const { digest, limitations: notes, ...canonical } = report;
  const issues: string[] = [];
  if (!same(digest, hash(canonical)))
    issues.push("Handoff package digest was changed.");
  if (report.summary.sourcesListed !== report.evidence.length ||
      report.summary.sourcesAvailable !== report.evidence.filter(x =>
        x.available).length ||
      report.summary.sections !== report.sections.length)
    issues.push("Handoff evidence or section counts were altered.");
  if (report.summary.concernsBlocking !== report.concerns.filter(x =>
    x.level === "BLOCK").length ||
      report.summary.concernsHuman !== report.concerns.filter(x =>
        x.level === "HUMAN").length)
    issues.push("Handoff concern counts do not match.");
  if (new Set(report.sections.map(x => x.id)).size !==
      report.sections.length)
    issues.push("Duplicate handoff section identifier.");
  if (report.summary.phaseAccepted || report.summary.mergeAuthorized ||
      report.productAccepted || report.githubMergeAuthorized ||
      report.legalApproved || report.backupDeletionVerified ||
      report.thirdPartySignaturesVerified ||
      report.databaseWrites !== 0 || report.providerRequests !== 0)
    issues.push("Handoff makes an unsupported external approval claim.");
  if (report.milestones.some(x =>
    x.humanCompletionVerified ||
    x.phaseClosedByMilestone || x.externallyRecorded))
    issues.push("A human milestone was marked automatically complete.");
  if (!report.scope.requiresRealHumanWitness ||
      report.scope.includesExternalTenants ||
      report.scope.includesLiveProviderCheck)
    issues.push("Offline acceptance scope was modified.");
  if (!Array.isArray(notes) || notes.length < 6)
    issues.push("Mandatory handoff limitations were removed.");
  return { valid: issues.length === 0, issues };
}
export function phase4HandoffChecklist(report: Phase4HandoffPackage) {
  if (!verifyPhase4Handoff(report).valid)
    fail("CONFLICT", "Cannot produce checklist from altered handoff.");
  return report.milestones.map(m => ({
    ...m, actionNeeded: !m.evidencePresent ||
      !m.humanCompletionVerified,
    validationSource: "OPERATOR_AND_INDEPENDENT_HUMANS_REQUIRED" as const,
    canBeAutomaticallyApproved: false as const,
  }));
}
export function phase4HandoffManifest(report: Phase4HandoffPackage) {
  if (!verifyPhase4Handoff(report).valid)
    fail("CONFLICT", "Cannot export altered handoff package.");
  return {
    schema: "cyberpilot.assets.phase4.handoff.manifest.v1" as const,
    organizationId: report.organizationId,
    evaluatedAt: report.evaluatedAt,
    packageDigest: report.digest,
    sources: report.evidence.map(item => ({
      kind: item.kind, sourceId: item.sourceId,
      digest: item.digest, available: item.available,
      independentlyAuthenticated: false as const,
    })),
    unresolvedHumanMilestones: report.milestones
      .map(item => item.sequence),
    requiresIndependentSignatureVerification: true as const,
    legalDecisionRecorded: false as const,
    productAccepted: false as const,
    mergeAuthorized: false as const,
  };
}
export async function inspectPhase4Handoff(scope: AssetScope,
  raw: unknown, now = new Date()) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Phase 4 handoff package requires ADMIN or OWNER.");
  const command = parseHandoffCommand(raw);
  const shared = {
    importId: command.importId, inspectionId: command.inspectionId,
    bindings: command.bindings,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
    maxAuditEvents: command.maxAuditEvents,
  };
  const [dossier, operational] = await Promise.all([
    inspectOfflineCloseoutDossier(scope, shared, now),
    inspectOperationalCloseout(scope, {
      ...shared, runId: command.runId,
    }, now),
  ]);
  if (!verifyCloseoutDossier(dossier).valid ||
      !verifyOperationalCloseout(operational).valid)
    fail("CONFLICT", "Current source/operational report is invalid.");
  if (dossier.organizationId !== operational.organizationId ||
      dossier.importId !== operational.importId ||
      dossier.inspectionId !== operational.inspectionId ||
      dossier.organizationId !== scope.organizationId)
    fail("CONFLICT", "Handoff sources belong to different tenants or IDs.");
  const manifest = closeoutEvidenceManifest(dossier);
  const [audit, independent] = await Promise.all([
    command.runId ? inspectAcceptanceAuditReconciliation(scope, {
      runId: command.runId,
      maximumRunEvents: command.maxAuditEvents,
      maximumReviewEvents: command.maxAuditEvents,
    }, now) : Promise.resolve(null),
    command.runId ? listIndependentEvidenceReviews(scope, {
      runId: command.runId, includeStale: true,
      includeOperatorReason: false,
    }, now) : Promise.resolve(null),
  ]);
  if (audit && !verifyAuditReconciliation(audit).valid)
    fail("CONFLICT", "Independent CAS report failed verification.");
  const input: Phase4HandoffInput = {
    organizationId: scope.organizationId,
    importId: command.importId,
    inspectionId: command.inspectionId,
    operatorRunId: command.runId,
    evaluatedAt: now.toISOString(),
    minimumReferenceCount: 9,
    base: {
      digest: dossier.digest,
      importDigest: dossier.inventory.inventoryDigest,
      inspectionDigest: dossier.inventory.inspectionDigest,
      privacyDigest: dossier.privacy.digest,
      scenarioDigest: dossier.scenario.digest,
      scenarioPassed: dossier.scenario.passed,
      scenarioComplete: dossier.scenario.complete,
      releaseId: dossier.release.reviewId,
      releaseDigest: dossier.release.digest,
      releaseAuditDigest: dossier.release.auditDigest,
      releaseAccepted: dossier.release.acceptedOffline,
      retentionId: dossier.retention.reviewId,
      retentionVerified: dossier.retention.verified,
      retentionState: dossier.retention.state,
      privacyBlocked: dossier.privacy.blocked,
      privacyReviewNeeded: dossier.privacy.reviewNeeded,
      offlineBlocked: dossier.counts.blocked,
    },
    operations: {
      digest: operational.digest,
      blocked: operational.overview.blocked,
      human: operational.overview.needsHuman,
      excluded: operational.overview.excluded,
      technicalReady: operational.overview.technicallyPreparedForOfflineSignoff,
      humanReady: operational.overview.canRequestHumanReview,
      operatorSteps: operational.overview.evidenceRecorded,
      reviewerChecks: operational.overview.independentChecks,
      sourceOperatorDigest: operational.sourceDigests.operatorSource,
      auditDigest: operational.sourceDigests.audit,
      pendingDependencies: operational.overview.dependencyBlocked,
      stages: operational.stages.map(stage => ({
        area: stage.area, state: stage.state,
        ownerRole: stage.ownerRole,
        nextAction: stage.nextAction,
        evidenceIds: stage.evidenceIds,
      })),
    },
    audits: {
      present: !!audit, digest: audit?.digest ?? null,
      runId: audit?.runId ?? null,
      runEvents: audit?.totalRunEvents ?? 0,
      reviewEvents: audit?.totalReviewEvents ?? 0,
      runComplete: audit?.runAuditComplete ?? false,
      reviewComplete: audit?.reviewAuditComplete ?? false,
      blockers: audit?.blockers ?? 1,
      integrity: audit?.localAuditIntegrityVerified ?? false,
      independentlyReviewedSteps: audit?.independentlyReviewedSteps ?? 0,
    },
    independent: {
      present: !!independent,
      totalSteps: independent?.totalSteps ?? OPERATOR_STEP_CODES.length,
      independentMatches: independent?.independentReferencesMatched ?? 0,
      missing: independent?.missing ?? OPERATOR_STEP_CODES.length,
      stale: independent?.stale ?? 0,
      disputed: independent?.disputed ?? 0,
      readyForHumanSignoff:
        independent?.readyForHumanSignoff ?? false,
      digest: independent?.digest ?? null,
    },
    generatedWithoutExternalCall: true,
  };
  if (!manifest.sources.some(item => item.type === "INVENTORY"))
    fail("CONFLICT", "The underlying closeout manifest has no inventory.");
  const result = assemblePhase4Handoff(input,
    command.maxEvidenceAgeDays);
  if (!verifyPhase4Handoff(result).valid)
    fail("CONFLICT", "Generated Phase 4 handoff failed validation.");
  return result;
}
