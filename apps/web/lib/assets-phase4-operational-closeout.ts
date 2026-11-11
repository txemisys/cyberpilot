import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { AssetScope } from "./assets-inventory-service";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { inspectOfflineCloseoutDossier,
  verifyCloseoutDossier } from "./assets-offline-closeout-dossier";
import { verifyOperatorRun, verifyOperatorSteps,
  stableSourceIdentity } from
  "./assets-offline-acceptance-run-service";
import { summarizeIndependentReviews } from
  "./assets-evidence-independent-review";
import { inspectAcceptanceAuditReconciliation,
  verifyAuditReconciliation } from
  "./assets-acceptance-audit-reconciliation";
import { verifyRetentionReview } from "./assets-retention-review-service";
import { verifyPersistedAssetReleaseReview } from
  "./assets-release-review-verification";
import { inspectReleaseAuditDossier } from "./assets-release-audit-dossier";

export type CloseoutArea =
  "INVENTORY" | "OSV_STORED" | "ACTION_CASES" |
  "OFFLINE_REFERENCE" | "PRIVACY" | "RETENTION" |
  "BACKUP_AND_EXPORTS" | "OPERATOR_WALKTHROUGH" |
  "INDEPENDENT_EVIDENCE" | "RELEASE_REVIEW" |
  "AUDIT_RECONCILIATION" | "MANUAL_APPROVAL" |
  "CI_HEAD_VERIFICATION" | "LIVE_EXCLUSION";
export type CloseoutStatus =
  "PASS_LOCAL" | "BLOCKED" | "HUMAN_REVIEW" | "EXCLUDED";
export type CloseoutStage = {
  area: CloseoutArea;
  state: CloseoutStatus;
  title: string;
  finding: string;
  evidenceIds: string[];
  prerequisites: CloseoutArea[];
  blockerCodes: string[];
  ownerRole: "ADMIN" | "PRIVACY_OWNER" | "BACKUP_OWNER" |
    "OPERATOR" | "INDEPENDENT_REVIEWER" |
    "RELEASE_OWNER" | "PRODUCT_OWNER" | "CI_MAINTAINER";
  nextAction: string;
  scope: "LOCAL_DB" | "SYNTHETIC" | "HUMAN_REQUIRED" |
    "EXCLUDED_OFFLINE";
  noAutoApproval: true;
};
export type CloseoutDependency = {
  source: CloseoutArea;
  target: CloseoutArea;
  satisfied: boolean;
  reason: string;
};
export type CloseoutAction = {
  priority: "BLOCK" | "HUMAN" | "LATER";
  area: CloseoutArea;
  ownerRole: CloseoutStage["ownerRole"];
  description: string;
  evidence: string[];
  mustBeExternallyVerified: boolean;
  mayNotBeAutoCompleted: true;
};
export type OperationalCloseoutInput = {
  organizationId: string;
  importId: string;
  inspectionId: string;
  evaluatedAt: string;
  dossier: {
    digest: string;
    counts: { blocked: number; passed: number;
      manualReview: number; excluded: number };
    inventory: { deviceCount: number;
      queryCount: number; positiveWithoutReview: number };
    scenario: { complete: boolean; passed: number };
    privacy: { fullyExamined: boolean; blocked: number;
      reviewNeeded: number };
    release: { present: boolean; verified: boolean;
      acceptedOffline: boolean; auditConsistent: boolean;
      reviewId: string | null };
    retention: { present: boolean; verified: boolean;
      state: string; reviewId: string | null;
      backupDisposition: string; nextReviewAt: string | null };
    gates: Array<{ code: string; status: string }>;
  };
  operator: {
    id: string | null;
    state: string;
    revision: number;
    complete: boolean;
    integrity: boolean;
    stepsRecorded: number;
    blockedSteps: number;
    sourceIdentityMatches: boolean;
    sourceDigest: string | null;
  };
  independent: {
    reviewCount: number;
    independentlyMatched: number;
    readyForHumanSignoff: boolean;
    mismatchCount: number;
  };
  audit: {
    checked: boolean;
    integrity: boolean;
    complete: boolean;
    blockers: number;
    reviewEvents: number;
    digest: string | null;
  };
  releaseAudit: {
    checked: boolean;
    valid: boolean;
    events: number;
  };
  retentionHumanApprovalDocumented: boolean;
  backupProcedureDocumented: boolean;
  manualProductSignoffConfirmed: false;
  currentCiHeadVerified: false;
  liveProviderValidated: false;
};
export type OperationalCloseoutReport = {
  schema: "cyberpilot.assets.phase4.operational.closeout.v1";
  organizationId: string;
  importId: string;
  inspectionId: string;
  operatorRunId: string | null;
  evaluatedAt: string;
  sourceDigests: {
    closeout: string;
    operatorSource: string | null;
    audit: string | null;
  };
  stages: CloseoutStage[];
  dependencies: CloseoutDependency[];
  actions: CloseoutAction[];
  overview: {
    total: number;
    passed: number;
    blocked: number;
    needsHuman: number;
    excluded: number;
    dependencyBlocked: number;
    evidenceRecorded: number;
    independentChecks: number;
    canRequestHumanReview: boolean;
    technicallyPreparedForOfflineSignoff: boolean;
    operationallyAccepted: false;
    authorizationToMerge: false;
  };
  policy: {
    offlineOnly: true;
    releaseDecisionIsNotLegalApproval: true;
    syntheticFixturesAreNotCustomerAcceptance: true;
    backupProcedureDoesNotProveErasure: true;
    providerLiveTestExcluded: true;
    manualWitnessMustBeConfirmedExternally: true;
  };
  localDatabaseWrites: 0;
  liveProviderRequests: 0;
  cybersecurityScoreChanged: false;
  findingsChanged: false;
  legalSignoffVerified: false;
  externalSignaturesVerified: false;
  backupDeletionVerified: false;
  mergeAuthorized: false;
  digest: string;
  limitations: string[];
};
export type OperationalCloseoutCommand = {
  importId: string;
  inspectionId: string;
  runId: string | null;
  bindings: unknown[];
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
  maxAuditEvents: number;
};
const caveats = [
  "All local PASS values mean only that recorded evidence passed a specific technical check.",
  "No selection or checklist automatically creates the responsible operator's signoff.",
  "Privacy and retention approval must be obtained from competent real persons.",
  "Backup procedure documentation does not attest to erasure of copies or exported personal data.",
  "The current GitHub HEAD and CI status are not retrieved by this database-only service.",
  "LIVE provider validation and external tenants remain excluded from this offline acceptance.",
  "SHA-256 digests provide local change detection, not digital non-repudiation.",
  "A manually entered evidence reference is not independent proof of its origin.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function obj(value: unknown): Record<string, unknown> {
  if (!value || Array.isArray(value) || typeof value !== "object")
    fail("INVALID", "Operational closeout command must be a JSON object.");
  return value as Record<string, unknown>;
}
function identifier(value: unknown, required = true): string | null {
  if (!required && (value === null || value === undefined || value === ""))
    return null;
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid scoped closeout identifier.");
  return value;
}
function bound(value: unknown, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > max)
    fail("INVALID", "Invalid bounded operational evidence query.");
  return value;
}
export function parseOperationalCloseoutCommand(
  raw: unknown,
): OperationalCloseoutCommand {
  const value = obj(raw);
  if (Object.keys(value).some(k => ![
    "importId", "inspectionId", "runId", "bindings",
    "acceptancePolicy", "privacyPolicy", "maxAuditEvents",
  ].includes(k)))
    fail("INVALID", "Unexpected operational closeout field.");
  if (!Array.isArray(value.bindings) || value.bindings.length > 2000)
    fail("INVALID", "Explicit bounded package bindings required.");
  return {
    importId: identifier(value.importId)!,
    inspectionId: identifier(value.inspectionId)!,
    runId: identifier(value.runId, false),
    bindings: value.bindings,
    acceptancePolicy: value.acceptancePolicy ?? {},
    privacyPolicy: value.privacyPolicy ?? {},
    maxAuditEvents: bound(value.maxAuditEvents ?? 250, 1000),
  };
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equal(a: unknown, b: unknown) {
  if (typeof a !== "string" || typeof b !== "string" ||
      !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b))
    return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
const definitions: Array<{
  area: CloseoutArea;
  title: string;
  ownerRole: CloseoutStage["ownerRole"];
  prerequisites: CloseoutArea[];
  nextAction: string;
  scope: CloseoutStage["scope"];
}> = [
  {
    area: "INVENTORY", title: "Declared CSV inventory",
    ownerRole: "OPERATOR", prerequisites: [],
    nextAction: "Confirm representative CSV and persisted inventory fingerprint.",
    scope: "LOCAL_DB",
  },
  {
    area: "OSV_STORED", title: "Stored OSV inspection",
    ownerRole: "OPERATOR", prerequisites: ["INVENTORY"],
    nextAction: "Inspect source version, exact package bindings and query completeness.",
    scope: "LOCAL_DB",
  },
  {
    area: "ACTION_CASES", title: "Human candidate and action cases",
    ownerRole: "OPERATOR", prerequisites: ["OSV_STORED"],
    nextAction: "Open or complete missing human review cases with transaction audit.",
    scope: "LOCAL_DB",
  },
  {
    area: "OFFLINE_REFERENCE", title: "Offline rules and synthetic regression matrix",
    ownerRole: "CI_MAINTAINER", prerequisites: [],
    nextAction: "Reconcile the mandatory gates with all thirteen synthetic references.",
    scope: "SYNTHETIC",
  },
  {
    area: "PRIVACY", title: "PII and data handling",
    ownerRole: "PRIVACY_OWNER", prerequisites: ["INVENTORY"],
    nextAction: "Review hostnames, pseudonymous identifiers, historic cases and retention.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "RETENTION", title: "Documented retention exceptions",
    ownerRole: "PRIVACY_OWNER", prerequisites: ["PRIVACY"],
    nextAction: "Confirm actual responsible retention policy, exceptions and next review.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "BACKUP_AND_EXPORTS", title: "Backup and export lifecycle",
    ownerRole: "BACKUP_OWNER", prerequisites: ["RETENTION"],
    nextAction: "Identify physical and restored/exported copies and obtain responsible review.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "OPERATOR_WALKTHROUGH", title: "Witnessed nine-step acceptance run",
    ownerRole: "OPERATOR", prerequisites: ["ACTION_CASES", "OFFLINE_REFERENCE"],
    nextAction: "Record actual operator-observed evidence for every step and submit for review.",
    scope: "LOCAL_DB",
  },
  {
    area: "INDEPENDENT_EVIDENCE", title: "Independent reference checks",
    ownerRole: "INDEPENDENT_REVIEWER",
    prerequisites: ["OPERATOR_WALKTHROUGH"],
    nextAction: "Require a different authenticated reviewer for every recorded source reference.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "RELEASE_REVIEW", title: "Manual offline release decision",
    ownerRole: "RELEASE_OWNER",
    prerequisites: ["ACTION_CASES", "PRIVACY"],
    nextAction: "Record a genuinely authorized operator decision against fresh evidence.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "AUDIT_RECONCILIATION", title: "Independent CAS audit reconciliation",
    ownerRole: "INDEPENDENT_REVIEWER",
    prerequisites: ["INDEPENDENT_EVIDENCE", "RELEASE_REVIEW"],
    nextAction: "Investigate duplicate/missing CAS revisions and altered evidence chains.",
    scope: "LOCAL_DB",
  },
  {
    area: "MANUAL_APPROVAL", title: "Product acceptance and responsible signoff",
    ownerRole: "PRODUCT_OWNER",
    prerequisites: ["AUDIT_RECONCILIATION", "BACKUP_AND_EXPORTS"],
    nextAction: "Record the real human acceptance separately from local evidence tools.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "CI_HEAD_VERIFICATION", title: "GitHub HEAD and five workflow checks",
    ownerRole: "CI_MAINTAINER", prerequisites: [],
    nextAction: "Verify five completed/success checks on the exact target HEAD.",
    scope: "HUMAN_REQUIRED",
  },
  {
    area: "LIVE_EXCLUSION", title: "External tenants and OSV LIVE",
    ownerRole: "PRODUCT_OWNER", prerequisites: [],
    nextAction: "Retain a separately scoped LIVE acceptance plan before activating providers.",
    scope: "EXCLUDED_OFFLINE",
  },
];
function step(area: CloseoutArea, state: CloseoutStatus,
  finding: string, evidenceIds: string[] = [],
  blockerCodes: string[] = []): CloseoutStage {
  const definition = definitions.find(d => d.area === area)!;
  return {
    ...definition, state, finding, evidenceIds,
    blockerCodes, noAutoApproval: true,
  };
}
function classify(input: OperationalCloseoutInput): CloseoutStage[] {
  const d = input.dossier;
  const op = input.operator;
  const ind = input.independent;
  const audit = input.audit;
  const required = (flag: boolean): CloseoutStatus =>
    flag ? "PASS_LOCAL" : "BLOCKED";
  return [
    step("INVENTORY", required(d.inventory.deviceCount > 0),
      "Declared asset count: " + d.inventory.deviceCount,
      [input.importId]),
    step("OSV_STORED", required(d.inventory.queryCount > 0),
      "Stored query count: " + d.inventory.queryCount,
      [input.inspectionId]),
    step("ACTION_CASES", required(
      d.inventory.positiveWithoutReview === 0),
      "Unreviewed positive candidates: " +
      d.inventory.positiveWithoutReview,
      [d.digest]),
    step("OFFLINE_REFERENCE", required(
      d.scenario.complete && d.scenario.passed === 13),
      "Synthetic reference pass count: " + d.scenario.passed,
      [d.digest]),
    step("PRIVACY", required(
      d.privacy.fullyExamined && d.privacy.blocked === 0 &&
      d.privacy.reviewNeeded === 0),
      "Unresolved privacy gates: " +
      (d.privacy.blocked + d.privacy.reviewNeeded),
      [d.digest]),
    step("RETENTION",
      d.retention.present && d.retention.verified &&
      input.retentionHumanApprovalDocumented &&
      d.retention.state === "DOCUMENTED_WITH_EXCEPTIONS" ?
        "HUMAN_REVIEW" : "BLOCKED",
      "Recorded retention status: " + d.retention.state +
      "; documentation is not legal signoff.",
      [d.retention.reviewId ?? "NOT_RECORDED"]),
    step("BACKUP_AND_EXPORTS",
      input.backupProcedureDocumented ? "HUMAN_REVIEW" : "BLOCKED",
      "A documented procedure does not certify all copies were erased.",
      [d.retention.backupDisposition]),
    step("OPERATOR_WALKTHROUGH", required(
      op.complete && op.integrity && op.blockedSteps === 0 &&
      op.sourceIdentityMatches),
      "Recorded steps: " + op.stepsRecorded +
      "; blocked: " + op.blockedSteps,
      [op.id ?? "NOT_RECORDED"]),
    step("INDEPENDENT_EVIDENCE",
      ind.readyForHumanSignoff &&
      ind.independentlyMatched === 9 &&
      ind.mismatchCount === 0 ? "HUMAN_REVIEW" : "BLOCKED",
      "Independently matched local references: " +
      ind.independentlyMatched + "/9",
      [op.id ?? "NOT_RECORDED"]),
    step("RELEASE_REVIEW",
      d.release.present && d.release.verified &&
      d.release.auditConsistent && d.release.acceptedOffline ?
        "HUMAN_REVIEW" : "BLOCKED",
      "Release state and decision must be valid and genuinely authorized.",
      [d.release.reviewId ?? "NOT_RECORDED"]),
    step("AUDIT_RECONCILIATION", required(
      audit.checked && audit.integrity && audit.complete &&
      audit.blockers === 0 &&
      input.releaseAudit.checked && input.releaseAudit.valid),
      "Audited operator/reviewer events: " + audit.reviewEvents,
      [op.id ?? "NOT_RECORDED"]),
    step("MANUAL_APPROVAL", "HUMAN_REVIEW",
      "Responsible product signoff must be independently confirmed.",
      []),
    step("CI_HEAD_VERIFICATION", "HUMAN_REVIEW",
      "The application does not have authoritative GitHub HEAD check data.",
      []),
    step("LIVE_EXCLUSION", "EXCLUDED",
      "Provider LIVE and external tenants are outside offline acceptance.",
      []),
  ];
}
export function buildOperationalCloseout(
  input: OperationalCloseoutInput,
): OperationalCloseoutReport {
  if (!/^[A-Za-z0-9_-]{5,150}$/.test(input.organizationId) ||
      !Number.isFinite(Date.parse(input.evaluatedAt)) ||
      !/^[a-f0-9]{64}$/.test(input.dossier.digest))
    fail("INVALID", "Malformed operational closeout source data.");
  const stages = classify(input);
  if (new Set(stages.map(s => s.area)).size !== definitions.length)
    fail("CONFLICT", "Closeout stage contract is incomplete.");
  const known = new Map(stages.map(s => [s.area, s]));
  const dependencies: CloseoutDependency[] = [];
  for (const stage of stages) {
    for (const source of stage.prerequisites) {
      const prior = known.get(source);
      dependencies.push({
        source, target: stage.area,
        satisfied: prior?.state === "PASS_LOCAL",
        reason: prior?.state === "PASS_LOCAL" ?
          "Local source passed its automated check." :
          "Prerequisite has a blocker, unresolved human review or exclusion.",
      });
    }
  }
  const actions: CloseoutAction[] = stages.filter(s =>
    s.state !== "PASS_LOCAL").map(stage => ({
    priority: stage.state === "BLOCKED" ? "BLOCK" :
      stage.state === "EXCLUDED" ? "LATER" : "HUMAN",
    area: stage.area, ownerRole: stage.ownerRole,
    description: stage.nextAction,
    evidence: stage.evidenceIds,
    mustBeExternallyVerified: stage.scope === "HUMAN_REQUIRED",
    mayNotBeAutoCompleted: true,
  }));
  const passed = stages.filter(s => s.state === "PASS_LOCAL").length;
  const blocked = stages.filter(s => s.state === "BLOCKED").length;
  const needsHuman = stages.filter(s => s.state === "HUMAN_REVIEW").length;
  const excluded = stages.filter(s => s.state === "EXCLUDED").length;
  const dependencyBlocked = dependencies.filter(d => !d.satisfied).length;
  const criticalAreas: CloseoutArea[] = [
    "INVENTORY", "OSV_STORED", "ACTION_CASES",
    "OFFLINE_REFERENCE", "OPERATOR_WALKTHROUGH",
    "AUDIT_RECONCILIATION",
  ];
  const technicalPass = criticalAreas.every(area =>
    known.get(area)?.state === "PASS_LOCAL");
  const canonical = {
    schema: "cyberpilot.assets.phase4.operational.closeout.v1" as const,
    organizationId: input.organizationId,
    importId: input.importId, inspectionId: input.inspectionId,
    operatorRunId: input.operator.id,
    evaluatedAt: input.evaluatedAt,
    sourceDigests: {
      closeout: input.dossier.digest,
      operatorSource: input.operator.sourceDigest,
      audit: input.audit.digest,
    },
    stages, dependencies, actions,
    overview: {
      total: stages.length, passed, blocked, needsHuman,
      excluded, dependencyBlocked,
      evidenceRecorded: input.operator.stepsRecorded,
      independentChecks: input.independent.independentlyMatched,
      canRequestHumanReview:
        technicalPass && input.independent.readyForHumanSignoff &&
        input.audit.integrity,
      technicallyPreparedForOfflineSignoff: technicalPass,
      operationallyAccepted: false as const,
      authorizationToMerge: false as const,
    },
    policy: {
      offlineOnly: true as const,
      releaseDecisionIsNotLegalApproval: true as const,
      syntheticFixturesAreNotCustomerAcceptance: true as const,
      backupProcedureDoesNotProveErasure: true as const,
      providerLiveTestExcluded: true as const,
      manualWitnessMustBeConfirmedExternally: true as const,
    },
    localDatabaseWrites: 0 as const,
    liveProviderRequests: 0 as const,
    cybersecurityScoreChanged: false as const,
    findingsChanged: false as const,
    legalSignoffVerified: false as const,
    externalSignaturesVerified: false as const,
    backupDeletionVerified: false as const,
    mergeAuthorized: false as const,
  };
  return { ...canonical, digest: sha(canonical), limitations: caveats };
}
export function verifyOperationalCloseout(
  report: OperationalCloseoutReport,
) {
  const { digest, limitations, ...canonical } = report;
  const issues: string[] = [];
  if (!equal(digest, sha(canonical)))
    issues.push("Operational closeout digest does not match its contents.");
  if (report.overview.total !== report.stages.length ||
      report.overview.passed !== report.stages.filter(s =>
        s.state === "PASS_LOCAL").length ||
      report.overview.blocked !== report.stages.filter(s =>
        s.state === "BLOCKED").length ||
      report.overview.needsHuman !== report.stages.filter(s =>
        s.state === "HUMAN_REVIEW").length ||
      report.overview.excluded !== report.stages.filter(s =>
        s.state === "EXCLUDED").length)
    issues.push("Stage summary count is invalid.");
  if (new Set(report.stages.map(s => s.area)).size !== definitions.length)
    issues.push("Duplicate or missing closeout stage.");
  if (report.overview.operationallyAccepted ||
      report.overview.authorizationToMerge ||
      report.mergeAuthorized || report.legalSignoffVerified ||
      report.externalSignaturesVerified || report.backupDeletionVerified ||
      report.liveProviderRequests !== 0 ||
      report.localDatabaseWrites !== 0 ||
      report.cybersecurityScoreChanged || report.findingsChanged)
    issues.push("Closeout makes an unsupported external approval claim.");
  if (report.stages.find(s =>
    s.area === "LIVE_EXCLUSION")?.state !== "EXCLUDED" ||
      report.stages.find(s =>
        s.area === "MANUAL_APPROVAL")?.state !== "HUMAN_REVIEW" ||
      report.stages.find(s =>
        s.area === "CI_HEAD_VERIFICATION")?.state !== "HUMAN_REVIEW")
    issues.push("Nonautomatable stage was marked complete.");
  if (!Array.isArray(limitations) || limitations.length < 6)
    issues.push("Required operational caveats are missing.");
  return { valid: issues.length === 0, issues };
}
export function operationalCloseoutActionPlan(
  report: OperationalCloseoutReport,
) {
  if (!verifyOperationalCloseout(report).valid)
    fail("CONFLICT", "Cannot plan from an altered operational report.");
  return report.actions.map((action, index) => ({
    order: index + 1,
    ...action,
    predecessors: report.dependencies.filter(d =>
      d.target === action.area && !d.satisfied)
      .map(d => d.source),
    automaticApprovalPossible: false as const,
    actualCompletionUnknown: true as const,
  }));
}
export function operationalCloseoutExport(
  report: OperationalCloseoutReport,
) {
  if (!verifyOperationalCloseout(report).valid)
    fail("CONFLICT", "Cannot export an invalid operational report.");
  return {
    schema: "cyberpilot.assets.phase4.operational.export.v1" as const,
    organizationId: report.organizationId,
    evaluatedAt: report.evaluatedAt,
    sourceDigest: report.digest,
    actionPlan: operationalCloseoutActionPlan(report),
    report,
    requiresIndependentHumanApproval: true as const,
    sha256NotDigitalSignature: true as const,
    cannotAuthorizeMerge: true as const,
  };
}
export async function inspectOperationalCloseout(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Operational closeout requires ADMIN or OWNER.");
  const command = parseOperationalCloseoutCommand(raw);
  const dossier = await inspectOfflineCloseoutDossier(scope, {
    importId: command.importId, inspectionId: command.inspectionId,
    bindings: command.bindings,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
    maxAuditEvents: command.maxAuditEvents,
  }, now);
  if (!verifyCloseoutDossier(dossier).valid)
    fail("CONFLICT", "Underlying offline source dossier is invalid.");
  const [operator, retention] = await Promise.all([
    command.runId ? db.assetOfflineAcceptanceRun.findFirst({
      where: { id: command.runId, organizationId: scope.organizationId,
        importId: command.importId, inspectionId: command.inspectionId },
    }) : Promise.resolve(null),
    db.assetRetentionReview.findFirst({
      where: { organizationId: scope.organizationId,
        importId: command.importId },
    }),
  ]);
  if (command.runId && !operator)
    fail("MISSING", "Selected acceptance run is not bound to this source.");
  const reviews = operator ? await db.assetEvidenceReview.findMany({
    where: { organizationId: scope.organizationId,
      acceptanceRunId: operator.id },
    orderBy: [{ stepCode: "asc" }],
    take: 10,
  }) : [];
  const steps = operator ? verifyOperatorSteps(operator.steps) : null;
  const operatorCheck = operator ? verifyOperatorRun(operator) : null;
  const independent = operator && steps?.valid ?
    summarizeIndependentReviews({
      organizationId: scope.organizationId, runId: operator.id,
      revision: operator.revision, state: operator.state,
      steps: steps.items, reviews,
    }, now) : null;
  const audit = operator ? await inspectAcceptanceAuditReconciliation(
    scope, { runId: operator.id,
      maximumRunEvents: command.maxAuditEvents,
      maximumReviewEvents: command.maxAuditEvents,
    }, now) : null;
  if (audit && !verifyAuditReconciliation(audit).valid)
    fail("CONFLICT", "Operator/reviewer audit report failed verification.");
  const release = dossier.release.reviewId ?
    await db.assetReleaseReview.findFirst({
      where: { id: dossier.release.reviewId,
        organizationId: scope.organizationId },
    }) : null;
  const releaseAudit = release ? await inspectReleaseAuditDossier(scope, {
    reviewId: release.id, maximumEvents: command.maxAuditEvents,
  }, now) : null;
  const retentionCheck = retention ? verifyRetentionReview(retention) : null;
  const releaseCheck = release ?
    verifyPersistedAssetReleaseReview(release) : null;
  const input: OperationalCloseoutInput = {
    organizationId: scope.organizationId,
    importId: command.importId, inspectionId: command.inspectionId,
    evaluatedAt: now.toISOString(),
    dossier: {
      digest: dossier.digest,
      counts: dossier.counts,
      inventory: {
        deviceCount: dossier.inventory.deviceCount,
        queryCount: dossier.inventory.queryCount,
        positiveWithoutReview:
          dossier.inventory.positiveWithoutReview,
      },
      scenario: { complete: dossier.scenario.complete,
        passed: dossier.scenario.passed },
      privacy: { fullyExamined: dossier.privacy.fullyExamined,
        blocked: dossier.privacy.blocked,
        reviewNeeded: dossier.privacy.reviewNeeded },
      release: {
        present: dossier.release.present,
        verified: dossier.release.verified &&
          !!releaseCheck?.verified,
        acceptedOffline: dossier.release.acceptedOffline,
        auditConsistent: dossier.release.auditConsistent,
        reviewId: dossier.release.reviewId,
      },
      retention: {
        present: dossier.retention.present,
        verified: dossier.retention.verified &&
          !!retentionCheck?.valid,
        state: dossier.retention.state,
        reviewId: dossier.retention.reviewId,
        backupDisposition: dossier.retention.backupDisposition,
        nextReviewAt: dossier.retention.nextReviewAt,
      },
      gates: dossier.gates.map(g => ({
        code: g.code, status: g.status,
      })),
    },
    operator: {
      id: operator?.id ?? null,
      state: operator?.state ?? "MISSING",
      revision: operator?.revision ?? 0,
      complete: operator?.state === "EVIDENCE_CAPTURED",
      integrity: operatorCheck?.valid ?? false,
      stepsRecorded: steps?.completed ?? 0,
      blockedSteps: steps?.blocked ?? 0,
      sourceDigest: operator?.sourceDigest ?? null,
      sourceIdentityMatches: !!operator &&
        operator.importId === dossier.importId &&
        operator.inspectionId === dossier.inspectionId &&
        equal(operator.sourceDigest, stableSourceIdentity(dossier, {
          acceptancePolicy: command.acceptancePolicy,
          privacyPolicy: command.privacyPolicy,
        })),
    },
    independent: {
      reviewCount: reviews.length,
      independentlyMatched: independent?.independentReferencesMatched ?? 0,
      readyForHumanSignoff: independent?.readyForHumanSignoff ?? false,
      mismatchCount: independent?.outstanding.length ?? 9,
    },
    audit: {
      checked: !!audit,
      integrity: audit?.localAuditIntegrityVerified ?? false,
      complete: audit?.runAuditComplete &&
        audit.reviewAuditComplete || false,
      blockers: audit?.blockers ?? 1,
      reviewEvents: audit?.totalReviewEvents ?? 0,
      digest: audit?.digest ?? null,
    },
    releaseAudit: {
      checked: !!releaseAudit,
      valid: !!releaseAudit?.auditConsistent &&
        !!releaseCheck?.verified,
      events: releaseAudit?.totalEvents ?? 0,
    },
    retentionHumanApprovalDocumented:
      !!retention?.reviewedByUserId &&
      retention.state === "DOCUMENTED_WITH_EXCEPTIONS" &&
      !!retentionCheck?.valid,
    backupProcedureDocumented: !!retention &&
      retention.backupDisposition === "PROCEDURE_DOCUMENTED" &&
      !!retentionCheck?.valid,
    manualProductSignoffConfirmed: false,
    currentCiHeadVerified: false,
    liveProviderValidated: false,
  };
  const result = buildOperationalCloseout(input);
  if (!verifyOperationalCloseout(result).valid)
    fail("CONFLICT", "New operational closeout report is invalid.");
  return result;
}
