import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";
import { retentionCandidate, parseAssetRetentionPolicy } from "./assets-inventory-retention";
import type { AssetPurgeCandidate } from "./assets-inventory-retention";

export type PrivacyPolicy = {
  minimumRetiredDays: number;
  maximumCandidateAgeDays: number;
  maximumActiveAgeDays: number;
  maximumEvidenceAgeDays: number;
  maximumOpenCaseAgeDays: number;
  maxImports: number;
  requireBackupDeletionProcedure: boolean;
  requireOwnerHashDisposalReview: boolean;
  requireHostnameReview: boolean;
  requireCaseDataRetentionReview: boolean;
};
export type PrivacyGate = {
  id: "RETENTION_APPROVAL" | "ACTIVE_INVENTORY_AGE" |
    "RETIRED_SNAPSHOT_AGE" | "HOSTNAME_PII" | "OWNER_HASH_PII" |
    "HISTORIC_INSPECTIONS" | "AUDIT_LINKAGE" | "CASE_RETENTION" |
    "BACKUP_PROCESS" | "PURGE_DEPENDENCIES" |
    "SCOPE_COMPLETENESS" | "DECLARATION_SCOPE";
  severity: "BLOCK" | "REVIEW" | "PASS";
  message: string; observed: number;
  target: number | null;
  affectedImportIds: string[];
  rationale: string;
};
export type PrivacyImport = AssetPurgeCandidate & {
  hostnamesPresent: number;
  ownerHashesPresent: number;
  deviceCount: number;
  inspectionCount: number;
  caseCount: number;
  scheduleCount: number;
  oldestInspectionAt: Date | null;
  newestInspectionAt: Date | null;
  openedCaseCount: number;
  oldestOpenCaseAt: Date | null;
};
export type PrivacyDataset = {
  organizationId: string;
  imports: PrivacyImport[];
  totalImports: number;
  auditRecords: number;
  auditWithUser: number;
  auditWithResource: number;
  now: Date;
};
export type PrivacyImportAssessment = {
  importId: string;
  state: string;
  ageDays: number;
  retiredDays: number | null;
  sourceDigest: string;
  declaredDeviceCount: number;
  verifiedDeviceCount: number;
  hostnameCount: number;
  ownerHashCount: number;
  linkedInspectionCount: number;
  linkedCaseCount: number;
  linkedScheduleCount: number;
  openCaseCount: number;
  oldestOpenCaseAgeDays: number | null;
  oldestInspectionAgeDays: number | null;
  eligibleForSeparatePurgePreview: boolean;
  blockers: string[];
  recommendations: string[];
  possiblePersonalData: boolean;
  dataProvenance: "CUSTOMER_DECLARED_CSV";
};
export type PrivacyReadinessReport = {
  schema: "cyberpilot.assets.privacy.readiness.v1";
  organizationId: string;
  evaluatedAt: string;
  policy: PrivacyPolicy;
  importedCount: number;
  fullyExamined: boolean;
  totalDeviceCount: number;
  totalPotentialHostnames: number;
  totalOwnerHashes: number;
  totalLinkedInspections: number;
  totalLinkedCases: number;
  totalLinkedSchedules: number;
  auditRecords: number;
  auditWithUser: number;
  auditWithResource: number;
  recordsWithPiiSignals: number;
  activeTooOld: number;
  retiredMatured: number;
  openCasesBeyondPolicy: number;
  gates: PrivacyGate[];
  imports: PrivacyImportAssessment[];
  readiness: {
    blocked: number;
    reviewNeeded: number;
    passed: number;
    pendingOperatorApproval: boolean;
    eligibleForPrivacySignoff: boolean;
  };
  procedure: Array<{
    stage: "CLASSIFY" | "APPROVE" | "RETIRE" | "VERIFY" |
      "PURGE" | "BACKUP_REVIEW" | "CLOSE";
    requiresHumanApproval: true;
    instruction: string;
    evidenceToRetain: string;
    destructive: boolean;
  }>;
  digest: string;
  databasesMutated: false;
  personalDataErased: false;
  backupDeletionVerified: false;
  userConsentInferred: false;
  warnings: string[];
};
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    invalid("Privacy policy must be a JSON object.");
  return value as Record<string, unknown>;
}
function number(value: unknown, name: string, lo: number, hi: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < lo || value > hi)
    invalid("Invalid privacy policy field " + name + ".");
  return value;
}
function flag(raw: Record<string, unknown>, name: string) {
  const value = raw[name] ?? true;
  if (typeof value !== "boolean")
    invalid("Privacy policy flag must be boolean: " + name + ".");
  return value;
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parsePrivacyPolicy(raw: unknown = {}): PrivacyPolicy {
  const input = object(raw);
  const allowed = [
    "minimumRetiredDays", "maximumCandidateAgeDays",
    "maximumActiveAgeDays", "maximumEvidenceAgeDays",
    "maximumOpenCaseAgeDays", "maxImports",
    "requireBackupDeletionProcedure",
    "requireOwnerHashDisposalReview",
    "requireHostnameReview",
    "requireCaseDataRetentionReview",
  ];
  if (Object.keys(input).some(key => !allowed.includes(key)))
    invalid("Unexpected privacy readiness field.");
  return {
    minimumRetiredDays: number(input.minimumRetiredDays ?? 30,
      "minimum retired days", 1, 3650),
    maximumCandidateAgeDays: number(input.maximumCandidateAgeDays ?? 365,
      "maximum candidate age", 1, 3650),
    maximumActiveAgeDays: number(input.maximumActiveAgeDays ?? 365,
      "maximum active age", 1, 3650),
    maximumEvidenceAgeDays: number(input.maximumEvidenceAgeDays ?? 365,
      "maximum inspection age", 1, 3650),
    maximumOpenCaseAgeDays: number(input.maximumOpenCaseAgeDays ?? 90,
      "maximum open case age", 1, 3650),
    maxImports: number(input.maxImports ?? 100,
      "max imports", 1, 500),
    requireBackupDeletionProcedure:
      flag(input, "requireBackupDeletionProcedure"),
    requireOwnerHashDisposalReview:
      flag(input, "requireOwnerHashDisposalReview"),
    requireHostnameReview:
      flag(input, "requireHostnameReview"),
    requireCaseDataRetentionReview:
      flag(input, "requireCaseDataRetentionReview"),
  };
}
function daysBetween(start: Date, end: Date) {
  if (!Number.isFinite(start.getTime()) ||
      start.getTime() > end.getTime())
    return null;
  return Math.floor((end.getTime() - start.getTime()) / 86400000);
}
export function assessPrivacyImport(
  row: PrivacyImport, policy: PrivacyPolicy, now: Date,
): PrivacyImportAssessment {
  const retention = retentionCandidate(row, now, parseAssetRetentionPolicy({
    minimumRetiredDays: policy.minimumRetiredDays,
    maximumCandidateAgeDays: policy.maximumCandidateAgeDays,
  }));
  const blockers: string[] = [];
  const recommendations: string[] = [];
  const activeTooOld = row.state === "COMMITTED" &&
    (daysBetween(row.createdAt, now) ?? -1) > policy.maximumActiveAgeDays;
  const oldestInspectionAgeDays = row.oldestInspectionAt ?
    daysBetween(row.oldestInspectionAt, now) : null;
  const oldestOpenCaseAgeDays = row.oldestOpenCaseAt ?
    daysBetween(row.oldestOpenCaseAt, now) : null;
  if (row.importedCount !== row.deviceCount)
    blockers.push("Persisted device count differs from immutable import count.");
  if (row.createdAt.getTime() > now.getTime())
    blockers.push("Snapshot was created after evaluation time.");
  if (row.state === "RETIRED" && !row.retiredAt)
    blockers.push("Retired import is missing its retirement timestamp.");
  if (row.state === "COMMITTED" && row.retiredAt)
    blockers.push("Committed import unexpectedly carries a retirement timestamp.");
  if (activeTooOld)
    recommendations.push("Review retention necessity for an active snapshot older than policy.");
  if (row.hostnamesPresent > 0)
    recommendations.push("Hostnames may contain personal identifiers; assess lawful purpose and disposal.");
  if (row.ownerHashesPresent > 0)
    recommendations.push("Owner hashes are pseudonymized identifiers, not anonymous data.");
  if (row.inspectionCount > 0)
    recommendations.push("Inspect historical OSV reports and their cascading database references before purge.");
  if (row.caseCount > 0)
    recommendations.push("Review human case rationale, activity notes and audit trail before retention decisions.");
  if (row.scheduleCount > 0)
    recommendations.push("Disable and review any schedule referring to this inventory before destructive operations.");
  if (oldestInspectionAgeDays !== null &&
      oldestInspectionAgeDays > policy.maximumEvidenceAgeDays)
    recommendations.push("Some inspection evidence exceeds configured age and needs independent policy review.");
  if (oldestOpenCaseAgeDays !== null &&
      oldestOpenCaseAgeDays > policy.maximumOpenCaseAgeDays)
    recommendations.push("Old unresolved human reviews require escalation or documented retention justification.");
  if (retention.eligible) {
    recommendations.push("Eligible for separate explicit purge preview; this report never performs deletion.");
    if (row.caseCount > 0)
      blockers.push("Review cases remain linked by identifiers and require separate disposal assessment.");
    if (row.scheduleCount > 0)
      blockers.push("Scheduling dependencies remain linked and require operator review.");
  }
  return {
    importId: row.importId,
    state: row.state,
    ageDays: retention.ageDays,
    retiredDays: retention.daysSinceRetirement,
    sourceDigest: row.payloadDigest,
    declaredDeviceCount: row.importedCount,
    verifiedDeviceCount: row.deviceCount,
    hostnameCount: row.hostnamesPresent,
    ownerHashCount: row.ownerHashesPresent,
    linkedInspectionCount: row.inspectionCount,
    linkedCaseCount: row.caseCount,
    linkedScheduleCount: row.scheduleCount,
    openCaseCount: row.openedCaseCount,
    oldestOpenCaseAgeDays,
    oldestInspectionAgeDays,
    eligibleForSeparatePurgePreview: retention.eligible,
    blockers, recommendations,
    possiblePersonalData: row.hostnamesPresent > 0 ||
      row.ownerHashesPresent > 0 || row.caseCount > 0,
    dataProvenance: "CUSTOMER_DECLARED_CSV",
  };
}
function gate(
  id: PrivacyGate["id"], ok: boolean,
  message: string, observed: number, target: number | null,
  rationale: string, affected: string[],
  whenFalse: PrivacyGate["severity"] = "BLOCK",
): PrivacyGate {
  return {
    id, severity: ok ? "PASS" : whenFalse,
    message, observed, target,
    affectedImportIds: [...new Set(affected)].sort(),
    rationale,
  };
}
export function assessPrivacyReadiness(
  data: PrivacyDataset, policy: PrivacyPolicy,
): PrivacyReadinessReport {
  if (!Number.isFinite(data.now.getTime()))
    invalid("Invalid privacy evaluation date.");
  if (data.totalImports > policy.maxImports ||
      data.imports.length !== data.totalImports)
    throw new WorkInputError("CONFLICT",
      "Privacy readiness requires the full bounded import set.");
  const imports = data.imports.map(row =>
    assessPrivacyImport(row, policy, data.now));
  const bad = imports.filter(row => row.blockers.length);
  const aged = imports.filter(row =>
    row.state === "COMMITTED" &&
    row.ageDays > policy.maximumActiveAgeDays);
  const mature = imports.filter(row =>
    row.state === "RETIRED" &&
    row.eligibleForSeparatePurgePreview);
  const host = imports.filter(row => row.hostnameCount > 0);
  const owner = imports.filter(row => row.ownerHashCount > 0);
  const cases = imports.filter(row => row.linkedCaseCount > 0);
  const oldCase = imports.filter(row =>
    row.oldestOpenCaseAgeDays !== null &&
    row.oldestOpenCaseAgeDays > policy.maximumOpenCaseAgeDays);
  const oldEvidence = imports.filter(row =>
    row.oldestInspectionAgeDays !== null &&
    row.oldestInspectionAgeDays > policy.maximumEvidenceAgeDays);
  const depends = imports.filter(row =>
    row.linkedCaseCount > 0 || row.linkedScheduleCount > 0 ||
    row.linkedInspectionCount > 0);
  const identifiers = (items: PrivacyImportAssessment[]) =>
    items.map(row => row.importId);
  const gates: PrivacyGate[] = [
    gate("RETENTION_APPROVAL", false,
      "A formal retention policy requires independent human approval.",
      imports.length, null,
      "Configuration parameters are not evidence of legal, organizational or DPO approval.",
      identifiers(imports), "REVIEW"),
    gate("ACTIVE_INVENTORY_AGE", aged.length === 0,
      "Active inventory snapshots should remain within declared retention age.",
      aged.length, 0,
      "Outdated active snapshots need an operational necessity decision.",
      identifiers(aged)),
    gate("RETIRED_SNAPSHOT_AGE", mature.length === 0,
      "Retired snapshots that satisfy purge eligibility require operator review.",
      mature.length, 0,
      "The automated report may only recommend an independent purge preview.",
      identifiers(mature), "REVIEW"),
    gate("HOSTNAME_PII", host.length === 0,
      "Hostnames may contain directly or indirectly identifying values.",
      host.reduce((n, row) => n + row.hostnameCount, 0), 0,
      "Removing direct owners does not make hostname data anonymous.",
      identifiers(host), policy.requireHostnameReview ? "REVIEW" : "PASS"),
    gate("OWNER_HASH_PII", owner.length === 0,
      "Owner hashes remain pseudonymous identifiers and require disposal review.",
      owner.reduce((n, row) => n + row.ownerHashCount, 0), 0,
      "Tenant-salted identifiers must not be treated as anonymous.",
      identifiers(owner), policy.requireOwnerHashDisposalReview ? "REVIEW" : "PASS"),
    gate("HISTORIC_INSPECTIONS", oldEvidence.length === 0,
      "Historic provider inspection evidence may outlive its intended purpose.",
      oldEvidence.length, 0,
      "Historical inspections are not a source of current endpoint security assurance.",
      identifiers(oldEvidence), "REVIEW"),
    gate("AUDIT_LINKAGE", data.auditRecords >= data.auditWithUser &&
      data.auditRecords >= data.auditWithResource,
      "Audit linkage counters must be bounded by the complete audit collection.",
      data.auditRecords, data.auditWithUser + data.auditWithResource,
      "Audit records can contain user IDs and resource references even after snapshot retirement.",
      [], "BLOCK"),
    gate("CASE_RETENTION", oldCase.length === 0,
      "Human review cases and notes require defined retention windows.",
      oldCase.length, 0,
      "A completed task does not imply the associated personal data may be retained indefinitely.",
      identifiers(oldCase),
      policy.requireCaseDataRetentionReview ? "REVIEW" : "PASS"),
    gate("BACKUP_PROCESS", false,
      "Backup deletion and recovery boundaries need a validated operational procedure.",
      0, 1,
      "Deleting rows in PostgreSQL is not proof of deleting copies from backups or exports.",
      identifiers(imports),
      policy.requireBackupDeletionProcedure ? "REVIEW" : "PASS"),
    gate("PURGE_DEPENDENCIES", bad.length === 0,
      "Purge candidates must be internally coherent and linked data assessed.",
      bad.length, 0,
      "Purge is a separate authorized transaction with idempotency and explicit confirmation.",
      identifiers(bad)),
    gate("SCOPE_COMPLETENESS", data.totalImports === data.imports.length,
      "Every import in the selected organization was included.",
      data.imports.length, data.totalImports,
      "Partial coverage must not be presented as acceptance.",
      []),
    gate("DECLARATION_SCOPE", true,
      "Imported assets and OSV inspections remain customer-declared and bounded evidence.",
      data.totalImports, null,
      "This report does not know all managed endpoints or determine lawful processing grounds.",
      []),
  ];
  const blocked = gates.filter(row => row.severity === "BLOCK").length;
  const reviewNeeded = gates.filter(row => row.severity === "REVIEW").length;
  const procedure: PrivacyReadinessReport["procedure"] = [
    { stage: "CLASSIFY", requiresHumanApproval: true,
      instruction: "Inventory hostname, owner hash, human note, provider report and export data classes.",
      evidenceToRetain: "Approved processing inventory with lawful purpose and ownership.",
      destructive: false },
    { stage: "APPROVE", requiresHumanApproval: true,
      instruction: "Obtain privacy and security signoff for retention durations and exceptions.",
      evidenceToRetain: "Versioned policy, approval identity, date and exception rationale.",
      destructive: false },
    { stage: "RETIRE", requiresHumanApproval: true,
      instruction: "Retire eligible active snapshots independently with compare-and-swap and audit.",
      evidenceToRetain: "Retirement event, immutable source digest and replacement snapshot.",
      destructive: false },
    { stage: "VERIFY", requiresHumanApproval: true,
      instruction: "Review unresolved cases, active schedules, linked inspections and audit references.",
      evidenceToRetain: "Dependency inventory and retention exceptions.",
      destructive: false },
    { stage: "PURGE", requiresHumanApproval: true,
      instruction: "Use the existing explicitly confirmed idempotent purge API after its dry-run.",
      evidenceToRetain: "Authorized purge request and audited completion result.",
      destructive: true },
    { stage: "BACKUP_REVIEW", requiresHumanApproval: true,
      instruction: "Validate provider-specific backup expiration, restoration and exported copy inventory.",
      evidenceToRetain: "Backup schedule, retention verification and disaster recovery approvals.",
      destructive: false },
    { stage: "CLOSE", requiresHumanApproval: true,
      instruction: "Document final data-processing decision without asserting unknown backup erasure.",
      evidenceToRetain: "Review signoff with outstanding limitations and follow-up owner.",
      destructive: false },
  ];
  const canonical = {
    schema: "cyberpilot.assets.privacy.readiness.v1" as const,
    organizationId: data.organizationId,
    evaluatedAt: data.now.toISOString(), policy,
    importedCount: data.totalImports,
    fullyExamined: data.totalImports === data.imports.length,
    totalDeviceCount: imports.reduce((n, row) => n + row.verifiedDeviceCount, 0),
    totalPotentialHostnames: imports.reduce((n, row) => n + row.hostnameCount, 0),
    totalOwnerHashes: imports.reduce((n, row) => n + row.ownerHashCount, 0),
    totalLinkedInspections: imports.reduce((n, row) => n + row.linkedInspectionCount, 0),
    totalLinkedCases: imports.reduce((n, row) => n + row.linkedCaseCount, 0),
    totalLinkedSchedules: imports.reduce((n, row) => n + row.linkedScheduleCount, 0),
    auditRecords: data.auditRecords,
    auditWithUser: data.auditWithUser,
    auditWithResource: data.auditWithResource,
    recordsWithPiiSignals: imports.filter(row => row.possiblePersonalData).length,
    activeTooOld: aged.length,
    retiredMatured: mature.length,
    openCasesBeyondPolicy: oldCase.length,
    gates, imports,
    readiness: {
      blocked, reviewNeeded,
      passed: gates.filter(row => row.severity === "PASS").length,
      pendingOperatorApproval: true,
      eligibleForPrivacySignoff: blocked === 0 && reviewNeeded === 0,
    },
    procedure,
    databasesMutated: false as const,
    personalDataErased: false as const,
    backupDeletionVerified: false as const,
    userConsentInferred: false as const,
  };
  return {
    ...canonical, digest: digest(canonical),
    warnings: [
      "This report is read-only. It neither deletes PostgreSQL records nor alters retention policy.",
      "No legal basis, privacy signoff or backup deletion can be inferred from a database query.",
      "Hostnames and owner hashes may remain personal data, depending on context.",
      "Real disposal requires independent authorization and backup recovery checks.",
      "Customer-declared CSV is not exhaustive device discovery.",
    ],
  };
}
