import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
  assessGoogleWorkspace, buildGoogleExecutiveReport,
  verifyGoogleRiskAssessment, verifyGoogleExecutiveReport,
  verifyObservation, diffGoogleReports, verifyGoogleReportDiff,
  buildGoogleHistory, verifyGoogleHistory,
  type GoogleDirectoryObservation, type GoogleRiskAssessment,
  type GoogleReportExport, type GoogleReportDiff,
  type GoogleLabScope,
  GoogleLabError,
} from "@cyberpilot/integrations/google-workspace";
import { PrismaGoogleLabRepository } from "./google-lab-prisma-repository";

export type GoogleOfflineSnapshotInput = {
  connectionId: string;
  observation: GoogleDirectoryObservation;
  retentionDays: number;
  expectedConnectionRevision: number;
  createdAt: string;
};
export type GoogleSnapshotSummary = {
  id: string;
  connectionId: string;
  organizationId: string;
  sourceDigest: string;
  assessmentDigest: string;
  reportDigest: string;
  createdAt: string;
  observedAt: string;
  expiresAt: string;
  sourceType: "SYNTHETIC_FIXTURE";
  findingCount: number;
  unknownCount: number;
  riskCount: number;
  identityCount: number;
  scope: "OFFLINE_LAB_ONLY";
  providerLiveValidated: false;
};
export type GoogleSnapshotListOptions = {
  connectionId: string;
  offset: number;
  limit: number;
  includeExpired: boolean;
  onlyWithRisks: boolean;
};
export type GoogleSnapshotRetentionPlan = {
  schema: "cyberpilot.google.snapshot.retention.v1";
  organizationId: string;
  observedAt: string;
  retentionDays: number;
  eligibleToPurgeRows: number;
  notYetEligibleRows: number;
  proposedIds: string[];
  sourceDigests: string[];
  backupErasureProven: false;
  databaseRowsDeleted: 0;
  legalRetentionPolicyAccepted: false;
  customerExportsPurged: false;
  automaticDestructiveActionEnabled: false;
  digest: string;
};
export type GoogleSnapshotAudit = {
  schema: "cyberpilot.google.snapshot.audit.v1";
  organizationId: string;
  snapshotId: string;
  connectionId: string;
  sourceDigest: string;
  reportDigest: string;
  assessmentDigest: string;
  linked: boolean;
  digestConsistent: boolean;
  scopeConsistent: boolean;
  expired: boolean;
  ageDays: number;
  issues: string[];
  validated: boolean;
  inspectedAt: string;
  providerLiveRevalidated: false;
  legalAcceptanceProven: false;
  digest: string;
};
export type GoogleSnapshotTrend = {
  schema: "cyberpilot.google.snapshot.trend.v1";
  organizationId: string;
  connectionId: string;
  baselineSnapshotId: string;
  currentSnapshotId: string;
  beforeDigest: string;
  afterDigest: string;
  diff: GoogleReportDiff;
  changedFindings: number;
  noRiskRemediationProven: true;
  realGoogleProviderValidated: false;
  cyberScoreRecomputed: false;
  evidenceScope: "TENANT_SCOPED_OFFLINE_SNAPSHOTS";
  digest: string;
};
const LIMITS = {
  minRetentionDays: 1, maxRetentionDays: 365,
  maxRowsPerOrganization: 10000,
  maxSnapshotJsonBytes: 1048576,
  maxListLimit: 100,
  maxAuditHistory: 100,
};
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function eq(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function invalid(message: string): never {
  throw new GoogleLabError("INVALID", message);
}
function conflict(message: string): never {
  throw new GoogleLabError("CONFLICT", message);
}
function requireScoped(scope: GoogleLabScope, manage = false) {
  if (!scope || typeof scope.organizationId !== "string" ||
      typeof scope.actorUserId !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(scope.organizationId) ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(scope.actorUserId))
    invalid("Invalid snapshot scope.");
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role))
    throw new GoogleLabError("FORBIDDEN", "Unknown organization role.");
  if (manage && !["OWNER", "ADMIN"].includes(scope.role))
    throw new GoogleLabError("FORBIDDEN",
      "Snapshot writes require an organization administrator.");
}
function identity(x: unknown, label: string) {
  if (typeof x !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(x))
    invalid("Invalid snapshot " + label + ".");
  return x;
}
function date(x: unknown, label: string) {
  if (typeof x !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(x) ||
      !Number.isFinite(Date.parse(x)))
    invalid("Invalid UTC snapshot " + label + ".");
  return new Date(x).toISOString();
}
function integer(x: unknown, name: string, lo: number, hi: number) {
  if (typeof x !== "number" ||
      !Number.isSafeInteger(x) || x < lo || x > hi)
    invalid("Invalid integer snapshot " + name + ".");
  return x;
}
function json(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}
export function parseGoogleSnapshotInput(raw: unknown) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    invalid("Snapshot input must be an object.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(key => ![
    "connectionId", "observation", "retentionDays",
    "expectedConnectionRevision", "createdAt",
  ].includes(key)))
    invalid("Unexpected Google snapshot input.");
  return {
    connectionId: identity(x.connectionId, "connection ID"),
    observation: x.observation as GoogleDirectoryObservation,
    retentionDays: integer(x.retentionDays,
      "retentionDays", LIMITS.minRetentionDays,
      LIMITS.maxRetentionDays),
    expectedConnectionRevision: integer(
      x.expectedConnectionRevision,
      "expected revision", 1, 10000),
    createdAt: date(x.createdAt, "creation timestamp"),
  } satisfies GoogleOfflineSnapshotInput;
}
export function parseGoogleSnapshotList(raw: unknown): GoogleSnapshotListOptions {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    invalid("Snapshot list options must be an object.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(key => ![
    "connectionId", "offset", "limit", "includeExpired",
    "onlyWithRisks",
  ].includes(key)))
    invalid("Unexpected snapshot filter.");
  if (x.includeExpired !== undefined &&
      typeof x.includeExpired !== "boolean" ||
      x.onlyWithRisks !== undefined &&
      typeof x.onlyWithRisks !== "boolean")
    invalid("Invalid snapshot filter switch.");
  return {
    connectionId: identity(x.connectionId, "connection ID"),
    offset: integer(x.offset ?? 0, "offset", 0, 100000),
    limit: integer(x.limit ?? 20, "limit", 1, LIMITS.maxListLimit),
    includeExpired: x.includeExpired === true,
    onlyWithRisks: x.onlyWithRisks === true,
  };
}
export function validateGoogleOfflineObservation(
  scope: GoogleLabScope,
  observation: GoogleDirectoryObservation,
  now: string,
) {
  requireScoped(scope, true);
  const timestamp = date(now, "evaluation time");
  const issues: string[] = [];
  if (!observation || !verifyObservation(observation).valid)
    issues.push("INVALID_SOURCE_DIGEST");
  if (observation?.organizationId !== scope.organizationId)
    issues.push("TENANT_ID_MISMATCH");
  if (observation?.source !== "SYNTHETIC_FIXTURE")
    issues.push("REAL_PROVIDER_NOT_ALLOWED_IN_OFFLINE_SNAPSHOT");
  if (observation?.liveProviderVerified ||
      observation?.securityCertified ||
      observation?.fullTenantCoverageClaimed)
    issues.push("UNSUPPORTED_PROVIDER_CLAIM");
  if (observation && observation.generatedAt > timestamp)
    issues.push("OBSERVATION_TIME_IN_FUTURE");
  if (observation && observation.unknownCapabilities.length === 0 &&
      observation.users.length === 0 &&
      observation.domains.length === 0)
    issues.push("EMPTY_PROVIDER_COVERAGE_NOT_ACCEPTABLE");
  return { valid: issues.length === 0, issues,
    readOnlyValidation: true,
    externalProviderValidated: false,
  };
}
export function assessPersistableGoogleSnapshot(
  scope: GoogleLabScope, input: GoogleOfflineSnapshotInput,
) {
  const validation = validateGoogleOfflineObservation(
    scope, input.observation, input.createdAt);
  if (!validation.valid)
    conflict("Offline source cannot be persisted: " +
      validation.issues.join(","));
  const now = new Date(input.createdAt);
  const assessment = assessGoogleWorkspace(
    input.observation, { referenceDate: now.toISOString() }, now);
  const report = buildGoogleExecutiveReport(assessment);
  if (!verifyGoogleRiskAssessment(assessment).valid ||
      !verifyGoogleExecutiveReport(report).valid)
    conflict("Google snapshot report does not verify.");
  const canonical = {
    sourceDigest: input.observation.digest,
    assessmentDigest: assessment.digest,
    reportDigest: report.machineReadableJsonDigest,
    retentionDays: input.retentionDays,
    connectionId: input.connectionId,
    organizationId: scope.organizationId,
    createdAt: input.createdAt,
  };
  const payloadBytes = Buffer.byteLength(
    JSON.stringify({ assessment, report }), "utf8");
  if (payloadBytes > LIMITS.maxSnapshotJsonBytes)
    throw new GoogleLabError("INVALID",
      "Offline Google snapshot exceeds the 1 MiB storage bound.");
  return {
    assessment, report,
    snapshotFingerprint: sha(canonical),
    payloadBytes,
    sourceDigest: input.observation.digest,
    assessmentDigest: assessment.digest,
    reportDigest: report.machineReadableJsonDigest,
    observedAt: input.createdAt,
    expiresAt: new Date(
      now.getTime() + input.retentionDays * 86400000).toISOString(),
    storageEncryptedByApplication: false as const,
    requiresDatabaseEncryptionAtRest: true as const,
    oauthTokensStored: false as const,
    rawSourceEmailStored: false as const,
    destructiveActionPerformed: false as const,
  };
}
type StoredSnapshot = {
  id: string;
  organizationId: string;
  connectionId: string;
  sourceDigest: string;
  assessmentDigest: string;
  reportDigest: string;
  schemaVersion: number;
  sourceType: string;
  observedAt: Date;
  expiresAt: Date;
  assessment: unknown;
  report: unknown;
  createdById: string;
  createdAt: Date;
};
function checked(row: StoredSnapshot) {
  const assessment = row.assessment as GoogleRiskAssessment;
  const report = row.report as GoogleReportExport;
  const issues: string[] = [];
  if (row.schemaVersion !== 1 ||
      row.sourceType !== "SYNTHETIC_FIXTURE")
    issues.push("UNSUPPORTED_SCHEMA_OR_SOURCE");
  if (assessment.organizationId !== row.organizationId ||
      report.organizationId !== row.organizationId ||
      assessment.sourceDigest !== row.sourceDigest ||
      report.assessmentSourceDigest !== row.sourceDigest)
    issues.push("SCOPE_OR_SOURCE_MISMATCH");
  if (assessment.digest !== row.assessmentDigest ||
      report.machineReadableJsonDigest !== row.reportDigest ||
      report.assessmentDigest !== row.assessmentDigest)
    issues.push("PERSISTED_DIGEST_MISMATCH");
  if (!verifyGoogleRiskAssessment(assessment).valid ||
      !verifyGoogleExecutiveReport(report).valid)
    issues.push("INVALID_REPORT_OR_ASSESSMENT");
  if (row.expiresAt <= row.observedAt)
    issues.push("NONPOSITIVE_RETENTION_WINDOW");
  if (issues.length)
    conflict("Google snapshot persisted integrity failure: " +
      issues.join(","));
  return { assessment, report };
}
function summary(row: StoredSnapshot): GoogleSnapshotSummary {
  const { assessment } = checked(row);
  return {
    id: row.id, connectionId: row.connectionId,
    organizationId: row.organizationId,
    sourceDigest: row.sourceDigest,
    assessmentDigest: row.assessmentDigest,
    reportDigest: row.reportDigest,
    createdAt: row.createdAt.toISOString(),
    observedAt: row.observedAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    sourceType: "SYNTHETIC_FIXTURE",
    findingCount: assessment.findings.length,
    unknownCount: assessment.counts.unknownFindings,
    riskCount: assessment.counts.possibleRisks,
    identityCount: assessment.counts.usersSeen,
    scope: "OFFLINE_LAB_ONLY",
    providerLiveValidated: false,
  };
}
async function checkAuthorizedMember(scope: GoogleLabScope,
  manager = false) {
  requireScoped(scope, manager);
  const membership = await db.membership.findFirst({
    where: {
      organizationId: scope.organizationId,
      userId: scope.actorUserId,
      ...(manager ? { role: { in: ["ADMIN", "OWNER"] as const } } : {}),
    },
    select: { id: true, role: true },
  });
  if (!membership)
    throw new GoogleLabError("FORBIDDEN",
      "Snapshot user is not a current tenant member.");
}
export async function persistGoogleOfflineSnapshot(
  scope: GoogleLabScope, raw: unknown,
) {
  await checkAuthorizedMember(scope, true);
  const input = parseGoogleSnapshotInput(raw);
  const candidate = assessPersistableGoogleSnapshot(scope, input);
  const connection = await new PrismaGoogleLabRepository()
    .getByOrganization(scope.organizationId, input.connectionId);
  if (!connection)
    throw new GoogleLabError("MISSING",
      "Google LAB connection not found in this organization.");
  if (connection.state !== "CONNECTED_LAB" ||
      connection.revision !== input.expectedConnectionRevision ||
      !connection.expiresAt ||
      input.createdAt >= connection.expiresAt)
    conflict("Google LAB connection is inactive, expired or stale.");
  const currentCount = await db.googleEvidenceSnapshot.count({
    where: { organizationId: scope.organizationId },
  });
  if (currentCount >= LIMITS.maxRowsPerOrganization)
    conflict("Organization Google snapshot capacity reached.");
  const digestCollision = await db.googleEvidenceSnapshot.findFirst({
    where: {
      organizationId: scope.organizationId,
      connectionId: input.connectionId,
      sourceDigest: input.observation.digest,
    },
  });
  if (digestCollision) {
    const old = checked(digestCollision);
    if (old.assessment.digest !== candidate.assessment.digest ||
        old.report.machineReadableJsonDigest !== candidate.reportDigest)
      conflict("Duplicate Google snapshot source digest has different content.");
    return { summary: summary(digestCollision), created: false,
      noProviderCall: true as const,
      noRawDirectoryRecordsStored: true as const,
      noCustomerLegalApproval: true as const };
  }
  const row = await db.$transaction(async tx => {
    const liveConnection = await tx.googleLabConnection.findFirst({
      where: {
        organizationId: scope.organizationId,
        id: input.connectionId,
        revision: connection.revision,
        state: "CONNECTED_LAB",
        stateDigest: connection.stateDigest,
      },
    });
    if (!liveConnection)
      conflict("Google LAB connection changed during snapshot storage.");
    const created = await tx.googleEvidenceSnapshot.create({
      data: {
        organizationId: scope.organizationId,
        connectionId: input.connectionId,
        sourceDigest: candidate.sourceDigest,
        assessmentDigest: candidate.assessmentDigest,
        reportDigest: candidate.reportDigest,
        schemaVersion: 1,
        sourceType: "SYNTHETIC_FIXTURE",
        observedAt: new Date(candidate.observedAt),
        expiresAt: new Date(candidate.expiresAt),
        assessment: json(candidate.assessment),
        report: json(candidate.report),
        createdById: scope.actorUserId,
      },
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER",
        actorUserId: scope.actorUserId,
        action: "GOOGLE_OFFLINE_SNAPSHOT_STORED",
        resourceType: "GOOGLE_OFFLINE_SNAPSHOT",
        resourceId: created.id,
        metadata: {
          schema: "cyberpilot.google.snapshot.audit.event.v1",
          connectionId: input.connectionId,
          sourceDigest: candidate.sourceDigest,
          assessmentDigest: candidate.assessmentDigest,
          reportDigest: candidate.reportDigest,
          simulated: true, providerRequests: 0,
          customerApproval: false, rawEmailsRetained: false,
        },
        occurredAt: new Date(input.createdAt),
      },
    });
    return created;
  }, { isolationLevel: "Serializable" });
  return { summary: summary(row), created: true,
    noProviderCall: true as const,
    noRawDirectoryRecordsStored: true as const,
    noCustomerLegalApproval: true as const };
}
export async function listGoogleOfflineSnapshots(
  scope: GoogleLabScope, raw: unknown,
  at: string = new Date().toISOString(),
) {
  await checkAuthorizedMember(scope);
  const query = parseGoogleSnapshotList(raw);
  const now = date(at, "list clock");
  const rows = await db.googleEvidenceSnapshot.findMany({
    where: {
      organizationId: scope.organizationId,
      connectionId: query.connectionId,
      ...(!query.includeExpired ?
        { expiresAt: { gt: new Date(now) } } : {}),
    },
    orderBy: [{ observedAt: "desc" }, { id: "asc" }],
    skip: query.offset, take: query.limit + 1,
  });
  const records = rows.slice(0, query.limit).map(summary);
  const filtered = query.onlyWithRisks ?
    records.filter(row => row.riskCount > 0) : records;
  return {
    organizationId: scope.organizationId,
    items: filtered,
    offset: query.offset, limit: query.limit,
    nextOffset: rows.length > query.limit ?
      query.offset + query.limit : null,
    filteredCount: filtered.length,
    scannedPageCount: records.length,
    sourcePartialBecauseFilter:
      query.onlyWithRisks && filtered.length < records.length,
    liveGoogleProviderContacted: false as const,
    customerRecordsOutsideTenant: 0 as const,
  };
}
export async function readGoogleOfflineSnapshot(
  scope: GoogleLabScope, id: string,
) {
  await checkAuthorizedMember(scope);
  const snapshotId = identity(id, "snapshot ID");
  const row = await db.googleEvidenceSnapshot.findFirst({
    where: { id: snapshotId, organizationId: scope.organizationId },
  });
  if (!row)
    throw new GoogleLabError("MISSING",
      "Google snapshot not found in this organization.");
  const result = checked(row);
  return {
    metadata: summary(row),
    assessment: result.assessment, report: result.report,
    liveProviderAttested: false as const,
    sourceEmailsReturned: false as const,
    secretsReturned: false as const,
  };
}
export async function auditGoogleOfflineSnapshot(
  scope: GoogleLabScope, id: string,
  at: string = new Date().toISOString(),
): Promise<GoogleSnapshotAudit> {
  const result = await readGoogleOfflineSnapshot(scope, id);
  const timestamp = date(at, "audit timestamp");
  const source = await db.googleEvidenceSnapshot.findFirst({
    where: { id: result.metadata.id,
      organizationId: scope.organizationId },
  });
  if (!source)
    throw new GoogleLabError("MISSING", "Google snapshot vanished.");
  const issues: string[] = [];
  const connection = await db.googleLabConnection.findFirst({
    where: { id: source.connectionId,
      organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!connection)
    issues.push("SOURCE_CONNECTION_NOT_FOUND");
  const related = await db.auditEvent.findFirst({
    where: {
      organizationId: scope.organizationId,
      action: "GOOGLE_OFFLINE_SNAPSHOT_STORED",
      resourceId: source.id,
    }, orderBy: { occurredAt: "desc" },
  });
  if (!related) issues.push("SNAPSHOT_AUDIT_EVENT_MISSING");
  const verified = verifyGoogleRiskAssessment(result.assessment).valid &&
    verifyGoogleExecutiveReport(result.report).valid;
  if (!verified)
    issues.push("SOURCE_DIGEST_INVALID");
  const scopeConsistent =
    result.assessment.organizationId === scope.organizationId &&
    result.report.organizationId === scope.organizationId;
  if (!scopeConsistent)
    issues.push("CROSS_TENANT_EVIDENCE");
  const canonical = {
    schema: "cyberpilot.google.snapshot.audit.v1" as const,
    organizationId: scope.organizationId,
    snapshotId: source.id,
    connectionId: source.connectionId,
    sourceDigest: source.sourceDigest,
    reportDigest: source.reportDigest,
    assessmentDigest: source.assessmentDigest,
    linked: !!connection && !!related,
    digestConsistent: verified, scopeConsistent,
    expired: source.expiresAt <= new Date(timestamp),
    ageDays: Math.max(0, Math.floor(
      (Date.parse(timestamp) - source.observedAt.getTime()) / 86400000)),
    issues, validated: issues.length === 0,
    inspectedAt: timestamp,
    providerLiveRevalidated: false as const,
    legalAcceptanceProven: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export async function diffStoredGoogleSnapshots(
  scope: GoogleLabScope, baselineId: string,
  currentId: string,
): Promise<GoogleSnapshotTrend> {
  const before = await readGoogleOfflineSnapshot(scope, baselineId);
  const after = await readGoogleOfflineSnapshot(scope, currentId);
  if (before.metadata.connectionId !== after.metadata.connectionId)
    conflict("Cannot compare Google evidence from different LAB connections.");
  const diff = diffGoogleReports(before.report, after.report);
  if (!verifyGoogleReportDiff(diff).valid)
    conflict("Google snapshot comparison is inconsistent.");
  const canonical = {
    schema: "cyberpilot.google.snapshot.trend.v1" as const,
    organizationId: scope.organizationId,
    connectionId: before.metadata.connectionId,
    baselineSnapshotId: baselineId,
    currentSnapshotId: currentId,
    beforeDigest: before.metadata.reportDigest,
    afterDigest: after.metadata.reportDigest,
    diff, changedFindings:
      diff.findingsAdded.length + diff.findingsRemovedFromSnapshot.length,
    noRiskRemediationProven: true as const,
    realGoogleProviderValidated: false as const,
    cyberScoreRecomputed: false as const,
    evidenceScope: "TENANT_SCOPED_OFFLINE_SNAPSHOTS" as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export async function inspectGoogleSnapshotRetention(
  scope: GoogleLabScope, at: string,
  limit = 100,
): Promise<GoogleSnapshotRetentionPlan> {
  await checkAuthorizedMember(scope, true);
  const clock = date(at, "retention timestamp");
  integer(limit, "retention rows", 1, 500);
  const rows = await db.googleEvidenceSnapshot.findMany({
    where: { organizationId: scope.organizationId },
    orderBy: [{ expiresAt: "asc" }, { id: "asc" }],
    take: limit,
  });
  const eligible = rows.filter(row => row.expiresAt <= new Date(clock));
  const canonical = {
    schema: "cyberpilot.google.snapshot.retention.v1" as const,
    organizationId: scope.organizationId,
    observedAt: clock, retentionDays: 0,
    eligibleToPurgeRows: eligible.length,
    notYetEligibleRows: rows.length - eligible.length,
    proposedIds: eligible.map(row => row.id),
    sourceDigests: eligible.map(row => row.sourceDigest),
    backupErasureProven: false as const,
    databaseRowsDeleted: 0 as const,
    legalRetentionPolicyAccepted: false as const,
    customerExportsPurged: false as const,
    automaticDestructiveActionEnabled: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyGoogleRetentionPlan(plan: GoogleSnapshotRetentionPlan) {
  const { digest, ...canonical } = plan;
  const issues: string[] = [];
  if (!eq(digest, sha(canonical)))
    issues.push("Plan contents were altered.");
  if (plan.databaseRowsDeleted !== 0 ||
      plan.backupErasureProven ||
      plan.legalRetentionPolicyAccepted ||
      plan.customerExportsPurged ||
      plan.automaticDestructiveActionEnabled)
    issues.push("Retention plan claims unsupported deletion or approval.");
  if (plan.eligibleToPurgeRows !== plan.proposedIds.length)
    issues.push("Retention candidate count inconsistent.");
  return { valid: issues.length === 0, issues };
}
export async function buildGoogleStoredHistory(
  scope: GoogleLabScope, connectionId: string,
  maxRows = 50,
) {
  await checkAuthorizedMember(scope);
  identity(connectionId, "connection ID");
  integer(maxRows, "history limit", 1, LIMITS.maxAuditHistory);
  const rows = await db.googleEvidenceSnapshot.findMany({
    where: { organizationId: scope.organizationId, connectionId },
    orderBy: [{ observedAt: "asc" }, { id: "asc" }],
    take: maxRows,
  });
  if (!rows.length)
    return { organizationId: scope.organizationId,
      reportsAvailable: 0, history: null,
      cannotAssertNoRisk: true as const };
  const reports = rows.map(row => checked(row).report);
  const history = buildGoogleHistory(reports);
  if (!verifyGoogleHistory(history).valid)
    conflict("Google stored history verification failed.");
  return {
    organizationId: scope.organizationId,
    reportsAvailable: rows.length, history,
    cannotAssertNoRisk: true as const,
  };
}
