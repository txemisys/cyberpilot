import { db, type Prisma } from "@cyberpilot/database";
import {
  type V2Manifest, type V2ExecutiveReport,
  type V2AdapterContext, type V2AdapterObservation,
  type V2AdapterRawFinding,
  type V2Coverage, type V2Score,
  defaultV2Controls, createV2AdapterBatch,
  buildV2Intake, assembleV2Intake,
  computeV2Coverage, calculateMultiSourceCyberScoreV2,
  buildV2ExecutiveReport, verifyV2ExecutiveReport,
  exportV2Report, compareV2ExecutiveReports,
  sha256V2, canonicalV2,
} from "@cyberpilot/risk-engine";

export type V2ServiceScope = {
  organizationId: string;
  actorUserId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type V2ServiceCommand = {
  operation: "PREVIEW" | "STORE" | "READ" |
    "LIST" | "COMPARE" | "EXPORT";
  snapshotId?: string;
  baselineId?: string;
  currentId?: string;
  exportFormat?: "JSON" | "CSV" | "MARKDOWN";
  evaluatedAt?: string;
  limit?: number;
  offset?: number;
};
export type V2ServiceEnvelope = {
  schema: "cyberpilot.multisource.v2.service.v1";
  organizationId: string;
  operation: V2ServiceCommand["operation"];
  data: unknown;
  mode: "OPT_IN_OFFLINE_PREVIEW";
  liveProviderRequests: 0;
  oauthTokensStored: false;
  historicalV1ScoresModified: false;
  customerSecurityCertified: false;
  automaticSecurityActions: 0;
};
type StoredV2Row = {
  id: string;
  organizationId: string;
  snapshotId: string;
  modelId: string;
  modelRevision: number;
  evaluatedAt: Date;
  score: number | null;
  status: string;
  coveragePercent: number;
  riskPoints: number;
  verifiedControls: number;
  totalControls: number;
  manifestDigest: string;
  coverageDigest: string;
  scoreDigest: string;
  reportDigest: string;
  manifest: unknown;
  coverage: unknown;
  scoreDetails: unknown;
  report: unknown;
  sourceClass: string;
  createdById: string;
  createdAt: Date;
};
const hardLimit = 100;
function fail(message: string): never {
  throw new Error("Multi-source v2: " + message);
}
function safeId(value: unknown) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value))
    fail("Invalid scoped identifier.");
  return value;
}
function iso(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    fail("Invalid evaluation timestamp.");
  return new Date(value).toISOString();
}
function boundedInteger(value: unknown, low: number,
  high: number) {
  if (typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < low || value > high)
    fail("Invalid pagination argument.");
  return value;
}
function toJson(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}
function digest(value: unknown) {
  return sha256V2(canonicalV2(value));
}
export function parseV2ServiceCommand(
  raw: unknown,
): V2ServiceCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected operation object.");
  const x = raw as Record<string, unknown>;
  const fields = ["operation", "snapshotId",
    "baselineId", "currentId", "evaluatedAt",
    "limit", "offset", "exportFormat"];
  if (Object.keys(x).some(k => !fields.includes(k)))
    fail("Unknown operation parameter.");
  if (!["PREVIEW", "STORE", "READ", "LIST",
    "COMPARE", "EXPORT"].includes(String(x.operation)))
    fail("Unsupported v2 operation.");
  const command: V2ServiceCommand = {
    operation: x.operation as V2ServiceCommand["operation"],
  };
  if (x.snapshotId !== undefined)
    command.snapshotId = safeId(x.snapshotId);
  if (x.baselineId !== undefined)
    command.baselineId = safeId(x.baselineId);
  if (x.currentId !== undefined)
    command.currentId = safeId(x.currentId);
  if (x.evaluatedAt !== undefined)
    command.evaluatedAt = iso(x.evaluatedAt);
  if (x.limit !== undefined)
    command.limit = boundedInteger(x.limit, 1, hardLimit);
  if (x.offset !== undefined)
    command.offset = boundedInteger(x.offset, 0, 100000);
  if (x.exportFormat !== undefined) {
    if (!["JSON", "MARKDOWN", "CSV"].includes(String(x.exportFormat)))
      fail("Unsupported report format.");
    command.exportFormat = x.exportFormat as "JSON" | "CSV" | "MARKDOWN";
  }
  return command;
}
export function createSyntheticV2Assessment(
  organizationId: string,
  evaluatedAt: string,
) {
  safeId(organizationId);
  const timestamp = iso(evaluatedAt);
  const snapshotId = "v2fixture-" + sha256V2(
    organizationId + ":" + timestamp).slice(0, 28);
  const base = {
    organizationId, evaluatedAt: timestamp,
    snapshotId, authority: "cyberpilot-offline-fixture",
    sourceReference: "phase1-v2-development",
    observedSubjects: 3, expectedSubjects: 3,
    pagesRead: 1, expectedPages: 1,
    status: "COMPLETE" as const,
    providerAuthenticated: false,
    scopeAuthenticityVerified: false,
    sourceIsSynthetic: true,
    allowTechnicalProof: false,
    maxAgeDays: 30,
  };
  const ctx = (
    scope: string, kind: V2AdapterContext["scopeKind"],
    provider: string,
  ): V2AdapterContext => ({
    ...base, scope, scopeKind: kind,
    sourceDigest: sha256V2(
      organizationId + "|" + provider + "|" + timestamp),
  });
  const record = (
    id: string, controlId: string,
    domain: V2AdapterObservation["domain"],
    scope: string,
    state: V2AdapterObservation["state"] = "OBSERVED",
  ): V2AdapterObservation => ({
    schema: "cyberpilot.multisource.adapter.observation.v2",
    externalId: id,
    subjectId: "synthetic-company-scope",
    controlId, domain, scope, state,
    confidence: state === "OBSERVED" ? "MEDIUM" : "UNKNOWN",
    observedAt: state === "OBSERVED" ? timestamp : null,
    checkedAt: timestamp,
    details: { fixture: true, automatedChanges: 0 },
    provenance: "synthetic-developer-scenario-no-live-proof",
  });
  const exposureScope = ctx(
    "example.invalid", "DOMAIN", "EXPOSURE");
  const baselineScope = ctx(
    "organization", "ORGANIZATION", "BASELINE");
  const assetsScope = ctx(
    "organization", "ORGANIZATION", "ASSETS");
  const web = createV2AdapterBatch(
    "EXPOSURE", exposureScope, [
      record("offline-web-tls", "WEB_TLS",
        "WEB", "example.invalid"),
      record("offline-web-headers",
        "WEB_SECURITY_HEADERS", "WEB",
        "example.invalid", "UNKNOWN"),
    ]);
  const baseline = createV2AdapterBatch(
    "BASELINE", baselineScope, [
      record("offline-backup-policy",
        "BACKUP_POLICY", "BACKUP",
        "organization", "DECLARED"),
      record("offline-incident-plan",
        "GOVERNANCE_INCIDENT_PLAN", "GOVERNANCE",
        "organization", "DECLARED"),
      record("offline-training",
        "GOVERNANCE_SECURITY_TRAINING", "GOVERNANCE",
        "organization", "UNKNOWN"),
    ]);
  const assetsObservation = record(
    "offline-device-patches", "ENDPOINT_PATCH_POSTURE",
    "ENDPOINT", "organization");
  const assets = createV2AdapterBatch(
    "ASSETS", assetsScope, [
      record("offline-device-inventory",
        "ENDPOINT_DEVICE_INVENTORY", "ENDPOINT",
        "organization"),
      assetsObservation,
    ], [{
      id: "offline-patch-finding",
      sourceId: assetsObservation.externalId,
      ruleId: "PATCH_REVIEW_REQUIRED",
      controlId: "ENDPOINT_PATCH_POSTURE",
      domain: "ENDPOINT",
      severity: "HIGH",
      state: "POTENTIAL_RISK",
      title: "Potentially unpatched device inventory",
      explanation: "This example is simulated and requires customer evidence.",
      remediation: "Verify actual software inventory and patch status.",
      subjectId: assetsObservation.subjectId,
      observedAt: timestamp,
      confidence: "LOW",
    } satisfies V2AdapterRawFinding]);
  const intake = buildV2Intake({
    ...base, scope: "organization",
    scopeKind: "ORGANIZATION",
    sourceDigest: sha256V2(organizationId + timestamp),
  }, [web, baseline, assets], defaultV2Controls());
  const result = assembleV2Intake(intake);
  const manifest = result.manifest;
  const coverage = computeV2Coverage(manifest);
  const score = calculateMultiSourceCyberScoreV2(manifest);
  const report = buildV2ExecutiveReport(manifest);
  if (!verifyV2ExecutiveReport(report, manifest).verified ||
      score.score !== null ||
      coverage.verifiedControls !== 0)
    fail("Synthetic assessment attempted to infer live security.");
  return {
    manifest, coverage, score, report,
    sourceClass: "SYNTHETIC_FIXTURE" as const,
    legacyV1Updated: false as const,
    customerApproved: false as const,
  };
}
function inspectStored(row: StoredV2Row) {
  const manifest = row.manifest as V2Manifest;
  const coverage = row.coverage as V2Coverage;
  const score = row.scoreDetails as V2Score;
  const report = row.report as V2ExecutiveReport;
  const problems: string[] = [];
  if (manifest.organizationId !== row.organizationId ||
      manifest.snapshotId !== row.snapshotId ||
      manifest.modelId !== row.modelId ||
      score.organizationId !== row.organizationId ||
      report.organizationId !== row.organizationId ||
      coverage.organizationId !== row.organizationId)
    problems.push("TENANT_OR_SNAPSHOT_SCOPE");
  if (row.modelId !== "cyberpilot.multisource.v2" ||
      row.modelRevision !== 1 ||
      row.sourceClass !== "SYNTHETIC_FIXTURE")
    problems.push("UNSUPPORTED_MODEL_OR_SOURCE");
  if (digest(manifest) !== row.manifestDigest ||
      digest(coverage) !== row.coverageDigest ||
      digest(score) !== row.scoreDigest ||
      report.digest !== row.reportDigest ||
      !verifyV2ExecutiveReport(report, manifest).verified)
    problems.push("DIGEST_OR_REPORT_INTEGRITY");
  if (score.score !== row.score ||
      coverage.coveragePercent !== row.coveragePercent ||
      score.riskPoints !== row.riskPoints ||
      coverage.verifiedControls !== row.verifiedControls ||
      coverage.totalControls !== row.totalControls)
    problems.push("INDEXED_METRICS_INCONSISTENT");
  if (score.legacyCyberScoreRecomputed ||
      score.eligibleForProductHealthBadge ||
      report.customerApprovalAttested ||
      report.historicalCyberScoreModified)
    problems.push("FALSE_APPROVAL_OR_V1_RECOMPUTATION");
  if (problems.length)
    fail("Persisted v2 data failed validation: " +
      problems.join(","));
  return { manifest, coverage, score, report };
}
function storedSummary(row: StoredV2Row) {
  inspectStored(row);
  return {
    organizationId: row.organizationId,
    snapshotId: row.snapshotId,
    modelId: row.modelId, modelRevision: row.modelRevision,
    evaluatedAt: row.evaluatedAt.toISOString(),
    numericScore: row.score,
    coveragePercent: row.coveragePercent,
    status: row.status, riskPoints: row.riskPoints,
    verifiedControls: row.verifiedControls,
    totalControls: row.totalControls,
    manifestDigest: row.manifestDigest,
    reportDigest: row.reportDigest,
    sourceClass: row.sourceClass,
    customerApproved: false as const,
    v1ScoreChanged: false as const,
  };
}
async function authorize(scope: V2ServiceScope,
  write = false) {
  safeId(scope.organizationId);
  safeId(scope.actorUserId);
  if (!["OWNER", "ADMIN", "MEMBER",
    "AUDITOR"].includes(scope.role))
    fail("Unknown organization role.");
  const member = await db.membership.findFirst({
    where: {
      organizationId: scope.organizationId,
      userId: scope.actorUserId,
    }, select: { id: true, role: true },
  });
  if (!member || member.role !== scope.role)
    fail("Current organization membership is required.");
  if (write && !["OWNER", "ADMIN"].includes(member.role))
    fail("Writing v2 assessments requires organization admin.");
}
async function read(scope: V2ServiceScope, snapshotId: string) {
  const row = await db.multiSourceV2Assessment.findFirst({
    where: {
      organizationId: scope.organizationId,
      snapshotId,
    },
  });
  if (!row)
    fail("Snapshot not found in this organization.");
  return row;
}
export class MultiSourceV2AssessmentService {
  async execute(
    scope: V2ServiceScope, raw: unknown,
  ): Promise<V2ServiceEnvelope> {
    const command = parseV2ServiceCommand(raw);
    await authorize(scope, command.operation === "STORE");
    const data = await this.dispatch(scope, command);
    return {
      schema: "cyberpilot.multisource.v2.service.v1",
      organizationId: scope.organizationId,
      operation: command.operation,
      data, mode: "OPT_IN_OFFLINE_PREVIEW",
      liveProviderRequests: 0,
      oauthTokensStored: false,
      historicalV1ScoresModified: false,
      customerSecurityCertified: false,
      automaticSecurityActions: 0,
    };
  }
  private async dispatch(
    scope: V2ServiceScope, command: V2ServiceCommand,
  ): Promise<unknown> {
    switch (command.operation) {
      case "PREVIEW": {
        const result = createSyntheticV2Assessment(
          scope.organizationId,
          command.evaluatedAt ?? new Date().toISOString());
        return {
          report: result.report, coverage: result.coverage,
          score: result.score, snapshotId: result.manifest.snapshotId,
          previewOnly: true, providerLIVEValidated: false,
          sourceClass: "SYNTHETIC_FIXTURE",
        };
      }
      case "STORE": {
        const result = createSyntheticV2Assessment(
          scope.organizationId,
          command.evaluatedAt ?? new Date().toISOString());
        const existing = await db.multiSourceV2Assessment.findFirst({
          where: {
            organizationId: scope.organizationId,
            snapshotId: result.manifest.snapshotId,
          },
        });
        if (existing) {
          if (existing.manifestDigest !== digest(result.manifest))
            fail("Snapshot ID collision with different evidence.");
          return { summary: storedSummary(existing),
            created: false, legacyV1WriteCount: 0 };
        }
        const created = await db.$transaction(async tx => {
          const row = await tx.multiSourceV2Assessment.create({
            data: {
              organizationId: scope.organizationId,
              snapshotId: result.manifest.snapshotId,
              modelId: result.score.modelId,
              modelRevision: result.score.modelRevision,
              evaluatedAt: new Date(result.manifest.evaluatedAt),
              score: result.score.score,
              status: result.score.status,
              coveragePercent: result.coverage.coveragePercent,
              riskPoints: result.score.riskPoints,
              verifiedControls: result.coverage.verifiedControls,
              totalControls: result.coverage.totalControls,
              manifestDigest: digest(result.manifest),
              coverageDigest: digest(result.coverage),
              scoreDigest: digest(result.score),
              reportDigest: result.report.digest,
              manifest: toJson(result.manifest),
              coverage: toJson(result.coverage),
              scoreDetails: toJson(result.score),
              report: toJson(result.report),
              sourceClass: "SYNTHETIC_FIXTURE",
              createdById: scope.actorUserId,
            },
          });
          await tx.auditEvent.create({
            data: {
              organizationId: scope.organizationId,
              actorType: "USER",
              actorUserId: scope.actorUserId,
              action: "MULTISOURCE_V2_FIXTURE_STORED",
              resourceType: "MULTISOURCE_V2_ASSESSMENT",
              resourceId: row.id,
              metadata: {
                modelId: result.score.modelId,
                snapshotId: result.manifest.snapshotId,
                reportDigest: result.report.digest,
                manifestDigest: digest(result.manifest),
                sourceClass: "SYNTHETIC_FIXTURE",
                customerApproval: false,
                providerRequests: 0,
                legacyScoreWrites: 0,
              },
              occurredAt: new Date(result.manifest.evaluatedAt),
            },
          });
          return row;
        }, { isolationLevel: "Serializable" });
        return { summary: storedSummary(created),
          created: true, legacyV1WriteCount: 0 };
      }
      case "LIST": {
        const rows = await db.multiSourceV2Assessment.findMany({
          where: { organizationId: scope.organizationId },
          orderBy: [{ evaluatedAt: "desc" }, { id: "asc" }],
          skip: command.offset ?? 0,
          take: command.limit ?? 20,
        });
        return {
          items: rows.map(storedSummary),
          offset: command.offset ?? 0,
          limit: command.limit ?? 20,
          otherTenantsIncluded: false,
          legacyScoreRead: false,
        };
      }
      case "READ": {
        if (!command.snapshotId)
          fail("Snapshot identifier is required.");
        const row = await read(scope, command.snapshotId);
        return { summary: storedSummary(row),
          report: inspectStored(row).report,
          providerLIVEValidated: false,
          customerApprovalProven: false };
      }
      case "EXPORT": {
        if (!command.snapshotId)
          fail("Snapshot identifier is required.");
        const row = await read(scope, command.snapshotId);
        return exportV2Report(
          inspectStored(row).report,
          command.exportFormat ?? "JSON");
      }
      case "COMPARE": {
        if (!command.baselineId || !command.currentId ||
            command.baselineId === command.currentId)
          fail("Comparison needs two different snapshot identifiers.");
        const before = await read(scope, command.baselineId);
        const after = await read(scope, command.currentId);
        return {
          trend: compareV2ExecutiveReports(
            inspectStored(before).report,
            inspectStored(after).report),
          sameOrganization: true, verifiedRemediation: false,
          historicalV1Recalculated: false,
        };
      }
    }
  }
}
