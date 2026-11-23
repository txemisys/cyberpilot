import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { validateIncidentSnapshot, incidentDigest,
  type IncidentSnapshot } from "./incident-case-domain";
import { reviewIncidentIntegratedEvidence } from "./incident-integrated-evidence-service";
import { readIncidentAssetImpact } from "./incident-integrated-assets-service";
import { reviewIncidentRemediationIntegration } from "./incident-integrated-remediation-service";
import { buildIncidentSituation, type SituationInput,
  type SituationSourceState } from "./incident-situation-domain";
export class SituationServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new SituationServiceError(code); }
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
export type SituationSelection = {
  incidentId: string;
  evidence: { evidenceIds: string[]; findingIds: string[];
    decisionIds: string[]; maxAgeHours?: number } | null;
  assets: { deviceIds: string[]; importIds: string[];
    externalIds: string[]; freshnessHours?: number } | null;
  remediation: { remediationIds: string[]; findingIds: string[];
    workItemIds: string[]; approvalMaxAgeHours?: number } | null;
  consistency: "FAIL_CLOSED" | "PARTIAL_READ";
};
async function authorize(actor: IncidentActor) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("SITUATION_REVIEW_ROLE_DENIED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("SITUATION_MEMBERSHIP_REVOKED");
}
async function snapshot(actor: IncidentActor, incidentId: string) {
  if (!ident(incidentId)) fail("SITUATION_INCIDENT_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { id: incidentId, organizationId: actor.organizationId },
    select: { id: true, organizationId: true, revision: true,
      status: true, snapshot: true, snapshotDigest: true },
  });
  if (!row) fail("SITUATION_NOT_IN_TENANT");
  const source = row.snapshot as unknown as IncidentSnapshot;
  if (!source || validateIncidentSnapshot(source).length ||
      source.id !== row.id ||
      source.organizationId !== row.organizationId ||
      source.revision !== row.revision || source.status !== row.status ||
      incidentDigest(source) !== row.snapshotDigest)
    fail("SITUATION_SNAPSHOT_INTEGRITY_INVALID");
  return source;
}
function assertSelection(x: SituationSelection) {
  if (!ident(x.incidentId) ||
      !["FAIL_CLOSED", "PARTIAL_READ"].includes(x.consistency))
    fail("SITUATION_REQUEST_INVALID");
  if (x.evidence !== null && (typeof x.evidence !== "object" ||
      !Array.isArray(x.evidence.evidenceIds) ||
      !Array.isArray(x.evidence.findingIds) ||
      !Array.isArray(x.evidence.decisionIds)))
    fail("SITUATION_EVIDENCE_SELECTION_INVALID");
  if (x.assets !== null && (typeof x.assets !== "object" ||
      !Array.isArray(x.assets.deviceIds) ||
      !Array.isArray(x.assets.importIds) ||
      !Array.isArray(x.assets.externalIds)))
    fail("SITUATION_ASSET_SELECTION_INVALID");
  if (x.remediation !== null && (typeof x.remediation !== "object" ||
      !Array.isArray(x.remediation.remediationIds) ||
      !Array.isArray(x.remediation.findingIds) ||
      !Array.isArray(x.remediation.workItemIds)))
    fail("SITUATION_REMEDIATION_SELECTION_INVALID");
}
type Collected = {
  evidence: Awaited<ReturnType<typeof reviewIncidentIntegratedEvidence>> | null;
  assets: Awaited<ReturnType<typeof readIncidentAssetImpact>> | null;
  remediation: Awaited<ReturnType<typeof reviewIncidentRemediationIntegration>> | null;
};
export async function readIncidentSituation(actor: IncidentActor,
  selection: SituationSelection,
) {
  await authorize(actor);
  assertSelection(selection);
  const initial = await snapshot(actor, selection.incidentId);
  const collected: Collected = { evidence: null, assets: null, remediation: null };
  const states: SituationInput["sourceStates"] = {
    evidence: "ABSENT", assets: "ABSENT", remediation: "ABSENT",
  };
  const sourceFailures: Array<{ source: string; code: string }> = [];
  async function collect<K extends keyof Collected>(key: K,
    promise: Promise<NonNullable<Collected[K]>>,
  ) {
    try {
      const value = await promise;
      collected[key] = value;
      states[key] = key === "evidence" ?
        (value as NonNullable<Collected["evidence"]>).correlation.truncated ?
          "TRUNCATED" : "PRESENT" :
        key === "assets" ?
          (value as NonNullable<Collected["assets"]>).impact.truncated ?
            "TRUNCATED" : "PRESENT" :
          (value as NonNullable<Collected["remediation"]>).readiness.truncated ?
            "TRUNCATED" : "PRESENT";
    } catch (error) {
      states[key] = "ERROR";
      sourceFailures.push({ source: key,
        code: error instanceof Error ? error.name : "UNKNOWN_FAILURE" });
    }
  }
  const commands: Promise<void>[] = [];
  if (selection.evidence) commands.push(collect("evidence",
    reviewIncidentIntegratedEvidence(actor, {
      incidentId: initial.id, ...selection.evidence,
    })));
  if (selection.assets) commands.push(collect("assets",
    readIncidentAssetImpact(actor, {
      incidentId: initial.id, ...selection.assets,
    })));
  if (selection.remediation) commands.push(collect("remediation",
    reviewIncidentRemediationIntegration(actor, {
      incidentId: initial.id, ...selection.remediation,
      expectedIncidentRevision: initial.revision,
    })));
  await Promise.all(commands);
  if (sourceFailures.length && selection.consistency === "FAIL_CLOSED")
    fail("SITUATION_SOURCE_QUERY_FAILED");
  // Read-after-check protects against concurrent incident workflow updates.
  // It does not claim a multi-table PostgreSQL snapshot: source tables may change.
  const latest = await snapshot(actor, selection.incidentId);
  if (latest.revision !== initial.revision ||
      incidentDigest(latest) !== incidentDigest(initial))
    fail("SITUATION_CONCURRENT_INCIDENT_CHANGE");
  if (collected.evidence &&
      collected.evidence.immutableCaseRevision !== initial.revision)
    fail("SITUATION_EVIDENCE_REVISION_CONFLICT");
  const report = buildIncidentSituation({
    incident: latest,
    evidence: collected.evidence?.correlation ?? null,
    assets: collected.assets?.impact ?? null,
    remediation: collected.remediation?.readiness ?? null,
    sourceStates: states,
    capturedAt: new Date().toISOString(),
    sourceMode: "PERSISTED_READ_ONLY",
  });
  return {
    schema: "cyberpilot.incident.situation.read.v1" as const,
    organizationId: actor.organizationId, incidentId: initial.id,
    incidentRevision: latest.revision,
    situation: report, sourceFailures,
    consistencyPolicy: selection.consistency,
    databaseReadSnapshotGuaranteed: false as const,
    providerCalls: 0 as const, externalWrites: 0 as const,
    customerSecurityImprovementVerified: false as const,
  };
}
export async function readIncidentSituationIndex(actor: IncidentActor,
  offset = 0, limit = 30,
) {
  await authorize(actor);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    fail("SITUATION_INDEX_PAGING_INVALID");
  const [rows, total] = await Promise.all([
    db.guidedIncidentCase.findMany({
      where: { organizationId: actor.organizationId },
      skip: offset, take: limit,
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      select: { id: true, organizationId: true, status: true,
        type: true, revision: true, ownerUserId: true, severity: true,
        title: true, updatedAt: true, snapshot: true, snapshotDigest: true },
    }),
    db.guidedIncidentCase.count({
      where: { organizationId: actor.organizationId },
    }),
  ]);
  const indexed = rows.map(row => {
    const source = row.snapshot as unknown as IncidentSnapshot;
    if (!source || validateIncidentSnapshot(source).length ||
        incidentDigest(source) !== row.snapshotDigest ||
        source.organizationId !== actor.organizationId ||
        source.revision !== row.revision || source.id !== row.id)
      fail("SITUATION_INDEX_SNAPSHOT_CORRUPT");
    return { id: row.id, title: row.title, type: row.type,
      status: row.status, severity: row.severity,
      revision: row.revision, ownerUserId: row.ownerUserId,
      updatedAt: row.updatedAt.toISOString(),
      stepsTotal: source.steps.length,
      stepsPending: source.steps.filter(x =>
        x.status === "PENDING" || x.status === "BLOCKED").length,
      independentContainmentProven: false as const };
  });
  return {
    schema: "cyberpilot.incident.situation.index.v1" as const,
    organizationId: actor.organizationId, total, offset, limit,
    nextOffset: offset + limit < total ? offset + limit : null,
    cases: indexed, source: "PERSISTED_CASES_ONLY" as const,
    actualContainmentVerified: false as const,
  };
}
export async function readIncidentSituationWithLinkedDecision(
  actor: IncidentActor, incidentId: string,
) {
  await authorize(actor);
  const current = await snapshot(actor, incidentId);
  const evidence = current.relatedDecisionCaseId ? {
    evidenceIds: [] as string[], findingIds: [] as string[],
    decisionIds: [current.relatedDecisionCaseId],
    maxAgeHours: 72,
  } : null;
  const result = await readIncidentSituation(actor, {
    incidentId, evidence, assets: null, remediation: null,
    consistency: "PARTIAL_READ",
  });
  return {
    ...result, linkedDecisionId: current.relatedDecisionCaseId,
    inferredAssetIdentity: false as const,
    inferredRemediationAuthorization: false as const,
  };
}
export async function evaluateIncidentSituationAcrossCases(
  actor: IncidentActor, input: {
    ids: string[]; maxItems?: number;
  },
) {
  await authorize(actor);
  if (!Array.isArray(input.ids) || input.ids.length > 50 ||
      input.ids.some(x => !ident(x)) ||
      !Number.isSafeInteger(input.maxItems ?? 50) ||
      (input.maxItems ?? 50) < 1 || (input.maxItems ?? 50) > 50)
    fail("SITUATION_CASE_BATCH_INVALID");
  const unique = [...new Set(input.ids)].slice(0, input.maxItems ?? 50);
  const summaries = [];
  for (const id of unique) {
    try {
      const report = await readIncidentSituation(actor, {
        incidentId: id, evidence: null, assets: null,
        remediation: null, consistency: "FAIL_CLOSED",
      });
      summaries.push({ incidentId: id,
        riskBand: report.situation.riskBand,
        priorityScore: report.situation.priorityScore,
        concerns: report.situation.concerns.length,
        revision: report.incidentRevision,
        sourceCoverage: report.situation.completeness,
        reportDigest: report.situation.situationDigest,
        providerWrites: 0 as const });
    } catch (error) {
      if (error instanceof SituationServiceError &&
          error.code === "SITUATION_NOT_IN_TENANT")
        fail("SITUATION_CASE_BATCH_CROSS_TENANT");
      throw error;
    }
  }
  return {
    schema: "cyberpilot.incident.situation.batch.v1" as const,
    organizationId: actor.organizationId,
    summaries: summaries.sort((a,b) =>
      b.priorityScore-a.priorityScore ||
      a.incidentId.localeCompare(b.incidentId)),
    batchCount: summaries.length, partialIndependentEvidence: true as const,
    providerCalls: 0 as const, externalWrites: 0 as const,
  };
}
