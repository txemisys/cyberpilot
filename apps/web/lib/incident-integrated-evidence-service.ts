import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { validateIncidentSnapshot, incidentDigest,
  type IncidentSnapshot } from "./incident-case-domain";
import { correlateIncidentEvidence, compareIncidentCorrelations,
  type IncidentSourceSelection, type IncidentEvidenceCorrelation,
  type EvidenceSourceRow, type FindingSourceRow, type DecisionSourceRow }
  from "./incident-integrated-evidence-domain";

export class IncidentIntegrationError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new IncidentIntegrationError(code); }
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
function selectionIds(value: unknown, cap: number): string[] {
  if (!Array.isArray(value) || value.length > cap ||
      value.some(x => !ident(x))) fail("INCIDENT_INTEGRATION_SELECTION_INVALID");
  return value as string[];
}
async function authorized(actor: IncidentActor) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("INCIDENT_INTEGRATION_ROLE_DENIED");
  const member = await db.membership.findFirst({ where: {
    organizationId: actor.organizationId, userId: actor.userId,
  }, select: { role: true } });
  if (!member || member.role !== actor.role)
    fail("INCIDENT_INTEGRATION_MEMBERSHIP_REVOKED");
}
async function loadIncident(organizationId: string, incidentId: string) {
  if (!ident(incidentId)) fail("INCIDENT_INTEGRATION_ID_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { organizationId, id: incidentId },
    select: { id: true, organizationId: true, revision: true,
      status: true, snapshotDigest: true, snapshot: true },
  });
  if (!row) fail("INCIDENT_INTEGRATION_CASE_NOT_IN_TENANT");
  const snapshot = row.snapshot as unknown as IncidentSnapshot;
  if (!snapshot || typeof snapshot !== "object" ||
      validateIncidentSnapshot(snapshot).length ||
      snapshot.id !== row.id || snapshot.organizationId !== organizationId ||
      snapshot.revision !== row.revision || snapshot.status !== row.status ||
      incidentDigest(snapshot) !== row.snapshotDigest)
    fail("INCIDENT_INTEGRATION_SNAPSHOT_INVALID");
  return snapshot;
}
export type EvidenceIntegrationRequest = {
  incidentId: string;
  evidenceIds: string[]; findingIds: string[]; decisionIds: string[];
  maxAgeHours?: number; asOf?: string;
};
async function resolveSources(actor: IncidentActor,
  selection: IncidentSourceSelection) {
  const knownDecisions = await db.evidenceDecisionCase.findMany({
    where: { organizationId: actor.organizationId,
      id: { in: selection.decisionIds } },
    take: 201,
    select: { id: true, organizationId: true, domain: true,
      controlId: true, scope: true, status: true, revision: true,
      evidenceIds: true, findingIds: true },
  });
  const decisions: DecisionSourceRow[] = knownDecisions.map(row => {
    const ids = (value: unknown): string[] => Array.isArray(value) ?
      value.filter(ident).slice(0, 500) : [];
    return { id: row.id, organizationId: row.organizationId,
      domain: row.domain, controlId: row.controlId, scope: row.scope,
      status: row.status, revision: row.revision,
      evidenceIds: ids(row.evidenceIds), findingIds: ids(row.findingIds) };
  });
  const evidenceKeys = [...new Set([
    ...selection.evidenceIds, ...decisions.flatMap(x => x.evidenceIds),
  ])].slice(0, 500);
  const findingKeys = [...new Set([
    ...selection.findingIds, ...decisions.flatMap(x => x.findingIds),
  ])].slice(0, 500);
  // Explicit ID or an existing decision-case membership is the only join.
  const [evidenceRows, findingRows] = await Promise.all([
    db.securityEvidence.findMany({ where: {
      organizationId: actor.organizationId, id: { in: evidenceKeys },
    }, take: 501, select: { id: true, organizationId: true,
      source: true, domain: true, controlId: true, scope: true,
      state: true, observedAt: true, createdAt: true, updatedAt: true } }),
    db.securityFinding.findMany({ where: {
      organizationId: actor.organizationId, id: { in: findingKeys },
    }, take: 501, select: { id: true, organizationId: true,
      key: true, ruleId: true, severity: true, status: true,
      title: true, lastSeenAt: true, resolvedAt: true } }),
  ]);
  const evidence: EvidenceSourceRow[] = evidenceRows.map(x => ({
    ...x, observedAt: x.observedAt?.toISOString() ?? null,
    createdAt: x.createdAt.toISOString(), updatedAt: x.updatedAt.toISOString(),
  }));
  const findings: FindingSourceRow[] = findingRows.map(x => ({
    ...x, severity: String(x.severity), status: String(x.status),
    lastSeenAt: x.lastSeenAt.toISOString(),
    resolvedAt: x.resolvedAt?.toISOString() ?? null,
  }));
  return { evidence, findings, decisions,
    truncated: knownDecisions.length > 200 ||
      evidenceRows.length > 500 || findingRows.length > 500 ||
      evidenceKeys.length >= 500 || findingKeys.length >= 500 };
}
export async function reviewIncidentIntegratedEvidence(
  actor: IncidentActor, request: EvidenceIntegrationRequest,
) {
  await authorized(actor);
  const selection: IncidentSourceSelection = {
    evidenceIds: selectionIds(request.evidenceIds, 100),
    findingIds: selectionIds(request.findingIds, 100),
    decisionIds: selectionIds(request.decisionIds, 50),
  };
  const maxAgeHours = request.maxAgeHours ?? 72;
  if (!Number.isSafeInteger(maxAgeHours) || maxAgeHours < 1 ||
      maxAgeHours > 8760)
    fail("INCIDENT_INTEGRATION_AGE_INVALID");
  const now = request.asOf ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(now)) || new Date(now).toISOString() !== now)
    fail("INCIDENT_INTEGRATION_TIME_INVALID");
  const incident = await loadIncident(actor.organizationId, request.incidentId);
  const sources = await resolveSources(actor, selection);
  const correlation = correlateIncidentEvidence({
    incident, selection, ...sources, asOf: now, maxAgeHours,
  });
  return {
    schema: "cyberpilot.incident.evidence.integration-review.v1" as const,
    organizationId: actor.organizationId, incidentId: incident.id,
    correlation, selection,
    immutableCaseRevision: incident.revision,
    providerCalls: 0 as const, providerChanges: 0 as const,
    evidenceWasCopiedToCase: false as const,
    incidentContainmentVerified: false as const,
  };
}
export async function inspectIncidentDecisionCase(
  actor: IncidentActor, incidentId: string,
) {
  await authorized(actor);
  const snapshot = await loadIncident(actor.organizationId, incidentId);
  const relatedId = snapshot.relatedDecisionCaseId;
  if (!relatedId) return {
    incidentId, organizationId: actor.organizationId,
    linked: false as const, decision: null, evidenceIds: [] as string[],
    findingIds: [] as string[], matchVerified: false as const,
    providerRemediationProven: false as const,
  };
  const row = await db.evidenceDecisionCase.findFirst({
    where: { organizationId: actor.organizationId, id: relatedId },
    select: { id: true, decisionKey: true, sourceReportDigest: true,
      domain: true, controlId: true, scope: true, status: true,
      revision: true, evidenceIds: true, findingIds: true,
      relatedActionId: true, dueAt: true, ownerUserId: true },
  });
  if (!row) return {
    incidentId, organizationId: actor.organizationId,
    linked: false as const, decision: null, evidenceIds: [] as string[],
    findingIds: [] as string[], matchVerified: false as const,
    providerRemediationProven: false as const,
  };
  const evidenceIds = selectionIds(
    Array.isArray(row.evidenceIds) ? row.evidenceIds : [], 500);
  const findingIds = selectionIds(
    Array.isArray(row.findingIds) ? row.findingIds : [], 500);
  return { incidentId, organizationId: actor.organizationId,
    linked: true as const,
    decision: {
      id: row.id, key: row.decisionKey, sourceDigest: row.sourceReportDigest,
      domain: row.domain, controlId: row.controlId, scope: row.scope,
      status: row.status, revision: row.revision, owner: row.ownerUserId,
      relatedActionId: row.relatedActionId,
      dueAt: row.dueAt?.toISOString() ?? null,
    }, evidenceIds, findingIds,
    matchVerified: true as const, providerRemediationProven: false as const,
  };
}
export async function reviewIncidentLinkedDecision(
  actor: IncidentActor, incidentId: string, maxAgeHours = 72,
) {
  const linked = await inspectIncidentDecisionCase(actor, incidentId);
  if (!linked.linked || !linked.decision) return {
    linked, review: null, linkedEvidenceIntegrityVerified: false as const,
  };
  const review = await reviewIncidentIntegratedEvidence(actor, {
    incidentId, evidenceIds: linked.evidenceIds,
    findingIds: linked.findingIds, decisionIds: [linked.decision.id],
    maxAgeHours,
  });
  return { linked, review,
    linkedEvidenceIntegrityVerified: !review.correlation.truncated &&
      review.correlation.missingIds.length === 0 &&
      review.correlation.foreignTenantIds.length === 0,
    actualProviderRemediationVerified: false as const };
}
export async function readIncidentEvidenceInventory(
  actor: IncidentActor, search: { offset?: number; limit?: number;
    kind?: "EVIDENCE" | "FINDING" | "DECISION"; },
) {
  await authorized(actor);
  const offset = search.offset ?? 0, limit = search.limit ?? 30;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    fail("INCIDENT_INTEGRATION_PAGING_INVALID");
  const where = { organizationId: actor.organizationId };
  const [evidence, findings, decisions] = await Promise.all([
    search.kind === undefined || search.kind === "EVIDENCE" ?
      db.securityEvidence.findMany({ where, skip: offset, take: limit,
        orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
        select: { id: true, source: true, domain: true, controlId: true,
          scope: true, state: true, observedAt: true } }) : Promise.resolve([]),
    search.kind === undefined || search.kind === "FINDING" ?
      db.securityFinding.findMany({ where, skip: offset, take: limit,
        orderBy: [{ lastSeenAt: "desc" }, { id: "asc" }],
        select: { id: true, ruleId: true, severity: true, status: true,
          lastSeenAt: true, title: true } }) : Promise.resolve([]),
    search.kind === undefined || search.kind === "DECISION" ?
      db.evidenceDecisionCase.findMany({ where, skip: offset, take: limit,
        orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
        select: { id: true, status: true, domain: true, controlId: true,
          scope: true, revision: true } }) : Promise.resolve([]),
  ]);
  return {
    schema: "cyberpilot.incident.evidence.inventory.v1" as const,
    organizationId: actor.organizationId, offset, limit,
    evidence: evidence.map(x => ({
      ...x, observedAt: x.observedAt?.toISOString() ?? null,
    })),
    findings: findings.map(x => ({
      ...x, severity: String(x.severity), status: String(x.status),
      lastSeenAt: x.lastSeenAt.toISOString(),
    })), decisions,
    completePopulation: false as const,
    hasPotentialNextPage: evidence.length === limit ||
      findings.length === limit || decisions.length === limit,
    externalSourceQueried: false as const,
  };
}
export function compareIncidentIntegratedReviews(
  earlier: Awaited<ReturnType<typeof reviewIncidentIntegratedEvidence>>,
  later: Awaited<ReturnType<typeof reviewIncidentIntegratedEvidence>>,
) {
  if (earlier.organizationId !== later.organizationId ||
      earlier.incidentId !== later.incidentId)
    fail("INCIDENT_INTEGRATION_COMPARISON_SCOPE_INVALID");
  return compareIncidentCorrelations(earlier.correlation, later.correlation);
}
