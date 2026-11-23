import { db } from "@cyberpilot/database";
import { getIncidentPlaybook } from "./incident-playbook-catalog";
import type { IncidentActor } from "./incident-case-service";
import { incidentDigest, validateIncidentSnapshot,
  type IncidentSnapshot } from "./incident-case-domain";
import { assessIncidentRemediationReadiness,
  type RemediationRecord, type RemediationFindingRecord,
  type RemediationWorkRecord, type RemediationSelection }
  from "./incident-integrated-remediation-domain";

export class IncidentRemediationIntegrationError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never {
  throw new IncidentRemediationIntegrationError(code);
}
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
function identifiers(values: unknown, limit: number) {
  if (!Array.isArray(values) || values.length > limit ||
      values.some(x => !ident(x)))
    fail("REMEDIATION_INTEGRATION_SELECTION_INVALID");
  return values as string[];
}
async function authorize(actor: IncidentActor) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("REMEDIATION_INTEGRATION_REVIEW_ROLE_DENIED");
  const member = await db.membership.findFirst({ where: {
    organizationId: actor.organizationId, userId: actor.userId,
  }, select: { role: true } });
  if (!member || member.role !== actor.role)
    fail("REMEDIATION_INTEGRATION_MEMBERSHIP_REVOKED");
}
async function incident(actor: IncidentActor, incidentId: string) {
  if (!ident(incidentId)) fail("REMEDIATION_INTEGRATION_INCIDENT_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId, id: incidentId },
    select: { id: true, organizationId: true, revision: true, status: true,
      snapshot: true, snapshotDigest: true },
  });
  if (!row) fail("REMEDIATION_INTEGRATION_INCIDENT_NOT_FOUND");
  const source = row.snapshot as unknown as IncidentSnapshot;
  if (!source || validateIncidentSnapshot(source).length ||
      source.organizationId !== actor.organizationId ||
      source.id !== row.id || source.revision !== row.revision ||
      source.status !== row.status ||
      incidentDigest(source) !== row.snapshotDigest)
    fail("REMEDIATION_INTEGRATION_SNAPSHOT_INTEGRITY_FAILED");
  return source;
}
export type RemediationIntegrationRequest = {
  incidentId: string; expectedIncidentRevision: number;
  remediationIds: string[]; findingIds: string[];
  workItemIds: string[]; approvalMaxAgeHours?: number;
};
export async function reviewIncidentRemediationIntegration(
  actor: IncidentActor, request: RemediationIntegrationRequest,
) {
  await authorize(actor);
  const remediationIds = identifiers(request.remediationIds, 100);
  const findingIds = identifiers(request.findingIds, 100);
  const workItemIds = identifiers(request.workItemIds, 100);
  if (!Number.isSafeInteger(request.expectedIncidentRevision) ||
      request.expectedIncidentRevision < 1 ||
      !Number.isSafeInteger(request.approvalMaxAgeHours ?? 24) ||
      (request.approvalMaxAgeHours ?? 24) < 1 ||
      (request.approvalMaxAgeHours ?? 24) > 8760)
    fail("REMEDIATION_INTEGRATION_COMMAND_INVALID");
  const s = await incident(actor, request.incidentId);
  const selection: RemediationSelection = {
    remediationIds, findingIds, workItemIds,
    expectedIncidentRevision: request.expectedIncidentRevision,
  };
  const org = actor.organizationId;
  const workCandidates = await db.remediationWorkItem.findMany({
    where: { organizationId: org, id: { in: workItemIds } },
    take: 101, select: { id: true, remediationId: true },
  });
  const remediations = await db.remediation.findMany({
    where: { organizationId: org, OR: [
      { id: { in: remediationIds } },
      { findingId: { in: findingIds } },
      { id: { in: workCandidates.map(x => x.remediationId) } },
    ] }, take: 301,
    select: {
      id: true, organizationId: true, findingId: true,
      playbookId: true, mode: true, status: true, title: true,
      summary: true, approvedByUserId: true, approvedAt: true,
      startedAt: true, completedAt: true, verifiedAt: true,
      failureCode: true, createdAt: true, updatedAt: true,
    },
  });
  const relevantRemediations = remediations.slice(0, 300);
  const relatedFindings = [...new Set([
    ...findingIds, ...relevantRemediations.map(x => x.findingId),
  ])].slice(0, 300);
  const [findings, works] = await Promise.all([
    db.securityFinding.findMany({ where: {
      organizationId: org, id: { in: relatedFindings },
    }, take: 301, select: {
      id: true, organizationId: true, severity: true,
      status: true, title: true, ruleId: true, lastSeenAt: true,
    } }),
    db.remediationWorkItem.findMany({ where: {
      organizationId: org, OR: [
        { id: { in: workItemIds } },
        { remediationId: { in: relevantRemediations.map(x => x.id) } },
      ],
    }, take: 501, select: {
      id: true, organizationId: true, remediationId: true,
      findingId: true, title: true, status: true, priority: true,
      assigneeUserId: true, dueAt: true, revision: true, completedAt: true,
    } }),
  ]);
  const records: RemediationRecord[] = relevantRemediations.map(x => ({
    ...x, mode: x.mode as "GUIDED" | "AUTOMATED",
    status: String(x.status), approvedAt: x.approvedAt?.toISOString() ?? null,
    startedAt: x.startedAt?.toISOString() ?? null,
    completedAt: x.completedAt?.toISOString() ?? null,
    verifiedAt: x.verifiedAt?.toISOString() ?? null,
    createdAt: x.createdAt.toISOString(), updatedAt: x.updatedAt.toISOString(),
  }));
  const workRecords: RemediationWorkRecord[] = works.slice(0, 500).map(x => ({
    ...x, status: String(x.status), priority: String(x.priority),
    dueAt: x.dueAt?.toISOString() ?? null,
    completedAt: x.completedAt?.toISOString() ?? null,
  }));
  const findingRecords: RemediationFindingRecord[] = findings.slice(0, 300)
    .map(x => ({ ...x, severity: String(x.severity), status: String(x.status),
      lastSeenAt: x.lastSeenAt.toISOString() }));
  const readiness = assessIncidentRemediationReadiness({
    incident: s, selection, remediations: records,
    works: workRecords, findings: findingRecords,
    at: new Date().toISOString(),
    approvalMaxAgeHours: request.approvalMaxAgeHours ?? 24,
    truncated: remediations.length > 300 || findings.length > 300 ||
      works.length > 500 || relatedFindings.length >= 300,
  });
  return {
    schema: "cyberpilot.incident.remediation.integration-read.v1" as const,
    organizationId: org, incidentId: s.id,
    readiness, linkedRemediationCount: records.length,
    linkedWorkItemCount: workRecords.length,
    independentlyVerifiedSecurityOutcome: false as const,
    providerWrites: 0 as const,
    externalApprovalCreated: false as const,
    remediationExecutorCalled: false as const,
  };
}
export async function discoverIncidentRemediationReferences(
  actor: IncidentActor, opts: { offset?: number; limit?: number } = {},
) {
  await authorize(actor);
  const offset = opts.offset ?? 0, limit = opts.limit ?? 30;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    fail("REMEDIATION_INTEGRATION_PAGING_INVALID");
  const org = actor.organizationId;
  const [remediations, findings, works, total] = await Promise.all([
    db.remediation.findMany({ where: { organizationId: org },
      take: limit, skip: offset,
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      select: { id: true, findingId: true, playbookId: true,
        title: true, mode: true, status: true,
        approvedByUserId: true, approvedAt: true } }),
    db.securityFinding.findMany({ where: { organizationId: org },
      take: limit, skip: offset,
      orderBy: [{ lastSeenAt: "desc" }, { id: "asc" }],
      select: { id: true, title: true, severity: true, status: true } }),
    db.remediationWorkItem.findMany({ where: { organizationId: org },
      take: limit, skip: offset,
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      select: { id: true, remediationId: true, findingId: true,
        title: true, status: true, priority: true, revision: true } }),
    db.remediation.count({ where: { organizationId: org } }),
  ]);
  return {
    schema: "cyberpilot.incident.remediation.references.v1" as const,
    organizationId: org, offset, limit, total,
    nextOffset: offset + limit < total ? offset + limit : null,
    remediations: remediations.map(x => ({
      ...x, mode: String(x.mode), status: String(x.status),
      approvedAt: x.approvedAt?.toISOString() ?? null,
    })),
    findings: findings.map(x => ({
      ...x, severity: String(x.severity), status: String(x.status),
    })), works: works.map(x => ({
      ...x, status: String(x.status), priority: String(x.priority),
    })),
    existingRecordsOnly: true as const, providerWrites: 0 as const,
  };
}
export async function readIncidentRemediationChecklist(
  actor: IncidentActor, incidentId: string,
) {
  await authorize(actor);
  const snapshot = await incident(actor, incidentId);
  const playbook = getIncidentPlaybook(snapshot.type);
  return {
    schema: "cyberpilot.incident.remediation.checklist.v1" as const,
    organizationId: actor.organizationId, incidentId,
    incidentRevision: snapshot.revision,
    steps: playbook.steps.map(step => ({
      stepId: step.id, title: step.title,
      risk: step.risk, requiresApproval: step.requiresApproval,
      providerCapability: step.providerCapability,
      suggestedOwner: step.suggestedOwner,
      instructions: step.instructions,
      proofRequired: step.proofRequired,
      fallback: step.fallback,
      automationAvailable: false as const,
      alreadyExecuted: false as const,
    })),
    defaultExecutionMode: "MANUAL_SUPERVISED" as const,
    customerConsentEstablished: false as const,
    providerChangesPerformed: 0 as const,
  };
}
