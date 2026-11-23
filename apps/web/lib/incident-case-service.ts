import { db, type Prisma } from "@cyberpilot/database";
import type { IncidentRole, IncidentType } from "./incident-playbook-catalog";
import { INCIDENT_TYPES, catalogIncidentPlaybooks, getIncidentPlaybook } from "./incident-playbook-catalog";
import { createIncident, incidentCreationEvent, incidentDigest, auditIncident,
  applyIncidentCommand, validateIncidentSnapshot, type IncidentMutation,
  type IncidentSnapshot, type IncidentEvent } from "./incident-case-domain";
import { exportIncidentDossier, buildIncidentPortfolio } from "./incident-operations-domain";

export class IncidentServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new IncidentServiceError(code); }
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
export type IncidentActor = { organizationId: string; userId: string; role: IncidentRole };
async function authorize(actor: IncidentActor, write = false) {
  if (!ident(actor.organizationId) || !ident(actor.userId)) fail("INCIDENT_ACTOR_INVALID");
  const member = await db.membership.findFirst({ where: {
    organizationId: actor.organizationId, userId: actor.userId,
  }, select: { role: true } });
  if (!member || member.role !== actor.role || member.role === "AUDITOR" && write)
    fail("INCIDENT_ACTIVE_MEMBERSHIP_REQUIRED");
  return member.role;
}
async function checkOwner(organizationId: string, ownerUserId: string | null) {
  if (ownerUserId === null) return;
  if (!ident(ownerUserId)) fail("INCIDENT_OWNER_INVALID");
  const member = await db.membership.findFirst({ where: {
    organizationId, userId: ownerUserId,
  }, select: { id: true } });
  if (!member) fail("INCIDENT_OWNER_NOT_IN_TENANT");
}
async function checkDecision(organizationId: string, decisionId: string | null) {
  if (decisionId === null) return;
  if (!ident(decisionId)) fail("INCIDENT_DECISION_INVALID");
  const decision = await db.evidenceDecisionCase.findFirst({ where: {
    organizationId, id: decisionId,
  }, select: { id: true } });
  if (!decision) fail("INCIDENT_DECISION_NOT_IN_TENANT");
}
type DbIncident = NonNullable<Awaited<ReturnType<typeof db.guidedIncidentCase.findFirst>>>;
type DbEvent = Awaited<ReturnType<typeof db.guidedIncidentEvent.findMany>>[number];
function fromRow(row: DbIncident): IncidentSnapshot {
  if (!row.snapshot || typeof row.snapshot !== "object" || Array.isArray(row.snapshot))
    fail("INCIDENT_SNAPSHOT_CORRUPT");
  const snapshot = row.snapshot as unknown as IncidentSnapshot;
  if (validateIncidentSnapshot(snapshot).length ||
      snapshot.organizationId !== row.organizationId ||
      snapshot.id !== row.id || snapshot.revision !== row.revision ||
      snapshot.status !== row.status || incidentDigest(snapshot) !== row.snapshotDigest)
    fail("INCIDENT_SNAPSHOT_INTEGRITY_FAILED");
  return snapshot;
}
function toEvent(row: DbEvent): IncidentEvent {
  return { organizationId: row.organizationId, incidentId: row.incidentId,
    revision: row.revision, kind: row.command as IncidentEvent["kind"],
    actorUserId: row.actorUserId, occurredAt: row.occurredAt.toISOString(),
    previousState: row.previousState as IncidentEvent["previousState"],
    nextState: row.nextState as IncidentEvent["nextState"],
    snapshotDigest: row.snapshotDigest, providerWrite: false,
    independentlyClosed: false };
}
export async function createGuidedIncident(actor: IncidentActor, input: {
  type: IncidentType; title: string; subjectReference: string;
  ownerUserId: string | null; relatedDecisionCaseId: string | null;
}) {
  const role = await authorize(actor, true);
  if (!["OWNER", "ADMIN"].includes(role)) fail("INCIDENT_CREATE_ROLE_REQUIRED");
  if (!INCIDENT_TYPES.includes(input.type)) fail("INCIDENT_TYPE_UNSUPPORTED");
  await checkOwner(actor.organizationId, input.ownerUserId);
  await checkDecision(actor.organizationId, input.relatedDecisionCaseId);
  const now = new Date();
  return db.$transaction(async tx => {
    const record = await tx.guidedIncidentCase.create({
      data: { organizationId: actor.organizationId, type: input.type,
        title: input.title, subjectReference: input.subjectReference,
        status: "OPEN", severity: "HIGH", revision: 1,
        ownerUserId: input.ownerUserId, relatedDecisionCaseId: input.relatedDecisionCaseId,
        snapshotDigest: "pending", snapshot: {}, createdById: actor.userId,
        updatedById: actor.userId, createdAt: now, updatedAt: now },
      select: { id: true },
    });
    const snapshot = createIncident({
      id: record.id, organizationId: actor.organizationId, type: input.type,
      title: input.title, subjectReference: input.subjectReference,
      ownerUserId: input.ownerUserId, actorUserId: actor.userId,
      at: now.toISOString(), relatedDecisionCaseId: input.relatedDecisionCaseId,
    });
    const event = incidentCreationEvent(snapshot);
    await tx.guidedIncidentCase.update({ where: { id: record.id },
      data: { severity: snapshot.severity, snapshot: snapshot as unknown as Prisma.InputJsonValue,
        snapshotDigest: event.snapshotDigest } });
    await tx.guidedIncidentEvent.create({ data: {
      organizationId: actor.organizationId, incidentId: record.id, revision: 1,
      command: "CREATE", actorUserId: actor.userId,
      previousState: "OPEN", nextState: "OPEN", occurredAt: now,
      snapshotDigest: event.snapshotDigest,
    } });
    return { case: snapshot, event, providerWrites: 0 as const,
      independentlyContained: false as const };
  }, { isolationLevel: "Serializable" });
}
export async function updateGuidedIncident(actor: IncidentActor,
  command: Omit<IncidentMutation, "organizationId" | "actorUserId" | "role" | "at">) {
  const role = await authorize(actor, true);
  if (!ident(command.incidentId) || !Number.isSafeInteger(command.expectedRevision) ||
      command.expectedRevision < 1) fail("INCIDENT_MUTATION_INVALID");
  if (command.kind === "ASSIGN") await checkOwner(actor.organizationId, command.ownerUserId ?? null);
  const record = await db.guidedIncidentCase.findFirst({ where: {
    organizationId: actor.organizationId, id: command.incidentId,
  } });
  if (!record) fail("INCIDENT_NOT_IN_TENANT");
  const previous = fromRow(record);
  // Browser-supplied evidence is a declaration, never independent provider proof.
  // The server controls the recording time and rejects forged independence.
  if (command.kind === "ATTACH_EVIDENCE" &&
      (!command.evidence || command.evidence.independent !== false ||
      command.evidence.providerOperation !== false))
    fail("INCIDENT_CLIENT_PROOF_NOT_INDEPENDENT");
  const safeCommand = command.kind === "ATTACH_EVIDENCE" && command.evidence ?
    { ...command, evidence: { ...command.evidence,
      recordedAt: new Date().toISOString(), independent: false as const,
      providerOperation: false as const } } : command;
  const result = applyIncidentCommand(previous, {
    ...safeCommand, actorUserId: actor.userId, organizationId: actor.organizationId,
    role, at: new Date().toISOString(),
  });
  if (!result.accepted || !result.event) fail(result.code);
  const next = result.snapshot, event = result.event;
  return db.$transaction(async tx => {
    const count = await tx.guidedIncidentCase.updateMany({ where: {
      id: record.id, organizationId: actor.organizationId,
      revision: record.revision, snapshotDigest: record.snapshotDigest,
    }, data: {
      revision: next.revision, status: next.status,
      ownerUserId: next.ownerUserId, snapshotDigest: event.snapshotDigest,
      snapshot: next as unknown as Prisma.InputJsonValue,
      updatedById: actor.userId, updatedAt: new Date(next.updatedAt),
    } });
    if (count.count !== 1) fail("INCIDENT_CONCURRENT_REVISION_CONFLICT");
    await tx.guidedIncidentEvent.create({ data: {
      organizationId: actor.organizationId, incidentId: record.id,
      revision: event.revision, command: event.kind,
      actorUserId: actor.userId, previousState: event.previousState,
      nextState: event.nextState, occurredAt: new Date(event.occurredAt),
      snapshotDigest: event.snapshotDigest,
    } });
    return { case: next, event, providerWrites: 0 as const,
      independentlyContained: false as const };
  }, { isolationLevel: "Serializable" });
}
export async function readGuidedIncidents(actor: IncidentActor, query: {
  offset?: number; limit?: number; type?: IncidentType;
  status?: string; includeHistory?: boolean;
} = {}) {
  await authorize(actor);
  const limit = query.limit ?? 30, offset = query.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      query.type !== undefined && !INCIDENT_TYPES.includes(query.type))
    fail("INCIDENT_PAGING_INVALID");
  const where = { organizationId: actor.organizationId,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}) };
  const [rows, total] = await Promise.all([
    db.guidedIncidentCase.findMany({ where, take: limit, skip: offset,
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }] }),
    db.guidedIncidentCase.count({ where }),
  ]);
  const incidents = rows.map(fromRow);
  const history: Record<string, IncidentEvent[]> = {};
  if (query.includeHistory) {
    const events = await db.guidedIncidentEvent.findMany({ where: {
      organizationId: actor.organizationId, incidentId: { in: rows.map(x => x.id) },
    }, take: 10001, orderBy: [{ occurredAt: "asc" }, { id: "asc" }] });
    if (events.length > 10000) fail("INCIDENT_HISTORY_TRUNCATED");
    for (const row of events) {
      (history[row.incidentId] ??= []).push(toEvent(row));
    }
  }
  return { schema: "cyberpilot.incident.page.v1" as const,
    organizationId: actor.organizationId, total, offset, limit,
    nextOffset: offset + limit < total ? offset + limit : null,
    cases: incidents, history: query.includeHistory ? history : null,
    catalog: catalogIncidentPlaybooks(),
    playbooks: INCIDENT_TYPES.map(getIncidentPlaybook), providerCalls: 0 as const };
}
export async function readGuidedIncidentDossier(actor: IncidentActor, id: string,
  format: "JSON" | "CSV" | "MARKDOWN" = "JSON") {
  await authorize(actor);
  if (!ident(id)) fail("INCIDENT_ID_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId, id } });
  if (!row) fail("INCIDENT_NOT_IN_TENANT");
  const snapshot = fromRow(row);
  const events = await db.guidedIncidentEvent.findMany({
    where: { organizationId: actor.organizationId, incidentId: id },
    take: 2001, orderBy: [{ revision: "asc" }],
  });
  const mapped = events.slice(0, 2000).map(toEvent);
  const audit = auditIncident(snapshot, mapped, events.length > 2000);
  return { snapshot, events: mapped, audit,
    artifact: exportIncidentDossier(snapshot, mapped, format),
    providerCalls: 0 as const, actualContainmentProven: false as const };
}
export async function readGuidedIncidentPortfolio(actor: IncidentActor) {
  await authorize(actor);
  const rows = await db.guidedIncidentCase.findMany({
    where: { organizationId: actor.organizationId }, take: 501,
    orderBy: { updatedAt: "desc" },
  });
  return buildIncidentPortfolio(actor.organizationId,
    rows.slice(0, 500).map(fromRow), rows.length > 500, new Date().toISOString());
}
