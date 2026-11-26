import { db, type Prisma } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import {
  coordinationDigest, verifyCoordinationHistory, coordinationAuditExport,
  validateCoordinationEnvelope, type CoordinationEnvelope,
  type CoordinationReceipt, type CoordinationKind,
} from "./incident-coordination-ledger-domain";

export class CoordinationPersistenceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => { throw new CoordinationPersistenceError(code); };
const id = (value: unknown): value is string => typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
const maxHistory = 10000;
type Stored = NonNullable<Awaited<ReturnType<
  typeof db.incidentCoordinationRecord.findFirst>>>;
export async function authorizeCoordination(
  actor: IncidentActor, write = false,
) {
  if (!actor || !id(actor.organizationId) || !id(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role) ||
      write && actor.role === "AUDITOR")
    fail("COORDINATION_ROLE_DENIED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("COORDINATION_MEMBERSHIP_REVOKED");
}
export async function checkIncidentMembership(
  actor: IncidentActor, incidentId: string,
) {
  if (!id(incidentId)) fail("COORDINATION_INCIDENT_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { id: incidentId, organizationId: actor.organizationId },
    select: { revision: true, snapshotDigest: true },
  });
  if (!row) fail("COORDINATION_INCIDENT_NOT_FOUND");
  return row!;
}
function unpack<T>(row: Stored): CoordinationEnvelope<T> {
  const snapshot = row.snapshot as unknown as CoordinationEnvelope<T>;
  if (!snapshot || validateCoordinationEnvelope(snapshot).length ||
      snapshot.id !== row.id ||
      snapshot.organizationId !== row.organizationId ||
      snapshot.incidentId !== row.incidentId ||
      snapshot.kind !== row.kind ||
      snapshot.state !== row.state ||
      snapshot.revision !== row.revision ||
      snapshot.sourceDigest !== row.sourceDigest ||
      coordinationDigest(snapshot) !== row.snapshotDigest)
    fail("COORDINATION_SNAPSHOT_CORRUPT");
  return snapshot;
}
function eventRecord(event: CoordinationReceipt) {
  return {
    organizationId: event.organizationId, recordId: event.recordId,
    revision: event.revision, commandId: event.commandId,
    actorUserId: event.actorId, action: event.operation,
    occurredAt: new Date(event.at),
    beforeDigest: event.beforeDigest, afterDigest: event.afterDigest,
    previousEventDigest: event.previousEventDigest,
    eventDigest: event.eventDigest,
  };
}
function unpackEvent(row: {
  organizationId: string; recordId: string; revision: number;
  commandId: string; actorUserId: string; action: string;
  occurredAt: Date; beforeDigest: string | null;
  afterDigest: string; previousEventDigest: string | null;
  eventDigest: string;
}, snapshot: CoordinationEnvelope<unknown>): CoordinationReceipt {
  return {
    schema: "cyberpilot.incident.coordination.event.v1",
    organizationId: row.organizationId,
    incidentId: snapshot.incidentId, recordId: row.recordId,
    kind: snapshot.kind, revision: row.revision,
    commandId: row.commandId, actorId: row.actorUserId,
    operation: row.action, at: row.occurredAt.toISOString(),
    beforeDigest: row.beforeDigest, afterDigest: row.afterDigest,
    previousEventDigest: row.previousEventDigest,
    eventDigest: row.eventDigest, providerWrites: 0,
    externallyVerified: false,
  };
}
export async function readCoordination<T>(
  actor: IncidentActor, recordId: string,
  kind: CoordinationKind,
) {
  await authorizeCoordination(actor);
  if (!id(recordId)) fail("COORDINATION_RECORD_ID_INVALID");
  const record = await db.incidentCoordinationRecord.findFirst({
    where: { id: recordId, organizationId: actor.organizationId, kind },
  });
  if (!record) fail("COORDINATION_RECORD_NOT_FOUND");
  const snapshot = unpack<T>(record!);
  await checkIncidentMembership(actor, snapshot.incidentId);
  const rows = await db.incidentCoordinationEvent.findMany({
    where: { organizationId: actor.organizationId, recordId },
    orderBy: { revision: "asc" }, take: maxHistory + 1,
  });
  if (rows.length > maxHistory)
    fail("COORDINATION_AUDIT_TOO_LONG");
  const events = rows.map(row => unpackEvent(
    row, snapshot as CoordinationEnvelope<unknown>));
  const failures = verifyCoordinationHistory(snapshot, events);
  if (failures.length)
    fail("COORDINATION_AUDIT_CORRUPT:" + failures.join(","));
  return { snapshot, events };
}
export async function createPersistedCoordination<T>(
  actor: IncidentActor,
  snapshot: CoordinationEnvelope<T>,
  event: CoordinationReceipt,
) {
  await authorizeCoordination(actor, true);
  if (snapshot.organizationId !== actor.organizationId ||
      snapshot.createdBy !== actor.userId || snapshot.revision !== 1 ||
      event.actorId !== actor.userId ||
      verifyCoordinationHistory(snapshot, [event]).length)
    fail("COORDINATION_CREATE_PROOF_INVALID");
  const incident = await checkIncidentMembership(actor, snapshot.incidentId);
  return db.$transaction(async tx => {
    const current = await tx.guidedIncidentCase.findFirst({
      where: { organizationId: actor.organizationId, id: snapshot.incidentId },
      select: { revision: true, snapshotDigest: true },
    });
    if (!current || current.revision !== incident!.revision ||
        current.snapshotDigest !== incident!.snapshotDigest)
      fail("COORDINATION_INCIDENT_CHANGED");
    const exists = await tx.incidentCoordinationRecord.findFirst({
      where: { id: snapshot.id, organizationId: actor.organizationId },
    });
    if (exists) {
      const saved = unpack<T>(exists);
      if (coordinationDigest(saved) !== coordinationDigest(snapshot))
        fail("COORDINATION_CREATE_IDEMPOTENCY_CONFLICT");
      return { snapshot: saved, created: false as const,
        externalWrites: 0 as const };
    }
    await tx.incidentCoordinationRecord.create({ data: {
      id: snapshot.id, organizationId: snapshot.organizationId,
      incidentId: snapshot.incidentId, kind: snapshot.kind,
      state: snapshot.state, revision: snapshot.revision,
      snapshot: snapshot as unknown as Prisma.InputJsonValue,
      snapshotDigest: coordinationDigest(snapshot),
      sourceDigest: snapshot.sourceDigest, createdById: actor.userId,
      createdAt: new Date(snapshot.createdAt),
      updatedAt: new Date(snapshot.updatedAt),
    } });
    await tx.incidentCoordinationEvent.create({ data: eventRecord(event) });
    return { snapshot, created: true as const, externalWrites: 0 as const };
  }, { isolationLevel: "Serializable" });
}
export async function mutatePersistedCoordination<T>(
  actor: IncidentActor, kind: CoordinationKind, recordId: string,
  prepare: (current: CoordinationEnvelope<T>, lastEventDigest: string) =>
    { snapshot: CoordinationEnvelope<T>; event: CoordinationReceipt },
) {
  await authorizeCoordination(actor, true);
  const previous = await readCoordination<T>(actor, recordId, kind);
  const last = previous.events.at(-1);
  if (!last) fail("COORDINATION_HISTORY_EMPTY");
  const next = prepare(previous.snapshot, last!.eventDigest);
  if (next.snapshot.kind !== kind ||
      next.snapshot.id !== recordId ||
      next.snapshot.organizationId !== actor.organizationId ||
      next.snapshot.revision !== previous.snapshot.revision + 1 ||
      next.event.beforeDigest !== coordinationDigest(previous.snapshot) ||
      next.event.previousEventDigest !== last!.eventDigest ||
      next.event.afterDigest !== coordinationDigest(next.snapshot) ||
      next.event.actorId !== actor.userId ||
      next.event.organizationId !== actor.organizationId ||
      next.event.recordId !== recordId)
    fail("COORDINATION_MUTATION_INVALID");
  const duplicate = previous.events.find(x =>
    x.commandId === next.event.commandId);
  if (duplicate) fail("COORDINATION_COMMAND_REPLAY");
  return db.$transaction(async tx => {
    const incident = await tx.guidedIncidentCase.findFirst({
      where: { organizationId: actor.organizationId,
        id: previous.snapshot.incidentId },
      select: { id: true },
    });
    if (!incident) fail("COORDINATION_INCIDENT_REVOKED");
    const cas = await tx.incidentCoordinationRecord.updateMany({
      where: { id: recordId, organizationId: actor.organizationId,
        kind, revision: previous.snapshot.revision,
        snapshotDigest: coordinationDigest(previous.snapshot) },
      data: {
        state: next.snapshot.state, revision: next.snapshot.revision,
        snapshot: next.snapshot as unknown as Prisma.InputJsonValue,
        snapshotDigest: coordinationDigest(next.snapshot),
        updatedAt: new Date(next.snapshot.updatedAt),
      },
    });
    if (cas.count !== 1) fail("COORDINATION_CAS_CONFLICT");
    await tx.incidentCoordinationEvent.create({
      data: eventRecord(next.event),
    });
    return { ...next, providerWrites: 0 as const };
  }, { isolationLevel: "Serializable" });
}
export async function listCoordinationRecords(
  actor: IncidentActor, incidentId: string, kind: CoordinationKind,
  offset = 0, limit = 30,
) {
  await authorizeCoordination(actor);
  await checkIncidentMembership(actor, incidentId);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    fail("COORDINATION_PAGING_INVALID");
  const where = { organizationId: actor.organizationId, incidentId, kind };
  const [records, total] = await Promise.all([
    db.incidentCoordinationRecord.findMany({
      where, orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: offset, take: limit,
    }),
    db.incidentCoordinationRecord.count({ where }),
  ]);
  return {
    data: records.map(row => unpack(row)),
    total, nextOffset: offset + records.length < total ?
      offset + records.length : null,
    externalWrites: 0 as const,
  };
}
export async function exportCoordinationAudit<T>(
  actor: IncidentActor, recordId: string, kind: CoordinationKind,
) {
  const result = await readCoordination<T>(actor, recordId, kind);
  return coordinationAuditExport(result.snapshot, result.events);
}
