import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import {
  readIncidentShiftBriefing,
} from "./incident-shift-briefing-service";
import type { ShiftWindow } from "./incident-shift-briefing-domain";
import {
  beginShiftHandoff, applyShiftHandoff,
  summarizeShiftHandoff, pendingShiftHandoffWork,
  shiftHandoffContinuityMatrix, shiftHandoffResponsibility,
  type ShiftHandoffPayload, type ShiftHandoffAction,
} from "./incident-persisted-shift-handoff-domain";
import { coordinationDigest, type CoordinationCommand } from
  "./incident-coordination-ledger-domain";
import {
  authorizeCoordination, checkIncidentMembership,
  createPersistedCoordination, mutatePersistedCoordination,
  readCoordination, listCoordinationRecords, exportCoordinationAudit,
} from "./incident-coordination-persistence-service";
const fail = (code: string): never => { throw Error(code); };
async function memberRole(actor: IncidentActor, id: string) {
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: id },
    select: { role: true },
  });
  if (!member || !["OWNER", "ADMIN"].includes(member.role))
    fail("SHIFT_HANDOFF_RECIPIENT_NOT_AUTHORIZED");
  return member.role as "OWNER" | "ADMIN";
}
export async function createPersistedShiftHandoff(
  actor: IncidentActor, args: {
    recordId: string; incidentId: string; shiftId: string;
    incomingUserId: string; commandId: string;
    startsAt: string; endsAt: string;
  },
) {
  await authorizeCoordination(actor, true);
  const incomingRole = await memberRole(actor, args.incomingUserId);
  if (args.incomingUserId === actor.userId)
    fail("SHIFT_HANDOFF_SELF_ACCEPTANCE_DENIED");
  const now = new Date().toISOString();
  const window: ShiftWindow = {
    shiftId: args.shiftId, startsAt: args.startsAt,
    endsAt: args.endsAt, evaluatedAt: now,
    outgoingRole: actor.role as "OWNER" | "ADMIN",
    incomingRole, outgoingUserId: actor.userId,
    incomingUserId: null, acknowledgedBy: null, acceptedAt: null,
  };
  const read = await readIncidentShiftBriefing(
    actor, args.incidentId, window);
  const incident = await checkIncidentMembership(actor, args.incidentId);
  if (read.briefing.incidentRevision !== incident!.revision)
    fail("SHIFT_HANDOFF_INCIDENT_CHANGED_DURING_CREATE");
  const created = beginShiftHandoff({
    recordId: args.recordId, organizationId: actor.organizationId,
    incidentId: args.incidentId, actorId: actor.userId,
    incomingUserId: args.incomingUserId, commandId: args.commandId,
    at: now, briefing: read.briefing,
  });
  return createPersistedCoordination(actor,
    created.snapshot, created.event);
}
export async function mutatePersistedShiftHandoff(
  actor: IncidentActor,
  input: Omit<CoordinationCommand<ShiftHandoffAction>,
    "organizationId" | "incidentId" | "kind" | "actorId" | "role" | "at">,
) {
  await authorizeCoordination(actor, true);
  const read = await readCoordination<ShiftHandoffPayload>(
    actor, input.recordId, "SHIFT");
  if (![read.snapshot.payload.outgoingUserId,
      read.snapshot.payload.incomingUserId].includes(actor.userId))
    fail("SHIFT_HANDOFF_NOT_PARTICIPANT");
  const participantRole = await memberRole(actor, actor.userId);
  if (actor.role !== participantRole)
    fail("SHIFT_HANDOFF_MEMBERSHIP_CHANGED");
  const source = await checkIncidentMembership(actor,
    read.snapshot.incidentId);
  // A stale incident cannot be acknowledged. The outgoing responder must
  // generate a new briefing when incident state has changed.
  if (["SUBMIT", "ACCEPT", "CLOSE"].includes(input.action.kind) &&
      source!.revision !== read.snapshot.payload.incidentRevision)
    fail("SHIFT_HANDOFF_SOURCE_REVISION_STALE");
  return mutatePersistedCoordination<ShiftHandoffPayload>(
    actor, "SHIFT", input.recordId,
    (snapshot, lastEventDigest) => applyShiftHandoff(snapshot, {
      ...input, organizationId: actor.organizationId,
      incidentId: snapshot.incidentId, kind: "SHIFT",
      actorId: actor.userId, role: actor.role as "OWNER" | "ADMIN",
      at: new Date().toISOString(),
    }, lastEventDigest));
}
export async function readPersistedShiftHandoff(
  actor: IncidentActor, recordId: string,
) {
  const { snapshot, events } = await readCoordination<ShiftHandoffPayload>(
    actor, recordId, "SHIFT");
  if (![snapshot.payload.outgoingUserId,
      snapshot.payload.incomingUserId].includes(actor.userId) &&
      actor.role !== "AUDITOR")
    fail("SHIFT_HANDOFF_READ_PARTICIPANT_DENIED");
  const incident = await checkIncidentMembership(actor, snapshot.incidentId);
  return {
    snapshot, events,
    snapshotDigest: coordinationDigest(snapshot),
    summary: summarizeShiftHandoff(snapshot),
    pendingWork: pendingShiftHandoffWork(snapshot),
    continuity: shiftHandoffContinuityMatrix(snapshot),
    responsibility: shiftHandoffResponsibility(snapshot),
    sourceIncidentRevisionDrift: incident!.revision !==
      snapshot.payload.incidentRevision,
    providerWrites: 0 as const, acceptanceExternal: false as const,
  };
}
export async function listPersistedShiftHandoffs(
  actor: IncidentActor, incidentId: string,
  offset = 0, limit = 30,
) {
  const result = await listCoordinationRecords(
    actor, incidentId, "SHIFT", offset, limit);
  return {
    ...result, data: result.data.filter(value => {
      const p = value.payload as ShiftHandoffPayload;
      return actor.role === "AUDITOR" ||
        [p.outgoingUserId, p.incomingUserId].includes(actor.userId);
    }),
  };
}
export async function exportPersistedShiftHandoffAudit(
  actor: IncidentActor, recordId: string,
) {
  await readPersistedShiftHandoff(actor, recordId);
  return exportCoordinationAudit<ShiftHandoffPayload>(
    actor, recordId, "SHIFT");
}
