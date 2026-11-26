import type { IncidentActor } from "./incident-case-service";
import { db } from "@cyberpilot/database";
import { readSelectedIncidentCorrelations } from
  "./incident-crosscase-correlation-service";
import {
  beginCorrelationBoard, applyCorrelationBoard,
  summarizeCorrelationBoard, correlationHypothesisQueue,
  correlationReviewIntegrityMatrix, assessCorrelationReadiness,
  correlationPendingReviewQueue, correlationDecisionLedger,
  type CorrelationBoardPayload,
  type CorrelationBoardAction,
} from "./incident-persisted-correlation-domain";
import type { CoordinationCommand } from
  "./incident-coordination-ledger-domain";
import {
  authorizeCoordination, checkIncidentMembership,
  createPersistedCoordination, mutatePersistedCoordination,
  readCoordination, listCoordinationRecords, exportCoordinationAudit,
} from "./incident-coordination-persistence-service";
const fail = (code: string): never => { throw Error(code); };
export async function createCorrelationBoard(
  actor: IncidentActor, recordId: string, commandId: string,
  selectedIncidentIds: string[],
) {
  await authorizeCoordination(actor, true);
  if (!Array.isArray(selectedIncidentIds) ||
      selectedIncidentIds.length < 2 || selectedIncidentIds.length > 12 ||
      new Set(selectedIncidentIds).size !== selectedIncidentIds.length)
    fail("CORRELATION_SELECTION_INVALID");
  const selected = [...selectedIncidentIds].sort();
  for (const incidentId of selected)
    await checkIncidentMembership(actor, incidentId);
  const read = await readSelectedIncidentCorrelations(actor, selected);
  const created = beginCorrelationBoard({
    recordId, organizationId: actor.organizationId,
    incidentId: selected[0]!, actorId: actor.userId,
    commandId, at: new Date().toISOString(), report: read.report,
  });
  return createPersistedCoordination(actor,
    created.snapshot, created.event);
}
export async function mutateCorrelationBoard(
  actor: IncidentActor,
  input: Omit<CoordinationCommand<CorrelationBoardAction>,
    "organizationId" | "incidentId" | "kind" | "actorId" |
    "role" | "at">,
) {
  await authorizeCoordination(actor, true);
  const current = await readCoordination<CorrelationBoardPayload>(
    actor, input.recordId, "CORRELATION");
  // Every referenced incident must still exist in the actor's tenant.
  for (const incidentId of current.snapshot.payload.selectedIncidentIds)
    await checkIncidentMembership(actor, incidentId);
  if (input.action.kind === "ASSIGN") {
    const member = await db.membership.findFirst({
      where: { organizationId: actor.organizationId,
        userId: input.action.assigneeId }, select: { role: true },
    });
    if (!member || !["OWNER", "ADMIN"].includes(member.role))
      fail("CORRELATION_ASSIGNEE_NOT_AUTHORIZED");
  }
  return mutatePersistedCoordination<CorrelationBoardPayload>(
    actor, "CORRELATION", input.recordId,
    (snapshot, lastEventDigest) => applyCorrelationBoard(snapshot, {
      ...input, actorId: actor.userId, organizationId: actor.organizationId,
      incidentId: snapshot.incidentId, kind: "CORRELATION",
      role: actor.role as "OWNER" | "ADMIN", at: new Date().toISOString(),
    }, lastEventDigest));
}
export async function readCorrelationBoard(
  actor: IncidentActor, recordId: string,
) {
  const { snapshot, events } = await readCoordination<CorrelationBoardPayload>(
    actor, recordId, "CORRELATION");
  for (const incidentId of snapshot.payload.selectedIncidentIds)
    await checkIncidentMembership(actor, incidentId);
  return {
    snapshot, events, summary: summarizeCorrelationBoard(snapshot),
    queue: correlationHypothesisQueue(snapshot),
    integrity: correlationReviewIntegrityMatrix(snapshot),
    readiness: assessCorrelationReadiness(snapshot),
    pendingReviews: correlationPendingReviewQueue(snapshot),
    decisions: correlationDecisionLedger(snapshot),
    providerWrites: 0 as const,
    providerIdentitiesVerified: false as const,
  };
}
export async function listCorrelationBoards(
  actor: IncidentActor, incidentId: string,
  offset = 0, limit = 30,
) {
  return listCoordinationRecords(
    actor, incidentId, "CORRELATION", offset, limit);
}
export async function exportCorrelationBoardAudit(
  actor: IncidentActor, recordId: string,
) {
  await readCorrelationBoard(actor, recordId);
  return exportCoordinationAudit<CorrelationBoardPayload>(
    actor, recordId, "CORRELATION");
}
