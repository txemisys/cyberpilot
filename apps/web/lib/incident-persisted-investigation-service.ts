import type { IncidentActor } from "./incident-case-service";
import { readOperationalTimeline } from "./incident-operational-timeline-service";
import {
  beginInvestigationReview, applyInvestigationReview,
  summarizeInvestigationReview, investigationWorkQueue,
  investigationEvidenceGapMatrix, type InvestigationReviewPayload,
  type InvestigationReviewCommandAction,
} from "./incident-persisted-investigation-domain";
import {
  authorizeCoordination, checkIncidentMembership,
  createPersistedCoordination, mutatePersistedCoordination,
  readCoordination, listCoordinationRecords, exportCoordinationAudit,
  CoordinationPersistenceError,
} from "./incident-coordination-persistence-service";
import type { CoordinationCommand } from "./incident-coordination-ledger-domain";
export async function createInvestigationRecord(
  actor: IncidentActor, recordId: string, commandId: string,
  incidentId: string,
) {
  await authorizeCoordination(actor, true);
  const current = await readOperationalTimeline(actor, incidentId);
  const incident = await checkIncidentMembership(actor, incidentId);
  if (incident.revision !== current.page.incidentRevision)
    throw Error("INVESTIGATION_SOURCE_DRIFT");
  const created = beginInvestigationReview({
    recordId, incidentId, organizationId: actor.organizationId,
    actorId: actor.userId, commandId,
    incidentRevision: incident.revision,
    at: new Date().toISOString(), casebook: current.investigation,
  });
  return createPersistedCoordination(actor, created.snapshot, created.event);
}
export async function updateInvestigationRecord(
  actor: IncidentActor,
  command: Omit<CoordinationCommand<InvestigationReviewCommandAction>,
    "organizationId" | "actorId" | "role" | "at" | "kind" | "incidentId">,
) {
  await authorizeCoordination(actor, true);
  if (command.action.kind === "ASSIGN") {
    const { db } = await import("@cyberpilot/database");
    const target = await db.membership.findFirst({
      where: { userId: command.action.assigneeId,
        organizationId: actor.organizationId },
      select: { role: true },
    });
    if (!target || !["OWNER", "ADMIN"].includes(target.role))
      throw Error("INVESTIGATION_ASSIGNEE_MEMBERSHIP_DENIED");
  }
  return mutatePersistedCoordination<InvestigationReviewPayload>(
    actor, "INVESTIGATION", command.recordId,
    (current, lastEventDigest) => applyInvestigationReview(current, {
      ...command, organizationId: actor.organizationId,
      incidentId: current.incidentId, actorId: actor.userId,
      role: actor.role as "OWNER" | "ADMIN", kind: "INVESTIGATION",
      at: new Date().toISOString(),
    }, lastEventDigest));
}
export async function readInvestigationRecord(
  actor: IncidentActor, recordId: string,
) {
  const { snapshot, events } =
    await readCoordination<InvestigationReviewPayload>(
      actor, recordId, "INVESTIGATION");
  return {
    snapshot, events,
    summary: summarizeInvestigationReview(snapshot),
    queue: investigationWorkQueue(snapshot),
    evidenceGaps: investigationEvidenceGapMatrix(snapshot),
    providerWrites: 0 as const,
  };
}
export async function listInvestigationRecords(
  actor: IncidentActor, incidentId: string,
  offset = 0, limit = 30,
) {
  return listCoordinationRecords(
    actor, incidentId, "INVESTIGATION", offset, limit);
}
export async function exportInvestigationAudit(
  actor: IncidentActor, recordId: string,
) {
  return exportCoordinationAudit<InvestigationReviewPayload>(
    actor, recordId, "INVESTIGATION");
}
