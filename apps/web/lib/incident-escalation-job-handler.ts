import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import {
  validateAssuranceHandoffBoard, assuranceHandoffBoardDigest,
  type AssuranceHandoffBoard,
} from "./incident-assurance-handoff-domain";
import {
  escalationDigest, evaluateEscalationDispatch,
  validateEscalationPolicy, type EscalationDispatch,
  type EscalationPolicy,
} from "./incident-escalation-dispatch-domain";

const ident = (x: unknown): x is string =>
  typeof x === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(x);
function record(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}
const fail = (code: string): never => { throw Error(code); };
/**
 * This is deliberately not an executor for provider control changes.
 * Its result is a local assertion that a board still merits review.
 * Every invocation rechecks the membership, incident and persisted digest.
 */
export async function evaluateClaimedIncidentEscalationJob(
  actor: IncidentActor, payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!record(payload) || payload.schema !==
      "cyberpilot.incident.escalation.offline-job.v1" ||
      payload.organizationId !== actor.organizationId ||
      !ident(payload.incidentId) || !record(payload.dispatch) ||
      !record(payload.policy) || !ident(payload.submittedBy) ||
      payload.externalNotificationsAllowed !== false ||
      payload.providerWritesAllowed !== false ||
      typeof payload.requestDigest !== "string")
    fail("ESCALATION_JOB_PAYLOAD_REJECTED");
  const dispatch = payload.dispatch as unknown as EscalationDispatch;
  const policy = payload.policy as unknown as EscalationPolicy;
  if (!dispatch || dispatch.organizationId !== actor.organizationId ||
      dispatch.incidentId !== payload.incidentId ||
      !ident(dispatch.boardId) || !ident(dispatch.handoffId) ||
      !ident(dispatch.ruleId) || !ident(dispatch.idempotencyKey) ||
      dispatch.authorizedProviderMutations !== 0 ||
      dispatch.notificationDeliveries !== 0 ||
      !dispatch.payload || dispatch.payload.internalOnly !== true ||
      dispatch.payload.externalNotificationsAllowed !== false ||
      validateEscalationPolicy(policy).length ||
      escalationDigest({ dispatch, policy }) !== payload.requestDigest)
    fail("ESCALATION_JOB_INTEGRITY_DENIED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role ||
      !["OWNER", "ADMIN"].includes(member.role))
    fail("ESCALATION_JOB_OPERATOR_REVOKED");
  const submitter = await db.membership.findFirst({
    where: { organizationId: actor.organizationId,
      userId: payload.submittedBy as string },
    select: { role: true },
  });
  if (!submitter || !["OWNER", "ADMIN"].includes(submitter.role))
    fail("ESCALATION_JOB_SUBMITTER_REVOKED");
  const incident = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId,
      id: payload.incidentId as string },
    select: { id: true, revision: true, status: true },
  });
  if (!incident) fail("ESCALATION_JOB_INCIDENT_NOT_FOUND");
  const row = await db.incidentAssuranceHandoffBoard.findFirst({
    where: { organizationId: actor.organizationId,
      incidentId: incident!.id, id: dispatch.boardId },
  });
  let board: AssuranceHandoffBoard | null = null;
  if (row) {
    const value = row.snapshot as unknown as AssuranceHandoffBoard;
    if (!value || validateAssuranceHandoffBoard(value).length ||
        value.id !== row.id ||
        value.organizationId !== row.organizationId ||
        value.incidentId !== incident.id ||
        value.revision !== row.revision ||
        value.status !== row.state ||
        assuranceHandoffBoardDigest(value) !== row.snapshotDigest)
      fail("ESCALATION_JOB_BOARD_TAMPERED");
    board = value;
  }
  const evaluatedAt = new Date().toISOString();
  const result = evaluateEscalationDispatch({
    dispatch, board, policy, at: evaluatedAt,
  });
  return {
    schema: "cyberpilot.incident.escalation.offline-result.v1",
    organizationId: actor.organizationId,
    incidentId: incident!.id,
    incidentRevision: incident!.revision,
    incidentInternalStatus: incident!.status,
    dispatchIdempotencyKey: dispatch.idempotencyKey,
    requestDigest: payload.requestDigest,
    evaluation: result,
    evaluatedAt,
    senderNotificationAttempted: false,
    providerWrites: 0,
    externalMessagesDispatched: 0,
    independentProviderProof: false,
    operatorReviewStillRequired: true,
  };
}
