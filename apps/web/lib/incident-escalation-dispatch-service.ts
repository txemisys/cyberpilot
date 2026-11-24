import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { enqueueOfflineJob } from "./durable-offline-job-service";
import {
  validateAssuranceHandoffBoard, assuranceHandoffBoardDigest,
  type AssuranceHandoffBoard,
} from "./incident-assurance-handoff-domain";
import {
  planIncidentEscalations, verifyEscalationPlan,
  summarizeEscalationPlan, groupEscalationsByOwner,
  assessEscalationAssignment, exportEscalationPlanCSV,
  exportEscalationPlanJSON, escalationDigest,
  type EscalationPolicy, type EscalationPlan,
  type EscalationDispatch,
} from "./incident-escalation-dispatch-domain";

export class IncidentEscalationServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => {
  throw new IncidentEscalationServiceError(code);
};
const id = (x: unknown): x is string =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
async function authorize(actor: IncidentActor, write = false) {
  if (!id(actor.organizationId) || !id(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role) ||
      write && !["OWNER", "ADMIN"].includes(actor.role))
    fail("ESCALATION_ROLE_DENIED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("ESCALATION_MEMBERSHIP_REVOKED");
}
async function incident(actor: IncidentActor, incidentId: string) {
  if (!id(incidentId)) fail("ESCALATION_INCIDENT_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId, id: incidentId },
    select: { id: true, revision: true, status: true },
  });
  if (!row) fail("ESCALATION_INCIDENT_NOT_FOUND");
  return row;
}
async function boardData(actor: IncidentActor, incidentId: string) {
  const rows = await db.incidentAssuranceHandoffBoard.findMany({
    where: { organizationId: actor.organizationId, incidentId },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    take: 501,
  });
  if (rows.length > 500) fail("ESCALATION_BOARD_LIMIT");
  const boards: AssuranceHandoffBoard[] = [];
  for (const row of rows) {
    const snapshot = row.snapshot as unknown as AssuranceHandoffBoard;
    if (!snapshot || validateAssuranceHandoffBoard(snapshot).length ||
        row.organizationId !== actor.organizationId ||
        snapshot.id !== row.id ||
        snapshot.incidentId !== incidentId ||
        snapshot.revision !== row.revision ||
        snapshot.status !== row.state ||
        assuranceHandoffBoardDigest(snapshot) !== row.snapshotDigest)
      fail("ESCALATION_BOARD_INTEGRITY_FAILED");
    boards.push(snapshot);
  }
  return boards;
}
async function assignableMembers(actor: IncidentActor,
  boards: AssuranceHandoffBoard[]) {
  const userIds = [...new Set(boards.flatMap(board =>
    board.handoffs.flatMap(item =>
      item.assignedUserId ? [item.assignedUserId] : [])))];
  const members = await db.membership.findMany({
    where: { organizationId: actor.organizationId,
      userId: { in: userIds } },
    select: { userId: true, role: true },
  });
  const map = new Map(members.map(x => [x.userId, x.role]));
  return boards.flatMap(board => assessEscalationAssignment(board, map));
}
export async function prepareIncidentEscalationPlan(
  actor: IncidentActor, incidentId: string, policy: EscalationPolicy,
) {
  await authorize(actor);
  const current = (await incident(actor, incidentId))!;
  const boards = await boardData(actor, incidentId);
  const plan = planIncidentEscalations({
    organizationId: actor.organizationId,
    incidentId, policy, boards, at: new Date().toISOString(),
  });
  if (verifyEscalationPlan(plan).length)
    fail("ESCALATION_PLAN_INTEGRITY_FAILED");
  return {
    plan, summary: summarizeEscalationPlan(plan),
    ownerWorkload: groupEscalationsByOwner(plan),
    assignments: await assignableMembers(actor, boards),
    incidentRevision: current.revision,
    incidentStatus: current.status,
    sourceVerifiedExternal: false as const,
    jobsAdmitted: 0 as const,
    providerWrites: 0 as const,
  };
}
function pickDispatch(plan: EscalationPlan, idempotencyKey: string) {
  if (!id(idempotencyKey))
    fail("ESCALATION_DISPATCH_KEY_INVALID");
  const match = plan.dispatches.filter(x =>
    x.idempotencyKey === idempotencyKey);
  if (match.length !== 1)
    fail("ESCALATION_DISPATCH_NOT_IN_CURRENT_PLAN");
  return match[0]!;
}
function policyForDispatch(policy: EscalationPolicy,
  dispatch: EscalationDispatch): EscalationPolicy {
  const rules = policy.rules.filter(x => x.id === dispatch.ruleId);
  if (rules.length !== 1)
    fail("ESCALATION_DISPATCH_RULE_INCONSISTENT");
  return { ...policy, rules };
}
export async function admitIncidentEscalationDispatch(
  actor: IncidentActor, incidentId: string, policy: EscalationPolicy,
  input: { idempotencyKey: string; boardDigest: string;
    expectedIncidentRevision: number },
) {
  await authorize(actor, true);
  const current = (await incident(actor, incidentId))!;
  if (!Number.isSafeInteger(input.expectedIncidentRevision) ||
      current.revision !== input.expectedIncidentRevision)
    fail("ESCALATION_INCIDENT_CAS_CONFLICT");
  const read = await prepareIncidentEscalationPlan(
    actor, incidentId, policy);
  // The current time is not a client authority. The one selected handoff
  // must retain its board snapshot digest before durable admission.
  const dispatch = pickDispatch(read.plan, input.idempotencyKey)!;
  const board = await db.incidentAssuranceHandoffBoard.findFirst({
    where: { organizationId: actor.organizationId, incidentId,
      id: dispatch.boardId },
  });
  if (!board) fail("ESCALATION_BOARD_DISAPPEARED");
  const value = board!.snapshot as unknown as AssuranceHandoffBoard;
  if (!value || board!.snapshotDigest !== input.boardDigest ||
      assuranceHandoffBoardDigest(value) !== board!.snapshotDigest ||
      board!.revision !== dispatch.payload.boardRevision)
    fail("ESCALATION_BOARD_CAS_CONFLICT");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("ESCALATION_ADMISSION_MEMBERSHIP_REVOKED");
  const singlePolicy = policyForDispatch(policy, dispatch);
  const payload = {
    schema: "cyberpilot.incident.escalation.offline-job.v1",
    incidentId, dispatch, policy: singlePolicy,
    submittedBy: actor.userId,
    organizationId: actor.organizationId,
    requestDigest: escalationDigest({ dispatch, policy: singlePolicy }),
    externalNotificationsAllowed: false,
    providerWritesAllowed: false,
  };
  const admitted = await enqueueOfflineJob(actor, {
    type: "INCIDENT_ESCALATION_REVIEW",
    idempotencyKey: dispatch.idempotencyKey,
    payload,
    delaySeconds: 0,
  });
  return {
    created: admitted.created,
    idempotencyKey: dispatch.idempotencyKey,
    dispatch, job: admitted.job,
    externalNotificationsSent: 0 as const,
    providerWrites: 0 as const,
  };
}
export async function exportIncidentEscalationPlan(
  actor: IncidentActor, incidentId: string,
  policy: EscalationPolicy, format: "csv" | "json",
) {
  const response = await prepareIncidentEscalationPlan(
    actor, incidentId, policy);
  return {
    content: format === "csv" ?
      exportEscalationPlanCSV(response.plan) :
      exportEscalationPlanJSON(response.plan),
    digest: response.plan.planDigest,
    contentType: format === "csv" ?
      "text/csv; charset=utf-8" :
      "application/json; charset=utf-8",
    providerWrites: 0 as const,
  };
}
