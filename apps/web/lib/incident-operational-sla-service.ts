import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { readOperationalTimeline } from "./incident-operational-timeline-service";
import { validateAssuranceHandoffBoard, assuranceHandoffBoardDigest,
  type AssuranceHandoffBoard } from "./incident-assurance-handoff-domain";
import {
  analyzeOperationalSla, calculateSlaDailyBuckets,
  calculateSlaActorWorkloads, forecastInternalDeadlines,
  assessIncidentOperationalHealth, summarizeSlaByPriority,
  buildSlaOperationalPriorityQueue, operationalSlaAuditEnvelope,
  validateOperationalSlaPolicy, type OperationalSlaPolicy,
  type HandoffSlaEvidence,
} from "./incident-operational-sla-domain";
import type { TimelineEvent } from "./incident-operational-timeline-domain";

export class IncidentSlaServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => { throw new IncidentSlaServiceError(code); };
const id = (x: unknown): x is string => typeof x === "string" &&
  /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(x);
async function membership(actor: IncidentActor) {
  if (!id(actor.organizationId) || !id(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("SLA_REVIEWER_REQUIRED");
  const active = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!active || active.role !== actor.role)
    fail("SLA_ACTIVE_MEMBERSHIP_REQUIRED");
}
async function getIncident(actor: IncidentActor, incidentId: string) {
  if (!id(incidentId)) fail("SLA_INCIDENT_INVALID");
  const incident = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId, id: incidentId },
    select: { id: true, organizationId: true, revision: true },
  });
  if (!incident) fail("SLA_INCIDENT_NOT_FOUND");
  return incident;
}
async function readHandoffs(actor: IncidentActor, incidentId: string) {
  const boards = await db.incidentAssuranceHandoffBoard.findMany({
    where: { organizationId: actor.organizationId, incidentId },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    take: 501,
  });
  if (boards.length > 500)
    fail("SLA_BOARD_LIMIT_EXCEEDED");
  const evidence: HandoffSlaEvidence[] = [];
  const integrityWarnings: string[] = [];
  for (const row of boards) {
    const board = row.snapshot as unknown as AssuranceHandoffBoard;
    if (!board || validateAssuranceHandoffBoard(board).length ||
        board.id !== row.id ||
        board.organizationId !== actor.organizationId ||
        board.incidentId !== incidentId ||
        board.revision !== row.revision ||
        assuranceHandoffBoardDigest(board) !== row.snapshotDigest)
      fail("SLA_HANDOFF_SNAPSHOT_TAMPERED");
    if (row.state !== "ACTIVE") {
      integrityWarnings.push("SLA_NON_ACTIVE_BOARD_INCLUDED:" + row.id);
    }
    for (const item of board.handoffs) {
      evidence.push({
        boardId: board.id, handoffId: item.id,
        controlId: item.controlId,
        priority: item.priority,
        createdAt: board.createdAt,
        dueAt: item.dueAt, assignedAt: item.assignedAt,
        acceptedAt: item.acceptedAt,
        lastEscalatedAt: item.lastEscalatedAt,
        updatedAt: item.updatedAt, status: item.status,
        assignedUserId: item.assignedUserId, externalWrites: 0,
      });
    }
  }
  if (evidence.length > 3000)
    fail("SLA_HANDOFF_LIMIT_EXCEEDED");
  return { evidence, integrityWarnings, boardCount: boards.length };
}
async function collectEvents(actor: IncidentActor, incidentId: string,
  maxPages = 20) {
  if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 100)
    fail("SLA_COLLECTION_BUDGET_INVALID");
  const events: TimelineEvent[] = [];
  let cursor: string | null = null;
  let inventoryComplete = false;
  let sourceWarnings: string[] = [];
  const observedRevisions = new Set<string>();
  let sourceIntegrity = "INCOMPLETE";
  for (let n = 0; n < maxPages; n++) {
    const read = await readOperationalTimeline(actor, incidentId, {
      limit: 100, cursor,
    });
    sourceWarnings = read.warnings;
    sourceIntegrity = read.page.integrity;
    for (const event of read.page.entries) {
      const key = [event.source, event.sourceId,
        event.sourceRevision].join(":");
      if (observedRevisions.has(key))
        fail("SLA_DUPLICATE_TIMELINE_REVISION");
      observedRevisions.add(key);
      events.push(event);
    }
    cursor = read.page.nextCursor;
    if (cursor === null) {
      inventoryComplete = read.page.completeness !== "UNKNOWN";
      break;
    }
  }
  if (cursor !== null) sourceWarnings.push("SLA_EVENT_COLLECTION_TRUNCATED");
  return { events, inventoryComplete, sourceWarnings, sourceIntegrity,
    truncated: cursor !== null };
}
function assertPolicy(policy: OperationalSlaPolicy) {
  const problems = validateOperationalSlaPolicy(policy);
  if (problems.length) fail(problems[0]);
  if (policy.effectiveAt > new Date().toISOString())
    fail("SLA_FUTURE_POLICY_NOT_ACTIVE");
}
export async function readIncidentOperationalSla(
  actor: IncidentActor, incidentId: string, policy: OperationalSlaPolicy,
  options?: { from?: string; to?: string; maxPages?: number },
) {
  await membership(actor);
  assertPolicy(policy);
  const incident = await getIncident(actor, incidentId);
  const [timeline, boardData] = await Promise.all([
    collectEvents(actor, incidentId, options?.maxPages ?? 20),
    readHandoffs(actor, incidentId),
  ]);
  const asOf = new Date().toISOString();
  const snapshot = analyzeOperationalSla({
    organizationId: actor.organizationId, incidentId,
    incidentRevision: incident.revision, asOf, policy,
    events: timeline.events, handoffs: boardData.evidence,
    inventoryComplete: timeline.inventoryComplete &&
      boardData.integrityWarnings.length === 0,
  });
  const from = options?.from ??
    new Date(Date.parse(asOf) - 30 * 86400000).toISOString();
  const to = options?.to ?? asOf;
  const trends = calculateSlaDailyBuckets(timeline.events, from, to);
  const actors = calculateSlaActorWorkloads(timeline.events, 100);
  const forecast = forecastInternalDeadlines(snapshot,
    [30, 60, 240, 1440, 10080]);
  const health = assessIncidentOperationalHealth(snapshot, timeline.events);
  const byPriority = summarizeSlaByPriority(boardData.evidence, snapshot);
  const internalQueue = buildSlaOperationalPriorityQueue(snapshot, 100);
  const auditEnvelope = operationalSlaAuditEnvelope(snapshot);
  return {
    schema: "cyberpilot.incident.operational-sla.report.v1" as const,
    snapshot, trends, actors, forecast, health, byPriority, internalQueue,
    auditEnvelope, sourceWarnings: [
      ...timeline.sourceWarnings, ...boardData.integrityWarnings,
    ],
    sampledEvents: timeline.events.length,
    includedBoards: boardData.boardCount,
    eventCollectionTruncated: timeline.truncated,
    sourceIntegrationScope: "PERSISTED_INTERNAL_LEDGER_ONLY" as const,
    independentProviderOutcome: "UNKNOWN" as const,
    providerWrites: 0 as const,
    externalNotificationsSent: 0 as const,
  };
}
export async function exportIncidentOperationalSla(
  actor: IncidentActor, incidentId: string, policy: OperationalSlaPolicy,
  mode: "report" | "audit",
) {
  const report = await readIncidentOperationalSla(actor, incidentId, policy);
  const exported = mode === "audit" ? report.auditEnvelope : report;
  return {
    content: JSON.stringify(exported, null, 2),
    digest: report.snapshot.digest,
    contentType: "application/json; charset=utf-8",
    exportedType: mode,
    providerWrites: 0 as const,
  };
}
