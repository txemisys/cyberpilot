import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { incidentDigest, validateIncidentSnapshot,
  type IncidentSnapshot } from "./incident-case-domain";
import { situationReviewDigest, validateSituationReview,
  type SituationReviewSnapshot } from "./incident-situation-review-domain";
import { tabletopSessionDigest, verifyPersistedTabletopSession,
  type PersistedTabletopSession } from "./incident-tabletop-session-domain";
import { assuranceHandoffBoardDigest, validateAssuranceHandoffBoard,
  type AssuranceHandoffBoard } from "./incident-assurance-handoff-domain";
import {
  paginateTimeline, normalizeTimelineEvent, exportTimelineCSV,
  exportTimelineJSON, summarizeTimeline, type RawTimelineEvent,
  type TimelineQuery, type TimelineIntegrity, type TimelineSource,
} from "./incident-operational-timeline-domain";

export class OperationalTimelineError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => { throw new OperationalTimelineError(code); };
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(x);
const limit = 25000;

async function authorize(actor: IncidentActor) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("TIMELINE_ROLE_DENIED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("TIMELINE_MEMBERSHIP_REVOKED");
}
type IncidentRow = NonNullable<Awaited<ReturnType<
  typeof db.guidedIncidentCase.findFirst>>>;
async function readIncident(actor: IncidentActor, incidentId: string) {
  if (!ident(incidentId)) fail("TIMELINE_INCIDENT_ID_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { organizationId: actor.organizationId, id: incidentId },
  });
  if (!row) fail("TIMELINE_INCIDENT_NOT_FOUND");
  const snapshot = row.snapshot as unknown as IncidentSnapshot;
  if (!snapshot || validateIncidentSnapshot(snapshot).length ||
      snapshot.id !== row.id ||
      snapshot.organizationId !== row.organizationId ||
      snapshot.revision !== row.revision ||
      incidentDigest(snapshot) !== row.snapshotDigest)
    fail("TIMELINE_INCIDENT_SNAPSHOT_CORRUPT");
  return row;
}
function recordEntry(e: RawTimelineEvent) {
  return normalizeTimelineEvent(e);
}
type CheckResult = { integrity: TimelineIntegrity; reason: string | null };
function checkSnapshot(row: { snapshot: unknown; snapshotDigest: string;
  revision: number; id: string; organizationId: string; incidentId: string },
  source: TimelineSource): CheckResult {
  try {
    if (source === "SITUATION_REVIEW") {
      const value = row.snapshot as SituationReviewSnapshot;
      if (validateSituationReview(value).length || value.id !== row.id ||
          value.organizationId !== row.organizationId ||
          value.incidentId !== row.incidentId ||
          value.revision !== row.revision ||
          situationReviewDigest(value) !== row.snapshotDigest)
        return { integrity: "CONFLICT", reason: "REVIEW_SNAPSHOT_INVALID" };
    } else if (source === "TABLETOP_SESSION") {
      const value = row.snapshot as PersistedTabletopSession;
      if (verifyPersistedTabletopSession(value).length ||
          value.id !== row.id ||
          value.organizationId !== row.organizationId ||
          value.incidentId !== row.incidentId ||
          value.revision !== row.revision ||
          tabletopSessionDigest(value) !== row.snapshotDigest)
        return { integrity: "CONFLICT", reason: "SESSION_SNAPSHOT_INVALID" };
    } else if (source === "ASSURANCE_HANDOFF") {
      const value = row.snapshot as AssuranceHandoffBoard;
      if (validateAssuranceHandoffBoard(value).length ||
          value.id !== row.id ||
          value.organizationId !== row.organizationId ||
          value.incidentId !== row.incidentId ||
          value.revision !== row.revision ||
          assuranceHandoffBoardDigest(value) !== row.snapshotDigest)
        return { integrity: "CONFLICT", reason: "HANDOFF_SNAPSHOT_INVALID" };
    } else return { integrity: "INCOMPLETE", reason: "SOURCE_NOT_SUPPORTED" };
    return { integrity: "INCOMPLETE", reason: "SNAPSHOT_ONLY_NOT_AUDIT_PROOF" };
  } catch {
    return { integrity: "CONFLICT", reason: "SOURCE_SNAPSHOT_UNREADABLE" };
  }
}
function ledgerIntegrity(revision: number, eventRevisions: number[],
  snapshot: CheckResult): TimelineIntegrity {
  if (snapshot.integrity === "CONFLICT") return "CONFLICT";
  if (eventRevisions.length !== revision ||
      eventRevisions.some((x, i) => x !== i + 1))
    return "INCOMPLETE";
  // Source chain and snapshot validation happen within each source service.
  // This read model cannot upgrade a local event to VERIFIED by itself.
  return "INCOMPLETE";
}
function eventFrom(args: {
  organizationId: string; incidentId: string; source: TimelineSource;
  sourceId: string; revision: number; eventId: string; actorId: string;
  operation: string; at: Date; priorState: string | null;
  nextState: string | null; priorDigest: string | null;
  nextDigest: string; eventDigest: string | null;
  integrity: TimelineIntegrity;
}) {
  return recordEntry({
    organizationId: args.organizationId,
    incidentId: args.incidentId, source: args.source,
    sourceId: args.sourceId, sourceRevision: args.revision,
    eventId: args.eventId, actorUserId: args.actorId,
    operation: args.operation, occurredAt: args.at.toISOString(),
    priorState: args.priorState, nextState: args.nextState,
    priorDigest: args.priorDigest, nextDigest: args.nextDigest,
    sourceEventDigest: args.eventDigest,
    sourceIntegrity: args.integrity,
  });
}
/**
 * Read all bounded event ledgers consistently. Never silently call an empty
 * result complete when the event inventory reaches the supported cap.
 */
export async function readOperationalTimeline(
  actor: IncidentActor, incidentId: string,
  query: TimelineQuery = {},
) {
  await authorize(actor);
  const incident = await readIncident(actor, incidentId);
  const where = { organizationId: actor.organizationId, incidentId };
  const [incidentEvents, reviews, sessions, boards] = await Promise.all([
    db.guidedIncidentEvent.findMany({
      where, orderBy: { revision: "asc" }, take: limit + 1,
    }),
    db.incidentSituationReview.findMany({
      where, orderBy: { createdAt: "asc" }, take: 501,
    }),
    db.incidentTabletopSession.findMany({
      where, orderBy: { createdAt: "asc" }, take: 501,
    }),
    db.incidentAssuranceHandoffBoard.findMany({
      where, orderBy: { createdAt: "asc" }, take: 501,
    }),
  ]);
  if (reviews.length > 500 || sessions.length > 500 ||
      boards.length > 500)
    fail("TIMELINE_SOURCE_INVENTORY_TOO_LARGE");
  const [reviewEvents, sessionEvents, boardEvents] = await Promise.all([
    db.incidentSituationReviewEvent.findMany({
      where: { organizationId: actor.organizationId,
        reviewId: { in: reviews.map(x => x.id) } },
      orderBy: [{ reviewId: "asc" }, { revision: "asc" }],
      take: limit + 1,
    }),
    db.incidentTabletopSessionEvent.findMany({
      where: { organizationId: actor.organizationId,
        sessionId: { in: sessions.map(x => x.id) } },
      orderBy: [{ sessionId: "asc" }, { revision: "asc" }],
      take: limit + 1,
    }),
    db.incidentAssuranceHandoffEvent.findMany({
      where: { organizationId: actor.organizationId,
        boardId: { in: boards.map(x => x.id) } },
      orderBy: [{ boardId: "asc" }, { revision: "asc" }],
      take: limit + 1,
    }),
  ]);
  if ([incidentEvents, reviewEvents, sessionEvents,
    boardEvents].some(list => list.length > limit))
    fail("TIMELINE_LEDGER_EVENT_CAP_EXCEEDED");
  const entries = [] as ReturnType<typeof recordEntry>[];
  const sourceWarnings: string[] = [];
  const incidentHistory = ledgerIntegrity(incident.revision,
    incidentEvents.map(x => x.revision),
    { integrity: "INCOMPLETE", reason: null });
  if (incidentEvents.length !== incident.revision)
    sourceWarnings.push("INCIDENT_LEDGER_REVISION_GAP");
  for (const event of incidentEvents) {
    entries.push(eventFrom({
      organizationId: actor.organizationId, incidentId,
      source: "INCIDENT", sourceId: incident.id,
      revision: event.revision, eventId: event.id,
      actorId: event.actorUserId, operation: event.command,
      at: event.occurredAt, priorState: event.previousState,
      nextState: event.nextState, priorDigest: null,
      nextDigest: event.snapshotDigest, eventDigest: null,
      integrity: incidentHistory,
    }));
  }
  function indexEvents<T extends { revision: number }>(
    collection: T[], id: (x: T) => string,
  ) {
    const index = new Map<string, T[]>();
    for (const row of collection) {
      const key = id(row);
      const group = index.get(key) ?? [];
      group.push(row);
      index.set(key, group);
    }
    return index;
  }
  const reviewIndex = indexEvents(reviewEvents, x => x.reviewId);
  const sessionIndex = indexEvents(sessionEvents, x => x.sessionId);
  const boardIndex = indexEvents(boardEvents, x => x.boardId);
  for (const review of reviews) {
    const rows = reviewIndex.get(review.id) ?? [];
    const checked = checkSnapshot(review, "SITUATION_REVIEW");
    const integrity = ledgerIntegrity(review.revision,
      rows.map(x => x.revision), checked);
    if (integrity === "CONFLICT" || rows.length !== review.revision)
      sourceWarnings.push("REVIEW_LEDGER_UNVERIFIED:" + review.id);
    for (const event of rows) {
      entries.push(eventFrom({
        organizationId: actor.organizationId, incidentId,
        source: "SITUATION_REVIEW", sourceId: review.id,
        revision: event.revision, eventId: event.id,
        actorId: event.actorUserId, operation: event.decision,
        at: event.occurredAt, priorState: event.previousState,
        nextState: event.nextState, priorDigest: event.previousDigest,
        nextDigest: event.nextDigest, eventDigest: event.eventDigest,
        integrity,
      }));
    }
  }
  for (const session of sessions) {
    const rows = sessionIndex.get(session.id) ?? [];
    const checked = checkSnapshot({
      ...session, incidentId,
    }, "TABLETOP_SESSION");
    const integrity = ledgerIntegrity(session.revision,
      rows.map(x => x.revision), checked);
    if (integrity === "CONFLICT" || rows.length !== session.revision)
      sourceWarnings.push("SESSION_LEDGER_UNVERIFIED:" + session.id);
    for (const event of rows) {
      entries.push(eventFrom({
        organizationId: actor.organizationId, incidentId,
        source: "TABLETOP_SESSION", sourceId: session.id,
        revision: event.revision, eventId: event.id,
        actorId: event.actorUserId, operation: event.kind,
        at: event.at, priorState: null, nextState: session.state,
        priorDigest: event.beforeDigest, nextDigest: event.afterDigest,
        eventDigest: event.eventDigest, integrity,
      }));
    }
  }
  for (const board of boards) {
    const rows = boardIndex.get(board.id) ?? [];
    const checked = checkSnapshot(board, "ASSURANCE_HANDOFF");
    const integrity = ledgerIntegrity(board.revision,
      rows.map(x => x.revision), checked);
    if (integrity === "CONFLICT" || rows.length !== board.revision)
      sourceWarnings.push("HANDOFF_LEDGER_UNVERIFIED:" + board.id);
    for (const event of rows) {
      entries.push(eventFrom({
        organizationId: actor.organizationId, incidentId,
        source: "ASSURANCE_HANDOFF", sourceId: board.id,
        revision: event.revision, eventId: event.id,
        actorId: event.actorUserId, operation: event.action,
        at: event.occurredAt, priorState: null, nextState: board.state,
        priorDigest: event.previousDigest,
        nextDigest: event.nextDigest,
        eventDigest: event.eventDigest, integrity,
      }));
    }
  }
  const page = paginateTimeline({
    organizationId: actor.organizationId, incidentId,
    incidentRevision: incident.revision,
    generatedAt: new Date().toISOString(), events: entries,
    inventoryComplete: sourceWarnings.length === 0,
    query,
  });
  return {
    page, summary: summarizeTimeline(page),
    warnings: sourceWarnings,
    integrityLimitations: [
      "Timeline event source digests have not been independently replayed.",
      "A persisted source snapshot is not proof of external containment.",
      "Source events with no evidence remain INCOMPLETE/UNKNOWN.",
    ], providerWrites: 0 as const,
    notificationsDispatched: 0 as const,
  };
}
export async function exportOperationalTimeline(
  actor: IncidentActor, incidentId: string,
  query: TimelineQuery, format: "json" | "csv",
) {
  const read = await readOperationalTimeline(actor, incidentId, query);
  return {
    content: format === "csv" ?
      exportTimelineCSV(read.page) : exportTimelineJSON(read.page),
    mime: format === "csv" ? "text/csv; charset=utf-8" :
      "application/json; charset=utf-8",
    digest: read.page.pageDigest, providerWrites: 0 as const,
  };
}
