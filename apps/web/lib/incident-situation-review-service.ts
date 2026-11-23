import { db, type Prisma } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { incidentDigest, validateIncidentSnapshot,
  type IncidentSnapshot } from "./incident-case-domain";
import { readIncidentSituation,
  type SituationSelection } from "./incident-situation-service";
import {
  createSituationReview, applySituationReview, validateSituationReview,
  validateSituationReviewHistory, situationReviewDigest,
  compareSituationReviewSources,
  type SituationReviewSnapshot, type SituationReviewEvent,
  type SituationReviewCommand,
} from "./incident-situation-review-domain";

export class SituationReviewServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new SituationReviewServiceError(code); }
const id = (s: unknown): s is string => typeof s === "string" &&
  /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(s);
const sha = (s: unknown): s is string =>
  typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const roleCanWrite = (role: string) => role === "OWNER" || role === "ADMIN";
async function membership(actor: IncidentActor, write = false) {
  if (!id(actor.organizationId) || !id(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role) ||
      (write && !roleCanWrite(actor.role))) fail("SITUATION_REVIEW_ACTOR_INVALID");
  const found = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!found || found.role !== actor.role)
    fail("SITUATION_REVIEW_MEMBERSHIP_REVOKED");
}
async function incident(actor: IncidentActor, incidentId: string) {
  if (!id(incidentId)) fail("SITUATION_REVIEW_INCIDENT_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { id: incidentId, organizationId: actor.organizationId },
    select: { id: true, organizationId: true, revision: true,
      snapshot: true, snapshotDigest: true },
  });
  if (!row) fail("SITUATION_REVIEW_INCIDENT_NOT_FOUND");
  const snapshot = row.snapshot as unknown as IncidentSnapshot;
  if (!snapshot || validateIncidentSnapshot(snapshot).length ||
      snapshot.id !== row.id || snapshot.organizationId !== row.organizationId ||
      snapshot.revision !== row.revision ||
      incidentDigest(snapshot) !== row.snapshotDigest)
    fail("SITUATION_REVIEW_INCIDENT_TAMPERED");
  return snapshot;
}
type Stored = NonNullable<Awaited<ReturnType<typeof db.incidentSituationReview.findFirst>>>;
function unpack(row: Stored): SituationReviewSnapshot {
  const snapshot = row.snapshot as unknown as SituationReviewSnapshot;
  if (!snapshot || validateSituationReview(snapshot).length ||
      snapshot.id !== row.id || snapshot.organizationId !== row.organizationId ||
      snapshot.incidentId !== row.incidentId ||
      snapshot.revision !== row.revision || snapshot.state !== row.state ||
      snapshot.situationDigest !== row.situationDigest ||
      situationReviewDigest(snapshot) !== row.snapshotDigest)
    fail("SITUATION_REVIEW_SNAPSHOT_CORRUPT");
  return snapshot;
}
function unpackEvents(rows: Array<{
  reviewId: string; organizationId: string; revision: number;
  actorUserId: string; decision: string; occurredAt: Date;
  eventDigest: string; previousDigest: string | null; nextDigest: string;
  previousState: string | null; nextState: string;
}>): SituationReviewEvent[] {
  return rows.map(row => ({
    schema: "cyberpilot.incident.situation.review.event.v1",
    ledgerId: row.reviewId, organizationId: row.organizationId,
    incidentId: "", revision: row.revision,
    decision: row.decision as SituationReviewEvent["decision"],
    actorId: row.actorUserId, at: row.occurredAt.toISOString(),
    previousDigest: row.previousDigest, nextDigest: row.nextDigest,
    previousState: row.previousState as SituationReviewEvent["previousState"],
    nextState: row.nextState as SituationReviewEvent["nextState"],
    eventDigest: row.eventDigest,
  }));
}
function eventData(event: SituationReviewEvent) {
  return {
    organizationId: event.organizationId, reviewId: event.ledgerId,
    revision: event.revision, actorUserId: event.actorId,
    decision: event.decision, occurredAt: new Date(event.at),
    eventDigest: event.eventDigest, previousDigest: event.previousDigest,
    nextDigest: event.nextDigest, previousState: event.previousState,
    nextState: event.nextState,
  };
}
async function fetchReview(actor: IncidentActor, reviewId: string) {
  if (!id(reviewId)) fail("SITUATION_REVIEW_ID_INVALID");
  const record = await db.incidentSituationReview.findFirst({
    where: { id: reviewId, organizationId: actor.organizationId },
  });
  if (!record) fail("SITUATION_REVIEW_NOT_FOUND");
  return { record, snapshot: unpack(record) };
}
export async function createPersistedSituationReview(
  actor: IncidentActor, selection: SituationSelection,
  requestedId: string,
) {
  await membership(actor, true);
  if (!id(requestedId)) fail("SITUATION_REVIEW_ID_INVALID");
  const situationRead = await readIncidentSituation(actor, selection);
  const before = await incident(actor, selection.incidentId);
  if (before.revision !== situationRead.incidentRevision ||
      incidentDigest(before) !== situationRead.situation.incidentSnapshotDigest)
    fail("SITUATION_REVIEW_CASE_DRIFT");
  const now = new Date().toISOString();
  const { snapshot, event } = createSituationReview(
    requestedId, situationRead.situation, actor.userId, actor.role, now,
  );
  return db.$transaction(async tx => {
    const current = await tx.guidedIncidentCase.findFirst({
      where: { organizationId: actor.organizationId, id: before.id },
      select: { revision: true, snapshotDigest: true },
    });
    if (!current || current.revision !== before.revision ||
        current.snapshotDigest !== snapshot.incidentDigest)
      fail("SITUATION_REVIEW_CONCURRENT_CASE_CHANGE");
    const exists = await tx.incidentSituationReview.findFirst({
      where: { organizationId: actor.organizationId, id: requestedId },
    });
    if (exists) {
      const old = unpack(exists);
      if (old.situationDigest !== snapshot.situationDigest ||
          old.openedBy !== actor.userId)
        fail("SITUATION_REVIEW_IDEMPOTENCY_CONFLICT");
      return { review: old, created: false as const,
        externalWrites: 0 as const };
    }
    await tx.incidentSituationReview.create({ data: {
      id: snapshot.id, organizationId: actor.organizationId,
      incidentId: snapshot.incidentId, revision: snapshot.revision,
      state: snapshot.state, situationDigest: snapshot.situationDigest,
      snapshotDigest: situationReviewDigest(snapshot),
      snapshot: snapshot as unknown as Prisma.InputJsonValue,
      createdById: actor.userId, createdAt: new Date(now),
      updatedAt: new Date(now),
    } });
    await tx.incidentSituationReviewEvent.create({ data: eventData(event) });
    return { review: snapshot, created: true as const,
      externalWrites: 0 as const };
  }, { isolationLevel: "Serializable" });
}
export async function mutatePersistedSituationReview(
  actor: IncidentActor,
  command: Omit<SituationReviewCommand,
    "organizationId" | "actorId" | "role" | "at"> & { reviewId: string },
) {
  await membership(actor, true);
  const { snapshot: previous } = await fetchReview(actor, command.reviewId);
  const currentCase = await incident(actor, previous.incidentId);
  if (currentCase.revision !== previous.incidentRevision ||
      incidentDigest(currentCase) !== previous.incidentDigest)
    fail("SITUATION_REVIEW_INCIDENT_MOVED");
  const { snapshot: next, event } = applySituationReview(previous, {
    ...command, organizationId: actor.organizationId,
    actorId: actor.userId, role: actor.role, at: new Date().toISOString(),
    incidentId: previous.incidentId,
  });
  return db.$transaction(async tx => {
    const currentCaseRow = await tx.guidedIncidentCase.findFirst({
      where: { organizationId: actor.organizationId, id: previous.incidentId },
      select: { revision: true, snapshotDigest: true },
    });
    if (!currentCaseRow || currentCaseRow.revision !== previous.incidentRevision ||
        currentCaseRow.snapshotDigest !== previous.incidentDigest)
      fail("SITUATION_REVIEW_INCIDENT_RACE");
    const cas = await tx.incidentSituationReview.updateMany({
      where: { id: previous.id, organizationId: actor.organizationId,
        revision: previous.revision,
        snapshotDigest: situationReviewDigest(previous) },
      data: {
        state: next.state, revision: next.revision,
        snapshotDigest: situationReviewDigest(next),
        snapshot: next as unknown as Prisma.InputJsonValue,
        updatedAt: new Date(next.updatedAt),
      },
    });
    if (cas.count !== 1) fail("SITUATION_REVIEW_CAS_CONFLICT");
    await tx.incidentSituationReviewEvent.create({ data: eventData(event) });
    return { review: next, event, externalWrites: 0 as const,
      independentlyContained: false as const };
  }, { isolationLevel: "Serializable" });
}
export async function readPersistedSituationReview(
  actor: IncidentActor, reviewId: string,
) {
  await membership(actor);
  const { snapshot } = await fetchReview(actor, reviewId);
  const rows = await db.incidentSituationReviewEvent.findMany({
    where: { organizationId: actor.organizationId, reviewId },
    orderBy: [{ revision: "asc" }],
    take: 1500,
  });
  // The event table stores no duplicate incidentId. Recover it only from the
  // validated parent row, never a caller-controlled argument.
  const events = unpackEvents(rows).map(row => ({
    ...row, incidentId: snapshot.incidentId,
  }));
  const violations = validateSituationReviewHistory(snapshot, events);
  if (violations.length)
    fail("SITUATION_REVIEW_AUDIT_INTEGRITY:" + violations.join(","));
  const currentCase = await incident(actor, snapshot.incidentId);
  return {
    schema: "cyberpilot.incident.situation.review.read.v1" as const,
    review: snapshot, events, caseDrift:
      currentCase.revision !== snapshot.incidentRevision ||
      incidentDigest(currentCase) !== snapshot.incidentDigest,
    provenance: "DATABASE_OFFLINE_ATTESTATION" as const,
    providerReadbackVerified: false as const,
    externalWrites: 0 as const,
  };
}
export async function listPersistedSituationReviews(
  actor: IncidentActor,
  incidentId: string,
  offset = 0, limit = 30,
) {
  await membership(actor);
  await incident(actor, incidentId);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    fail("SITUATION_REVIEW_PAGINATION_INVALID");
  const where = { organizationId: actor.organizationId, incidentId };
  const [rows, total] = await Promise.all([
    db.incidentSituationReview.findMany({ where, skip: offset, take: limit,
      orderBy: [{ createdAt: "desc" }, { id: "asc" }] }),
    db.incidentSituationReview.count({ where }),
  ]);
  return {
    schema: "cyberpilot.incident.situation.review.index.v1" as const,
    total, offset, limit,
    nextOffset: offset + limit < total ? offset + limit : null,
    reviews: rows.map(unpack),
    source: "PERSISTED_OPERATOR_REVIEW" as const,
    independentProviderVerification: false as const,
  };
}
export async function comparePersistedSituationReview(
  actor: IncidentActor, reviewId: string,
  selection: SituationSelection,
) {
  await membership(actor);
  const { snapshot } = await fetchReview(actor, reviewId);
  if (selection.incidentId !== snapshot.incidentId)
    fail("SITUATION_REVIEW_COMPARISON_CASE_MISMATCH");
  const report = await readIncidentSituation(actor, selection);
  return {
    schema: "cyberpilot.incident.situation.review.compare.v1" as const,
    reviewId, reviewRevision: snapshot.revision,
    comparison: compareSituationReviewSources(snapshot, report.situation),
    reviewedSituationDigest: snapshot.situationDigest,
    currentSituationDigest: report.situation.situationDigest,
    independentProviderVerification: false as const,
  };
}
