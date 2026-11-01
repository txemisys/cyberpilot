import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, WorkInputError, type WorkRole } from "./remediation-work-input";
import {
  hydrateTriageEvent, TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE,
  type TriageEvent,
} from "./work-integrity-triage";

/**
 * Aggregation of recorded, tenant-scoped review activity in a bounded time
 * window. It is not a control check and cannot certify remediation.
 */
export type AuditDigestScope = { organizationId: string; userId: string; role: WorkRole };
export type AuditDigestFilter = {
  from: Date; to: Date; limit: number;
  actorUserId: string | null; workItemId: string | null;
};
export type AuditDigestBucket = {
  day: string; recorded: number; investigations: number;
  acknowledgements: number; dismissals: number; reopenings: number;
  uniqueCases: number; uniqueWorkItems: number; actors: number;
  unknownActors: number; staleReviews: number; malformed: number;
};
export type AuditDigestActor = {
  actorUserId: string | null; recorded: number;
  decisions: Record<string, number>; workItems: number;
};
export type AuditDigestCase = {
  caseKey: string; workItemId: string; code: string;
  resourceId: string; events: number; lastDecision: string;
  lastEventId: string; lastAt: string;
  latestReviewedRevision: number;
  currentWorkRevision: number | null;
  currentlyReviewed: boolean | null;
};
export type AuditDigest = {
  organizationId: string; generatedAt: string;
  from: string; to: string; rawRecordsRead: number;
  historyTruncated: boolean; malformed: number;
  recorded: number; uniqueWorkItems: number; uniqueCases: number;
  reviewedByActors: number;
  knownActorCount: number;
  unattributedDecisionCount: number;
  outdatedReviewCount: number;
  historyCoverage: "TRUNCATED" | "MALFORMED" | "BOUNDED_COMPLETE";
  decisions: { INVESTIGATE: number; ACKNOWLEDGE: number; DISMISS: number; REOPEN: number };
  daily: AuditDigestBucket[];
  actors: AuditDigestActor[];
  cases: AuditDigestCase[];
  limitations: string[];
};
type Raw = {
  id: string; organizationId: string; resourceId: string | null;
  actorUserId: string | null; occurredAt: Date; metadata: Prisma.JsonValue | null;
};
type Work = { id: string; revision: number };
const MS_DAY = 86400000;
function isoDay(date: Date): string { return date.toISOString().slice(0, 10); }
function uniqueKey(event: TriageEvent): string {
  return JSON.stringify([event.workItemId, event.code, event.resourceId]);
}
export function parseAuditDigestFilter(input: Record<string, unknown>, now = new Date()): AuditDigestFilter {
  const allowed = new Set(["from", "to", "limit", "actorUserId", "workItemId"]);
  for (const key of Object.keys(input))
    if (!allowed.has(key)) throw new WorkInputError("INVALID", "Unknown audit digest option.");
  const end = input.to === undefined ? now : new Date(String(input.to));
  const start = input.from === undefined ?
    new Date(end.getTime() - 6 * MS_DAY) : new Date(String(input.from));
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) ||
      start.getTime() > end.getTime() || end.getTime() - start.getTime() > 31 * MS_DAY)
    throw new WorkInputError("INVALID", "Review window must be ordered and no longer than 31 days.");
  if (end.getTime() > now.getTime() + 5 * 60 * 1000)
    throw new WorkInputError("INVALID", "Review window cannot end in the future.");
  const limit = input.limit === undefined ? 2000 : Number(input.limit);
  if (![100, 500, 2000, 5000].includes(limit))
    throw new WorkInputError("INVALID", "Digest history limit must be 100, 500, 2000 or 5000.");
  const identifier = (value: unknown): string | null => {
    if (value === undefined || value === "") return null;
    if (typeof value !== "string" || value.length < 5 || value.length > 120 ||
        !/^[A-Za-z0-9_-]+$/.test(value))
      throw new WorkInputError("INVALID", "Invalid audit identity filter.");
    return value;
  };
  return {
    from: start, to: end, limit,
    actorUserId: identifier(input.actorUserId),
    workItemId: identifier(input.workItemId),
  };
}
export function aggregateAuditDigest(input: {
  organizationId: string; generatedAt: string;
  filter: AuditDigestFilter; rows: readonly Raw[];
  work: ReadonlyMap<string, Work>; truncated: boolean;
}): AuditDigest {
  const { organizationId, generatedAt, filter, rows, work, truncated } = input;
  if (!organizationId) throw new Error("Trusted tenant identity is required.");
  const cases = new Map<string, AuditDigestCase>();
  const actors = new Map<string, { recorded: number; workItems: Set<string>; decisions: Record<string, number> }>();
  const buckets = new Map<string, {
    bucket: AuditDigestBucket; cases: Set<string>; works: Set<string>; actors: Set<string>;
  }>();
  let malformed = 0;
  const decisions = { INVESTIGATE: 0, ACKNOWLEDGE: 0, DISMISS: 0, REOPEN: 0 };
  const days = Math.floor((filter.to.getTime() - filter.from.getTime()) / MS_DAY) + 1;
  for (let i = 0; i <= days; i++) {
    const day = isoDay(new Date(filter.from.getTime() + i * MS_DAY));
    if (!buckets.has(day)) buckets.set(day, {
      bucket: {
        day, recorded: 0, investigations: 0, acknowledgements: 0,
        dismissals: 0, reopenings: 0, uniqueCases: 0,
        uniqueWorkItems: 0, actors: 0, unknownActors: 0, staleReviews: 0, malformed: 0,
      },
      cases: new Set(), works: new Set(), actors: new Set(),
    });
  }
  const seen = new Set<string>();
  for (const raw of rows) {
    if (raw.organizationId !== organizationId)
      throw new Error("Foreign organization event in audit digest.");
    if (seen.has(raw.id)) throw new Error("Duplicate audit event in digest.");
    seen.add(raw.id);
    if (raw.occurredAt < filter.from || raw.occurredAt > filter.to)
      throw new Error("Audit event outside trusted digest range.");
    const day = isoDay(raw.occurredAt);
    const data = buckets.get(day);
    if (!data) throw new Error("Digest day bucket missing.");
    const event = hydrateTriageEvent(raw);
    if (!event) {
      malformed++;
      data.bucket.malformed++;
      continue;
    }
    if (filter.actorUserId && event.actorUserId !== filter.actorUserId) continue;
    if (filter.workItemId && event.workItemId !== filter.workItemId) continue;
    decisions[event.decision]++;
    data.bucket.recorded++;
    if (event.decision === "INVESTIGATE") data.bucket.investigations++;
    if (event.decision === "ACKNOWLEDGE") data.bucket.acknowledgements++;
    if (event.decision === "DISMISS") data.bucket.dismissals++;
    if (event.decision === "REOPEN") data.bucket.reopenings++;
    const key = uniqueKey(event);
    data.cases.add(key);
    data.works.add(event.workItemId);
    if (event.actorUserId !== null) data.actors.add(event.actorUserId);
    else data.bucket.unknownActors++;
    const current = work.get(event.workItemId)?.revision ?? null;
    if (current !== null && event.revision !== current) data.bucket.staleReviews++;
    const id = event.actorUserId ?? "__missing__";
    const actor = actors.get(id) ?? { recorded: 0, workItems: new Set<string>(), decisions: {} };
    actor.recorded++;
    actor.workItems.add(event.workItemId);
    actor.decisions[event.decision] = (actor.decisions[event.decision] ?? 0) + 1;
    actors.set(id, actor);
    const existing = cases.get(key);
    if (!existing || event.occurredAt.toISOString() > existing.lastAt ||
        (event.occurredAt.toISOString() === existing.lastAt && event.id > existing.lastEventId))
      cases.set(key, {
        caseKey: key, workItemId: event.workItemId,
        code: event.code, resourceId: event.resourceId,
        events: (existing?.events ?? 0) + 1,
        lastDecision: event.decision, lastEventId: event.id,
        lastAt: event.occurredAt.toISOString(), latestReviewedRevision: event.revision,
        currentWorkRevision: current,
        currentlyReviewed: current === null ? null : current === event.revision,
      });
    else existing.events++;
  }
  const daily = [...buckets.values()].map(data => {
    data.bucket.uniqueCases = data.cases.size;
    data.bucket.uniqueWorkItems = data.works.size;
    data.bucket.actors = data.actors.size;
    return data.bucket;
  }).sort((a, b) => a.day.localeCompare(b.day));
  return {
    organizationId, generatedAt,
    from: filter.from.toISOString(), to: filter.to.toISOString(),
    rawRecordsRead: rows.length, historyTruncated: truncated,
    malformed, recorded: Object.values(decisions).reduce((a, b) => a + b, 0),
    uniqueWorkItems: new Set([...cases.values()].map(c => c.workItemId)).size,
    uniqueCases: cases.size, reviewedByActors: actors.size,
    knownActorCount: [...actors.keys()].filter(id => id !== "__missing__").length,
    unattributedDecisionCount: daily.reduce((sum, day) => sum + day.unknownActors, 0),
    outdatedReviewCount: daily.reduce((sum, day) => sum + day.staleReviews, 0),
    historyCoverage: truncated ? "TRUNCATED" : malformed > 0 ?
      "MALFORMED" : "BOUNDED_COMPLETE",
    decisions, daily,
    actors: [...actors].map(([id, actor]) => ({
      actorUserId: id === "__missing__" ? null : id,
      recorded: actor.recorded,
      decisions: actor.decisions, workItems: actor.workItems.size,
    })).sort((a, b) => b.recorded - a.recorded ||
      (a.actorUserId ?? "").localeCompare(b.actorUserId ?? "")),
    cases: [...cases.values()].sort((a, b) =>
      b.lastAt.localeCompare(a.lastAt) || a.caseKey.localeCompare(b.caseKey)),
    limitations: [
      "This report counts recorded human triage actions, never verified remediation.",
      "Case and actor counts are bounded to the filtered source audit window.",
      "Current work revision is contextual and can change after an audit decision.",
      ...(truncated ? ["The audit history cap was reached; all counts are lower bounds."] : []),
      ...(malformed ? ["Unparseable source audit events are excluded from decision counts."] : []),
    ],
  };
}
export async function loadAuditDigest(
  scope: AuditDigestScope, raw: Record<string, unknown>, now = new Date(),
): Promise<AuditDigest> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization membership required.");
  const filter = parseAuditDigestFilter(raw, now);
  if (filter.workItemId) {
    const work = await db.remediationWorkItem.findFirst({
      where: { organizationId: scope.organizationId, id: filter.workItemId },
      select: { id: true },
    });
    if (!work) throw new WorkInputError("MISSING", "Work item unavailable in organization.");
  }
  const rows = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      action: TRIAGE_AUDIT_ACTION, resourceType: TRIAGE_RESOURCE_TYPE,
      occurredAt: { gte: filter.from, lte: filter.to },
      ...(filter.workItemId ? { resourceId: filter.workItemId } : {}),
      ...(filter.actorUserId ? { actorUserId: filter.actorUserId } : {}),
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: filter.limit + 1,
    select: {
      id: true, organizationId: true, resourceId: true, actorUserId: true,
      occurredAt: true, metadata: true,
    },
  });
  const truncated = rows.length > filter.limit;
  const visible = rows.slice(0, filter.limit);
  const ids = [...new Set(visible.map(row => row.resourceId)
    .filter((id): id is string => id !== null))];
  const work = ids.length ? await db.remediationWorkItem.findMany({
    where: { organizationId: scope.organizationId, id: { in: ids } },
    select: { id: true, revision: true },
  }) : [];
  return aggregateAuditDigest({
    organizationId: scope.organizationId, generatedAt: now.toISOString(),
    filter, rows: visible, truncated,
    work: new Map(work.map(item => [item.id, item])),
  });
}
export function auditDigestCsv(digest: AuditDigest): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const fields = [
    "day", "recorded", "investigations", "acknowledgements",
    "dismissals", "reopenings", "uniqueCases", "uniqueWorkItems",
    "actors", "unknownActors", "staleReviews", "malformed",
  ];
  const lines = [fields.map(quote).join(",")];
  for (const day of digest.daily) {
    lines.push(fields.map(field => quote(day[field as keyof AuditDigestBucket])).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
