import { createHash } from "node:crypto";

/**
 * Unified, immutable projection of four incident ledgers. A timeline is a
 * read model, never an authorization to execute remediation.
 */
export type TimelineSource = "INCIDENT" | "SITUATION_REVIEW" |
  "TABLETOP_SESSION" | "ASSURANCE_HANDOFF";
export type TimelineIntegrity = "VERIFIED" | "INCOMPLETE" | "CONFLICT";
export type TimelineEvent = {
  schema: "cyberpilot.incident.timeline.entry.v1";
  organizationId: string;
  incidentId: string;
  source: TimelineSource;
  sourceId: string;
  sourceRevision: number;
  eventId: string;
  actorUserId: string;
  operation: string;
  occurredAt: string;
  priorState: string | null;
  nextState: string | null;
  priorDigest: string | null;
  nextDigest: string;
  sourceEventDigest: string | null;
  sourceIntegrity: TimelineIntegrity;
  internalOnly: true;
  providerWrites: 0;
  providerOutcomeIndependentlyVerified: false;
};
export type TimelineSourceStatus = {
  source: TimelineSource;
  ledgers: number;
  entries: number;
  valid: number;
  incomplete: number;
  conflicts: number;
  lastActivityAt: string | null;
};
export type TimelinePage = {
  schema: "cyberpilot.incident.timeline.page.v1";
  organizationId: string;
  incidentId: string;
  incidentRevision: number;
  generatedAt: string;
  entries: TimelineEvent[];
  nextCursor: string | null;
  total: number;
  sourceStatus: TimelineSourceStatus[];
  completeness: "COMPLETE" | "PARTIAL" | "UNKNOWN";
  integrity: TimelineIntegrity;
  queryDigest: string;
  pageDigest: string;
  externalActions: 0;
  providerOutcomeIndependentlyVerified: false;
};
export type TimelineQuery = {
  sources?: TimelineSource[];
  actorUserId?: string;
  from?: string;
  to?: string;
  operation?: string;
  integrity?: TimelineIntegrity[];
  limit?: number;
  cursor?: string | null;
};
export type RawTimelineEvent = Omit<TimelineEvent,
  "schema" | "sourceIntegrity" | "internalOnly" | "providerWrites" |
  "providerOutcomeIndependentlyVerified"> & {
    sourceIntegrity?: TimelineIntegrity;
  };
export type TimelineReconciliation = {
  entries: TimelineEvent[];
  problems: Array<{
    code: string;
    source: TimelineSource;
    sourceId: string;
    revision: number | null;
  }>;
  sourceStatus: TimelineSourceStatus[];
  integrity: TimelineIntegrity;
};
const sources: TimelineSource[] = ["INCIDENT", "SITUATION_REVIEW",
  "TABLETOP_SESSION", "ASSURANCE_HANDOFF"];
const states: TimelineIntegrity[] = ["VERIFIED", "INCOMPLETE", "CONFLICT"];
const identifier = (x: unknown): x is string =>
  typeof x === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(x);
const digest = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const iso = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
    new Date(x).toISOString() === x;
function canonical(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canonical);
  if (x !== null && typeof x === "object") {
    const r = x as Record<string, unknown>;
    return Object.fromEntries(Object.keys(r).sort()
      .filter(k => r[k] !== undefined).map(k => [k, canonical(r[k])]));
  }
  return x;
}
export function timelineDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}
const reject = (code: string): never => { throw Error(code); };
function tuple(event: Pick<TimelineEvent,
  "occurredAt" | "source" | "sourceId" | "sourceRevision" | "eventId">) {
  return [event.occurredAt, event.source, event.sourceId,
    String(event.sourceRevision).padStart(12, "0"), event.eventId].join("\0");
}
export function validateTimelineQuery(query: TimelineQuery): TimelineQuery {
  if (!query || typeof query !== "object" || Array.isArray(query))
    reject("TIMELINE_QUERY_REQUIRED");
  if (Object.keys(query).some(k => ![
    "sources", "actorUserId", "from", "to", "operation", "integrity",
    "limit", "cursor",
  ].includes(k))) reject("TIMELINE_QUERY_FIELD_UNKNOWN");
  if (query.sources !== undefined &&
      (!Array.isArray(query.sources) || query.sources.length > 4 ||
        query.sources.some(x => !sources.includes(x)) ||
        new Set(query.sources).size !== query.sources.length))
    reject("TIMELINE_SOURCES_INVALID");
  if (query.integrity !== undefined &&
      (!Array.isArray(query.integrity) || query.integrity.length > 3 ||
        query.integrity.some(x => !states.includes(x)) ||
        new Set(query.integrity).size !== query.integrity.length))
    reject("TIMELINE_INTEGRITY_FILTER_INVALID");
  if (query.actorUserId !== undefined && !identifier(query.actorUserId))
    reject("TIMELINE_ACTOR_INVALID");
  if (query.from !== undefined && !iso(query.from))
    reject("TIMELINE_FROM_INVALID");
  if (query.to !== undefined && !iso(query.to))
    reject("TIMELINE_TO_INVALID");
  if (query.from && query.to && query.from > query.to)
    reject("TIMELINE_RANGE_REVERSED");
  if (query.operation !== undefined &&
      (typeof query.operation !== "string" ||
        !/^[A-Z][A-Z0-9_]{1,47}$/.test(query.operation)))
    reject("TIMELINE_OPERATION_INVALID");
  if (query.limit !== undefined &&
      (!Number.isSafeInteger(query.limit) || query.limit < 1 ||
        query.limit > 100)) reject("TIMELINE_LIMIT_INVALID");
  if (query.cursor !== undefined && query.cursor !== null &&
      (typeof query.cursor !== "string" || query.cursor.length > 4096))
    reject("TIMELINE_CURSOR_INVALID");
  return query;
}
export function verifyTimelineEvent(event: TimelineEvent): string[] {
  const issues: string[] = [];
  if (event?.schema !== "cyberpilot.incident.timeline.entry.v1")
    issues.push("TIMELINE_ENTRY_SCHEMA_INVALID");
  if (![event?.organizationId, event?.incidentId, event?.sourceId,
    event?.actorUserId, event?.eventId].every(identifier))
    issues.push("TIMELINE_ENTRY_ID_INVALID");
  if (!sources.includes(event?.source)) issues.push("TIMELINE_SOURCE_INVALID");
  if (!Number.isSafeInteger(event?.sourceRevision) ||
    event.sourceRevision < 1) issues.push("TIMELINE_REVISION_INVALID");
  if (!iso(event?.occurredAt)) issues.push("TIMELINE_AT_INVALID");
  if (typeof event?.operation !== "string" ||
      !/^[A-Z][A-Z0-9_]{1,47}$/.test(event.operation))
    issues.push("TIMELINE_OPERATION_INVALID");
  if (event.priorState !== null &&
      (typeof event.priorState !== "string" ||
        event.priorState.length > 48)) issues.push("TIMELINE_PRIOR_STATE_INVALID");
  if (event.nextState !== null &&
      (typeof event.nextState !== "string" ||
        event.nextState.length > 48)) issues.push("TIMELINE_NEXT_STATE_INVALID");
  if (event.priorDigest !== null && !digest(event.priorDigest) ||
      !digest(event.nextDigest) ||
      event.sourceEventDigest !== null && !digest(event.sourceEventDigest))
    issues.push("TIMELINE_DIGEST_INVALID");
  if (!states.includes(event.sourceIntegrity))
    issues.push("TIMELINE_INTEGRITY_INVALID");
  if (event.internalOnly !== true || event.providerWrites !== 0 ||
      event.providerOutcomeIndependentlyVerified !== false)
    issues.push("TIMELINE_PROVIDER_ASSERTION_FORGED");
  return issues;
}
export function normalizeTimelineEvent(raw: RawTimelineEvent): TimelineEvent {
  const event: TimelineEvent = {
    ...raw,
    schema: "cyberpilot.incident.timeline.entry.v1",
    sourceIntegrity: raw.sourceIntegrity ?? "INCOMPLETE",
    internalOnly: true,
    providerWrites: 0,
    providerOutcomeIndependentlyVerified: false,
  };
  const problems = verifyTimelineEvent(event);
  if (problems.length) reject(problems.join(","));
  return event;
}
export function reconcileTimeline(entries: TimelineEvent[]): TimelineReconciliation {
  if (!Array.isArray(entries) || entries.length > 25000)
    reject("TIMELINE_BOUNDED_INPUT_REQUIRED");
  const ledgerMap = new Map<string, TimelineEvent[]>();
  const problems: TimelineReconciliation["problems"] = [];
  const seen = new Set<string>();
  const result: TimelineEvent[] = [];
  for (const entry of entries) {
    const invalid = verifyTimelineEvent(entry);
    if (invalid.length) {
      problems.push({ code: invalid[0]!, source: entry.source,
        sourceId: entry.sourceId, revision: entry.sourceRevision });
      continue;
    }
    const eventKey = [entry.organizationId, entry.source,
      entry.sourceId, entry.sourceRevision].join(":");
    if (seen.has(eventKey)) {
      problems.push({ code: "TIMELINE_REVISION_DUPLICATE", source: entry.source,
        sourceId: entry.sourceId, revision: entry.sourceRevision });
      continue;
    }
    seen.add(eventKey);
    const key = [entry.source, entry.sourceId].join(":");
    const ledger = ledgerMap.get(key) ?? [];
    ledger.push(entry);
    ledgerMap.set(key, ledger);
    result.push(entry);
  }
  for (const ledger of ledgerMap.values()) {
    ledger.sort((a, b) => a.sourceRevision - b.sourceRevision);
    for (let i = 0; i < ledger.length; i++) {
      const event = ledger[i]!;
      if (event.sourceRevision !== i + 1) {
        problems.push({ code: "TIMELINE_REVISION_GAP", source: event.source,
          sourceId: event.sourceId, revision: event.sourceRevision });
        event.sourceIntegrity = "INCOMPLETE";
      }
      if (i > 0 && event.occurredAt < ledger[i - 1]!.occurredAt) {
        problems.push({ code: "TIMELINE_TIME_REGRESSION", source: event.source,
          sourceId: event.sourceId, revision: event.sourceRevision });
        event.sourceIntegrity = "CONFLICT";
      }
      if (i > 0 && event.priorDigest !== null &&
          event.priorDigest !== ledger[i - 1]!.nextDigest) {
        problems.push({ code: "TIMELINE_DIGEST_CHAIN_BROKEN", source: event.source,
          sourceId: event.sourceId, revision: event.sourceRevision });
        event.sourceIntegrity = "CONFLICT";
      }
      // Presence of a source event digest alone does not prove chain validity.
      if (event.sourceIntegrity === "VERIFIED" &&
          event.sourceEventDigest === null && event.source !== "INCIDENT")
        event.sourceIntegrity = "INCOMPLETE";
    }
  }
  result.sort((a, b) => tuple(b).localeCompare(tuple(a)));
  const sourceStatus = sources.map(source => {
    const own = result.filter(x => x.source === source);
    return {
      source, ledgers: new Set(own.map(x => x.sourceId)).size,
      entries: own.length,
      valid: own.filter(x => x.sourceIntegrity === "VERIFIED").length,
      incomplete: own.filter(x => x.sourceIntegrity === "INCOMPLETE").length,
      conflicts: own.filter(x => x.sourceIntegrity === "CONFLICT").length,
      lastActivityAt: own[0]?.occurredAt ?? null,
    };
  });
  const integrity = problems.some(x =>
    /DUPLICATE|BROKEN|REGRESSION/.test(x.code)) ||
    result.some(x => x.sourceIntegrity === "CONFLICT") ? "CONFLICT" :
    problems.length || result.some(x => x.sourceIntegrity === "INCOMPLETE") ?
      "INCOMPLETE" : "VERIFIED";
  return { entries: result, problems, sourceStatus, integrity };
}
function encodeCursor(key: string, queryDigest: string): string {
  return Buffer.from(JSON.stringify({ v: 1, key, queryDigest }))
    .toString("base64url");
}
function decodeCursor(cursor: string, queryDigest: string): string {
  try {
    const obj = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as
      { v?: unknown; key?: unknown; queryDigest?: unknown };
    if (obj.v !== 1 || typeof obj.key !== "string" ||
        obj.queryDigest !== queryDigest || obj.key.length > 512)
      reject("TIMELINE_CURSOR_STALE");
    return obj.key as string;
  } catch { return reject("TIMELINE_CURSOR_INVALID"); }
}
export function paginateTimeline(args: {
  organizationId: string; incidentId: string; incidentRevision: number;
  generatedAt: string; events: TimelineEvent[]; query: TimelineQuery;
  inventoryComplete: boolean;
}): TimelinePage {
  if (!identifier(args.organizationId) || !identifier(args.incidentId) ||
      !Number.isSafeInteger(args.incidentRevision) ||
      args.incidentRevision < 1 || !iso(args.generatedAt))
    reject("TIMELINE_CONTEXT_INVALID");
  const query = validateTimelineQuery(args.query);
  const reconciled = reconcileTimeline(args.events.map(x => ({ ...x })));
  if (reconciled.entries.some(x => x.organizationId !== args.organizationId ||
      x.incidentId !== args.incidentId))
    reject("TIMELINE_CROSS_TENANT_OR_INCIDENT");
  const filters = { ...query, cursor: undefined, limit: undefined };
  const queryDigest = timelineDigest({
    organizationId: args.organizationId, incidentId: args.incidentId,
    incidentRevision: args.incidentRevision, filters,
    inventoryDigest: timelineDigest(reconciled.entries),
  });
  const cursorKey = query.cursor ? decodeCursor(query.cursor, queryDigest) : null;
  const filtered = reconciled.entries.filter(x =>
    (!query.sources || query.sources.includes(x.source)) &&
    (!query.actorUserId || x.actorUserId === query.actorUserId) &&
    (!query.from || x.occurredAt >= query.from) &&
    (!query.to || x.occurredAt <= query.to) &&
    (!query.operation || x.operation === query.operation) &&
    (!query.integrity || query.integrity.includes(x.sourceIntegrity)));
  const after = cursorKey ? filtered.filter(x => tuple(x) < cursorKey) : filtered;
  const limit = query.limit ?? 40;
  const entries = after.slice(0, limit);
  const nextCursor = after.length > limit && entries.length ?
    encodeCursor(tuple(entries[entries.length - 1]!), queryDigest) : null;
  const completeness = !args.inventoryComplete ? "UNKNOWN" :
    reconciled.integrity === "VERIFIED" ? "COMPLETE" : "PARTIAL";
  const page: Omit<TimelinePage, "pageDigest"> = {
    schema: "cyberpilot.incident.timeline.page.v1",
    organizationId: args.organizationId, incidentId: args.incidentId,
    incidentRevision: args.incidentRevision,
    generatedAt: args.generatedAt, entries, nextCursor,
    total: filtered.length, sourceStatus: reconciled.sourceStatus,
    completeness, integrity: reconciled.integrity,
    queryDigest, externalActions: 0,
    providerOutcomeIndependentlyVerified: false,
  };
  return { ...page, pageDigest: timelineDigest(page) };
}
export function exportTimelineJSON(page: TimelinePage): string {
  if (page.pageDigest !== timelineDigest({ ...page, pageDigest: undefined }))
    reject("TIMELINE_PAGE_DIGEST_MISMATCH");
  return JSON.stringify(page, null, 2);
}
const csvField = (value: string) => {
  // All exported values are untrusted. Quote CSV formulas, including tabs.
  const safe = /^[\s]*[=+@-]/.test(value) || /^[\s]*[\t\r]/.test(value) ?
    "'" + value : value;
  return '"' + safe.replace(/"/g, '""') + '"';
};
export function exportTimelineCSV(page: TimelinePage): string {
  if (page.pageDigest !== timelineDigest({ ...page, pageDigest: undefined }))
    reject("TIMELINE_PAGE_DIGEST_MISMATCH");
  const columns = ["occurredAt", "source", "sourceId", "sourceRevision",
    "eventId", "actorUserId", "operation", "priorState", "nextState",
    "sourceIntegrity", "sourceEventDigest", "nextDigest"];
  return [columns.join(","), ...page.entries.map(row =>
    columns.map(k => csvField(String(
      (row as unknown as Record<string, unknown>)[k] ?? ""))).join(","))]
    .join("\r\n") + "\r\n";
}
export function summarizeTimeline(page: TimelinePage) {
  const counts = Object.fromEntries(sources.map(source => [
    source, { entries: 0, lastAt: null as string | null,
      actors: new Set<string>(), operations: new Map<string, number>() },
  ])) as Record<TimelineSource, {
    entries: number; lastAt: string | null;
    actors: Set<string>; operations: Map<string, number>;
  }>;
  for (const row of page.entries) {
    const count = counts[row.source];
    count.entries++;
    count.actors.add(row.actorUserId);
    count.lastAt = count.lastAt === null || row.occurredAt > count.lastAt ?
      row.occurredAt : count.lastAt;
    count.operations.set(row.operation,
      (count.operations.get(row.operation) ?? 0) + 1);
  }
  return {
    schema: "cyberpilot.incident.timeline.summary.v1" as const,
    completeness: page.completeness,
    integrity: page.integrity, pageDigest: page.pageDigest,
    displayed: page.entries.length, matchingTotal: page.total,
    nextCursorAvailable: page.nextCursor !== null,
    categories: sources.map(source => ({
      source, entries: counts[source].entries,
      uniqueInternalActors: counts[source].actors.size,
      lastAt: counts[source].lastAt,
      operations: [...counts[source].operations].map(([operation, count]) =>
        ({ operation, count })).sort((a, b) =>
          b.count - a.count || a.operation.localeCompare(b.operation)),
    })),
    providerWrites: 0 as const,
    providerOutcomesVerified: false as const,
  };
}
