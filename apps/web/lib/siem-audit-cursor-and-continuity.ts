import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { normalizePortableAuditEvent, verifyPortableAuditBatch,
  type PortableAuditEvent, type PortableAuditInput,
  type SiemExportPolicy, DEFAULT_SIEM_POLICY } from "./siem-audit-interchange-domain";
export type SiemCursorData = {
  version: 1; organizationId: string; afterAt: string;
  afterEventId: string; actionFilter: string | null;
  resourceFilter: string | null; upperBound: string;
};
export type SiemPage = {
  schema: "cyberpilot.siem.audit.page.v1";
  organizationId: string; evaluatedAt: string; selection: {
    since: string; until: string; action: string | null;
    resourceType: string | null; limit: number;
  }; events: PortableAuditEvent[]; hasMore: boolean;
  nextCursor: string | null; source: "PERSISTED_POSTGRESQL_AUDIT";
  coverage: "PAGED_READ_ONLY"; providerCalls: 0;
  independentlyDelivered: false; productionSIEMIntegrated: false;
  integrity: ReturnType<typeof verifyPortableAuditBatch>;
  pageDigest: string;
};
const validDate = (s: unknown): s is string =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const ident = (s: unknown): s is string =>
  typeof s === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
function safeCompare(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function encodeSiemCursor(data: SiemCursorData, secret: string) {
  if (!ident(data.organizationId) || !ident(data.afterEventId) ||
      !validDate(data.afterAt) || !validDate(data.upperBound) ||
      data.afterAt > data.upperBound || data.version !== 1 ||
      secret.length < 32) throw Error("SIEM_CURSOR_CREATION_INVALID");
  const encoded = Buffer.from(JSON.stringify(data), "utf8").toString("base64url");
  const mac = createHmac("sha256", secret).update(encoded).digest("base64url");
  return encoded + "." + mac;
}
export function decodeSiemCursor(cursor: string, secret: string,
  organizationId: string): SiemCursorData {
  if (typeof cursor !== "string" || cursor.length > 1200 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(cursor) ||
      secret.length < 32) throw Error("SIEM_CURSOR_INVALID");
  const [encoded, mac] = cursor.split(".");
  if (!encoded || !mac || !safeCompare(
      createHmac("sha256", secret).update(encoded).digest("base64url"), mac))
    throw Error("SIEM_CURSOR_AUTHENTICATION_FAILED");
  let item: unknown;
  try { item = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")); }
  catch { throw Error("SIEM_CURSOR_CONTENT_INVALID"); }
  if (!item || typeof item !== "object" || Array.isArray(item))
    throw Error("SIEM_CURSOR_CONTENT_INVALID");
  const value = item as SiemCursorData;
  if (value.version !== 1 || value.organizationId !== organizationId ||
      !ident(value.afterEventId) || !validDate(value.afterAt) ||
      !validDate(value.upperBound) || value.afterAt > value.upperBound ||
      value.actionFilter !== null && (typeof value.actionFilter !== "string" ||
        value.actionFilter.length > 150) ||
      value.resourceFilter !== null && (typeof value.resourceFilter !== "string" ||
        value.resourceFilter.length > 100))
    throw Error("SIEM_CURSOR_SCOPE_INVALID");
  return value;
}
export type SiemPageQuery = {
  organizationId: string; since: string; until: string;
  limit: number; action: string | null; resourceType: string | null;
  cursor: string | null;
};
export function validateSiemPageQuery(query: SiemPageQuery): string[] {
  const issues: string[] = [];
  if (!ident(query.organizationId)) issues.push("SIEM_ORG_INVALID");
  if (!validDate(query.since) || !validDate(query.until) ||
      query.since >= query.until ||
      Date.parse(query.until) - Date.parse(query.since) > 366 * 86400000)
    issues.push("SIEM_TIME_WINDOW_INVALID");
  if (!Number.isSafeInteger(query.limit) || query.limit < 1 || query.limit > 100)
    issues.push("SIEM_LIMIT_INVALID");
  if (query.action !== null &&
      !/^[A-Za-z0-9_.:-]{2,150}$/.test(query.action))
    issues.push("SIEM_ACTION_FILTER_INVALID");
  if (query.resourceType !== null &&
      !/^[A-Za-z0-9_.:-]{2,100}$/.test(query.resourceType))
    issues.push("SIEM_RESOURCE_FILTER_INVALID");
  if (query.cursor !== null && (typeof query.cursor !== "string" ||
      query.cursor.length > 1200)) issues.push("SIEM_CURSOR_TOO_LONG");
  return issues;
}
export function buildSiemPage(query: SiemPageQuery,
  input: PortableAuditInput[], at: string, hasMore: boolean,
  secret: string, policy: SiemExportPolicy = DEFAULT_SIEM_POLICY): SiemPage {
  const errors = validateSiemPageQuery(query);
  if (errors.length) throw Error(errors.join(","));
  if (!validDate(at) || input.length > query.limit) throw Error("SIEM_PAGE_SOURCE_BOUND_INVALID");
  const events = input.map(row => normalizePortableAuditEvent(row, policy));
  const integrity = verifyPortableAuditBatch(query.organizationId, events);
  if (!integrity.valid) throw Error("SIEM_PAGE_INTEGRITY_FAILED:" + integrity.issues.join(","));
  const last = events.at(-1);
  if (hasMore && !last) throw Error("SIEM_PAGE_CURSOR_WITHOUT_EVENT");
  const pageDigest = createHash("sha256").update(JSON.stringify({
    query: { organizationId: query.organizationId, since: query.since,
      until: query.until, action: query.action, resourceType: query.resourceType },
    events,
  })).digest("hex");
  const nextCursor = hasMore && last ? encodeSiemCursor({
    version: 1, organizationId: query.organizationId,
    afterAt: last.occurredAt, afterEventId: last.eventId,
    actionFilter: query.action, resourceFilter: query.resourceType,
    upperBound: query.until,
  }, secret) : null;
  return { schema: "cyberpilot.siem.audit.page.v1",
    organizationId: query.organizationId, evaluatedAt: at,
    selection: { since: query.since, until: query.until,
      action: query.action, resourceType: query.resourceType, limit: query.limit },
    events, hasMore, nextCursor,
    source: "PERSISTED_POSTGRESQL_AUDIT", coverage: "PAGED_READ_ONLY",
    providerCalls: 0, independentlyDelivered: false,
    productionSIEMIntegrated: false, integrity, pageDigest };
}
export type SiemContinuity = {
  schema: "cyberpilot.siem.continuity.v1"; organizationId: string;
  pageCount: number; uniqueEvents: number;
  repeatedEvents: string[]; gaps: string[]; pageDigests: string[];
  complete: boolean; externallyAcknowledged: false;
};
export function verifySiemContinuity(pages: SiemPage[],
  organizationId: string): SiemContinuity {
  const ids = new Set<string>(), repeatedEvents: string[] = [],
    gaps: string[] = [];
  const digests: string[] = [];
  for (let index = 0; index < pages.length; index++) {
    const page = pages[index]!;
    if (page.organizationId !== organizationId ||
        !page.integrity.valid) throw Error("SIEM_CONTINUITY_TENANT_INVALID");
    digests.push(page.pageDigest);
    for (const event of page.events) {
      if (ids.has(event.eventId)) repeatedEvents.push(event.eventId);
      ids.add(event.eventId);
    }
    const prior = pages[index - 1];
    if (prior) {
      const last = prior.events.at(-1), first = page.events[0];
      if (!last || !first || last.occurredAt > first.occurredAt ||
          last.occurredAt === first.occurredAt && last.eventId >= first.eventId)
        gaps.push("NON_MONOTONIC_PAGE_" + index);
      if (!prior.hasMore || !prior.nextCursor)
        gaps.push("CONTINUATION_NOT_ADVERTISED_" + index);
      if (prior.selection.since !== page.selection.since ||
          prior.selection.until !== page.selection.until ||
          prior.selection.action !== page.selection.action ||
          prior.selection.resourceType !== page.selection.resourceType)
        gaps.push("FILTER_DRIFT_" + index);
    }
  }
  return { schema: "cyberpilot.siem.continuity.v1",
    organizationId, pageCount: pages.length,
    uniqueEvents: ids.size, repeatedEvents, gaps, pageDigests: digests,
    complete: pages.length > 0 && repeatedEvents.length === 0 &&
      gaps.length === 0 && pages.at(-1)!.hasMore === false,
    externallyAcknowledged: false };
}
