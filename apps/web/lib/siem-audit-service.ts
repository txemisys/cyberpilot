import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { DEFAULT_SIEM_POLICY, type SiemFormat, type PortableAuditInput,
  validateSiemPolicy } from "./siem-audit-interchange-domain";
import { buildSiemPage, decodeSiemCursor, validateSiemPageQuery,
  type SiemPageQuery } from "./siem-audit-cursor-and-continuity";
import { buildSiemExport, inspectSiemPageQuality,
  inspectSiemForwardingReadiness } from "./siem-audit-exports";

export class SiemAuditServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new SiemAuditServiceError(code); }
const ident = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
type Actor = { organizationId: string; userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR" };
export type SiemAuditRequest = {
  since?: string; until?: string; limit?: number;
  action?: string; resourceType?: string; cursor?: string;
  format?: SiemFormat; includeActorReference?: boolean;
  includeResourceReference?: boolean;
};
async function authorize(actor: Actor, exportRequested: boolean) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("SIEM_ACCESS_DENIED");
  if (exportRequested && !["OWNER", "ADMIN"].includes(actor.role))
    fail("SIEM_EXPORT_ADMIN_REQUIRED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role) fail("SIEM_MEMBERSHIP_REVOKED");
}
function toPortable(row: {
  id: string; organizationId: string; action: string; resourceType: string;
  resourceId: string | null; actorType: string; actorUserId: string | null;
  metadata: Prisma.JsonValue | null; occurredAt: Date;
}): PortableAuditInput {
  return { id: row.id, organizationId: row.organizationId,
    action: row.action, resourceType: row.resourceType,
    resourceId: row.resourceId, actorType: row.actorType,
    actorUserId: row.actorUserId, metadata: row.metadata,
    occurredAt: row.occurredAt.toISOString() };
}
function secretForCursors() {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) fail("SIEM_CURSOR_SECRET_UNAVAILABLE");
  return secret;
}
/** Database-canonical stable order (occurredAt, id); cursor is org-scoped HMAC. */
export async function readSiemAuditPage(actor: Actor, input: SiemAuditRequest = {}) {
  await authorize(actor, input.format !== undefined);
  const now = new Date(), start = new Date(now.getTime() - 7 * 86400000);
  const since = input.since ?? start.toISOString(),
    until = input.until ?? now.toISOString();
  const limit = input.limit ?? 50;
  if (input.format !== undefined &&
      !["JSONL", "ECS", "CEF", "CSV"].includes(input.format))
    fail("SIEM_EXPORT_FORMAT_INVALID");
  const secret = secretForCursors();
  const cursor = input.cursor ?
    decodeSiemCursor(input.cursor, secret, actor.organizationId) : null;
  if (cursor && (input.until !== undefined && cursor.upperBound !== until ||
      input.action !== undefined && input.action !== cursor.actionFilter ||
      input.resourceType !== undefined && input.resourceType !== cursor.resourceFilter))
    fail("SIEM_CURSOR_FILTER_CONFLICT");
  const query: SiemPageQuery = {
    organizationId: actor.organizationId,
    since, until: cursor?.upperBound ?? until, limit,
    action: cursor?.actionFilter ?? input.action ?? null,
    resourceType: cursor?.resourceFilter ?? input.resourceType ?? null,
    cursor: input.cursor ?? null,
  };
  const errors = validateSiemPageQuery(query);
  if (errors.length) fail(errors[0]!);
  if (cursor && (cursor.afterAt < query.since ||
      cursor.afterAt > query.until)) fail("SIEM_CURSOR_TIME_OUTSIDE_WINDOW");
  const policy = {
    ...DEFAULT_SIEM_POLICY,
    includeActorReferences: input.includeActorReference === true &&
      ["OWNER", "ADMIN"].includes(actor.role),
    includeResourceReferences: input.includeResourceReference === true &&
      ["OWNER", "ADMIN"].includes(actor.role),
    resourceReferenceMode: "HASH" as const,
  };
  if (validateSiemPolicy(policy).length) fail("SIEM_EFFECTIVE_POLICY_INVALID");
  const filters = {
    organizationId: actor.organizationId,
    occurredAt: { gte: new Date(query.since), lte: new Date(query.until) },
    ...(query.action ? { action: query.action } : {}),
    ...(query.resourceType ? { resourceType: query.resourceType } : {}),
  };
  const where: Prisma.AuditEventWhereInput = {
    ...filters,
    ...(cursor ? { OR: [
      { occurredAt: { gt: new Date(cursor.afterAt), lte: new Date(query.until) } },
      { occurredAt: new Date(cursor.afterAt), id: { gt: cursor.afterEventId } },
    ] } : {}),
  };
  const rows = await db.auditEvent.findMany({
    where, take: limit + 1,
    orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
    select: { id: true, organizationId: true, actorType: true,
      actorUserId: true, action: true, resourceType: true,
      resourceId: true, metadata: true, occurredAt: true },
  });
  if (rows.some(row => row.organizationId !== actor.organizationId))
    fail("SIEM_DB_CROSS_TENANT_ROW");
  const page = buildSiemPage(query,
    rows.slice(0, limit).map(toPortable),
    new Date().toISOString(), rows.length > limit, secret, policy);
  const artifact = input.format ? buildSiemExport(page, input.format) : null;
  return { page, artifact, quality: inspectSiemPageQuality(page),
    readiness: inspectSiemForwardingReadiness(page),
    externalEventDelivery: 0 as const, providerWrites: 0 as const };
}
/** Available action/resource classes for safe filter discovery, bounded to tenant. */
export async function readSiemAuditFacets(actor: Actor) {
  await authorize(actor, false);
  const [actions, resources, total] = await Promise.all([
    db.auditEvent.groupBy({ by: ["action"], where: {
      organizationId: actor.organizationId },
      _count: { _all: true }, orderBy: { _count: { action: "desc" } },
      take: 50 }),
    db.auditEvent.groupBy({ by: ["resourceType"], where: {
      organizationId: actor.organizationId },
      _count: { _all: true }, orderBy: { _count: { resourceType: "desc" } },
      take: 50 }),
    db.auditEvent.count({ where: { organizationId: actor.organizationId } }),
  ]);
  return { schema: "cyberpilot.siem.facets.v1" as const,
    organizationId: actor.organizationId, total,
    actionFacets: actions.map(x => ({ value: x.action, count: x._count._all })),
    resourceFacets: resources.map(x => ({
      value: x.resourceType, count: x._count._all })),
    truncated: actions.length === 50 || resources.length === 50,
    noExternalQueries: true as const };
}
/** Only capability inventory: no remote transport or secret configuration. */
export async function siemExportCapabilities(actor: Actor) {
  await authorize(actor, false);
  return {
    schema: "cyberpilot.siem.capabilities.v1" as const,
    organizationId: actor.organizationId,
    formats: ["JSONL", "ECS", "CEF", "CSV"] as const,
    pageMaximum: 100, authenticatedCursor: true,
    includeActorReferences: ["OWNER", "ADMIN"].includes(actor.role),
    includeResourceReferences: ["OWNER", "ADMIN"].includes(actor.role),
    metadataPolicy: [...DEFAULT_SIEM_POLICY.allowlistedMetadataKeys],
    pseudonymizedReferences: true,
    directSplunkDelivery: false, directSentinelDelivery: false,
    directDatadogDelivery: false, notificationsSent: 0,
    externalSiemIntegrationValidated: false,
  };
}
/** Summary across safely bounded time buckets, without raw metadata leakage. */
export async function readSiemAuditHistogram(actor: Actor,
  days = 14) {
  await authorize(actor, false);
  if (!Number.isSafeInteger(days) || days < 1 || days > 90)
    fail("SIEM_HISTOGRAM_WINDOW_INVALID");
  const now = new Date(), from = new Date(now.getTime() - days * 86400000);
  const rows = await db.auditEvent.findMany({
    where: { organizationId: actor.organizationId,
      occurredAt: { gte: from, lte: now } },
    select: { id: true, action: true, resourceType: true, occurredAt: true },
    take: 10001, orderBy: { occurredAt: "asc" },
  });
  const counts = new Map<string, number>();
  const actionCounts = new Map<string, number>();
  for (const row of rows.slice(0, 10000)) {
    const day = row.occurredAt.toISOString().slice(0, 10);
    counts.set(day, (counts.get(day) ?? 0) + 1);
    actionCounts.set(row.action, (actionCounts.get(row.action) ?? 0) + 1);
  }
  return { schema: "cyberpilot.siem.histogram.v1" as const,
    organizationId: actor.organizationId, asOf: now.toISOString(),
    from: from.toISOString(), days, observed: Math.min(rows.length, 10000),
    truncated: rows.length > 10000,
    series: [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))
      .map(([date, count]) => ({ date, count })),
    mostFrequentActions: [...actionCounts.entries()].sort(
      ([a, na], [b, nb]) => nb-na || a.localeCompare(b)).slice(0, 20)
      .map(([action, count]) => ({ action, count })),
    completeAuditPopulationProven: rows.length <= 10000,
    productionSIEMDelivered: false as const };
}
