import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, WorkInputError, parseWorkId, type WorkRole } from "./remediation-work-input";
import {
  hydrateTriageEvent, TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE,
  type TriageDecision, type TriageEvent,
} from "./work-integrity-triage";

/**
 * Cursor-bounded view of the actual recorded human integrity decisions.
 * This is a read-only audit-ledger explorer, not a reconstructed snapshot.
 */
export type LedgerScope = { organizationId: string; userId: string; role: WorkRole };
export type LedgerFilters = {
  limit: 10 | 25 | 50 | 100;
  cursor: string | null;
  workItemId: string | null;
  actorUserId: string | null;
  decision: TriageDecision | null;
  includeMalformed: boolean;
};
export type LedgerEntry = {
  eventId: string;
  organizationId: string;
  occurredAt: string;
  actorUserId: string | null;
  workItemId: string;
  code: string;
  resourceId: string;
  revision: number;
  decision: TriageDecision;
  rationale: string;
  reference: string | null;
  predecessorEventId: string | null;
  predecessorInPage: boolean;
  predecessorChronologicallyPrior: boolean | null;
  workTitle: string | null;
  workStatus: string | null;
  currentWorkRevision: number | null;
  reviewedRevisionIsCurrent: boolean | null;
  source: "AUDIT_EVENT";
};
export type MalformedLedgerEntry = {
  eventId: string;
  occurredAt: string;
  workItemId: string | null;
  reason: "MALFORMED_TRIAGE_PAYLOAD";
};
export type LedgerPage = {
  organizationId: string;
  generatedAt: string;
  filters: LedgerFilters;
  entries: LedgerEntry[];
  malformed: MalformedLedgerEntry[];
  fetched: number;
  matched: number;
  nextCursor: string | null;
  coverage: "BOUNDED_RAW_AUDIT_PAGE";
  limitations: string[];
};
export type LedgerRawEvent = {
  id: string;
  organizationId: string;
  resourceId: string | null;
  actorUserId: string | null;
  occurredAt: Date;
  metadata: Prisma.JsonValue | null;
};
export type LedgerWorkItem = {
  id: string; title: string; status: string; revision: number;
};
const DECISIONS: readonly TriageDecision[] = [
  "INVESTIGATE", "ACKNOWLEDGE", "DISMISS", "REOPEN",
];
export function parseLedgerFilters(raw: Record<string, unknown>): LedgerFilters {
  const accepted = new Set([
    "limit", "cursor", "workItemId", "actorUserId", "decision", "includeMalformed",
  ]);
  for (const key of Object.keys(raw))
    if (!accepted.has(key))
      throw new WorkInputError("INVALID", "Unknown audit-ledger filter.");
  const limit = raw.limit === undefined ? 25 : Number(raw.limit);
  if (![10, 25, 50, 100].includes(limit))
    throw new WorkInputError("INVALID", "Ledger limit must be 10, 25, 50 or 100.");
  const cursor = raw.cursor === undefined || raw.cursor === "" ? null : raw.cursor;
  if (cursor !== null && (typeof cursor !== "string" || cursor.length > 200 ||
      !/^[A-Za-z0-9_-]+$/.test(cursor)))
    throw new WorkInputError("INVALID", "Invalid ledger cursor.");
  const workItemId = raw.workItemId === undefined || raw.workItemId === "" ? null :
    parseWorkId(raw.workItemId, "work item ID");
  const actorUserId = raw.actorUserId === undefined || raw.actorUserId === "" ? null :
    parseWorkId(raw.actorUserId, "actor user ID");
  const decision = raw.decision === undefined || raw.decision === "" ? null : raw.decision;
  if (decision !== null &&
      (typeof decision !== "string" || !DECISIONS.includes(decision as TriageDecision)))
    throw new WorkInputError("INVALID", "Unknown human review decision.");
  if (raw.includeMalformed !== undefined &&
      raw.includeMalformed !== "true" && raw.includeMalformed !== "false")
    throw new WorkInputError("INVALID", "Invalid malformed-record inclusion.");
  return {
    limit: limit as LedgerFilters["limit"],
    cursor: cursor as string | null, workItemId,
    actorUserId, decision: decision as TriageDecision | null,
    includeMalformed: raw.includeMalformed === "true",
  };
}
function invalidEntry(raw: LedgerRawEvent): MalformedLedgerEntry {
  return {
    eventId: raw.id, occurredAt: raw.occurredAt.toISOString(),
    workItemId: raw.resourceId, reason: "MALFORMED_TRIAGE_PAYLOAD",
  };
}
export function projectLedgerPage(
  organizationId: string,
  generatedAt: string,
  filters: LedgerFilters,
  rawRows: readonly LedgerRawEvent[],
  works: ReadonlyMap<string, LedgerWorkItem>,
  hasMore: boolean,
): LedgerPage {
  if (!organizationId) throw new Error("Missing trusted organization.");
  const entries: LedgerEntry[] = [];
  const malformed: MalformedLedgerEntry[] = [];
  const parsed = new Map<string, TriageEvent>();
  for (const raw of rawRows) {
    if (raw.organizationId !== organizationId)
      throw new Error("Cross-organization audit record in trusted ledger query.");
    const event = hydrateTriageEvent(raw);
    if (event) {
      if (parsed.has(event.id)) throw new Error("Repeated event identity in ledger page.");
      parsed.set(event.id, event);
    } else if (filters.includeMalformed) malformed.push(invalidEntry(raw));
  }
  for (const event of parsed.values()) {
    if (filters.decision && event.decision !== filters.decision) continue;
    if (filters.actorUserId && event.actorUserId !== filters.actorUserId) continue;
    const work = works.get(event.workItemId) ?? null;
    const predecessor = event.previousEventId ? parsed.get(event.previousEventId) : null;
    entries.push({
      eventId: event.id, organizationId, occurredAt: event.occurredAt.toISOString(),
      actorUserId: event.actorUserId,
      workItemId: event.workItemId, code: event.code, resourceId: event.resourceId,
      revision: event.revision, decision: event.decision,
      rationale: event.rationale, reference: event.reference,
      predecessorEventId: event.previousEventId,
      predecessorInPage: !!predecessor,
      predecessorChronologicallyPrior: predecessor
        ? predecessor.occurredAt.getTime() <= event.occurredAt.getTime() : null,
      workTitle: work?.title ?? null,
      workStatus: work?.status ?? null,
      currentWorkRevision: work?.revision ?? null,
      reviewedRevisionIsCurrent: work ? work.revision === event.revision : null,
      source: "AUDIT_EVENT",
    });
  }
  const ordered = [...entries].sort((a, b) =>
    b.occurredAt.localeCompare(a.occurredAt) || b.eventId.localeCompare(a.eventId));
  return {
    organizationId, generatedAt, filters, entries: ordered,
    malformed, fetched: rawRows.length, matched: ordered.length,
    nextCursor: hasMore ? rawRows[rawRows.length - 1]?.id ?? null : null,
    coverage: "BOUNDED_RAW_AUDIT_PAGE",
    limitations: [
      "Only immutable-intent audit-event rows from the current organization's selected page are read.",
      "Actor and decision filters are applied to this bounded raw event page, not to the entire event store.",
      "A missing predecessor outside this page is unknown, not proof of deletion.",
      "Current work revision is compared for context, not proof that historical decisions remain valid.",
      "A review records a human decision and does not verify remediation or control effectiveness.",
      ...(hasMore ? ["Additional audit ledger events exist beyond this page."] : []),
    ],
  };
}
export async function loadAuditLedger(
  scope: LedgerScope, raw: Record<string, unknown>,
  now = new Date(),
): Promise<LedgerPage> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization membership required.");
  const filters = parseLedgerFilters(raw);
  if (filters.workItemId) {
    const exists = await db.remediationWorkItem.findFirst({
      where: { id: filters.workItemId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!exists) throw new WorkInputError("MISSING", "Work item unavailable in this organization.");
  }
  const where: Prisma.AuditEventWhereInput = {
    organizationId: scope.organizationId,
    action: TRIAGE_AUDIT_ACTION,
    resourceType: TRIAGE_RESOURCE_TYPE,
    ...(filters.workItemId ? { resourceId: filters.workItemId } : {}),
  };
  const auditRows = await db.auditEvent.findMany({
    where, orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    ...(filters.cursor ? { cursor: { id: filters.cursor }, skip: 1 } : {}),
    take: filters.limit + 1,
    select: {
      id: true, organizationId: true, resourceId: true,
      actorUserId: true, occurredAt: true, metadata: true,
    },
  });
  const more = auditRows.length > filters.limit;
  const visible = auditRows.slice(0, filters.limit);
  const ids = [...new Set(visible.map(row => row.resourceId)
    .filter((id): id is string => id !== null))];
  const work = ids.length ? await db.remediationWorkItem.findMany({
    where: { organizationId: scope.organizationId, id: { in: ids } },
    select: { id: true, title: true, status: true, revision: true },
  }) : [];
  return projectLedgerPage(
    scope.organizationId, now.toISOString(), filters, visible,
    new Map(work.map(row => [row.id, {
      id: row.id, title: row.title, status: row.status, revision: row.revision,
    }])), more,
  );
}
export function auditLedgerCsv(page: LedgerPage): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const columns = [
    "eventId", "occurredAt", "actorUserId", "workItemId", "workTitle",
    "code", "resourceId", "decision", "revision", "currentWorkRevision",
    "reviewedRevisionIsCurrent", "predecessorEventId", "predecessorInPage",
    "predecessorChronologicallyPrior", "rationale", "reference", "source",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const event of page.entries) {
    lines.push([
      event.eventId, event.occurredAt, event.actorUserId, event.workItemId,
      event.workTitle, event.code, event.resourceId, event.decision,
      event.revision, event.currentWorkRevision, event.reviewedRevisionIsCurrent,
      event.predecessorEventId, event.predecessorInPage,
      event.predecessorChronologicallyPrior, event.rationale,
      event.reference, event.source,
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
