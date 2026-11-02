import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { WorkInputError } from "./remediation-work-input";

export type LinkAnalyticsFilter = {
  caseKey?: string | undefined;
  workItemId?: string | undefined;
  actorUserId?: string | undefined;
  action?: "LINK" | "UNLINK" | undefined;
  since?: string | undefined;
  until?: string | undefined;
};
export type LinkAnalyticsSort = "newest" | "oldest" | "case" | "work";
export type LinkAnalyticsQuery = {
  filter: LinkAnalyticsFilter;
  sort: LinkAnalyticsSort;
  offset: number;
  limit: number;
};
export type LinkAnalyticsSummary = {
  totalEvents: number;
  linksCreated: number;
  withdrawals: number;
  activeLinks: number;
  withdrawnLinks: number;
  orphanWithdrawals: number;
  duplicateWithdrawals: number;
  distinctCases: number;
  distinctWorkItems: number;
  distinctActors: number;
  firstEventAt: string | null;
  lastEventAt: string | null;
};
export type LinkAnalyticsCase = {
  caseKey: string;
  totalLinks: number;
  activeLinks: number;
  withdrawnLinks: number;
  workItemIds: string[];
  lastActivityAt: string | null;
};
export type LinkAnalyticsWork = {
  workItemId: string;
  totalLinks: number;
  activeLinks: number;
  withdrawnLinks: number;
  caseKeys: string[];
  lastActivityAt: string | null;
};
export type LinkAnalyticsActor = {
  actorUserId: string | null;
  linksCreated: number;
  withdrawals: number;
  lastActivityAt: string | null;
};
export type LinkAnalyticsDay = {
  day: string;
  linksCreated: number;
  withdrawals: number;
};
export type LinkAnalyticsReport = {
  summary: LinkAnalyticsSummary;
  cases: LinkAnalyticsCase[];
  workItems: LinkAnalyticsWork[];
  actors: LinkAnalyticsActor[];
  days: LinkAnalyticsDay[];
  events: IntegrityLinkHistoryEvent[];
  pagination: { offset: number; limit: number; total: number; hasMore: boolean };
  integrity: { orphanWithdrawalIds: string[]; duplicateWithdrawalIds: string[] };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function parseText(value: unknown, name: string, max = 1500): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", `Invalid ${name}.`);
  return value;
}
function parseTimestamp(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", `Invalid ${name}.`);
  return value;
}
function parseInteger(value: unknown, name: string, min: number, max: number, fallback: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max)
    throw new WorkInputError("INVALID", `Invalid ${name}.`);
  return value as number;
}
export function parseLinkAnalyticsQuery(value: unknown): LinkAnalyticsQuery {
  if (!isRecord(value)) throw new WorkInputError("INVALID", "Expected analytics query object.");
  const allowed = new Set(["caseKey", "workItemId", "actorUserId", "action",
    "since", "until", "sort", "offset", "limit"]);
  if (Object.keys(value).some(key => !allowed.has(key)))
    throw new WorkInputError("INVALID", "Unknown analytics query parameter.");
  const since = parseTimestamp(value.since, "since");
  const until = parseTimestamp(value.until, "until");
  if (since && until && since > until)
    throw new WorkInputError("INVALID", "Since must precede until.");
  if (value.action !== undefined && value.action !== "LINK" && value.action !== "UNLINK")
    throw new WorkInputError("INVALID", "Invalid action.");
  const sort = value.sort ?? "newest";
  if (sort !== "newest" && sort !== "oldest" && sort !== "case" && sort !== "work")
    throw new WorkInputError("INVALID", "Invalid sort.");
  return {
    filter: {
      caseKey: parseText(value.caseKey, "caseKey"),
      workItemId: parseText(value.workItemId, "workItemId", 100),
      actorUserId: parseText(value.actorUserId, "actorUserId", 100),
      action: value.action as "LINK" | "UNLINK" | undefined,
      since, until,
    },
    sort,
    offset: parseInteger(value.offset, "offset", 0, 1000000, 0),
    limit: parseInteger(value.limit, "limit", 1, 1000, 100),
  };
}
export function filterLinkAnalyticsEvents(
  events: readonly IntegrityLinkHistoryEvent[], filter: LinkAnalyticsFilter,
): IntegrityLinkHistoryEvent[] {
  return events.filter(event =>
    (filter.caseKey === undefined || event.caseKey === filter.caseKey) &&
    (filter.workItemId === undefined || event.workItemId === filter.workItemId) &&
    (filter.actorUserId === undefined || event.actorUserId === filter.actorUserId) &&
    (filter.action === undefined || event.action === filter.action) &&
    (filter.since === undefined || event.occurredAt >= filter.since) &&
    (filter.until === undefined || event.occurredAt <= filter.until));
}
function latest(a: string | null, b: string): string {
  return a === null || b > a ? b : a;
}
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
export function sortLinkAnalyticsEvents(
  events: readonly IntegrityLinkHistoryEvent[], sort: LinkAnalyticsSort,
): IntegrityLinkHistoryEvent[] {
  const result = [...events];
  result.sort((a, b) => {
    if (sort === "case") {
      const byCase = compareText(a.caseKey, b.caseKey);
      if (byCase) return byCase;
    }
    if (sort === "work") {
      const byWork = compareText(a.workItemId, b.workItemId);
      if (byWork) return byWork;
    }
    const byTime = compareText(a.occurredAt, b.occurredAt);
    if (byTime) return sort === "oldest" ? byTime : -byTime;
    return sort === "oldest" ? compareText(a.auditId, b.auditId) :
      compareText(b.auditId, a.auditId);
  });
  return result;
}
export function analyzeIntegrityLinkEvents(
  events: readonly IntegrityLinkHistoryEvent[],
  query: LinkAnalyticsQuery = { filter: {}, sort: "newest", offset: 0, limit: 100 },
): LinkAnalyticsReport {
  const allLinks = new Map<string, IntegrityLinkHistoryEvent>();
  const withdrawals = new Map<string, IntegrityLinkHistoryEvent[]>();
  const orphanWithdrawalIds: string[] = [];
  const duplicateWithdrawalIds: string[] = [];
  for (const event of events) {
    if (event.action === "LINK") allLinks.set(event.auditId, event);
    else if (event.originalAuditId) {
      const existing = withdrawals.get(event.originalAuditId) ?? [];
      existing.push(event);
      withdrawals.set(event.originalAuditId, existing);
    } else orphanWithdrawalIds.push(event.auditId);
  }
  for (const [originalId, withdrawn] of withdrawals) {
    if (!allLinks.has(originalId)) {
      orphanWithdrawalIds.push(...withdrawn.map(event => event.auditId));
    } else if (withdrawn.length > 1) {
      duplicateWithdrawalIds.push(...withdrawn.slice(1).map(event => event.auditId));
    }
  }
  const cases = new Map<string, LinkAnalyticsCase>();
  const workItems = new Map<string, LinkAnalyticsWork>();
  const actors = new Map<string, LinkAnalyticsActor>();
  const days = new Map<string, LinkAnalyticsDay>();
  let firstEventAt: string | null = null;
  let lastEventAt: string | null = null;
  let linksCreated = 0;
  let withdrawalCount = 0;
  let activeLinks = 0;
  let withdrawnLinks = 0;
  for (const event of events) {
    if (firstEventAt === null || event.occurredAt < firstEventAt)
      firstEventAt = event.occurredAt;
    lastEventAt = latest(lastEventAt, event.occurredAt);
    const day = event.occurredAt.slice(0, 10);
    const daily = days.get(day) ?? { day, linksCreated: 0, withdrawals: 0 };
    const actor = actors.get(event.actorUserId ?? "") ?? {
      actorUserId: event.actorUserId, linksCreated: 0, withdrawals: 0,
      lastActivityAt: null,
    };
    actor.lastActivityAt = latest(actor.lastActivityAt, event.occurredAt);
    if (event.action === "LINK") {
      linksCreated++;
      daily.linksCreated++;
      actor.linksCreated++;
      const withdrawn = withdrawals.has(event.auditId);
      if (withdrawn) withdrawnLinks++;
      else activeLinks++;
      const c = cases.get(event.caseKey) ?? {
        caseKey: event.caseKey, totalLinks: 0, activeLinks: 0,
        withdrawnLinks: 0, workItemIds: [], lastActivityAt: null,
      };
      const w = workItems.get(event.workItemId) ?? {
        workItemId: event.workItemId, totalLinks: 0, activeLinks: 0,
        withdrawnLinks: 0, caseKeys: [], lastActivityAt: null,
      };
      c.totalLinks++;
      w.totalLinks++;
      if (withdrawn) { c.withdrawnLinks++; w.withdrawnLinks++; }
      else { c.activeLinks++; w.activeLinks++; }
      if (!c.workItemIds.includes(event.workItemId)) c.workItemIds.push(event.workItemId);
      if (!w.caseKeys.includes(event.caseKey)) w.caseKeys.push(event.caseKey);
      c.lastActivityAt = latest(c.lastActivityAt, event.occurredAt);
      w.lastActivityAt = latest(w.lastActivityAt, event.occurredAt);
      cases.set(event.caseKey, c);
      workItems.set(event.workItemId, w);
    } else {
      withdrawalCount++;
      daily.withdrawals++;
      actor.withdrawals++;
      const original = event.originalAuditId ? allLinks.get(event.originalAuditId) : undefined;
      if (original) {
        const c = cases.get(original.caseKey);
        const w = workItems.get(original.workItemId);
        if (c) c.lastActivityAt = latest(c.lastActivityAt, event.occurredAt);
        if (w) w.lastActivityAt = latest(w.lastActivityAt, event.occurredAt);
      }
    }
    days.set(day, daily);
    actors.set(event.actorUserId ?? "", actor);
  }
  // Recompute the last activity for every association after collecting all links.
  // Audit rows are not guaranteed to arrive in chronological order, and a
  // withdrawal may precede its corresponding creation in the input array.
  for (const event of events) {
    if (event.action !== "UNLINK" || !event.originalAuditId) continue;
    const original = allLinks.get(event.originalAuditId);
    if (!original) continue;
    const c = cases.get(original.caseKey);
    const w = workItems.get(original.workItemId);
    if (c) c.lastActivityAt = latest(c.lastActivityAt, event.occurredAt);
    if (w) w.lastActivityAt = latest(w.lastActivityAt, event.occurredAt);
  }
  const filtered = sortLinkAnalyticsEvents(
    filterLinkAnalyticsEvents(events, query.filter), query.sort,
  );
  return {
    summary: {
      totalEvents: events.length, linksCreated, withdrawals: withdrawalCount,
      activeLinks, withdrawnLinks, orphanWithdrawals: orphanWithdrawalIds.length,
      duplicateWithdrawals: duplicateWithdrawalIds.length,
      distinctCases: cases.size, distinctWorkItems: workItems.size,
      distinctActors: actors.size, firstEventAt, lastEventAt,
    },
    cases: [...cases.values()].map(c => ({
      ...c, workItemIds: c.workItemIds.sort(compareText),
    })).sort((a, b) => compareText(a.caseKey, b.caseKey)),
    workItems: [...workItems.values()].map(w => ({
      ...w, caseKeys: w.caseKeys.sort(compareText),
    })).sort((a, b) => compareText(a.workItemId, b.workItemId)),
    actors: [...actors.values()].sort((a, b) =>
      compareText(a.actorUserId ?? "", b.actorUserId ?? "")),
    days: [...days.values()].sort((a, b) => compareText(a.day, b.day)),
    events: filtered.slice(query.offset, query.offset + query.limit),
    pagination: {
      offset: query.offset, limit: query.limit, total: filtered.length,
      hasMore: query.offset + query.limit < filtered.length,
    },
    integrity: { orphanWithdrawalIds, duplicateWithdrawalIds },
  };
}
