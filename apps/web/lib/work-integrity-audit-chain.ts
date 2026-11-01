import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, WorkInputError, parseWorkId, type WorkRole } from "./remediation-work-input";
import {
  TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE, hydrateTriageEvent,
  type TriageEvent,
} from "./work-integrity-triage";

/**
 * Verifies the internal continuity of events read directly from the tenant's
 * authoritative audit table, rather than trusting uploaded snapshots.
 * Coverage is explicit: a missing predecessor outside the bounded window is
 * unknown, never automatically characterized as deletion or corruption.
 */
export type AuditChainScope = { organizationId: string; userId: string; role: WorkRole };
export type AuditChainFilters = {
  workItemId: string;
  limit: number;
  includeEvents: boolean;
};
export type AuditChainProblemCode =
  | "MISSING_PREDECESSOR"
  | "CROSS_CASE_PREDECESSOR"
  | "CYCLE"
  | "FORK"
  | "MULTIPLE_ROOTS"
  | "EVENT_TIME_REVERSED"
  | "REVISION_REVERSED"
  | "UNATTRIBUTED_REVIEW"
  | "INVALID_AUDIT_PAYLOAD"
  | "HEAD_NOT_UNIQUE"
  | "UNEXPECTED_ROOT"
  | "REPEATED_EVENT_ID";
export type AuditChainProblem = {
  code: AuditChainProblemCode;
  severity: "ERROR" | "WARNING" | "UNKNOWN";
  eventId: string | null;
  predecessorId: string | null;
  caseKey: string | null;
  message: string;
  recommendedAction: string;
};
export type AuditChainCase = {
  caseKey: string;
  workItemId: string;
  code: string;
  resourceId: string;
  eventCount: number;
  rootCount: number;
  headCount: number;
  latestEventId: string | null;
  latestDecision: string | null;
  latestRevision: number | null;
  isCurrentRevision: boolean | null;
  chainLength: number;
  completeHistory: boolean;
  errors: number;
  warnings: number;
  unknowns: number;
  eventIds: string[];
};
export type AuditChainReport = {
  organizationId: string;
  workItemId: string;
  workTitle: string;
  currentRevision: number;
  generatedAt: string;
  bounded: boolean;
  historyComplete: boolean;
  recordsRead: number;
  malformedRecords: number;
  cases: AuditChainCase[];
  problems: AuditChainProblem[];
  totals: { cases: number; errors: number; warnings: number; unknowns: number };
  limitations: string[];
};
export function parseAuditChainFilters(raw: Record<string, unknown>): AuditChainFilters {
  for (const key of Object.keys(raw))
    if (!["workItemId", "limit", "includeEvents"].includes(key))
      throw new WorkInputError("INVALID", "Unsupported audit chain filter.");
  const workItemId = parseWorkId(raw.workItemId, "work item ID");
  const limit = raw.limit === undefined ? 500 : Number(raw.limit);
  if (!Number.isInteger(limit) || limit < 10 || limit > 2000)
    throw new WorkInputError("INVALID", "Audit history limit must be 10–2000.");
  if (raw.includeEvents !== undefined &&
      raw.includeEvents !== "true" && raw.includeEvents !== "false")
    throw new WorkInputError("INVALID", "Invalid event display option.");
  return { workItemId, limit, includeEvents: raw.includeEvents === "true" };
}
export function auditChainKey(event: Pick<TriageEvent, "workItemId" | "code" | "resourceId">): string {
  return JSON.stringify([event.workItemId, event.code, event.resourceId]);
}
type ChainInput = {
  organizationId: string;
  workItemId: string;
  workTitle: string;
  currentRevision: number;
  generatedAt: string;
  bounded: boolean;
  rawRecordsRead: number;
  events: readonly TriageEvent[];
  malformedRecords: number;
  includeEvents: boolean;
};
export function inspectAuditChain(input: ChainInput): AuditChainReport {
  if (!input.organizationId || !input.workItemId ||
      !Number.isSafeInteger(input.currentRevision) || input.currentRevision < 1)
    throw new Error("Invalid trusted audit chain context.");
  const byId = new Map<string, TriageEvent>();
  const groups = new Map<string, TriageEvent[]>();
  const problems: AuditChainProblem[] = [];
  const push = (
    code: AuditChainProblemCode, severity: AuditChainProblem["severity"],
    event: TriageEvent | null, message: string, recommendedAction: string,
    predecessorId: string | null = null,
  ) => {
    problems.push({
      code, severity,
      eventId: event?.id ?? null,
      predecessorId: predecessorId ?? event?.previousEventId ?? null,
      caseKey: event ? auditChainKey(event) : null,
      message, recommendedAction,
    });
  };
  for (const event of input.events) {
    if (event.organizationId !== input.organizationId ||
        event.workItemId !== input.workItemId)
      throw new Error("Cross-tenant or cross-work-item event in trusted audit collection.");
    if (byId.has(event.id)) {
      push("REPEATED_EVENT_ID", "ERROR", event,
        "The same event identifier occurs more than once in the supplied audit collection.",
        "Inspect audit row identity and duplicate query results.");
      continue;
    }
    byId.set(event.id, event);
    const key = auditChainKey(event);
    const group = groups.get(key) ?? [];
    group.push(event);
    groups.set(key, group);
  }
  if (input.malformedRecords > 0) push("INVALID_AUDIT_PAYLOAD", "WARNING", null,
    `${input.malformedRecords} audit rows could not be interpreted as triage decisions.`,
    "Inspect malformed audit metadata using an authorized source review.");
  const cases: AuditChainCase[] = [];
  for (const [key, group] of groups) {
    const ids = new Map(group.map(event => [event.id, event]));
    const childCounts = new Map<string, number>();
    for (const event of group) {
      if (event.previousEventId)
        childCounts.set(event.previousEventId,
          (childCounts.get(event.previousEventId) ?? 0) + 1);
      if (event.actorUserId === null) push("UNATTRIBUTED_REVIEW", "WARNING", event,
        "The review's current user reference is missing.",
        "Inspect the original audit actor and account retention history.");
      if (event.revision > input.currentRevision) push("REVISION_REVERSED", "ERROR", event,
        "The review references a work revision not present in the current work item.",
        "Inspect the authoritative work revision and audit chronology.");
      if (event.previousEventId) {
        const predecessor = byId.get(event.previousEventId);
        if (!predecessor) {
          push("MISSING_PREDECESSOR", input.bounded ? "UNKNOWN" : "ERROR", event,
            "The referenced predecessor was not available in the selected audit window.",
            input.bounded
              ? "Increase the bounded audit window before drawing conclusions."
              : "Inspect the original audit event and its retention history.");
        } else if (auditChainKey(predecessor) !== key) {
          push("CROSS_CASE_PREDECESSOR", "ERROR", event,
            "The predecessor belongs to a different diagnostic case.",
            "Investigate the reference and source audit chain before accepting the review.");
        } else {
          if (predecessor.occurredAt.getTime() > event.occurredAt.getTime())
            push("EVENT_TIME_REVERSED", "WARNING", event,
              "The predecessor has a later timestamp than the current event.",
              "Check audit timestamps and transaction ordering.");
          if (predecessor.revision > event.revision)
            push("REVISION_REVERSED", "WARNING", event,
              "The review revision decreased along a predecessor link.",
              "Review the work-item revision history and decision ordering.");
        }
      }
    }
    for (const [id, count] of childCounts) {
      if (count > 1) {
        const event = ids.get(id) ?? group.find(item => item.previousEventId === id) ?? null;
        push("FORK", "ERROR", event,
          `${count} reviews reference the same predecessor event.`,
          "Investigate concurrent triage submissions and optimistic locking.");
      }
    }
    const roots = group.filter(event => event.previousEventId === null);
    const heads = group.filter(event => !childCounts.has(event.id));
    if (!input.bounded && roots.length !== 1)
      push(roots.length ? "MULTIPLE_ROOTS" : "UNEXPECTED_ROOT", "ERROR",
        roots[0] ?? group[0] ?? null,
        `This case contains ${roots.length} root review events.`,
        "Reconstruct the audited review sequence from source records.");
    if (!input.bounded && heads.length !== 1)
      push("HEAD_NOT_UNIQUE", "ERROR", heads[0] ?? group[0] ?? null,
        `This case contains ${heads.length} terminal review events.`,
        "Inspect whether multiple review branches exist.");
    const visited = new Set<string>();
    for (const event of group) {
      const path = new Set<string>();
      let cursor: TriageEvent | undefined = event;
      while (cursor && !path.has(cursor.id) && !visited.has(cursor.id)) {
        path.add(cursor.id);
        cursor = cursor.previousEventId ? ids.get(cursor.previousEventId) : undefined;
      }
      if (cursor && path.has(cursor.id))
        push("CYCLE", "ERROR", event,
          "The event predecessor graph contains a cycle.",
          "Quarantine the inconsistent review chain and inspect audit row references.");
      for (const id of path) visited.add(id);
    }
    const ordered = [...group].sort((a, b) =>
      b.occurredAt.getTime() - a.occurredAt.getTime() || b.id.localeCompare(a.id));
    const latest = ordered[0] ?? null;
    let chainLength = 0;
    let cursor = latest;
    const chainVisited = new Set<string>();
    while (cursor && !chainVisited.has(cursor.id)) {
      chainVisited.add(cursor.id);
      chainLength++;
      cursor = cursor.previousEventId ? ids.get(cursor.previousEventId) ?? null : null;
    }
    const related = problems.filter(problem => problem.caseKey === key);
    const completeHistory = !input.bounded &&
      roots.length === 1 && heads.length === 1 &&
      related.every(problem => problem.severity !== "ERROR" && problem.severity !== "UNKNOWN");
    cases.push({
      caseKey: key,
      workItemId: group[0]!.workItemId,
      code: group[0]!.code,
      resourceId: group[0]!.resourceId,
      eventCount: group.length,
      rootCount: roots.length,
      headCount: heads.length,
      latestEventId: latest?.id ?? null,
      latestDecision: latest?.decision ?? null,
      latestRevision: latest?.revision ?? null,
      isCurrentRevision: latest ? latest.revision === input.currentRevision : null,
      chainLength,
      completeHistory,
      errors: related.filter(problem => problem.severity === "ERROR").length,
      warnings: related.filter(problem => problem.severity === "WARNING").length,
      unknowns: related.filter(problem => problem.severity === "UNKNOWN").length,
      eventIds: input.includeEvents ? ordered.map(event => event.id) : [],
    });
  }
  cases.sort((a, b) => b.errors - a.errors || b.unknowns - a.unknowns ||
    a.caseKey.localeCompare(b.caseKey));
  problems.sort((a, b) => {
    const rank = { ERROR: 0, UNKNOWN: 1, WARNING: 2 };
    return rank[a.severity] - rank[b.severity] ||
      (a.caseKey ?? "").localeCompare(b.caseKey ?? "") ||
      a.code.localeCompare(b.code);
  });
  return {
    organizationId: input.organizationId,
    workItemId: input.workItemId,
    workTitle: input.workTitle,
    currentRevision: input.currentRevision,
    generatedAt: input.generatedAt,
    bounded: input.bounded,
    historyComplete: !input.bounded && input.malformedRecords === 0 &&
      cases.every(row => row.completeHistory),
    recordsRead: input.rawRecordsRead,
    malformedRecords: input.malformedRecords,
    cases,
    problems,
    totals: {
      cases: cases.length,
      errors: problems.filter(problem => problem.severity === "ERROR").length,
      warnings: problems.filter(problem => problem.severity === "WARNING").length,
      unknowns: problems.filter(problem => problem.severity === "UNKNOWN").length,
    },
    limitations: [
      "The analysis reads authoritative organization-scoped audit rows; it does not authenticate external source data.",
      "Database event ordering alone does not independently prove audit immutability.",
      "A valid audit chain records human decisions and cannot certify remediation or compliance.",
      ...(input.bounded ? ["The audit event window is bounded; missing predecessors may predate this window."] : []),
      ...(input.malformedRecords ? ["Some source audit rows could not be parsed; completeness is not established."] : []),
    ],
  };
}
export async function loadAuditChain(
  scope: AuditChainScope, raw: Record<string, unknown>,
  now = new Date(),
): Promise<AuditChainReport> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization access required.");
  const filters = parseAuditChainFilters(raw);
  const work = await db.remediationWorkItem.findFirst({
    where: { organizationId: scope.organizationId, id: filters.workItemId },
    select: { id: true, title: true, revision: true },
  });
  if (!work) throw new WorkInputError("MISSING", "Work item not found in this organization.");
  const rawEvents = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: TRIAGE_RESOURCE_TYPE,
      resourceId: work.id,
      action: TRIAGE_AUDIT_ACTION,
    },
    select: {
      id: true, organizationId: true, resourceId: true,
      actorUserId: true, occurredAt: true, metadata: true,
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: filters.limit + 1,
  });
  const bounded = rawEvents.length > filters.limit;
  const visible = rawEvents.slice(0, filters.limit);
  const events = visible.map(hydrateTriageEvent)
    .filter((event): event is TriageEvent => event !== null);
  return inspectAuditChain({
    organizationId: scope.organizationId,
    workItemId: work.id,
    workTitle: work.title,
    currentRevision: work.revision,
    generatedAt: now.toISOString(),
    bounded,
    rawRecordsRead: visible.length,
    events,
    malformedRecords: visible.length - events.length,
    includeEvents: filters.includeEvents,
  });
}
export function auditChainCsv(report: AuditChainReport): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const header = [
    "caseKey", "code", "resourceId", "eventCount", "rootCount",
    "headCount", "latestEventId", "latestDecision", "latestRevision",
    "isCurrentRevision", "chainLength", "completeHistory",
    "errors", "warnings", "unknowns",
  ];
  const lines = [header.map(quote).join(",")];
  for (const row of report.cases) {
    lines.push([
      row.caseKey, row.code, row.resourceId, row.eventCount, row.rootCount,
      row.headCount, row.latestEventId, row.latestDecision, row.latestRevision,
      row.isCurrentRevision, row.chainLength, row.completeHistory,
      row.errors, row.warnings, row.unknowns,
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
