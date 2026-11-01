import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError, type WorkRole } from "./remediation-work-input";
import {
  TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE, hydrateTriageEvent,
  type TriageEvent,
} from "./work-integrity-triage";

/**
 * Explore all predecessor branches observable within a bounded, tenant-scoped
 * work-item audit source window. Unlike single-lineage traversal, this can
 * identify competing review successors and disconnected recorded decisions.
 */
export type BranchScope = { organizationId: string; userId: string; role: WorkRole };
export type BranchFilters = { workItemId: string; limit: number; includeRationale: boolean };
export type BranchRaw = {
  id: string; organizationId: string; resourceId: string | null;
  actorUserId: string | null; occurredAt: Date; metadata: Prisma.JsonValue | null;
};
export type BranchNode = {
  id: string; caseKey: string; decision: string; code: string;
  resourceId: string; previousEventId: string | null; revision: number;
  occurredAt: string; actorUserId: string | null;
  rationale: string | null; successorIds: string[];
  depthFromRoot: number | null;
  isRoot: boolean; isTerminal: boolean;
};
export type BranchIssueCode =
  | "MULTIPLE_SUCCESSORS" | "MISSING_PREDECESSOR" | "CROSS_CASE_LINK"
  | "PREDECESSOR_CYCLE" | "DISCONNECTED_ROOTS" | "NO_ROOT"
  | "REVERSED_REVIEW_TIME" | "REVIEW_REVISION_DECREASED"
  | "UNPARSEABLE_SOURCE" | "HISTORY_LIMIT_REACHED";
export type BranchIssue = {
  code: BranchIssueCode; severity: "ERROR" | "WARNING" | "UNKNOWN";
  eventId: string | null; relatedEventId: string | null;
  caseKey: string | null; message: string; suggestedAction: string;
};
export type BranchCase = {
  caseKey: string; code: string; resourceId: string;
  events: number; roots: number; terminals: number; forks: number;
  maxDepth: number | null; hasCycle: boolean; hasUnknownHistory: boolean;
  latestDecision: string; latestEventId: string;
};
export type BranchReport = {
  organizationId: string; workItemId: string; workTitle: string;
  workRevision: number; generatedAt: string;
  sourceRows: number; malformedRows: number;
  sourceTruncated: boolean; nodes: BranchNode[];
  cases: BranchCase[]; issues: BranchIssue[];
  totals: { cases: number; nodes: number; errors: number; warnings: number; unknowns: number; forks: number };
  limitations: string[];
};
export function parseBranchFilters(raw: Record<string, unknown>): BranchFilters {
  for (const key of Object.keys(raw))
    if (!["workItemId", "limit", "includeRationale"].includes(key))
      throw new WorkInputError("INVALID", "Unsupported audit branch option.");
  const workItemId = parseWorkId(raw.workItemId, "work item ID");
  const limit = raw.limit === undefined ? 500 : Number(raw.limit);
  if (![100, 250, 500, 1000, 2000].includes(limit))
    throw new WorkInputError("INVALID", "Audit branch source cap must be 100–2000.");
  if (raw.includeRationale !== undefined &&
      raw.includeRationale !== "true" && raw.includeRationale !== "false")
    throw new WorkInputError("INVALID", "Invalid rationale disclosure option.");
  return { workItemId, limit, includeRationale: raw.includeRationale === "true" };
}
function key(event: TriageEvent): string {
  return JSON.stringify([event.workItemId, event.code, event.resourceId]);
}
export function inspectAuditBranches(input: {
  organizationId: string; workItemId: string; workTitle: string;
  workRevision: number; generatedAt: string; rows: readonly BranchRaw[];
  truncated: boolean; includeRationale: boolean;
}): BranchReport {
  const { organizationId, workItemId, rows, truncated } = input;
  if (!organizationId || !workItemId || !Number.isInteger(input.workRevision))
    throw new Error("Invalid trusted branch inspection context.");
  const events: TriageEvent[] = [];
  const identities = new Set<string>();
  let malformedRows = 0;
  for (const raw of rows) {
    if (raw.organizationId !== organizationId || raw.resourceId !== workItemId)
      throw new Error("Source event outside the authorized work scope.");
    if (identities.has(raw.id)) throw new Error("Repeated source audit event ID.");
    identities.add(raw.id);
    const event = hydrateTriageEvent(raw);
    if (!event) { malformedRows++; continue; }
    if (event.workItemId !== workItemId)
      throw new Error("Audit event metadata work item does not match source resource.");
    events.push(event);
  }
  const byId = new Map(events.map(event => [event.id, event]));
  const byCase = new Map<string, TriageEvent[]>();
  const successors = new Map<string, string[]>();
  const issues: BranchIssue[] = [];
  const emit = (
    code: BranchIssueCode, severity: BranchIssue["severity"],
    event: TriageEvent | null, relatedEventId: string | null,
    message: string, suggestedAction: string,
  ) => issues.push({
    code, severity, eventId: event?.id ?? null,
    relatedEventId, caseKey: event ? key(event) : null,
    message, suggestedAction,
  });
  for (const event of events) {
    const identity = key(event);
    const group = byCase.get(identity) ?? [];
    group.push(event);
    byCase.set(identity, group);
    if (!event.previousEventId) continue;
    const children = successors.get(event.previousEventId) ?? [];
    children.push(event.id);
    successors.set(event.previousEventId, children);
    const parent = byId.get(event.previousEventId);
    if (!parent) emit("MISSING_PREDECESSOR", truncated ? "UNKNOWN" : "ERROR",
      event, event.previousEventId,
      "A referenced audit predecessor is not contained in this source window.",
      truncated ? "Increase the bounded source cap." :
        "Inspect original source audit history and retention.");
    else if (key(parent) !== identity) emit("CROSS_CASE_LINK", "ERROR",
      event, parent.id, "A review links to a different diagnostic identity.",
      "Reconcile event identity and diagnostic mapping from source audit records.");
    else {
      if (parent.occurredAt > event.occurredAt) emit(
        "REVERSED_REVIEW_TIME", "WARNING", event, parent.id,
        "Predecessor timestamp follows its successor.",
        "Check source event clock and transaction ordering.");
      if (parent.revision > event.revision) emit(
        "REVIEW_REVISION_DECREASED", "ERROR", event, parent.id,
        "Reviewed revision moves backwards across recorded event links.",
        "Inspect work revision concurrency and stored review history.");
    }
  }
  const depths = new Map<string, number | null>();
  const cycles = new Set<string>();
  for (const event of events) {
    if (depths.has(event.id)) continue;
    const chain: TriageEvent[] = [];
    const position = new Map<string, number>();
    let cursor: TriageEvent | undefined = event;
    let depth: number | null = null;
    while (cursor) {
      const done = depths.get(cursor.id);
      if (done !== undefined) { depth = done; break; }
      const at = position.get(cursor.id);
      if (at !== undefined) {
        for (const node of chain.slice(at)) cycles.add(node.id);
        depth = null;
        break;
      }
      position.set(cursor.id, chain.length);
      chain.push(cursor);
      if (!cursor.previousEventId) { depth = -1; break; }
      cursor = byId.get(cursor.previousEventId);
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      const item = chain[i]!;
      depth = depth === null ? null : depth + 1;
      depths.set(item.id, depth);
    }
  }
  for (const event of events) {
    const linked = successors.get(event.id) ?? [];
    if (linked.length > 1) emit("MULTIPLE_SUCCESSORS", "ERROR",
      event, null, "Multiple human reviews share one predecessor identity.",
      "Investigate concurrent reviews and optimistic concurrency safeguards.");
    if (cycles.has(event.id)) emit("PREDECESSOR_CYCLE", "ERROR",
      event, event.previousEventId, "The recorded predecessor graph has a cycle.",
      "Inspect original audit row references; do not rewrite source history.");
  }
  const cases: BranchCase[] = [];
  for (const [identity, group] of byCase) {
    const ordered = [...group].sort((a, b) =>
      b.occurredAt.getTime() - a.occurredAt.getTime() || b.id.localeCompare(a.id));
    const roots = group.filter(event => !event.previousEventId);
    const terminals = group.filter(event => !(successors.get(event.id)?.length));
    const forks = group.filter(event => (successors.get(event.id)?.length ?? 0) > 1);
    const missing = group.some(event => event.previousEventId && !byId.has(event.previousEventId));
    if (!truncated && roots.length > 1) emit("DISCONNECTED_ROOTS", "ERROR",
      roots[0]!, null, "A diagnostic has multiple independent recorded review roots.",
      "Reconstruct human review chronology from the authoritative audit ledger.");
    if (!truncated && roots.length === 0) emit("NO_ROOT", "ERROR",
      group[0]!, null, "No initial review root is recorded for this diagnostic.",
      "Investigate missing events or cyclical predecessor references.");
    const values = group.map(event => depths.get(event.id)).filter(
      (depth): depth is number => typeof depth === "number");
    cases.push({
      caseKey: identity, code: group[0]!.code, resourceId: group[0]!.resourceId,
      events: group.length, roots: roots.length, terminals: terminals.length,
      forks: forks.length,
      maxDepth: values.length ? Math.max(...values) : null,
      hasCycle: group.some(event => cycles.has(event.id)),
      hasUnknownHistory: truncated || missing,
      latestDecision: ordered[0]!.decision, latestEventId: ordered[0]!.id,
    });
  }
  if (malformedRows) emit("UNPARSEABLE_SOURCE", "WARNING", null, null,
    "Some recorded source audit rows cannot be decoded as human reviews.",
    "Inspect the affected original audit-event metadata.");
  if (truncated) emit("HISTORY_LIMIT_REACHED", "UNKNOWN", null, null,
    "The source audit-event query exceeded its configured record limit.",
    "Increase the permitted cap or inspect a narrower work audit history.");
  const nodes = events.map(event => ({
    id: event.id, caseKey: key(event), decision: event.decision,
    code: event.code, resourceId: event.resourceId,
    previousEventId: event.previousEventId, revision: event.revision,
    occurredAt: event.occurredAt.toISOString(), actorUserId: event.actorUserId,
    rationale: input.includeRationale ? event.rationale : null,
    successorIds: [...(successors.get(event.id) ?? [])].sort(),
    depthFromRoot: depths.get(event.id) ?? null,
    isRoot: !event.previousEventId,
    isTerminal: !(successors.get(event.id)?.length),
  })).sort((a, b) => a.caseKey.localeCompare(b.caseKey) ||
    (a.depthFromRoot ?? 999999) - (b.depthFromRoot ?? 999999) ||
    a.id.localeCompare(b.id));
  cases.sort((a, b) => b.forks - a.forks || a.caseKey.localeCompare(b.caseKey));
  issues.sort((a, b) => {
    const rank = { ERROR: 0, WARNING: 1, UNKNOWN: 2 };
    return rank[a.severity] - rank[b.severity] ||
      a.code.localeCompare(b.code) ||
      (a.eventId ?? "").localeCompare(b.eventId ?? "");
  });
  return {
    organizationId, workItemId, workTitle: input.workTitle,
    workRevision: input.workRevision, generatedAt: input.generatedAt,
    sourceRows: rows.length, malformedRows, sourceTruncated: truncated,
    nodes, cases, issues,
    totals: {
      cases: cases.length, nodes: nodes.length,
      errors: issues.filter(issue => issue.severity === "ERROR").length,
      warnings: issues.filter(issue => issue.severity === "WARNING").length,
      unknowns: issues.filter(issue => issue.severity === "UNKNOWN").length,
      forks: cases.reduce((sum, entry) => sum + entry.forks, 0),
    },
    limitations: [
      "The analysis reads only organization-scoped stored audit events for the selected work item.",
      "Review event identities are checked for internal links; they are not cryptographic proofs of immutability.",
      "Truncated source windows may omit predecessors and successors.",
      "This investigation does not change any reviewed decision, work item or finding.",
      "Recorded human reviews cannot certify remediation or security-control effectiveness.",
    ],
  };
}
export async function loadAuditBranches(
  scope: BranchScope, raw: Record<string, unknown>,
  now = new Date(),
): Promise<BranchReport> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization access required.");
  const filters = parseBranchFilters(raw);
  const work = await db.remediationWorkItem.findFirst({
    where: { id: filters.workItemId, organizationId: scope.organizationId },
    select: { id: true, title: true, revision: true },
  });
  if (!work) throw new WorkInputError("MISSING", "Work item unavailable.");
  const rows = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceId: work.id, resourceType: TRIAGE_RESOURCE_TYPE,
      action: TRIAGE_AUDIT_ACTION,
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: filters.limit + 1,
    select: {
      id: true, organizationId: true, resourceId: true,
      actorUserId: true, occurredAt: true, metadata: true,
    },
  });
  return inspectAuditBranches({
    organizationId: scope.organizationId, workItemId: work.id,
    workTitle: work.title, workRevision: work.revision,
    generatedAt: now.toISOString(),
    rows: rows.slice(0, filters.limit),
    truncated: rows.length > filters.limit,
    includeRationale: filters.includeRationale,
  });
}
export function auditBranchesCsv(report: BranchReport): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const header = ["caseKey", "eventId", "decision", "occurredAt",
    "revision", "previousEventId", "successorIds", "depthFromRoot",
    "isRoot", "isTerminal"];
  const lines = [header.map(quote).join(",")];
  for (const node of report.nodes) lines.push([
    node.caseKey, node.id, node.decision, node.occurredAt,
    node.revision, node.previousEventId, node.successorIds.join(";"),
    node.depthFromRoot, node.isRoot, node.isTerminal,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
