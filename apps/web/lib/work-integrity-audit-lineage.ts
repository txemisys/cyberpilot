import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError, type WorkRole } from "./remediation-work-input";
import {
  TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE, hydrateTriageEvent,
  type TriageEvent,
} from "./work-integrity-triage";

/**
 * Follow a single stored review's predecessor links directly in the trusted
 * tenant audit store. Every hop is separately constrained by organization.
 * The bounded walk is read-only, and never certifies source immutability.
 */
export type LineageScope = { organizationId: string; userId: string; role: WorkRole };
export type LineageFilters = { eventId: string; maxDepth: number; includeRationale: boolean };
export type LineageSource = {
  id: string; organizationId: string; resourceId: string | null;
  actorUserId: string | null; occurredAt: Date; metadata: Prisma.JsonValue | null;
};
export type LineageNode = {
  eventId: string; workItemId: string; code: string; resourceId: string;
  caseKey: string; actorUserId: string | null;
  occurredAt: string; decision: string; reviewedRevision: number;
  previousEventId: string | null; rationale: string | null;
  reference: string | null; depth: number;
};
export type LineageIssueKind =
  | "MISSING_PREDECESSOR" | "CROSS_CASE_REFERENCE"
  | "PREDECESSOR_CYCLE" | "TIME_INVERSION"
  | "REVISION_DECREASE" | "MISSING_ACTOR"
  | "MISSING_RATIONALE" | "INVALID_PREDECESSOR_METADATA"
  | "WORK_ITEM_MISSING" | "WORK_REVISION_DRIFT"
  | "DEPTH_LIMIT_REACHED" | "EVENT_IDENTITY_MISMATCH";
export type LineageIssue = {
  kind: LineageIssueKind;
  severity: "ERROR" | "REVIEW" | "UNKNOWN";
  eventId: string | null; referencedEventId: string | null;
  message: string; nextAction: string;
};
export type LineageReport = {
  organizationId: string; requestedEventId: string; generatedAt: string;
  workItemId: string; workTitle: string | null;
  currentRevision: number | null; nodes: LineageNode[];
  issues: LineageIssue[]; terminal: "ROOT" | "MISSING" | "CYCLE" | "LIMIT" | "INVALID";
  sourceChainComplete: boolean; inspectedEvents: number;
  newestRecordedDecision: string;
  latestReviewedRevision: number;
  latestReviewIsCurrent: boolean | null;
  limitations: string[];
};
export function parseLineageFilters(raw: Record<string, unknown>): LineageFilters {
  for (const key of Object.keys(raw))
    if (!["eventId", "maxDepth", "includeRationale"].includes(key))
      throw new WorkInputError("INVALID", "Unknown audit lineage parameter.");
  const eventId = parseWorkId(raw.eventId, "audit event ID");
  const maxDepth = raw.maxDepth === undefined ? 100 : Number(raw.maxDepth);
  if (![25, 50, 100, 250, 500].includes(maxDepth))
    throw new WorkInputError("INVALID", "Audit lineage depth must be 25, 50, 100, 250 or 500.");
  if (raw.includeRationale !== undefined &&
      raw.includeRationale !== "true" && raw.includeRationale !== "false")
    throw new WorkInputError("INVALID", "Invalid rationale display option.");
  return { eventId, maxDepth, includeRationale: raw.includeRationale === "true" };
}
function identity(event: TriageEvent): string {
  return JSON.stringify([event.workItemId, event.code, event.resourceId]);
}
function makeNode(event: TriageEvent, depth: number, includeRationale: boolean): LineageNode {
  return {
    eventId: event.id, workItemId: event.workItemId,
    code: event.code, resourceId: event.resourceId,
    caseKey: identity(event), actorUserId: event.actorUserId,
    occurredAt: event.occurredAt.toISOString(),
    decision: event.decision, reviewedRevision: event.revision,
    previousEventId: event.previousEventId,
    rationale: includeRationale ? event.rationale : null,
    reference: includeRationale ? event.reference : null,
    depth,
  };
}
export function reconstructAuditLineage(input: {
  organizationId: string; generatedAt: string; eventId: string;
  raw: readonly LineageSource[];
  completeToRoot: boolean; maxDepth: number;
  includeRationale: boolean;
  work: { id: string; title: string; revision: number } | null;
}): LineageReport {
  const { organizationId, eventId, raw, work, maxDepth } = input;
  if (!organizationId || raw.length === 0)
    throw new Error("Source lineage requires a trusted selected event.");
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1 || raw.length > maxDepth)
    throw new Error("Invalid bounded lineage reconstruction.");
  for (const record of raw)
    if (record.organizationId !== organizationId)
      throw new Error("Cross-organization audit source lineage.");
  if (raw[0]!.id !== eventId)
    throw new Error("The selected source event does not match requested identity.");
  const first = hydrateTriageEvent(raw[0]!);
  if (!first) throw new WorkInputError("INVALID", "Selected audit event is not a decoded triage review.");
  if (work && work.id !== first.workItemId)
    throw new Error("Linked work does not match the source audit identity.");
  const nodes: LineageNode[] = [];
  const issues: LineageIssue[] = [];
  const seen = new Set<string>();
  let terminal: LineageReport["terminal"] = "MISSING";
  const add = (
    kind: LineageIssueKind, severity: LineageIssue["severity"],
    eventId: string | null, referencedEventId: string | null,
    message: string, nextAction: string,
  ) => issues.push({ kind, severity, eventId, referencedEventId, message, nextAction });
  let previous: TriageEvent | null = null;
  for (let depth = 0; depth < raw.length; depth++) {
    const record = raw[depth]!;
    if (seen.has(record.id)) {
      terminal = "CYCLE";
      add("PREDECESSOR_CYCLE", "ERROR", record.id, record.id,
        "A source event identity was encountered twice in one predecessor walk.",
        "Investigate the original audit metadata references.");
      break;
    }
    seen.add(record.id);
    const current = hydrateTriageEvent(record);
    if (!current) {
      terminal = "INVALID";
      add("INVALID_PREDECESSOR_METADATA", "ERROR", previous?.id ?? null, record.id,
        "A referenced predecessor cannot be interpreted as a review event.",
        "Inspect source audit metadata under the current organization.");
      break;
    }
    if (previous && previous.previousEventId !== current.id) add(
      "EVENT_IDENTITY_MISMATCH", "ERROR", previous.id, current.id,
      "The next source row is not the predecessor referenced by the previous row.",
      "Re-read audit events and validate source query ordering.");
    if (identity(current) !== identity(first)) add(
      "CROSS_CASE_REFERENCE", "ERROR", previous?.id ?? null, current.id,
      "A predecessor event refers to another diagnostic case.",
      "Investigate a cross-case audit reference without silently merging identities.");
    if (current.actorUserId === null) add(
      "MISSING_ACTOR", "REVIEW", current.id, null,
      "The recorded actor reference is no longer available.",
      "Inspect original actor type and user retention metadata.");
    if (!current.rationale.trim()) add(
      "MISSING_RATIONALE", "REVIEW", current.id, null,
      "A recorded review event has no readable rationale.",
      "Request a new auditable explanation; do not rewrite the original event.");
    if (previous) {
      if (current.occurredAt > previous.occurredAt) add(
        "TIME_INVERSION", "REVIEW", previous.id, current.id,
        "A predecessor is recorded later than the review that references it.",
        "Compare event source clocks and transaction ordering.");
      if (current.revision > previous.revision) add(
        "REVISION_DECREASE", "ERROR", previous.id, current.id,
        "The reviewed work revision decreases between linked events.",
        "Reconcile stored work revision history and audit decisions.");
    }
    nodes.push(makeNode(current, depth, input.includeRationale));
    previous = current;
    if (current.previousEventId === null) {
      terminal = "ROOT";
      break;
    }
  }
  if (terminal === "MISSING") {
    const last = nodes[nodes.length - 1]!;
    if (last?.previousEventId && seen.has(last.previousEventId)) {
      terminal = "CYCLE";
      add("PREDECESSOR_CYCLE", "ERROR", last.eventId, last.previousEventId,
        "The next predecessor points to an event already visited.",
        "Inspect cyclical event references in stored audit metadata.");
    } else if (last?.previousEventId && raw.length >= maxDepth) {
      terminal = "LIMIT";
      add("DEPTH_LIMIT_REACHED", "UNKNOWN", last.eventId, last.previousEventId,
        "The chain extends beyond the configured maximum depth.",
        "Increase the bounded depth or inspect earlier audit history.");
    } else if (last?.previousEventId) add(
      "MISSING_PREDECESSOR", "UNKNOWN", last.eventId, last.previousEventId,
      "The next referenced predecessor was not available in the selected audit source.",
      "Investigate event retention and the source record identity.");
  }
  if (terminal === "LIMIT" && input.completeToRoot)
    throw new Error("Inconsistent source completion flag.");
  if (!work) add(
    "WORK_ITEM_MISSING", "UNKNOWN", first.id, null,
    "The associated work item was not found in current tenant records.",
    "Inspect the work archive before interpreting historical review coverage.");
  else if (work.revision !== first.revision) add(
    "WORK_REVISION_DRIFT", "REVIEW", first.id, null,
    "The selected human review refers to a different work revision than currently stored.",
    "Determine whether the current work revision requires an authorized new review.");
  const sourceChainComplete = terminal === "ROOT" &&
    issues.every(issue => issue.severity !== "ERROR" && issue.severity !== "UNKNOWN");
  return {
    organizationId, requestedEventId: eventId,
    generatedAt: input.generatedAt,
    workItemId: first.workItemId, workTitle: work?.title ?? null,
    currentRevision: work?.revision ?? null,
    nodes, issues, terminal, sourceChainComplete,
    inspectedEvents: nodes.length, newestRecordedDecision: first.decision,
    latestReviewedRevision: first.revision,
    latestReviewIsCurrent: work ? first.revision === work.revision : null,
    limitations: [
      "Predecessor links were queried separately from the organization's stored audit events.",
      "A complete link walk is not cryptographic evidence of audit immutability.",
      "The selected event is not necessarily the latest review for the diagnostic case.",
      "Human decisions cannot certify the effectiveness of remediation or security controls.",
      "No source record was modified by this investigation.",
    ],
  };
}
export async function loadAuditLineage(
  scope: LineageScope, rawFilters: Record<string, unknown>, now = new Date(),
): Promise<LineageReport> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Authorized organization membership required.");
  const filters = parseLineageFilters(rawFilters);
  const select = {
    id: true, organizationId: true, resourceId: true,
    actorUserId: true, occurredAt: true, metadata: true,
  } as const;
  const rows: LineageSource[] = [];
  const visited = new Set<string>();
  let cursor: string | null = filters.eventId;
  let completeToRoot = false;
  for (let depth = 0; cursor !== null && depth < filters.maxDepth; depth++) {
    if (visited.has(cursor)) break;
    visited.add(cursor);
    const record: LineageSource | null = await db.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId, id: cursor,
        action: TRIAGE_AUDIT_ACTION, resourceType: TRIAGE_RESOURCE_TYPE,
      },
      select,
    });
    if (!record) {
      if (!rows.length)
        throw new WorkInputError("MISSING", "Audit event unavailable in this organization.");
      break;
    }
    rows.push(record);
    const parsed = hydrateTriageEvent(record);
    if (!parsed) break;
    if (!parsed.previousEventId) {
      completeToRoot = true;
      break;
    }
    cursor = parsed.previousEventId;
  }
  const first = rows.length ? hydrateTriageEvent(rows[0]!) : null;
  if (!first) throw new WorkInputError("INVALID", "Selected audit event cannot be decoded.");
  const work = await db.remediationWorkItem.findFirst({
    where: { id: first.workItemId, organizationId: scope.organizationId },
    select: { id: true, title: true, revision: true },
  });
  return reconstructAuditLineage({
    organizationId: scope.organizationId, eventId: filters.eventId,
    generatedAt: now.toISOString(),
    raw: rows.slice(0, filters.maxDepth),
    completeToRoot, maxDepth: filters.maxDepth,
    includeRationale: filters.includeRationale, work,
  });
}
export function auditLineageCsv(report: LineageReport): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const neutral = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutral.replace(/"/g, '""') + '"';
  };
  const columns = [
    "depth", "eventId", "workItemId", "code", "resourceId", "actorUserId",
    "occurredAt", "decision", "reviewedRevision", "previousEventId", "rationale", "reference",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const node of report.nodes) lines.push([
    node.depth, node.eventId, node.workItemId, node.code, node.resourceId,
    node.actorUserId, node.occurredAt, node.decision, node.reviewedRevision,
    node.previousEventId, node.rationale, node.reference,
  ].map(quote).join(","));
  return lines.join("\r\n") + "\r\n";
}
