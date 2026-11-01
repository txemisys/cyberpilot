import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError, type WorkRole } from "./remediation-work-input";
import {
  TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE,
  hydrateTriageEvent, type TriageEvent,
} from "./work-integrity-triage";

/**
 * Inspect a single recorded audit event and its immediate source relationships.
 * All database reads are constrained by the trusted organization, never by
 * organization identifiers supplied by clients.
 */
export type EventDetailScope = {
  organizationId: string;
  userId: string;
  role: WorkRole;
};
export type AuditEventSource = {
  id: string;
  organizationId: string;
  resourceId: string | null;
  actorUserId: string | null;
  occurredAt: Date;
  metadata: Prisma.JsonValue | null;
};
export type AuditEventLink = {
  id: string;
  relation: "SELECTED" | "PREDECESSOR" | "SUCCESSOR";
  workItemId: string;
  caseKey: string;
  occurredAt: string;
  actorUserId: string | null;
  decision: string;
  reviewedRevision: number;
  previousEventId: string | null;
  rationale: string;
  reference: string | null;
  isCurrentWorkRevision: boolean | null;
};
export type AuditEventDetailIssueCode =
  | "MISSING_PREDECESSOR"
  | "PREDECESSOR_DIFFERENT_CASE"
  | "REPEATED_REVIEW_SUCCESSOR"
  | "REVIEW_REVISION_DECREASED"
  | "REVIEW_TIME_REVERSED"
  | "SUCCESSOR_UNLINKED_FROM_SELECTED"
  | "WORK_ITEM_UNAVAILABLE"
  | "OUTDATED_WORK_REVISION"
  | "REVIEW_ACTOR_UNAVAILABLE"
  | "SOURCE_METADATA_UNINTERPRETABLE"
  | "EVENT_NOT_IN_TRIAGE_SCOPE";
export type AuditEventDetailIssue = {
  code: AuditEventDetailIssueCode;
  severity: "ERROR" | "WARNING" | "UNKNOWN";
  message: string;
  nextAction: string;
  relatedEventId: string | null;
};
export type AuditEventDetail = {
  organizationId: string;
  eventId: string;
  generatedAt: string;
  workItemId: string | null;
  workTitle: string | null;
  workStatus: string | null;
  currentWorkRevision: number | null;
  selected: AuditEventLink | null;
  predecessor: AuditEventLink | null;
  successors: AuditEventLink[];
  linkedEventCount: number;
  successorQueryTruncated: boolean;
  problems: AuditEventDetailIssue[];
  sourceIsComplete: boolean;
  limitations: string[];
};
type Work = {
  id: string;
  title: string;
  status: string;
  revision: number;
};
function caseKey(e: TriageEvent): string {
  return JSON.stringify([e.workItemId, e.code, e.resourceId]);
}
function link(
  e: TriageEvent, relation: AuditEventLink["relation"],
  work: Work | null,
): AuditEventLink {
  return {
    id: e.id, relation, workItemId: e.workItemId, caseKey: caseKey(e),
    occurredAt: e.occurredAt.toISOString(),
    actorUserId: e.actorUserId, decision: e.decision,
    reviewedRevision: e.revision, previousEventId: e.previousEventId,
    rationale: e.rationale, reference: e.reference,
    isCurrentWorkRevision: work ? e.revision === work.revision : null,
  };
}
export function inspectAuditEventDetail(input: {
  organizationId: string;
  generatedAt: string;
  eventId: string;
  selectedRaw: AuditEventSource;
  predecessorRaw: AuditEventSource | null;
  candidateSuccessors: readonly AuditEventSource[];
  successorQueryTruncated: boolean;
  work: Work | null;
}): AuditEventDetail {
  const {
    organizationId, generatedAt, eventId, selectedRaw,
    predecessorRaw, candidateSuccessors, successorQueryTruncated, work,
  } = input;
  if (!organizationId || selectedRaw.id !== eventId)
    throw new Error("Invalid trusted event inspection context.");
  for (const raw of [selectedRaw, predecessorRaw, ...candidateSuccessors]) {
    if (raw && raw.organizationId !== organizationId)
      throw new Error("Cross-organization audit event in source inspection.");
  }
  const selected = hydrateTriageEvent(selectedRaw);
  const predecessor = predecessorRaw ? hydrateTriageEvent(predecessorRaw) : null;
  const successors = candidateSuccessors.map(hydrateTriageEvent)
    .filter((event): event is TriageEvent => event !== null);
  const problems: AuditEventDetailIssue[] = [];
  const emit = (
    code: AuditEventDetailIssueCode, severity: AuditEventDetailIssue["severity"],
    message: string, nextAction: string, relatedEventId: string | null = null,
  ) => problems.push({ code, severity, message, nextAction, relatedEventId });
  if (!selected) {
    emit("SOURCE_METADATA_UNINTERPRETABLE", "ERROR",
      "The source audit record cannot be decoded as an integrity triage decision.",
      "Inspect its original immutable-intent audit metadata.");
    return {
      organizationId, eventId, generatedAt,
      workItemId: selectedRaw.resourceId,
      workTitle: work?.title ?? null, workStatus: work?.status ?? null,
      currentWorkRevision: work?.revision ?? null,
      selected: null, predecessor: null, successors: [],
      linkedEventCount: 0, successorQueryTruncated,
      problems, sourceIsComplete: false,
      limitations: ["The selected audit record is not a decodable integrity review event."],
    };
  }
  if (work && work.id !== selected.workItemId)
    throw new Error("Work source does not match the trusted event identity.");
  if (!work) emit("WORK_ITEM_UNAVAILABLE", "UNKNOWN",
    "The event references work not available under this organization's current work records.",
    "Inspect archival and retention records without discarding audit history.");
  if (work && selected.revision !== work.revision) emit(
    "OUTDATED_WORK_REVISION", "WARNING",
    "This review references a different revision than currently stored work.",
    "Check whether an authorized new review is required.");
  if (selected.actorUserId === null) emit(
    "REVIEW_ACTOR_UNAVAILABLE", "WARNING",
    "The recorded review actor is not retained in its user reference.",
    "Inspect source actor and account lifecycle.");
  if (selected.previousEventId) {
    if (!predecessor) emit("MISSING_PREDECESSOR", "UNKNOWN",
      "The predecessor referenced by the selected event was not available.",
      "Inspect the tenant audit source for a missing or retained historical event.",
      selected.previousEventId);
    else if (caseKey(predecessor) !== caseKey(selected)) emit(
      "PREDECESSOR_DIFFERENT_CASE", "ERROR",
      "The predecessor belongs to another diagnostic case identity.",
      "Reconcile source predecessor references before relying on the decision.",
      predecessor.id);
    else {
      if (predecessor.revision > selected.revision) emit(
        "REVIEW_REVISION_DECREASED", "ERROR",
        "The reviewed work revision moved backward across linked events.",
        "Check work revision concurrency and event sequence.",
        predecessor.id);
      if (predecessor.occurredAt > selected.occurredAt) emit(
        "REVIEW_TIME_REVERSED", "WARNING",
        "The selected event is earlier than its linked predecessor.",
        "Inspect source event time and transaction ordering.",
        predecessor.id);
    }
  }
  if (successors.length > 1) emit(
    "REPEATED_REVIEW_SUCCESSOR", "ERROR",
    "More than one subsequent review points to the selected event.",
    "Inspect concurrent triage decisions and optimistic-lock enforcement.");
  for (const successor of successors) {
    if (successor.previousEventId !== selected.id) emit(
      "SUCCESSOR_UNLINKED_FROM_SELECTED", "ERROR",
      "The returned event does not actually reference the selected predecessor.",
      "Verify the audit query and event predecessor metadata.",
      successor.id);
    if (caseKey(successor) !== caseKey(selected)) emit(
      "PREDECESSOR_DIFFERENT_CASE", "ERROR",
      "A subsequent event reuses this predecessor across different cases.",
      "Inspect audit reference identity and tenant-scoped case history.",
      successor.id);
    if (successor.revision < selected.revision) emit(
      "REVIEW_REVISION_DECREASED", "ERROR",
      "A subsequent review refers to an earlier work revision.",
      "Inspect revision and decision ordering.",
      successor.id);
    if (successor.occurredAt < selected.occurredAt) emit(
      "REVIEW_TIME_REVERSED", "WARNING",
      "A subsequent review was recorded earlier than its predecessor.",
      "Compare source event clocks and ordering.",
      successor.id);
  }
  if (successorQueryTruncated) emit(
    "REPEATED_REVIEW_SUCCESSOR", "UNKNOWN",
    "The bounded successor search exceeded the source cap.",
    "Inspect a narrowed source event range to establish all linked decisions.");
  const linkedEventCount = 1 + (predecessor ? 1 : 0) + successors.length;
  return {
    organizationId, eventId, generatedAt, workItemId: selected.workItemId,
    workTitle: work?.title ?? null, workStatus: work?.status ?? null,
    currentWorkRevision: work?.revision ?? null,
    selected: link(selected, "SELECTED", work),
    predecessor: predecessor ? link(predecessor, "PREDECESSOR", work) : null,
    successors: successors.map(event => link(event, "SUCCESSOR", work)),
    linkedEventCount, successorQueryTruncated, problems,
    sourceIsComplete: !successorQueryTruncated &&
      problems.every(problem => problem.severity !== "ERROR" &&
        problem.severity !== "UNKNOWN"),
    limitations: [
      "The direct source query is scoped to one organization and a single selected audit event.",
      "Immediate links do not guarantee the complete historical chain is present.",
      "Audit event metadata documents human actions and is not an independent immutability proof.",
      "No reviewed decision establishes successful remediation or security-control effectiveness.",
      "This read-only investigation never changes a task, decision or finding.",
    ],
  };
}
/**
 * Produce a source-linked, bounded case chronology for audit investigators.
 * The links below are only the selected event and its direct relationships;
 * gaps are deliberately retained instead of being reconstructed as facts.
 */
export type EventReviewChronology = {
  organizationId: string;
  workItemId: string | null;
  selectedEventId: string;
  events: Array<{
    id: string;
    relation: AuditEventLink["relation"];
    timestamp: string;
    decision: string;
    reviewedRevision: number;
    actorUserId: string | null;
    predecessorEventId: string | null;
    isCurrentWorkRevision: boolean | null;
  }>;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  chronologicalReversals: number;
  missingSourceLinks: number;
  reviewActors: number;
  revisionChanges: number;
  successorBranches: number;
  coverage: "PARTIAL" | "LINKS_OBSERVED";
  recommendations: string[];
};
export function eventReviewChronology(detail: AuditEventDetail): EventReviewChronology {
  const linked = [
    ...(detail.predecessor ? [detail.predecessor] : []),
    ...(detail.selected ? [detail.selected] : []),
    ...detail.successors,
  ];
  const events = [...linked].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) || a.id.localeCompare(b.id));
  const index = new Map(events.map(event => [event.id, event]));
  let chronologicalReversals = 0;
  let missingSourceLinks = 0;
  for (const event of events) {
    if (event.previousEventId === null) continue;
    const predecessor = index.get(event.previousEventId);
    if (!predecessor) {
      missingSourceLinks++;
      continue;
    }
    if (predecessor.occurredAt > event.occurredAt) chronologicalReversals++;
  }
  const reviewActors = new Set(events.map(event => event.actorUserId)
    .filter((id): id is string => id !== null)).size;
  let revisionChanges = 0;
  for (let i = 1; i < events.length; i++) {
    if (events[i]!.reviewedRevision !== events[i - 1]!.reviewedRevision)
      revisionChanges++;
  }
  const recommendations: string[] = [];
  if (missingSourceLinks > 0) recommendations.push(
    "Open the broader work-item audit chain to inspect missing immediate history.");
  if (chronologicalReversals > 0) recommendations.push(
    "Compare authoritative audit timestamps before trusting review ordering.");
  if (detail.successors.length > 1) recommendations.push(
    "Investigate review concurrency because one decision has multiple successors.");
  if (detail.successorQueryTruncated) recommendations.push(
    "Narrow the audit history window; the successor source query was capped.");
  if (detail.problems.some(problem => problem.severity === "ERROR"))
    recommendations.push("Reconcile source review links before accepting recorded dispositions.");
  if (!recommendations.length) recommendations.push(
    "No direct-link issue identified; independently verify any remediation claims.");
  const partial = detail.successorQueryTruncated || missingSourceLinks > 0 ||
    !detail.selected || detail.problems.some(problem => problem.severity === "UNKNOWN");
  return {
    organizationId: detail.organizationId,
    workItemId: detail.workItemId,
    selectedEventId: detail.eventId,
    events: events.map(event => ({
      id: event.id, relation: event.relation,
      timestamp: event.occurredAt, decision: event.decision,
      reviewedRevision: event.reviewedRevision,
      actorUserId: event.actorUserId,
      predecessorEventId: event.previousEventId,
      isCurrentWorkRevision: event.isCurrentWorkRevision,
    })),
    firstObservedAt: events[0]?.occurredAt ?? null,
    lastObservedAt: events[events.length - 1]?.occurredAt ?? null,
    chronologicalReversals, missingSourceLinks, reviewActors,
    revisionChanges, successorBranches: detail.successors.length,
    coverage: partial ? "PARTIAL" : "LINKS_OBSERVED",
    recommendations,
  };
}
export async function loadAuditEventDetail(
  scope: EventDetailScope, rawId: unknown, now = new Date(),
): Promise<AuditEventDetail> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization access required.");
  const id = parseWorkId(rawId, "audit event ID");
  const select = {
    id: true, organizationId: true, resourceId: true,
    actorUserId: true, occurredAt: true, metadata: true,
  } as const;
  const selectedRaw = await db.auditEvent.findFirst({
    where: {
      organizationId: scope.organizationId, id,
      resourceType: TRIAGE_RESOURCE_TYPE, action: TRIAGE_AUDIT_ACTION,
    },
    select,
  });
  if (!selectedRaw) throw new WorkInputError("MISSING", "Audit event unavailable in this organization.");
  const selected = hydrateTriageEvent(selectedRaw);
  const previous = selected?.previousEventId ?
    await db.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId,
        id: selected.previousEventId,
        resourceType: TRIAGE_RESOURCE_TYPE, action: TRIAGE_AUDIT_ACTION,
      }, select,
    }) : null;
  const rawSuccessors = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: TRIAGE_RESOURCE_TYPE, action: TRIAGE_AUDIT_ACTION,
      ...(selected?.workItemId ? { resourceId: selected.workItemId } : {
        resourceId: selectedRaw.resourceId,
      }),
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: 1001, select,
  });
  const successors = rawSuccessors.map(hydrateTriageEvent)
    .filter((event): event is TriageEvent => !!event && event.previousEventId === id);
  const work = selected?.workItemId ? await db.remediationWorkItem.findFirst({
    where: { id: selected.workItemId, organizationId: scope.organizationId },
    select: { id: true, title: true, status: true, revision: true },
  }) : null;
  return inspectAuditEventDetail({
    organizationId: scope.organizationId, generatedAt: now.toISOString(),
    eventId: id, selectedRaw, predecessorRaw: previous,
    candidateSuccessors: rawSuccessors.length > 1000 ? successors.slice(0, 1000) : successors,
    successorQueryTruncated: rawSuccessors.length > 1000,
    work,
  });
}
