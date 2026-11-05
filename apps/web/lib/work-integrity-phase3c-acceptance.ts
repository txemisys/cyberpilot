import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

export type AcceptanceQuery = {
  captureId: string;
  offset: number;
  limit: number;
  includeClosed: boolean;
  minimumProviderAgeHours: number;
  maxNotificationAgeHours: number;
};
export type AcceptanceTask = {
  id: string; captureId: string; severity: string;
  disposition: string; revision: number;
  ownerUserId: string | null; createdAt: Date;
  completedAt: Date | null;
};
export type AcceptanceReviewEvent = {
  id: string; taskId: string; action: string;
  revisionBefore: number; revisionAfter: number;
  before: string; after: string; occurredAt: Date;
};
export type AcceptanceNotification = {
  id: string; taskId: string; recipientUserId: string;
  revision: number; kind: string; createdAt: Date;
  readAt: Date | null; dismissedAt: Date | null;
};
export type AcceptanceEscalation = {
  id: string; taskId: string; state: string;
  revision: number; level: number;
  openedAt: Date; dueAt: Date;
  acknowledgedAt: Date | null; resolvedAt: Date | null;
};
export type AcceptanceProvider = {
  id: string; taskId: string; outcome: string;
  checkedAt: Date; providerObservedAt: Date | null;
};
export type AcceptanceWorkLink = {
  taskId: string; workItemId: string;
  linkedAt: Date; unlinkedAt: Date | null;
};
export type AcceptanceAudit = {
  id: string; resourceId: string | null;
  action: string; occurredAt: Date;
};
export type AcceptanceCode =
  | "INVALID_REVIEW_REVISION"
  | "CLOSED_WITHOUT_COMPLETION"
  | "OPEN_WITH_COMPLETION"
  | "COMPLETION_BEFORE_CREATION"
  | "REVIEW_EVENT_REVISION_GAP"
  | "REVIEW_EVENT_REVISION_COLLISION"
  | "REVIEW_EVENT_STATE_MISMATCH"
  | "REVIEW_EVENT_FUTURE_REVISION"
  | "NOTIFICATION_BEFORE_TASK"
  | "NOTIFICATION_INVALID_REVISION"
  | "NOTIFICATION_READ_BEFORE_CREATION"
  | "NOTIFICATION_DISMISSED_BEFORE_CREATION"
  | "NOTIFICATION_UNREAD_AGED"
  | "NOTIFICATION_RECIPIENT_NOT_MEMBER"
  | "ESCALATION_OPEN_BEFORE_TASK"
  | "ESCALATION_DUE_BEFORE_OPEN"
  | "ESCALATION_ACK_BEFORE_OPEN"
  | "ESCALATION_RESOLVED_BEFORE_OPEN"
  | "ESCALATION_STATE_INCONSISTENT"
  | "PROVIDER_CHECK_BEFORE_TASK"
  | "PROVIDER_CHECK_FUTURE_OBSERVATION"
  | "PROVIDER_OBSERVATION_OLD"
  | "PROVIDER_FAILURE_WITH_HUMAN_CLOSURE"
  | "WORK_LINK_AFTER_UNLINK"
  | "AUDIT_MISSING_TRIAGE_ACTION"
  | "PROVIDER_CHECK_NOT_PRESENT"
  | "NO_REVIEW_EVENTS";
export type AcceptanceFinding = {
  code: AcceptanceCode;
  level: "BLOCKER" | "REVIEW" | "INFORMATION";
  taskId: string;
  entity: "REVIEW" | "EVENT" | "NOTIFICATION" |
    "ESCALATION" | "PROVIDER" | "WORK" | "AUDIT";
  entityId: string;
  message: string;
};
export type AcceptanceTaskReport = {
  taskId: string;
  captureId: string;
  disposition: string;
  revision: number;
  reviews: number;
  notifications: number;
  escalations: number;
  providerChecks: number;
  workLinks: number;
  auditEvents: number;
  blockers: number;
  reviewsRequired: number;
  findings: AcceptanceFinding[];
  digest: string;
};
export type AcceptanceSummary = {
  tasks: number;
  taskBlockers: number;
  tasksRequiringReview: number;
  blockers: number;
  reviewsRequired: number;
  information: number;
  notifications: number;
  escalations: number;
  providerChecks: number;
  reviewEvents: number;
  auditedActions: number;
  byCode: Partial<Record<AcceptanceCode, number>>;
};
export type AcceptanceReport = {
  schema: "cyberpilot.integrity.phase3c.acceptance.v1";
  organizationId: string;
  captureId: string;
  generatedAt: string;
  offset: number;
  limit: number;
  totalTasks: number;
  hasMore: boolean;
  complete: boolean;
  outcome: "BLOCKED" | "REQUIRES_REVIEW" | "READY_FOR_MANUAL_ACCEPTANCE";
  summary: AcceptanceSummary;
  tasks: AcceptanceTaskReport[];
  digest: string;
  manualRequirements: string[];
  limitations: string[];
};
export type AcceptanceRecords = {
  events: AcceptanceReviewEvent[];
  notifications: AcceptanceNotification[];
  escalations: AcceptanceEscalation[];
  providers: AcceptanceProvider[];
  workLinks: AcceptanceWorkLink[];
  audits: AcceptanceAudit[];
  memberIds: Set<string>;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected phase 3C acceptance query.");
  return value as Record<string, unknown>;
}
function int(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid acceptance " + label + ".");
  return value;
}
export function parseAcceptanceQuery(value: unknown): AcceptanceQuery {
  const raw = object(value);
  if (Object.keys(raw).some(k => ![
    "captureId", "offset", "limit", "includeClosed",
    "minimumProviderAgeHours", "maxNotificationAgeHours",
  ].includes(k)))
    throw new WorkInputError("INVALID", "Unknown acceptance query parameter.");
  if (raw.includeClosed !== undefined && typeof raw.includeClosed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeClosed.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    offset: int(raw.offset ?? 0, "offset", 0, 1000000),
    limit: int(raw.limit ?? 50, "limit", 1, 100),
    includeClosed: raw.includeClosed !== false,
    minimumProviderAgeHours: int(raw.minimumProviderAgeHours ?? 168,
      "provider age", 1, 8760),
    maxNotificationAgeHours: int(raw.maxNotificationAgeHours ?? 72,
      "unread notification age", 1, 8760),
  };
}
export function acceptanceDigest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function analyzeAcceptanceTask(
  task: AcceptanceTask, records: AcceptanceRecords,
  query: AcceptanceQuery, now: Date,
): AcceptanceTaskReport {
  const findings: AcceptanceFinding[] = [];
  const events = records.events.filter(x => x.taskId === task.id)
    .sort((a, b) => a.revisionAfter - b.revisionAfter ||
      a.occurredAt.getTime() - b.occurredAt.getTime() || a.id.localeCompare(b.id));
  const notices = records.notifications.filter(x => x.taskId === task.id);
  const escalations = records.escalations.filter(x => x.taskId === task.id);
  const providers = records.providers.filter(x => x.taskId === task.id)
    .sort((a, b) => b.checkedAt.getTime() - a.checkedAt.getTime() ||
      b.id.localeCompare(a.id));
  const links = records.workLinks.filter(x => x.taskId === task.id);
  const audits = records.audits.filter(x => x.resourceId === task.id);
  function issue(
    code: AcceptanceCode, level: AcceptanceFinding["level"],
    entity: AcceptanceFinding["entity"], entityId: string, message: string,
  ) {
    findings.push({ code, level, taskId: task.id, entity, entityId, message });
  }
  if (!Number.isSafeInteger(task.revision) || task.revision < 1)
    issue("INVALID_REVIEW_REVISION", "BLOCKER", "REVIEW", task.id,
      "The review revision must be a positive integer.");
  const closed = task.disposition === "RESOLVED" || task.disposition === "WAIVED";
  if (closed && !task.completedAt)
    issue("CLOSED_WITHOUT_COMPLETION", "BLOCKER", "REVIEW", task.id,
      "A terminal review has no completion timestamp.");
  if (!closed && task.completedAt)
    issue("OPEN_WITH_COMPLETION", "BLOCKER", "REVIEW", task.id,
      "An active review retains a completion timestamp.");
  if (task.completedAt && task.completedAt < task.createdAt)
    issue("COMPLETION_BEFORE_CREATION", "BLOCKER", "REVIEW", task.id,
      "Completion precedes creation.");
  if (!events.length && task.revision !== 1)
    issue("NO_REVIEW_EVENTS", "BLOCKER", "REVIEW", task.id,
      "Persisted revision exceeds the initial revision but has no events.");
  let prior = 1;
  let priorAfter: string | null = null;
  const seenRevisions = new Set<number>();
  for (const event of events) {
    if (seenRevisions.has(event.revisionAfter))
      issue("REVIEW_EVENT_REVISION_COLLISION", "BLOCKER", "EVENT", event.id,
        "Multiple events claim the same resulting revision.");
    seenRevisions.add(event.revisionAfter);
    if (event.revisionBefore !== prior ||
        event.revisionAfter !== event.revisionBefore + 1)
      issue("REVIEW_EVENT_REVISION_GAP", "BLOCKER", "EVENT", event.id,
        "Event revision does not continue from the preceding revision.");
    if (priorAfter !== null && event.before !== priorAfter)
      issue("REVIEW_EVENT_STATE_MISMATCH", "BLOCKER", "EVENT", event.id,
        "Event before-state differs from the previous after-state.");
    if (event.revisionAfter > task.revision)
      issue("REVIEW_EVENT_FUTURE_REVISION", "BLOCKER", "EVENT", event.id,
        "Event revision exceeds persisted review revision.");
    prior = event.revisionAfter;
    priorAfter = event.after;
  }
  if (events.length && prior !== task.revision)
    issue("REVIEW_EVENT_REVISION_GAP", "BLOCKER", "REVIEW", task.id,
      "Latest event does not reach the persisted review revision.");
  if (priorAfter && priorAfter !== task.disposition)
    issue("REVIEW_EVENT_STATE_MISMATCH", "BLOCKER", "REVIEW", task.id,
      "Latest revision event does not match current review disposition.");
  for (const notice of notices) {
    if (notice.revision < 1)
      issue("NOTIFICATION_INVALID_REVISION", "BLOCKER", "NOTIFICATION", notice.id,
        "Notification revision is not positive.");
    if (notice.createdAt < task.createdAt)
      issue("NOTIFICATION_BEFORE_TASK", "BLOCKER", "NOTIFICATION", notice.id,
        "Notification predates its review.");
    if (notice.readAt && notice.readAt < notice.createdAt)
      issue("NOTIFICATION_READ_BEFORE_CREATION", "BLOCKER",
        "NOTIFICATION", notice.id, "Notification was read before creation.");
    if (notice.dismissedAt && notice.dismissedAt < notice.createdAt)
      issue("NOTIFICATION_DISMISSED_BEFORE_CREATION", "BLOCKER",
        "NOTIFICATION", notice.id, "Notification was dismissed before creation.");
    if (!records.memberIds.has(notice.recipientUserId))
      issue("NOTIFICATION_RECIPIENT_NOT_MEMBER", "REVIEW",
        "NOTIFICATION", notice.id,
        "A persisted recipient is no longer an organization member.");
    if (!notice.readAt && !notice.dismissedAt &&
        now.getTime() - notice.createdAt.getTime() >
          query.maxNotificationAgeHours * 3600000)
      issue("NOTIFICATION_UNREAD_AGED", "REVIEW", "NOTIFICATION", notice.id,
        "An in-app notification has remained unread past the configured threshold.");
  }
  for (const escalation of escalations) {
    if (escalation.openedAt < task.createdAt)
      issue("ESCALATION_OPEN_BEFORE_TASK", "BLOCKER", "ESCALATION", escalation.id,
        "Escalation predates its review.");
    if (escalation.dueAt < escalation.openedAt)
      issue("ESCALATION_DUE_BEFORE_OPEN", "BLOCKER", "ESCALATION", escalation.id,
        "Escalation deadline precedes opening.");
    if (escalation.acknowledgedAt && escalation.acknowledgedAt < escalation.openedAt)
      issue("ESCALATION_ACK_BEFORE_OPEN", "BLOCKER", "ESCALATION", escalation.id,
        "Acknowledgement predates opening.");
    if (escalation.resolvedAt && escalation.resolvedAt < escalation.openedAt)
      issue("ESCALATION_RESOLVED_BEFORE_OPEN", "BLOCKER", "ESCALATION", escalation.id,
        "Escalation was resolved before opening.");
    if ((escalation.state === "RESOLVED" && !escalation.resolvedAt) ||
        (escalation.state === "OPEN" && escalation.resolvedAt))
      issue("ESCALATION_STATE_INCONSISTENT", "BLOCKER", "ESCALATION", escalation.id,
        "Escalation timestamps contradict the persisted lifecycle state.");
  }
  for (const provider of providers) {
    if (provider.checkedAt < task.createdAt)
      issue("PROVIDER_CHECK_BEFORE_TASK", "REVIEW", "PROVIDER", provider.id,
        "Provider observation precedes review creation.");
    if (provider.providerObservedAt && provider.providerObservedAt > provider.checkedAt)
      issue("PROVIDER_CHECK_FUTURE_OBSERVATION", "REVIEW", "PROVIDER",
        provider.id, "Provider observation time follows the check timestamp.");
  }
  const latest = providers[0];
  if (!latest)
    issue("PROVIDER_CHECK_NOT_PRESENT", "INFORMATION", "REVIEW", task.id,
      "No independent provider check is persisted.");
  else {
    if (now.getTime() - latest.checkedAt.getTime() >
        query.minimumProviderAgeHours * 3600000)
      issue("PROVIDER_OBSERVATION_OLD", "REVIEW", "PROVIDER", latest.id,
        "The latest provider result exceeds the configured diagnostic age.");
    if (closed && latest.outcome !== "PASS")
      issue("PROVIDER_FAILURE_WITH_HUMAN_CLOSURE", "REVIEW",
        "PROVIDER", latest.id,
        "A human-closed review has no latest passing provider observation.");
  }
  for (const link of links)
    if (link.unlinkedAt && link.unlinkedAt < link.linkedAt)
      issue("WORK_LINK_AFTER_UNLINK", "BLOCKER", "WORK", link.workItemId,
        "A work link is unlinked before it was created.");
  if ((notices.length || escalations.length) && !audits.length)
    issue("AUDIT_MISSING_TRIAGE_ACTION", "INFORMATION", "AUDIT", task.id,
      "There are operational records but no triage audit events on this page.");
  findings.sort((a, b) => a.code.localeCompare(b.code) ||
    a.entityId.localeCompare(b.entityId));
  const canonical = {
    taskId: task.id, captureId: task.captureId,
    disposition: task.disposition, revision: task.revision,
    reviews: events.length, notifications: notices.length,
    escalations: escalations.length, providerChecks: providers.length,
    workLinks: links.length, auditEvents: audits.length,
    blockers: findings.filter(x => x.level === "BLOCKER").length,
    reviewsRequired: findings.filter(x => x.level === "REVIEW").length,
    findings,
  };
  return { ...canonical, digest: acceptanceDigest(canonical) };
}
export function summarizeAcceptance(tasks: AcceptanceTaskReport[]): AcceptanceSummary {
  const summary: AcceptanceSummary = {
    tasks: tasks.length, taskBlockers: 0, tasksRequiringReview: 0,
    blockers: 0, reviewsRequired: 0, information: 0,
    notifications: 0, escalations: 0, providerChecks: 0,
    reviewEvents: 0, auditedActions: 0, byCode: {},
  };
  for (const task of tasks) {
    if (task.blockers) summary.taskBlockers++;
    if (task.reviewsRequired) summary.tasksRequiringReview++;
    summary.blockers += task.blockers;
    summary.reviewsRequired += task.reviewsRequired;
    summary.notifications += task.notifications;
    summary.escalations += task.escalations;
    summary.providerChecks += task.providerChecks;
    summary.reviewEvents += task.reviews;
    summary.auditedActions += task.auditEvents;
    for (const finding of task.findings) {
      if (finding.level === "INFORMATION") summary.information++;
      summary.byCode[finding.code] = (summary.byCode[finding.code] ?? 0) + 1;
    }
  }
  return summary;
}
export function buildAcceptanceReport(
  organizationId: string, query: AcceptanceQuery, tasks: AcceptanceTask[],
  records: AcceptanceRecords, totalTasks: number, now: Date,
): AcceptanceReport {
  const rows = tasks.map(task => analyzeAcceptanceTask(task, records, query, now));
  const summary = summarizeAcceptance(rows);
  const complete = query.offset === 0 && tasks.length === totalTasks;
  const outcome: AcceptanceReport["outcome"] =
    summary.blockers ? "BLOCKED" :
      summary.reviewsRequired || !complete || !tasks.length ? "REQUIRES_REVIEW" :
        "READY_FOR_MANUAL_ACCEPTANCE";
  const canonical = {
    schema: "cyberpilot.integrity.phase3c.acceptance.v1" as const,
    organizationId, captureId: query.captureId,
    generatedAt: now.toISOString(), offset: query.offset, limit: query.limit,
    totalTasks, hasMore: query.offset + tasks.length < totalTasks,
    complete, outcome, summary, tasks: rows,
  };
  return {
    ...canonical, digest: acceptanceDigest(canonical),
    manualRequirements: [
      "Authenticate as administrator and member; verify menus and page navigation.",
      "Perform a real browser review of inbox read, unread, dismissal and restoration.",
      "Preview and approve one intervention; inspect its persisted audit history.",
      "Exercise concurrent operators and verify that stale ownership is rejected.",
      "Confirm that no provider observation is presented as a current security guarantee.",
      "Confirm release owner sign-off and maintain PR approval separate from this report.",
    ],
    limitations: [
      "This read-only report is not an automated acceptance signature.",
      "Counts and findings describe the inspected page and may omit other tasks.",
      "No network delivery, email, external scheduler or live provider call is assessed.",
      "An operational PASS or human RESOLVED does not change CyberScore.",
      "No acceptance result can substitute for real authenticated user testing.",
    ],
  };
}
export async function readPhase3CAcceptance(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<AcceptanceReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Phase 3C acceptance requires administrator privileges.");
  const query = parseAcceptanceQuery(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: query.captureId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId, captureId: query.captureId,
    ...(query.includeClosed ? {} : {
      disposition: { notIn: ["RESOLVED", "WAIVED"] as Array<"RESOLVED" | "WAIVED"> },
    }),
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, skip: query.offset, take: query.limit,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      select: {
        id: true, captureId: true, severity: true, disposition: true,
        revision: true, ownerUserId: true, createdAt: true, completedAt: true,
      },
    }),
  ]);
  if (!tasks.length)
    return buildAcceptanceReport(scope.organizationId, query, [], {
      events: [], notifications: [], escalations: [], providers: [],
      workLinks: [], audits: [], memberIds: new Set(),
    }, total, now);
  const ids = tasks.map(x => x.id);
  const scoped = { organizationId: scope.organizationId, taskId: { in: ids } };
  const [events, notifications, escalations, providers, workLinks, audits, members] =
    await Promise.all([
      db.integrityReviewEvent.findMany({
        where: scoped, take: 5001, orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, action: true,
          revisionBefore: true, revisionAfter: true,
          before: true, after: true, occurredAt: true,
        },
      }),
      db.integrityNotification.findMany({
        where: scoped, take: 5001, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, recipientUserId: true, revision: true,
          kind: true, createdAt: true, readAt: true, dismissedAt: true,
        },
      }),
      db.integrityEscalation.findMany({
        where: scoped, take: 5001, orderBy: [{ openedAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, state: true, revision: true, level: true,
          openedAt: true, dueAt: true, acknowledgedAt: true, resolvedAt: true,
        },
      }),
      db.integrityProviderCheck.findMany({
        where: scoped, take: 5001, orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
        select: {
          id: true, taskId: true, outcome: true, checkedAt: true,
          providerObservedAt: true,
        },
      }),
      db.integrityReviewWorkLink.findMany({
        where: scoped, take: 5001, select: {
          taskId: true, workItemId: true, linkedAt: true, unlinkedAt: true,
        },
      }),
      db.auditEvent.findMany({
        take: 5001,
        where: {
          organizationId: scope.organizationId,
          resourceType: "IntegrityReviewTask",
          resourceId: { in: ids }, action: { startsWith: "integrity.triage." },
        },
        select: {
          id: true, resourceId: true, action: true, occurredAt: true,
        },
      }),
      db.membership.findMany({
        where: { organizationId: scope.organizationId },
        select: { userId: true },
      }),
    ]);
  const report = buildAcceptanceReport(scope.organizationId, query, tasks, {
    events, notifications, escalations, providers, workLinks, audits,
    memberIds: new Set(members.map(x => x.userId)),
  }, total, now);
  if ([events, notifications, escalations, providers, workLinks, audits]
    .some(rows => rows.length >= 5001)) {
    report.complete = false;
    report.outcome = report.summary.blockers ? "BLOCKED" : "REQUIRES_REVIEW";
    report.limitations.push(
      "One or more related collections exceeded the 5000-record inspection cap. " +
      "This report cannot support a complete acceptance decision.");
    report.digest = acceptanceDigest({
      schema: report.schema, captureId: report.captureId,
      generatedAt: report.generatedAt, summary: report.summary,
      tasks: report.tasks, complete: false, truncated: true,
    });
  }
  return report;
}
