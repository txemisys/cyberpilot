import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import {
  canManageWork, canReadWork, parseWorkId, WorkInputError,
} from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Reconciles durable review events and provider observations with the in-app
 * inbox. Explicitly invoked by an administrator; it is not a scheduler.
 * Source events are immutable and notification deduplication is recipient
 * scoped, so a repeated reconciliation never sends a second inbox item.
 */
export type EventFeed = "REVIEW" | "PROVIDER";
export type EventNotice = {
  sourceId: string;
  taskId: string;
  source: EventFeed;
  kind: "REVIEW_RESOLVED" | "PROVIDER_FAILURE" | "PROVIDER_RECOVERED";
  recipientUserId: string;
  title: string;
  message: string;
  dedupeKey: string;
  context: Record<string, string | number | boolean | null>;
};
export type EventReconcileInput = {
  captureId: string;
  includeReviewEvents: boolean;
  includeProviderChecks: boolean;
  dryRun: boolean;
  offset: number;
  limit: number;
  maxNotifications: number;
};
export type EventReconcileRow = {
  taskId: string;
  source: EventFeed;
  sourceId: string;
  kind: EventNotice["kind"];
  recipients: number;
  created: number;
  replayed: number;
  skipped: boolean;
  reason: string;
  notificationIds: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected event reconciliation object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseEventReconcileInput(value: unknown): EventReconcileInput {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "includeReviewEvents", "includeProviderChecks",
    "dryRun", "offset", "limit", "maxNotifications",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown event reconciliation field.");
  for (const key of [
    "includeReviewEvents", "includeProviderChecks", "dryRun",
  ]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid " + key + ".");
  }
  const includeReviewEvents = raw.includeReviewEvents !== false;
  const includeProviderChecks = raw.includeProviderChecks !== false;
  if (!includeReviewEvents && !includeProviderChecks)
    throw new WorkInputError("INVALID", "At least one event feed is required.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    includeReviewEvents,
    includeProviderChecks,
    dryRun: raw.dryRun !== false,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 25, "limit", 1, 100),
    maxNotifications: integer(
      raw.maxNotifications ?? 200, "notification limit", 1, 1000),
  };
}
export type SourceReviewEvent = {
  id: string;
  taskId: string;
  action: string;
  after: string;
  revisionAfter: number;
  occurredAt: Date;
};
export type SourceProviderCheck = {
  id: string;
  taskId: string;
  outcome: string;
  provider: string;
  controlId: string;
  checkedAt: Date;
};
export type EventTask = {
  id: string;
  title: string;
  severity: string;
  ownerUserId: string | null;
  disposition: string;
};
export type EventMember = { userId: string; role: string };
export function eventRecipients(
  members: EventMember[], task: EventTask,
): string[] {
  const allowed = new Set(members.map(member => member.userId));
  const recipients = new Set<string>();
  if (task.ownerUserId && allowed.has(task.ownerUserId))
    recipients.add(task.ownerUserId);
  for (const member of members)
    if (member.role === "ADMIN" || member.role === "OWNER")
      recipients.add(member.userId);
  return [...recipients].sort();
}
function contentDigest(value: {
  kind: string; sourceId: string; taskId: string;
}) {
  return createHash("sha256")
    .update(JSON.stringify(value)).digest("hex").slice(0, 32);
}
export function reviewEventNotice(
  event: SourceReviewEvent,
  task: EventTask,
  recipientUserId: string,
): EventNotice | null {
  if (event.after !== "RESOLVED" || event.action !== "RESOLVE")
    return null;
  return {
    sourceId: event.id, source: "REVIEW",
    taskId: event.taskId,
    kind: "REVIEW_RESOLVED",
    recipientUserId,
    title: "Integrity review resolved",
    message: "The human review \"" + task.title +
      "\" was marked resolved. This does not certify the underlying security control.",
    dedupeKey: "event:review:" + contentDigest({
      kind: "REVIEW_RESOLVED",
      sourceId: event.id, taskId: event.taskId,
    }),
    context: {
      source: "REVIEW_EVENT",
      sourceId: event.id,
      reviewRevision: event.revisionAfter,
      occurredAt: event.occurredAt.toISOString(),
      verified: false,
    },
  };
}
export function providerEventNotice(
  check: SourceProviderCheck,
  task: EventTask,
  recipientUserId: string,
): EventNotice | null {
  if (check.outcome !== "PASS" && check.outcome !== "FAIL")
    return null;
  const passed = check.outcome === "PASS";
  const kind = passed ? "PROVIDER_RECOVERED" : "PROVIDER_FAILURE";
  return {
    sourceId: check.id, source: "PROVIDER",
    taskId: check.taskId, kind, recipientUserId,
    title: passed ? "Provider check passed" : "Provider check failed",
    message: "Independent provider observation for \"" + task.title +
      "\" reported " + check.outcome + " on control " +
      check.controlId + ". Inspect the underlying evidence before acting.",
    dedupeKey: "event:provider:" + contentDigest({
      kind, sourceId: check.id, taskId: check.taskId,
    }),
    context: {
      source: "PROVIDER_CHECK",
      sourceId: check.id, provider: check.provider,
      controlId: check.controlId,
      outcome: check.outcome,
      checkedAt: check.checkedAt.toISOString(),
      reviewDisposition: task.disposition,
    },
  };
}
export function planEventNotifications(
  tasks: EventTask[],
  members: EventMember[],
  reviews: SourceReviewEvent[],
  checks: SourceProviderCheck[],
) {
  const taskById = new Map(tasks.map(task => [task.id, task]));
  const notices: EventNotice[] = [];
  const ignored: Array<{ source: EventFeed; sourceId: string; reason: string }> = [];
  for (const event of reviews) {
    const task = taskById.get(event.taskId);
    if (!task) {
      ignored.push({ source: "REVIEW", sourceId: event.id, reason: "Task not in scope." });
      continue;
    }
    const recipients = eventRecipients(members, task);
    if (!recipients.length) {
      ignored.push({ source: "REVIEW", sourceId: event.id, reason: "No recipients." });
      continue;
    }
    for (const recipient of recipients) {
      const notice = reviewEventNotice(event, task, recipient);
      if (notice) notices.push(notice);
    }
  }
  for (const check of checks) {
    const task = taskById.get(check.taskId);
    if (!task) {
      ignored.push({ source: "PROVIDER", sourceId: check.id, reason: "Task not in scope." });
      continue;
    }
    const recipients = eventRecipients(members, task);
    if (!recipients.length) {
      ignored.push({ source: "PROVIDER", sourceId: check.id, reason: "No recipients." });
      continue;
    }
    for (const recipient of recipients) {
      const notice = providerEventNotice(check, task, recipient);
      if (notice) notices.push(notice);
    }
  }
  return {
    notices: notices.sort((a, b) =>
      a.source.localeCompare(b.source) ||
      a.sourceId.localeCompare(b.sourceId) ||
      a.recipientUserId.localeCompare(b.recipientUserId)),
    ignored,
  };
}
export function groupEventReconcileRows(
  notices: EventNotice[],
  outcome: Map<string, { id: string; replayed: boolean }>,
): EventReconcileRow[] {
  const grouped = new Map<string, EventReconcileRow>();
  for (const notice of notices) {
    const key = notice.source + ":" + notice.sourceId;
    const row = grouped.get(key) ?? {
      taskId: notice.taskId, source: notice.source,
      sourceId: notice.sourceId, kind: notice.kind,
      recipients: 0, created: 0, replayed: 0,
      skipped: false, reason: "In-app delivery evaluated.",
      notificationIds: [],
    };
    row.recipients++;
    const result = outcome.get(notice.dedupeKey + ":" + notice.recipientUserId);
    if (result) {
      row.notificationIds.push(result.id);
      if (result.replayed) row.replayed++;
      else row.created++;
    } else {
      row.skipped = true;
      row.reason = "Preview or notification cap reached.";
    }
    grouped.set(key, row);
  }
  return [...grouped.values()].sort((a, b) =>
    a.source.localeCompare(b.source) || a.sourceId.localeCompare(b.sourceId));
}
export async function reconcileIntegrityEvents(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  const input = parseEventReconcileInput(value);
  if (input.dryRun ? !canReadWork(scope.role) : !canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Event reconciliation denied.");
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: input.captureId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const [total, tasks, members] = await Promise.all([
    db.integrityReviewTask.count({
      where: {
        organizationId: scope.organizationId,
        captureId: input.captureId,
      },
    }),
    db.integrityReviewTask.findMany({
      where: {
        organizationId: scope.organizationId,
        captureId: input.captureId,
      },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: input.offset, take: input.limit,
      select: {
        id: true, title: true, severity: true,
        disposition: true, ownerUserId: true,
      },
    }),
    db.membership.findMany({
      where: { organizationId: scope.organizationId },
      select: { userId: true, role: true },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const [reviews, checks] = await Promise.all([
    input.includeReviewEvents && taskIds.length ?
      db.integrityReviewEvent.findMany({
        where: {
          organizationId: scope.organizationId,
          taskId: { in: taskIds },
          action: "RESOLVE",
        },
        orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
        take: 1000,
        select: {
          id: true, taskId: true, action: true, after: true,
          revisionAfter: true, occurredAt: true,
        },
      }) : Promise.resolve([]),
    input.includeProviderChecks && taskIds.length ?
      db.integrityProviderCheck.findMany({
        where: {
          organizationId: scope.organizationId,
          taskId: { in: taskIds },
          outcome: { in: ["PASS", "FAIL"] },
        },
        orderBy: [{ checkedAt: "asc" }, { id: "asc" }],
        take: 1000,
        select: {
          id: true, taskId: true, outcome: true,
          provider: true, controlId: true, checkedAt: true,
        },
      }) : Promise.resolve([]),
  ]);
  const plan = planEventNotifications(tasks, members, reviews, checks);
  const outcomes = new Map<string, { id: string; replayed: boolean }>();
  const selected = plan.notices.slice(0, input.maxNotifications);
  if (!input.dryRun) {
    for (const notice of selected) {
      // Revalidate source, task, recipient and organization within the
      // transaction. An old event must not be dispatched across tenants.
      const result = await db.$transaction(async tx => {
        const [task, member] = await Promise.all([
          tx.integrityReviewTask.findFirst({
            where: {
              id: notice.taskId, organizationId: scope.organizationId,
              captureId: input.captureId,
            },
            select: { id: true },
          }),
          tx.membership.findFirst({
            where: {
              organizationId: scope.organizationId,
              userId: notice.recipientUserId,
            },
            select: { id: true },
          }),
        ]);
        if (!task || !member) return null;
        const sourceExists = notice.source === "REVIEW" ?
          await tx.integrityReviewEvent.findFirst({
            where: {
              id: notice.sourceId,
              taskId: notice.taskId,
              organizationId: scope.organizationId,
            },
            select: { id: true },
          }) :
          await tx.integrityProviderCheck.findFirst({
            where: {
              id: notice.sourceId,
              taskId: notice.taskId,
              organizationId: scope.organizationId,
            },
            select: { id: true },
          });
        if (!sourceExists) return null;
        const existing = await tx.integrityNotification.findUnique({
          where: {
            organizationId_recipientUserId_dedupeKey: {
              organizationId: scope.organizationId,
              recipientUserId: notice.recipientUserId,
              dedupeKey: notice.dedupeKey,
            },
          },
        });
        if (existing) {
          if (existing.taskId !== notice.taskId ||
              existing.kind !== notice.kind ||
              existing.title !== notice.title ||
              existing.message !== notice.message)
            throw new WorkInputError("CONFLICT", "Event notification key collision.");
          return { id: existing.id, replayed: true };
        }
        const created = await tx.integrityNotification.create({
          data: {
            organizationId: scope.organizationId,
            taskId: notice.taskId,
            recipientUserId: notice.recipientUserId,
            kind: notice.kind,
            dedupeKey: notice.dedupeKey,
            title: notice.title, message: notice.message,
            context: notice.context,
          },
        });
        await tx.auditEvent.create({
          data: {
            organizationId: scope.organizationId,
            actorType: "USER", actorUserId: scope.userId,
            action: "integrity.notification.event_reconciled",
            resourceType: "IntegrityNotification",
            resourceId: created.id,
            metadata: {
              taskId: notice.taskId, source: notice.source,
              sourceId: notice.sourceId,
              recipientUserId: notice.recipientUserId,
              kind: notice.kind,
              dedupeKey: notice.dedupeKey,
              occurredAt: now.toISOString(),
              delivery: "IN_APP",
            },
          },
        });
        return { id: created.id, replayed: false };
      });
      if (result)
        outcomes.set(notice.dedupeKey + ":" + notice.recipientUserId, result);
    }
  }
  const rows = groupEventReconcileRows(plan.notices, outcomes);
  return {
    captureId: input.captureId,
    dryRun: input.dryRun,
    totalTasks: total,
    offset: input.offset, limit: input.limit,
    scannedTasks: tasks.length,
    hasMore: input.offset + tasks.length < total,
    reviewEventsScanned: reviews.length,
    providerChecksScanned: checks.length,
    sourceLimitReached: reviews.length >= 1000 || checks.length >= 1000,
    plannedNotifications: plan.notices.length,
    selectedNotifications: selected.length,
    capReached: plan.notices.length > input.maxNotifications,
    created: [...outcomes.values()].filter(row => !row.replayed).length,
    replayed: [...outcomes.values()].filter(row => row.replayed).length,
    rows, ignored: plan.ignored,
    limitations: [
      "Reconciliation is an explicit administrator action, not a background scheduler.",
      "Only the selected task page is scanned.",
      "Each source query is capped at 1,000 records and reports truncation.",
      "The notification cap applies to the selected page, not the entire capture.",
      "Provider PASS observations are historical and do not certify current security.",
      "Delivery is in-app only; review disposition and CyberScore remain unchanged.",
    ],
  };
}
