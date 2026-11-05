import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { calculateEscalationCandidate, parseEscalationPolicy } from "./work-integrity-escalations";
import type { EscalationPolicy } from "./work-integrity-escalations";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Explicit, administrator-triggered dispatch.
 * No background schedule, external email, SMS or push is claimed.
 * All writes occur within one database transaction per task.
 */
export type DispatchInput = {
  captureId: string;
  policy: EscalationPolicy;
  offset: number;
  limit: number;
  dryRun: boolean;
};
export type DispatchRow = {
  taskId: string;
  level: number;
  dedupeKey: string;
  recipients: string[];
  escalationId: string | null;
  notificationIds: string[];
  replayed: boolean;
  skipped: boolean;
  reason: string;
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid dispatch request.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseDispatchInput(value: unknown): DispatchInput {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "policy", "offset", "limit", "dryRun",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown dispatch field.");
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dry-run flag.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    policy: parseEscalationPolicy(raw.policy),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    dryRun: raw.dryRun !== false,
  };
}
type Recipient = {
  userId: string;
  role: string;
};
export function selectEscalationRecipients(
  members: Recipient[], ownerUserId: string | null,
): string[] {
  const eligible = new Set(members.map(member => member.userId));
  const recipients = new Set<string>();
  if (ownerUserId && eligible.has(ownerUserId))
    recipients.add(ownerUserId);
  for (const member of members) {
    if (member.role === "OWNER" || member.role === "ADMIN")
      recipients.add(member.userId);
  }
  return [...recipients].sort();
}
export function dispatchNotificationContent(
  task: { title: string; severity: string },
  level: number, dueAt: Date,
) {
  const title = "Integrity review escalation L" + level;
  const message = "Review \"" + task.title + "\" (" + task.severity +
    ") exceeded its response threshold at " + dueAt.toISOString() +
    ". Open the integrity review workspace to investigate.";
  return { title, message };
}
export async function dispatchCaptureEscalations(
  scope: ReviewScope, value: unknown,
  now = new Date(),
) {
  const query = parseDispatchInput(value);
  if (query.dryRun ? !canReadWork(scope.role) : !canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation dispatch denied.");
  const capture = await db.integrityCaseCapture.findFirst({
    where: {
      id: query.captureId, organizationId: scope.organizationId,
    },
    select: { id: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    captureId: query.captureId,
    disposition: { notIn: ["RESOLVED", "WAIVED"] as
      Array<"RESOLVED" | "WAIVED"> },
  };
  const [total, tasks, members] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, title: true, severity: true,
        disposition: true, ownerUserId: true, createdAt: true,
      },
    }),
    db.membership.findMany({
      where: { organizationId: scope.organizationId },
      select: { userId: true, role: true },
    }),
  ]);
  const rows: DispatchRow[] = [];
  for (const task of tasks) {
    const candidate = calculateEscalationCandidate(
      task, now, query.policy);
    if (!candidate) continue;
    const recipients = selectEscalationRecipients(members, task.ownerUserId);
    if (!recipients.length) {
      rows.push({
        taskId: task.id, level: candidate.level,
        dedupeKey: candidate.dedupeKey, recipients,
        escalationId: null, notificationIds: [],
        replayed: false, skipped: true,
        reason: "No eligible organization recipient.",
      });
      continue;
    }
    if (query.dryRun) {
      rows.push({
        taskId: task.id, level: candidate.level,
        dedupeKey: candidate.dedupeKey, recipients,
        escalationId: null, notificationIds: [],
        replayed: false, skipped: false,
        reason: "Dry-run: no writes or delivery performed.",
      });
      continue;
    }
    const row = await db.$transaction(async tx => {
      // Re-check inside transaction: an earlier page scan is not proof
      // that the review is still actionable when dispatch executes.
      const fresh = await tx.integrityReviewTask.findFirst({
        where: {
          id: task.id, organizationId: scope.organizationId,
        },
        select: {
          id: true, title: true, severity: true,
          disposition: true, ownerUserId: true, createdAt: true,
        },
      });
      const current = fresh ?
        calculateEscalationCandidate(fresh, now, query.policy) : null;
      if (!current || current.dedupeKey !== candidate.dedupeKey)
        return {
          taskId: task.id, level: candidate.level,
          dedupeKey: candidate.dedupeKey, recipients,
          escalationId: null, notificationIds: [],
          replayed: false, skipped: true,
          reason: "Review state changed before dispatch.",
        };
      const existing = await tx.integrityEscalation.findUnique({
        where: {
          organizationId_taskId_dedupeKey: {
            organizationId: scope.organizationId,
            taskId: task.id, dedupeKey: current.dedupeKey,
          },
        },
      });
      const escalation = existing ?? await tx.integrityEscalation.create({
        data: {
          organizationId: scope.organizationId,
          taskId: task.id,
          level: current.level,
          state: "OPEN", reason: current.reason,
          dedupeKey: current.dedupeKey,
          dueAt: current.dueAt, actorUserId: scope.userId,
        },
      });
      if (!existing) {
        await tx.auditEvent.create({
          data: {
            organizationId: scope.organizationId,
            actorType: "USER", actorUserId: scope.userId,
            action: "integrity.escalation.dispatched",
            resourceType: "IntegrityEscalation",
            resourceId: escalation.id,
            metadata: {
              taskId: task.id, level: current.level,
              recipients: recipients.length,
              dueAt: current.dueAt.toISOString(),
            },
          },
        });
      }
      const content = dispatchNotificationContent(
        fresh!, current.level, current.dueAt);
      const notificationIds: string[] = [];
      for (const recipientUserId of recipients) {
        // The dedupe key is scoped per recipient and organization.
        const dedupeKey = "escalation:" + escalation.id;
        const previous = await tx.integrityNotification.findUnique({
          where: {
            organizationId_recipientUserId_dedupeKey: {
              organizationId: scope.organizationId,
              recipientUserId, dedupeKey,
            },
          },
          select: { id: true },
        });
        if (previous) {
          notificationIds.push(previous.id);
          continue;
        }
        const notification = await tx.integrityNotification.create({
          data: {
            organizationId: scope.organizationId,
            taskId: task.id, recipientUserId,
            kind: "REVIEW_ESCALATED",
            dedupeKey, title: content.title,
            message: content.message,
            context: {
              escalationId: escalation.id,
              level: current.level,
              dueAt: current.dueAt.toISOString(),
            },
          },
        });
        notificationIds.push(notification.id);
        await tx.auditEvent.create({
          data: {
            organizationId: scope.organizationId,
            actorType: "USER", actorUserId: scope.userId,
            action: "integrity.notification.dispatched",
            resourceType: "IntegrityNotification",
            resourceId: notification.id,
            metadata: {
              taskId: task.id, escalationId: escalation.id,
              recipientUserId, delivery: "IN_APP",
            },
          },
        });
      }
      return {
        taskId: task.id, level: current.level,
        dedupeKey: current.dedupeKey, recipients,
        escalationId: escalation.id, notificationIds,
        replayed: existing !== null, skipped: false,
        reason: existing ?
          "Existing escalation and inbox messages reused." :
          "Escalation and in-app messages persisted.",
      };
    });
    rows.push(row);
  }
  return {
    captureId: query.captureId, total,
    offset: query.offset, limit: query.limit,
    hasMore: query.offset + tasks.length < total,
    dryRun: query.dryRun,
    rows,
    summary: {
      eligible: rows.length,
      dispatched: rows.filter(x => !x.skipped && !query.dryRun).length,
      replayed: rows.filter(x => x.replayed).length,
      skipped: rows.filter(x => x.skipped).length,
      recipients: rows.reduce((sum, x) => sum + x.recipients.length, 0),
    },
    limitations: [
      "Dispatch is an explicit authenticated administrator action.",
      "Delivery is in-app only; no external messaging is attempted.",
      "A dispatch does not resolve review tasks or security findings.",
      "Summary counts cover the selected task page only.",
    ],
  };
}
