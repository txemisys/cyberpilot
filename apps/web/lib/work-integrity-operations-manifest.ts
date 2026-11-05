import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Read-only, deterministic operational evidence manifest. It deliberately
 * excludes raw provider payloads, access tokens, personal message bodies,
 * and organization secrets. The manifest is not an attestation of security.
 */
export type ManifestQuery = {
  captureId: string;
  offset: number;
  limit: number;
  includeNotificationMetadata: boolean;
  includeEscalationHistory: boolean;
  includeProviderObservations: boolean;
  includeReviewEvents: boolean;
};
export type ManifestEntry = {
  category: "REVIEW" | "REVIEW_EVENT" | "NOTIFICATION" |
    "ESCALATION" | "PROVIDER";
  id: string;
  taskId: string;
  at: string;
  revision: number | null;
  outcome: string;
  actor: string | null;
  sourceDigest: string;
  metadata: Record<string, string | number | boolean | null>;
};
export type ManifestPage = {
  schema: "cyberpilot.integrity.operations.manifest.v1";
  organizationId: string;
  captureId: string;
  offset: number;
  limit: number;
  totalTasks: number;
  hasMore: boolean;
  generatedAt: string;
  entries: ManifestEntry[];
  counts: Record<ManifestEntry["category"], number>;
  taskDigests: Array<{ taskId: string; digest: string; entries: number }>;
  pageDigest: string;
  warnings: string[];
  complete: boolean;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected manifest query object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseManifestQuery(value: unknown): ManifestQuery {
  const raw = object(value);
  const flags = [
    "includeNotificationMetadata", "includeEscalationHistory",
    "includeProviderObservations", "includeReviewEvents",
  ] as const;
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", ...flags,
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown manifest field.");
  for (const flag of flags)
    if (raw[flag] !== undefined && typeof raw[flag] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid manifest flag.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 20, "limit", 1, 50),
    includeNotificationMetadata: raw.includeNotificationMetadata !== false,
    includeEscalationHistory: raw.includeEscalationHistory !== false,
    includeProviderObservations: raw.includeProviderObservations !== false,
    includeReviewEvents: raw.includeReviewEvents !== false,
  };
}
export function manifestDigest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function canonicalManifestEntries(entries: ManifestEntry[]) {
  return [...entries].sort((a, b) =>
    a.taskId.localeCompare(b.taskId) ||
    a.at.localeCompare(b.at) ||
    a.category.localeCompare(b.category) ||
    a.id.localeCompare(b.id));
}
export function buildManifestPage(
  organizationId: string,
  query: ManifestQuery,
  totalTasks: number,
  taskIds: string[],
  entries: ManifestEntry[],
  generatedAt: Date,
  truncated: string[],
): ManifestPage {
  const ordered = canonicalManifestEntries(entries);
  const counts: ManifestPage["counts"] = {
    REVIEW: 0, REVIEW_EVENT: 0,
    NOTIFICATION: 0, ESCALATION: 0, PROVIDER: 0,
  };
  for (const entry of ordered) counts[entry.category]++;
  const taskDigests = taskIds.map(taskId => {
    const relevant = ordered.filter(entry => entry.taskId === taskId);
    return {
      taskId, entries: relevant.length,
      digest: manifestDigest(relevant),
    };
  });
  const canonical = {
    schema: "cyberpilot.integrity.operations.manifest.v1" as const,
    organizationId, captureId: query.captureId,
    offset: query.offset, limit: query.limit,
    totalTasks,
    taskDigests,
    counts,
  };
  const warnings = [
    "Operational record manifest is not a security certification.",
    "No raw provider responses, OAuth tokens or message bodies are included.",
    "Membership and source validity must be evaluated at the time of use.",
    "Each page has its own digest; no capture-wide digest is implied.",
    ...truncated,
  ];
  return {
    ...canonical,
    hasMore: query.offset + taskIds.length < totalTasks,
    generatedAt: generatedAt.toISOString(),
    entries: ordered,
    pageDigest: manifestDigest(canonical),
    warnings, complete: truncated.length === 0,
  };
}
export type ManifestTask = {
  id: string; title: string; severity: string;
  disposition: string; revision: number;
  ownerUserId: string | null; createdAt: Date;
  updatedAt: Date; completedAt: Date | null;
};
export type ManifestReviewEvent = {
  id: string; taskId: string; action: string;
  before: string; after: string;
  actorUserId: string | null; revisionAfter: number;
  occurredAt: Date;
};
export type ManifestNotification = {
  id: string; taskId: string; kind: string;
  recipientUserId: string; revision: number;
  createdAt: Date; readAt: Date | null;
  dismissedAt: Date | null; dedupeKey: string;
};
export type ManifestEscalation = {
  id: string; taskId: string; level: number;
  state: string; revision: number;
  openedAt: Date; dueAt: Date;
  actorUserId: string | null;
  acknowledgedAt: Date | null; resolvedAt: Date | null;
};
export type ManifestProviderCheck = {
  id: string; taskId: string; provider: string;
  outcome: string; controlId: string; subject: string;
  checkedAt: Date; providerObservedAt: Date | null;
  requestDigest: string; observationDigest: string;
  responseDigest: string; failureCode: string | null;
};
export function mapManifestRecords(input: {
  tasks: ManifestTask[];
  reviewEvents: ManifestReviewEvent[];
  notifications: ManifestNotification[];
  escalations: ManifestEscalation[];
  checks: ManifestProviderCheck[];
}): ManifestEntry[] {
  const entries: ManifestEntry[] = [];
  for (const task of input.tasks) {
    const metadata = {
      severity: task.severity,
      ownerAssigned: task.ownerUserId !== null,
      completed: task.completedAt !== null,
      updatedAt: task.updatedAt.toISOString(),
    };
    entries.push({
      category: "REVIEW", id: task.id, taskId: task.id,
      at: task.createdAt.toISOString(), revision: task.revision,
      outcome: task.disposition,
      actor: null,
      sourceDigest: manifestDigest({
        taskId: task.id, revision: task.revision,
        disposition: task.disposition, metadata,
      }),
      metadata,
    });
  }
  for (const event of input.reviewEvents) {
    const metadata = {
      before: event.before, after: event.after,
      action: event.action,
    };
    entries.push({
      category: "REVIEW_EVENT", id: event.id,
      taskId: event.taskId, at: event.occurredAt.toISOString(),
      revision: event.revisionAfter, outcome: event.action,
      actor: event.actorUserId,
      sourceDigest: manifestDigest({
        id: event.id, taskId: event.taskId,
        revision: event.revisionAfter, metadata,
      }),
      metadata,
    });
  }
  for (const notification of input.notifications) {
    const metadata = {
      recipientHash: manifestDigest(notification.recipientUserId),
      dedupeHash: manifestDigest(notification.dedupeKey),
      read: notification.readAt !== null,
      dismissed: notification.dismissedAt !== null,
    };
    entries.push({
      category: "NOTIFICATION", id: notification.id,
      taskId: notification.taskId,
      at: notification.createdAt.toISOString(),
      revision: notification.revision,
      outcome: notification.kind,
      actor: null,
      sourceDigest: manifestDigest({
        id: notification.id, revision: notification.revision,
        kind: notification.kind, metadata,
      }),
      metadata,
    });
  }
  for (const escalation of input.escalations) {
    const metadata = {
      level: escalation.level,
      dueAt: escalation.dueAt.toISOString(),
      acknowledged: escalation.acknowledgedAt !== null,
      closed: escalation.resolvedAt !== null,
    };
    entries.push({
      category: "ESCALATION", id: escalation.id,
      taskId: escalation.taskId,
      at: escalation.openedAt.toISOString(),
      revision: escalation.revision,
      outcome: escalation.state,
      actor: escalation.actorUserId,
      sourceDigest: manifestDigest({
        id: escalation.id, revision: escalation.revision,
        state: escalation.state, metadata,
      }),
      metadata,
    });
  }
  for (const check of input.checks) {
    const metadata = {
      provider: check.provider,
      controlId: check.controlId,
      subjectHash: manifestDigest(check.subject),
      providerObservedAt: check.providerObservedAt?.toISOString() ?? null,
      requestDigest: check.requestDigest,
      observationDigest: check.observationDigest,
      responseDigest: check.responseDigest,
      failureCode: check.failureCode,
    };
    entries.push({
      category: "PROVIDER", id: check.id,
      taskId: check.taskId, at: check.checkedAt.toISOString(),
      revision: null, outcome: check.outcome,
      actor: null,
      sourceDigest: manifestDigest({
        id: check.id, taskId: check.taskId,
        outcome: check.outcome, metadata,
      }),
      metadata,
    });
  }
  return entries;
}
export async function readIntegrityOperationsManifest(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<ManifestPage> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Manifest access denied.");
  const query = parseManifestQuery(value);
  // Exports contain cross-recipient operational metadata and therefore
  // require an administrator even when ordinary inbox reads are allowed.
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Manifest requires an administrator.");
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
  };
  const [totalTasks, tasks] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, title: true, severity: true,
        disposition: true, revision: true,
        ownerUserId: true, createdAt: true,
        updatedAt: true, completedAt: true,
      },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const scoped = {
    organizationId: scope.organizationId,
    taskId: { in: taskIds },
  };
  const cap = 3000;
  const [reviewEvents, notifications, escalations, checks] =
    await Promise.all([
      query.includeReviewEvents && taskIds.length ?
        db.integrityReviewEvent.findMany({
          where: scoped,
          orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
          take: cap,
          select: {
            id: true, taskId: true, action: true,
            before: true, after: true,
            actorUserId: true, revisionAfter: true,
            occurredAt: true,
          },
        }) : Promise.resolve([]),
      query.includeNotificationMetadata && taskIds.length ?
        db.integrityNotification.findMany({
          where: scoped,
          orderBy: [{ createdAt: "asc" }, { id: "asc" }],
          take: cap,
          select: {
            id: true, taskId: true, kind: true,
            recipientUserId: true, revision: true,
            createdAt: true, readAt: true,
            dismissedAt: true, dedupeKey: true,
          },
        }) : Promise.resolve([]),
      query.includeEscalationHistory && taskIds.length ?
        db.integrityEscalation.findMany({
          where: scoped,
          orderBy: [{ openedAt: "asc" }, { id: "asc" }],
          take: cap,
          select: {
            id: true, taskId: true, level: true,
            state: true, revision: true,
            openedAt: true, dueAt: true,
            actorUserId: true, acknowledgedAt: true,
            resolvedAt: true,
          },
        }) : Promise.resolve([]),
      query.includeProviderObservations && taskIds.length ?
        db.integrityProviderCheck.findMany({
          where: scoped,
          orderBy: [{ checkedAt: "asc" }, { id: "asc" }],
          take: cap,
          select: {
            id: true, taskId: true, provider: true,
            outcome: true, controlId: true,
            subject: true, checkedAt: true,
            providerObservedAt: true, requestDigest: true,
            observationDigest: true, responseDigest: true,
            failureCode: true,
          },
        }) : Promise.resolve([]),
    ]);
  const sourceCounts: Array<[string, number]> = [
    ["review events", reviewEvents.length],
    ["notifications", notifications.length],
    ["escalations", escalations.length],
    ["provider checks", checks.length],
  ];
  const truncated = sourceCounts.filter(([, count]) => count >= cap)
    .map(([name]) => "The " + name + " query reached its 3,000-record limit.");
  const entries = mapManifestRecords({
    tasks, reviewEvents, notifications, escalations, checks,
  });
  return buildManifestPage(
    scope.organizationId, query, totalTasks, taskIds,
    entries, now, truncated,
  );
}
