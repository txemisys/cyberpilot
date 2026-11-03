import { db } from "@cyberpilot/database";
import {
  canReadWork, parseWorkId, WorkInputError,
} from "./remediation-work-input";
import type {
  ReviewAction, ReviewDisposition, ReviewScope,
} from "./work-integrity-persistent-review";

/**
 * Independent consistency check of the persisted review ledger.
 * The checker reads database records; it does not accept client-supplied
 * event histories as proof of successful execution.
 */
export type PersistedReviewLedgerFinding = {
  code:
    | "REVISION_GAP" | "REVISION_MISMATCH" | "INVALID_TRANSITION"
    | "STATE_MISMATCH" | "OWNER_MISMATCH" | "EVENT_ACTOR_MISSING"
    | "COMMAND_MISSING" | "COMMAND_DUPLICATE"
    | "COMMAND_RESPONSE_MISMATCH" | "AUDIT_MISSING"
    | "AUDIT_DUPLICATE" | "AUDIT_ACTOR_MISMATCH"
    | "AUDIT_REVISION_MISMATCH" | "RESOLUTION_EVIDENCE_MISSING"
    | "RESOLUTION_EVIDENCE_INVALID" | "COMPLETION_MISMATCH"
    | "UNSUPPORTED_EVENT" | "CAPTURE_MISSING";
  revision: number | null;
  eventId: string | null;
  message: string;
};
export type PersistedReviewLedgerReport = {
  taskId: string;
  captureId: string;
  organizationId: string;
  evaluatedAt: string;
  currentDisposition: ReviewDisposition;
  currentRevision: number;
  expectedDisposition: ReviewDisposition;
  expectedRevision: number;
  eventCount: number;
  commandCount: number;
  auditCount: number;
  complete: boolean;
  consistent: boolean;
  findings: PersistedReviewLedgerFinding[];
  limitations: string[];
};
type LedgerEvent = {
  id: string;
  action: ReviewAction;
  actorUserId: string | null;
  revisionBefore: number;
  revisionAfter: number;
  before: ReviewDisposition;
  after: ReviewDisposition;
  evidenceRefs: unknown;
};
type LedgerCommand = {
  taskId: string;
  actorUserId: string;
  response: unknown;
};
type LedgerAudit = {
  action: string;
  actorUserId: string | null;
  metadata: unknown;
};
type LedgerTask = {
  id: string;
  organizationId: string;
  captureId: string;
  disposition: ReviewDisposition;
  revision: number;
  ownerUserId: string | null;
  completedAt: Date | null;
  resolutionRefs: unknown;
};
const transitions: Record<ReviewAction, {
  from: readonly ReviewDisposition[];
  to: ReviewDisposition;
}> = {
  ACKNOWLEDGE: {
    from: ["OPEN", "REOPENED"], to: "ACKNOWLEDGED",
  },
  START_REVIEW: {
    from: ["ACKNOWLEDGED"], to: "IN_REVIEW",
  },
  RESOLVE: {
    from: ["IN_REVIEW"], to: "RESOLVED",
  },
  WAIVE: {
    from: ["ACKNOWLEDGED", "IN_REVIEW"], to: "WAIVED",
  },
  REOPEN: {
    from: ["RESOLVED", "WAIVED"], to: "REOPENED",
  },
};
function record(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null ||
      Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value) ||
      value.some(x => typeof x !== "string")) return null;
  return value;
}
function sameStrings(a: unknown, b: unknown) {
  const left = stringArray(a);
  const right = stringArray(b);
  return left !== null && right !== null &&
    left.length === right.length &&
    left.every((value, index) => value === right[index]);
}
export function verifyPersistedReviewLedger(
  task: LedgerTask,
  events: readonly LedgerEvent[],
  commands: readonly LedgerCommand[],
  audits: readonly LedgerAudit[],
  evaluatedAt = new Date(),
): PersistedReviewLedgerReport {
  const findings: PersistedReviewLedgerFinding[] = [];
  const add = (
    code: PersistedReviewLedgerFinding["code"],
    revision: number | null,
    eventId: string | null,
    message: string,
  ) => findings.push({ code, revision, eventId, message });
  let expectedRevision = 1;
  let expectedDisposition: ReviewDisposition = "OPEN";
  let expectedOwner: string | null = null;
  let lastResolutionRefs: string[] = [];
  const eventIds = new Set<string>();
  for (const event of events) {
    const revision = event.revisionAfter;
    if (eventIds.has(event.id)) {
      add("REVISION_GAP", revision, event.id,
        "The event ID appears more than once.");
    }
    eventIds.add(event.id);
    if (event.revisionBefore !== expectedRevision ||
        event.revisionAfter !== expectedRevision + 1) {
      add("REVISION_GAP", revision, event.id,
        "The event revision sequence is not contiguous.");
    }
    if (event.before !== expectedDisposition) {
      add("STATE_MISMATCH", revision, event.id,
        "The event before-state disagrees with the replayed state.");
    }
    const transition = transitions[event.action];
    if (!transition) {
      add("UNSUPPORTED_EVENT", revision, event.id,
        "Unknown event action.");
      continue;
    }
    if (!transition.from.includes(expectedDisposition) ||
        event.after !== transition.to) {
      add("INVALID_TRANSITION", revision, event.id,
        "Event action or after-state violates the review state machine.");
    }
    if (event.actorUserId === null) {
      add("EVENT_ACTOR_MISSING", revision, event.id,
        "The event actor is no longer attributable.");
    } else if (event.action === "ACKNOWLEDGE") {
      if (expectedOwner !== null &&
          expectedOwner !== event.actorUserId)
        add("OWNER_MISMATCH", revision, event.id,
          "Another actor acknowledged an owned review.");
      expectedOwner = event.actorUserId;
    } else if (event.actorUserId !== expectedOwner) {
      add("OWNER_MISMATCH", revision, event.id,
        "The actor does not match the acknowledged review owner.");
    }
    if (event.action === "RESOLVE") {
      const refs = stringArray(event.evidenceRefs);
      if (refs === null || refs.length === 0)
        add("RESOLUTION_EVIDENCE_MISSING", revision, event.id,
          "Resolution has no valid evidence reference list.");
      lastResolutionRefs = refs ?? [];
    } else if (event.action === "REOPEN") {
      lastResolutionRefs = [];
    }
    const matchedCommands = commands.filter(command => {
      const response = record(command.response);
      return response?.eventId === event.id;
    });
    if (matchedCommands.length === 0)
      add("COMMAND_MISSING", revision, event.id,
        "No persisted idempotency command references this event.");
    if (matchedCommands.length > 1)
      add("COMMAND_DUPLICATE", revision, event.id,
        "Multiple commands reference the same event.");
    for (const command of matchedCommands) {
      const response = record(command.response);
      if (command.taskId !== task.id ||
          command.actorUserId !== event.actorUserId ||
          response?.revision !== revision ||
          response?.action !== event.action ||
          response?.disposition !== event.after) {
        add("COMMAND_RESPONSE_MISMATCH", revision, event.id,
          "The command response does not match the persisted event.");
      }
    }
    const matchingAudits = audits.filter(audit => {
      const metadata = record(audit.metadata);
      return metadata?.eventId === event.id;
    });
    if (matchingAudits.length === 0)
      add("AUDIT_MISSING", revision, event.id,
        "No audit record references this event.");
    if (matchingAudits.length > 1)
      add("AUDIT_DUPLICATE", revision, event.id,
        "Multiple audit records reference this event.");
    for (const audit of matchingAudits) {
      const metadata = record(audit.metadata);
      if (audit.actorUserId !== event.actorUserId ||
          audit.action !==
            "integrity.review." + event.action.toLowerCase()) {
        add("AUDIT_ACTOR_MISMATCH", revision, event.id,
          "The audit actor or action disagrees with the event.");
      }
      if (metadata?.revisionBefore !== event.revisionBefore ||
          metadata?.revisionAfter !== event.revisionAfter ||
          metadata?.dispositionBefore !== event.before ||
          metadata?.dispositionAfter !== event.after) {
        add("AUDIT_REVISION_MISMATCH", revision, event.id,
          "The audit revision or state metadata disagrees with the event.");
      }
    }
    expectedRevision = event.revisionAfter;
    expectedDisposition = event.after;
  }
  if (task.revision !== expectedRevision)
    add("REVISION_MISMATCH", null, null,
      "The task revision does not match the replayed event ledger.");
  if (task.disposition !== expectedDisposition)
    add("STATE_MISMATCH", null, null,
      "The current task state does not match replayed events.");
  if (task.ownerUserId !== expectedOwner)
    add("OWNER_MISMATCH", null, null,
      "The current task owner differs from the event ledger.");
  const isCompleted = ["RESOLVED", "WAIVED"].includes(task.disposition);
  if (isCompleted !== (task.completedAt !== null))
    add("COMPLETION_MISMATCH", null, null,
      "Completion timestamp disagrees with task disposition.");
  if (task.disposition === "RESOLVED" &&
      !sameStrings(task.resolutionRefs, lastResolutionRefs))
    add("RESOLUTION_EVIDENCE_INVALID", null, null,
      "Stored resolution references disagree with the resolution event.");
  if (commands.length !== events.length)
    add("COMMAND_DUPLICATE", null, null,
      "Persisted command count differs from event count.");
  if (audits.length !== events.length)
    add("AUDIT_DUPLICATE", null, null,
      "Persisted audit count differs from event count.");
  const complete = findings.length === 0;
  return {
    taskId: task.id, captureId: task.captureId,
    organizationId: task.organizationId,
    evaluatedAt: evaluatedAt.toISOString(),
    currentDisposition: task.disposition,
    currentRevision: task.revision,
    expectedDisposition, expectedRevision,
    eventCount: events.length,
    commandCount: commands.length,
    auditCount: audits.length,
    complete, consistent: complete,
    findings,
    limitations: [
      "Ledger consistency checks database records; it is not cryptographic attestation.",
      "A consistent ledger does not independently verify remediation effectiveness.",
      "Deleted actors and external evidence changes may require separate investigation.",
    ],
  };
}
export async function inspectPersistedReviewLedger(
  scope: ReviewScope, taskId: string,
): Promise<PersistedReviewLedgerReport> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review access denied.");
  const id = parseWorkId(taskId, "review task ID");
  const task = await db.integrityReviewTask.findFirst({
    where: { id, organizationId: scope.organizationId },
    select: {
      id: true, organizationId: true, captureId: true,
      disposition: true, revision: true, ownerUserId: true,
      completedAt: true, resolutionRefs: true,
    },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  if (task.revision > 10001)
    throw new WorkInputError("INVALID",
      "Ledger exceeds the maximum 10,000 transitions.");
  const [events, commands, audits] = await db.$transaction([
    db.integrityReviewEvent.findMany({
      where: { organizationId: scope.organizationId, taskId: id },
      orderBy: [{ revisionAfter: "asc" }, { id: "asc" }],
      take: 10001,
      select: {
        id: true, action: true, actorUserId: true,
        revisionBefore: true, revisionAfter: true,
        before: true, after: true, evidenceRefs: true,
      },
    }),
    db.integrityReviewCommand.findMany({
      where: { organizationId: scope.organizationId, taskId: id },
      take: 10001,
      select: {
        taskId: true, actorUserId: true, response: true,
      },
    }),
    db.auditEvent.findMany({
      where: {
        organizationId: scope.organizationId,
        resourceType: "IntegrityReviewTask",
        resourceId: id,
        action: { startsWith: "integrity.review." },
        NOT: { action: "integrity.review.created" },
      },
      take: 10001,
      select: { action: true, actorUserId: true, metadata: true },
    }),
  ]);
  if (events.length > 10000 || commands.length > 10000 ||
      audits.length > 10000)
    throw new WorkInputError("INVALID",
      "Ledger exceeds the maximum 10,000 records.");
  return verifyPersistedReviewLedger(
    task, events, commands, audits, new Date());
}
