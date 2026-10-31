import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canReadWork, WorkInputError, type WorkRole } from "./remediation-work-input";

/**
 * Independent, read-only consistency check of recorded remediation operations.
 * It never changes a work item, security finding, evidence or remediation status.
 * No anomaly is treated as proof that a security control failed.
 */
export type IntegrityScope = {
  organizationId: string;
  userId: string;
  role: WorkRole;
};
export const INTEGRITY_CODES = [
  "FINDING_MISMATCH",
  "ASSIGNEE_NOT_MEMBER",
  "DONE_WITHOUT_COMPLETION",
  "OPEN_WITH_COMPLETION",
  "COMPLETION_BEFORE_CREATION",
  "DEADLINE_BEFORE_CREATION",
  "MISSING_CREATE_EVENT",
  "EVENT_AFTER_LAST_UPDATE",
  "EVENT_TIME_ORDER",
  "EVENT_REVISION_AHEAD",
  "EVENT_SNAPSHOT_MISMATCH",
  "INVALID_EVENT_SNAPSHOT",
  "CHECKLIST_COMPLETER_MISMATCH",
  "CHECKLIST_COMPLETED_WITHOUT_ACTOR",
  "CHECKLIST_ACTOR_WITHOUT_COMPLETION",
  "EVIDENCE_ORGANIZATION_MISMATCH",
  "EVIDENCE_LINK_MISSING_TARGET",
  "EVIDENCE_UNLINKED_WITHOUT_ACTOR",
  "EVIDENCE_UNLINK_ACTOR_WITHOUT_DATE",
  "HANDOFF_RECIPIENT_NOT_MEMBER",
  "HANDOFF_DECISION_INCOMPLETE",
  "HANDOFF_UNDECIDED_WITH_DECISION",
  "HANDOFF_EXPIRED_PENDING",
  "HANDOFF_ASSIGNEE_DIVERGENCE",
] as const;
export type IntegrityCode = typeof INTEGRITY_CODES[number];
export type IntegritySeverity = "critical" | "attention" | "info";
export type IntegrityFinding = {
  code: IntegrityCode;
  severity: IntegritySeverity;
  workItemId: string;
  resourceId: string;
  message: string;
  recommendation: string;
};
export type IntegrityCursor = { updatedAt: Date; id: string };
export type IntegrityQuery = {
  limit: number;
  cursor: IntegrityCursor | null;
  includeInfo: boolean;
};
type Snapshot = Record<string, unknown>;
export type IntegrityWork = {
  id: string;
  organizationId: string;
  findingId: string;
  remediationId: string;
  assigneeUserId: string | null;
  status: string;
  revision: number;
  createdAt: Date;
  updatedAt: Date;
  completedAt: Date | null;
  dueAt: Date | null;
  finding: { organizationId: string };
  remediation: { organizationId: string; findingId: string };
  events: Array<{
    id: string;
    kind: string;
    occurredAt: Date;
    before: unknown;
    after: unknown;
  }>;
  checklist: Array<{
    id: string;
    completedAt: Date | null;
    completedByUserId: string | null;
  }>;
  evidenceLinks: Array<{
    id: string;
    evidenceId: string;
    unlinkedAt: Date | null;
    unlinkedByUserId: string | null;
    evidence: { organizationId: string } | null;
  }>;
  handoffs: Array<{
    id: string;
    recipientUserId: string;
    status: string;
    decidedAt: Date | null;
    decidedByUserId: string | null;
    expiresAt: Date | null;
  }>;
};
const descriptions: Record<IntegrityCode, { severity: IntegritySeverity; message: string; recommendation: string }> = {
  FINDING_MISMATCH: {
    severity: "critical",
    message: "The work item, remediation and finding do not agree on their relationship or tenant.",
    recommendation: "Investigate the source relationship before relying on this record.",
  },
  ASSIGNEE_NOT_MEMBER: {
    severity: "attention",
    message: "The assigned person is no longer a member of this organization.",
    recommendation: "An authorized owner or admin should review the assignment.",
  },
  DONE_WITHOUT_COMPLETION: {
    severity: "attention",
    message: "The task is marked done but has no completion timestamp.",
    recommendation: "Review the task history; do not infer verification.",
  },
  OPEN_WITH_COMPLETION: {
    severity: "attention",
    message: "An active or cancelled task retains a completion timestamp.",
    recommendation: "Review the status transition and completion timestamp.",
  },
  COMPLETION_BEFORE_CREATION: {
    severity: "critical",
    message: "Completion predates creation.",
    recommendation: "Investigate timestamps and migration history.",
  },
  DEADLINE_BEFORE_CREATION: {
    severity: "info",
    message: "The deadline predates the work item's creation.",
    recommendation: "Confirm whether this was an intentional retrospective deadline.",
  },
  MISSING_CREATE_EVENT: {
    severity: "attention",
    message: "No creation event was found in the retrieved history.",
    recommendation: "Review the full event log before drawing conclusions.",
  },
  EVENT_AFTER_LAST_UPDATE: {
    severity: "info",
    message: "A recorded activity is later than the work item's update timestamp.",
    recommendation: "This can be normal for comments; reconcile the two timelines.",
  },
  EVENT_TIME_ORDER: {
    severity: "critical",
    message: "An event predates the creation of its work item.",
    recommendation: "Investigate clock or data migration inconsistencies.",
  },
  EVENT_REVISION_AHEAD: {
    severity: "critical",
    message: "An event snapshot has a revision greater than the current work item.",
    recommendation: "Check concurrent updates and audit event integrity.",
  },
  EVENT_SNAPSHOT_MISMATCH: {
    severity: "attention",
    message: "The latest update snapshot is inconsistent with the stored work item.",
    recommendation: "Compare the latest mutation and recorded snapshot.",
  },
  INVALID_EVENT_SNAPSHOT: {
    severity: "attention",
    message: "An update event has a missing or unusable snapshot.",
    recommendation: "Inspect the original event and its serializer.",
  },
  CHECKLIST_COMPLETER_MISMATCH: {
    severity: "attention",
    message: "A checklist completion was attributed to a non-member.",
    recommendation: "Review the identity attribution and membership change.",
  },
  CHECKLIST_COMPLETED_WITHOUT_ACTOR: {
    severity: "info",
    message: "A completed checklist entry does not identify the actor.",
    recommendation: "Confirm whether it originated from a migration or integration.",
  },
  CHECKLIST_ACTOR_WITHOUT_COMPLETION: {
    severity: "attention",
    message: "A checklist entry names a completer but has no completion time.",
    recommendation: "Review the checklist transition.",
  },
  EVIDENCE_ORGANIZATION_MISMATCH: {
    severity: "critical",
    message: "Linked evidence belongs to another organization.",
    recommendation: "Review tenant isolation and revoke the invalid relationship.",
  },
  EVIDENCE_LINK_MISSING_TARGET: {
    severity: "critical",
    message: "An evidence link has no accessible evidence target.",
    recommendation: "Investigate referential integrity without exposing other-tenant records.",
  },
  EVIDENCE_UNLINKED_WITHOUT_ACTOR: {
    severity: "info",
    message: "Evidence was unlinked without a recorded actor.",
    recommendation: "Review whether the unlink originated from migration or system action.",
  },
  EVIDENCE_UNLINK_ACTOR_WITHOUT_DATE: {
    severity: "attention",
    message: "An evidence unlink actor is present without an unlink timestamp.",
    recommendation: "Review the unlink operation.",
  },
  HANDOFF_RECIPIENT_NOT_MEMBER: {
    severity: "attention",
    message: "The handoff recipient is no longer a member of this organization.",
    recommendation: "Review whether reassignment is needed.",
  },
  HANDOFF_DECISION_INCOMPLETE: {
    severity: "attention",
    message: "A decided handoff lacks decision timestamp or actor.",
    recommendation: "Review the recorded handoff decision.",
  },
  HANDOFF_UNDECIDED_WITH_DECISION: {
    severity: "attention",
    message: "A pending handoff already has decision metadata.",
    recommendation: "Review the pending handoff state.",
  },
  HANDOFF_EXPIRED_PENDING: {
    severity: "attention",
    message: "A requested handoff has passed its expiry time.",
    recommendation: "Follow up with the recipient or cancel and reassign.",
  },
  HANDOFF_ASSIGNEE_DIVERGENCE: {
    severity: "info",
    message: "An accepted handoff recipient differs from the current assignee.",
    recommendation: "Confirm whether a subsequent reassignment was intentional.",
  },
};
function object(value: unknown): Snapshot | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Snapshot : null;
}
function validDate(value: Date | null): number | null {
  if (!value) return null;
  const n = value.getTime();
  return Number.isFinite(n) ? n : null;
}
function iso(value: Date): string {
  return Number.isFinite(value.getTime()) ? value.toISOString() : "";
}
function snapshotMatches(item: IntegrityWork, data: Snapshot): boolean {
  const fields = ["status", "revision", "assigneeUserId"] as const;
  for (const field of fields) {
    if (data[field] !== item[field]) return false;
  }
  if (data.completedAt !== (item.completedAt ? iso(item.completedAt) : null)) return false;
  if (data.dueAt !== (item.dueAt ? iso(item.dueAt) : null)) return false;
  return true;
}
export function inspectIntegrityWork(
  item: IntegrityWork,
  members: ReadonlySet<string>,
  now: Date,
  options: { eventsComplete: boolean; checklistComplete: boolean; evidenceComplete: boolean; handoffsComplete: boolean },
): IntegrityFinding[] {
  const output: IntegrityFinding[] = [];
  const add = (code: IntegrityCode, resourceId = item.id) => {
    const description = descriptions[code];
    output.push({ code, severity: description.severity, workItemId: item.id, resourceId,
      message: description.message, recommendation: description.recommendation });
  };
  if (item.finding.organizationId !== item.organizationId ||
      item.remediation.organizationId !== item.organizationId ||
      item.remediation.findingId !== item.findingId) add("FINDING_MISMATCH");
  if (item.assigneeUserId && !members.has(item.assigneeUserId)) add("ASSIGNEE_NOT_MEMBER");
  if (item.status === "DONE" && !item.completedAt) add("DONE_WITHOUT_COMPLETION");
  if (item.status !== "DONE" && item.completedAt) add("OPEN_WITH_COMPLETION");
  const created = validDate(item.createdAt);
  const completed = validDate(item.completedAt);
  const due = validDate(item.dueAt);
  if (created !== null && completed !== null && completed < created) add("COMPLETION_BEFORE_CREATION");
  if (created !== null && due !== null && due < created) add("DEADLINE_BEFORE_CREATION");
  if (options.eventsComplete) {
    if (!item.events.some(event => event.kind === "CREATED")) add("MISSING_CREATE_EVENT");
    const sorted = [...item.events].sort((a, b) =>
      b.occurredAt.getTime() - a.occurredAt.getTime() || b.id.localeCompare(a.id));
    for (const event of sorted) {
      const time = validDate(event.occurredAt);
      if (created !== null && time !== null && time < created) add("EVENT_TIME_ORDER", event.id);
      if (event.kind === "CREATED" || event.kind === "UPDATED" || event.kind === "REOPENED") {
        const state = object(event.after);
        if (!state) {
          add("INVALID_EVENT_SNAPSHOT", event.id);
        } else if (typeof state.revision === "number" && state.revision > item.revision) {
          add("EVENT_REVISION_AHEAD", event.id);
        }
      }
    }
    // Only compare the latest mutation; newer comments do not change work item fields.
    const latest = sorted.find(event =>
      event.kind === "CREATED" || event.kind === "UPDATED" || event.kind === "REOPENED");
    if (latest && object(latest.after) && !snapshotMatches(item, object(latest.after)!)) {
      add("EVENT_SNAPSHOT_MISMATCH", latest.id);
    }
    const updated = validDate(item.updatedAt);
    if (updated !== null && sorted.some(event => {
      const at = validDate(event.occurredAt);
      return at !== null && at > updated && event.kind !== "COMMENTED";
    })) add("EVENT_AFTER_LAST_UPDATE");
  }
  if (options.checklistComplete) for (const entry of item.checklist) {
    if (entry.completedAt && !entry.completedByUserId) add("CHECKLIST_COMPLETED_WITHOUT_ACTOR", entry.id);
    if (!entry.completedAt && entry.completedByUserId) add("CHECKLIST_ACTOR_WITHOUT_COMPLETION", entry.id);
    if (entry.completedByUserId && !members.has(entry.completedByUserId))
      add("CHECKLIST_COMPLETER_MISMATCH", entry.id);
  }
  if (options.evidenceComplete) for (const link of item.evidenceLinks) {
    if (!link.evidence) add("EVIDENCE_LINK_MISSING_TARGET", link.id);
    else if (link.evidence.organizationId !== item.organizationId)
      add("EVIDENCE_ORGANIZATION_MISMATCH", link.id);
    if (link.unlinkedAt && !link.unlinkedByUserId) add("EVIDENCE_UNLINKED_WITHOUT_ACTOR", link.id);
    if (!link.unlinkedAt && link.unlinkedByUserId) add("EVIDENCE_UNLINK_ACTOR_WITHOUT_DATE", link.id);
  }
  if (options.handoffsComplete) for (const handoff of item.handoffs) {
    if (!members.has(handoff.recipientUserId)) add("HANDOFF_RECIPIENT_NOT_MEMBER", handoff.id);
    if (handoff.status === "REQUESTED") {
      if (handoff.decidedAt || handoff.decidedByUserId) add("HANDOFF_UNDECIDED_WITH_DECISION", handoff.id);
      if (handoff.expiresAt && handoff.expiresAt.getTime() < now.getTime())
        add("HANDOFF_EXPIRED_PENDING", handoff.id);
    } else {
      if (!handoff.decidedAt || !handoff.decidedByUserId)
        add("HANDOFF_DECISION_INCOMPLETE", handoff.id);
      if (handoff.status === "ACCEPTED" && handoff.recipientUserId !== item.assigneeUserId)
        add("HANDOFF_ASSIGNEE_DIVERGENCE", handoff.id);
    }
  }
  return output;
}
export function parseIntegrityQuery(values: Record<string, unknown>): IntegrityQuery {
  const raw = values.limit;
  const limit = raw === undefined ? 25 : Number(raw);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100)
    throw new WorkInputError("INVALID", "Limit must be an integer from 1 to 100.");
  if (values.includeInfo !== undefined && values.includeInfo !== "true" && values.includeInfo !== "false")
    throw new WorkInputError("INVALID", "includeInfo must be true or false.");
  let cursor: IntegrityCursor | null = null;
  if (values.cursor !== undefined) {
    if (typeof values.cursor !== "string" || values.cursor.length > 300)
      throw new WorkInputError("INVALID", "Invalid cursor.");
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\.([a-zA-Z0-9_-]{5,100})$/.exec(values.cursor);
    if (!match) throw new WorkInputError("INVALID", "Invalid cursor format.");
    const updatedAt = new Date(match[1]!);
    if (!Number.isFinite(updatedAt.getTime()) || iso(updatedAt) !== match[1])
      throw new WorkInputError("INVALID", "Invalid cursor date.");
    cursor = { updatedAt, id: match[2]! };
  }
  return { limit, cursor, includeInfo: values.includeInfo === "true" };
}
export function encodeIntegrityCursor(cursor: IntegrityCursor): string {
  return `${iso(cursor.updatedAt)}.${cursor.id}`;
}
const MAX_LINKED = 201;
export async function loadWorkIntegrity(scope: IntegrityScope, input: Record<string, unknown>, now = new Date()) {
  if (!canReadWork(scope.role)) throw new WorkInputError("FORBIDDEN", "Work review not allowed.");
  if (!scope.organizationId) throw new WorkInputError("INVALID", "Organization required.");
  const query = parseIntegrityQuery(input);
  const where: Prisma.RemediationWorkItemWhereInput = { organizationId: scope.organizationId };
  if (query.cursor) where.OR = [
    { updatedAt: { lt: query.cursor.updatedAt } },
    { updatedAt: query.cursor.updatedAt, id: { lt: query.cursor.id } },
  ];
  const rows = await db.remediationWorkItem.findMany({
    where,
    orderBy: [{ updatedAt: "desc" }, { id: "desc" }],
    take: query.limit + 1,
    select: {
      id: true, organizationId: true, findingId: true, remediationId: true,
      assigneeUserId: true, status: true, revision: true,
      createdAt: true, updatedAt: true, completedAt: true, dueAt: true,
      finding: { select: { organizationId: true } },
      remediation: { select: { organizationId: true, findingId: true } },
      events: { where: { organizationId: scope.organizationId },
        orderBy: [{ occurredAt: "desc" }, { id: "desc" }], take: MAX_LINKED,
        select: { id: true, kind: true, occurredAt: true, before: true, after: true } },
      checklist: { where: { organizationId: scope.organizationId }, take: MAX_LINKED,
        select: { id: true, completedAt: true, completedByUserId: true } },
      evidenceLinks: { where: { organizationId: scope.organizationId }, take: MAX_LINKED,
        select: { id: true, evidenceId: true, unlinkedAt: true, unlinkedByUserId: true,
          evidence: { select: { organizationId: true } } } },
      handoffs: { where: { organizationId: scope.organizationId }, take: MAX_LINKED,
        select: { id: true, recipientUserId: true, status: true, decidedAt: true,
          decidedByUserId: true, expiresAt: true } },
    },
  });
  const hasNext = rows.length > query.limit;
  const batch = rows.slice(0, query.limit);
  const members = await db.membership.findMany({
    where: { organizationId: scope.organizationId },
    select: { userId: true },
  });
  const memberIds = new Set(members.map(x => x.userId));
  const summaries = batch.map(item => {
    const coverage = {
      eventsComplete: item.events.length < MAX_LINKED,
      checklistComplete: item.checklist.length < MAX_LINKED,
      evidenceComplete: item.evidenceLinks.length < MAX_LINKED,
      handoffsComplete: item.handoffs.length < MAX_LINKED,
    };
    const findings = inspectIntegrityWork(item as IntegrityWork, memberIds, now, coverage)
      .filter(f => query.includeInfo || f.severity !== "info");
    return {
      workItemId: item.id,
      status: item.status,
      revision: item.revision,
      updatedAt: item.updatedAt,
      findings,
      complete: Object.values(coverage).every(Boolean),
      coverage,
    };
  });
  const last = batch.at(-1);
  return {
    generatedAt: now.toISOString(),
    organizationId: scope.organizationId,
    checked: batch.length,
    findings: summaries.flatMap(item => item.findings),
    items: summaries,
    nextCursor: hasNext && last ? encodeIntegrityCursor(last) : null,
    limitations: [
      "Read-only diagnostic: anomalies are not verified security incidents.",
      "Pages use a mutable updatedAt cursor; simultaneous edits may move records between pages.",
      "Linked records are bounded at 201 each per task; a saturated collection is marked incomplete and related checks are withheld.",
      "Only the membership state at the time of review is available; former members can trigger attention signals.",
      "The scan does not test Microsoft 365, refresh evidence or verify remediation outcomes.",
    ],
  };
}
