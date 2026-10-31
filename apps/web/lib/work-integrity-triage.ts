import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError, type WorkRole } from "./remediation-work-input";
import { INTEGRITY_CODES, type IntegrityCode } from "./work-integrity";

/**
 * Append-only human triage for integrity diagnostics. A triage decision documents
 * investigation, never certifies that the underlying security control is effective.
 *
 * Records are retained in the existing tenant-scoped AuditEvent store, so this
 * module introduces no parallel mutable source of truth.
 */
export const TRIAGE_DECISIONS = [
  "INVESTIGATE", "ACKNOWLEDGE", "DISMISS", "REOPEN",
] as const;
export type TriageDecision = typeof TRIAGE_DECISIONS[number];
export type TriageRole = WorkRole;
export type TriageScope = {
  organizationId: string;
  userId: string;
  role: TriageRole;
};
export type TriageCommand = {
  workItemId: string;
  code: IntegrityCode;
  resourceId: string;
  revision: number;
  decision: TriageDecision;
  rationale: string;
  reference: string | null;
  expectedPreviousEventId: string | null;
};
export type TriageEvent = {
  id: string;
  organizationId: string;
  workItemId: string;
  actorUserId: string | null;
  occurredAt: Date;
  decision: TriageDecision;
  code: IntegrityCode;
  resourceId: string;
  revision: number;
  rationale: string;
  reference: string | null;
  previousEventId: string | null;
};
export type TriageProjection = {
  workItemId: string;
  code: IntegrityCode;
  resourceId: string;
  latestDecision: TriageDecision;
  latestRationale: string;
  latestActorUserId: string | null;
  latestEventId: string;
  lastReviewedAt: Date;
  revisionAtReview: number;
  staleRevision: boolean;
  totalDecisions: number;
  history: TriageEvent[];
};
export const TRIAGE_AUDIT_ACTION = "WORK_INTEGRITY_TRIAGE_REVIEWED";
export const TRIAGE_RESOURCE_TYPE = "RemediationWorkItem";
const MAX_REASON = 2000;
const MAX_REFERENCE = 200;
const MAX_HISTORY = 200;
const MAX_PAGE = 100;

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected an object.");
  return value as Record<string, unknown>;
}
function stringField(value: unknown, label: string, max: number, min = 1): string {
  if (typeof value !== "string")
    throw new WorkInputError("INVALID", `${label} must be text.`);
  const result = value.trim();
  if (result.length < min || result.length > max ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(result))
    throw new WorkInputError("INVALID", `${label} must contain ${min}–${max} printable characters.`);
  return result;
}
function optionalId(value: unknown, label: string): string | null {
  return value === null ? null : parseWorkId(value, label);
}
function decisionField(value: unknown): TriageDecision {
  if (typeof value === "string" && TRIAGE_DECISIONS.some(x => x === value))
    return value as TriageDecision;
  throw new WorkInputError("INVALID", "Unsupported triage decision.");
}
function codeField(value: unknown): IntegrityCode {
  if (typeof value === "string" && INTEGRITY_CODES.some(x => x === value))
    return value as IntegrityCode;
  throw new WorkInputError("INVALID", "Unsupported diagnostic code.");
}
function revisionField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 ||
      value > 2147483647)
    throw new WorkInputError("INVALID", "Expected a current positive revision.");
  return value;
}
export function parseTriageCommand(value: unknown): TriageCommand {
  const data = asObject(value);
  const allowed = new Set([
    "workItemId", "code", "resourceId", "revision",
    "decision", "rationale", "reference", "expectedPreviousEventId",
  ]);
  for (const key of Object.keys(data))
    if (!allowed.has(key)) throw new WorkInputError("INVALID", `Unsupported triage field: ${key}.`);
  return {
    workItemId: parseWorkId(data.workItemId, "work item ID"),
    code: codeField(data.code),
    resourceId: parseWorkId(data.resourceId, "linked resource ID"),
    revision: revisionField(data.revision),
    decision: decisionField(data.decision),
    rationale: stringField(data.rationale, "Rationale", MAX_REASON, 10),
    reference: data.reference === null || data.reference === undefined ||
      data.reference === "" ? null : stringField(data.reference, "Reference", MAX_REFERENCE),
    expectedPreviousEventId: data.expectedPreviousEventId === null ||
      data.expectedPreviousEventId === undefined ? null :
      optionalId(data.expectedPreviousEventId, "previous event ID"),
  };
}
export function parseTriageQuery(values: Record<string, unknown>) {
  const page = values.page === undefined ? 1 : Number(values.page);
  const limit = values.limit === undefined ? 25 : Number(values.limit);
  if (!Number.isInteger(page) || page < 1 || page > 1000000)
    throw new WorkInputError("INVALID", "Page must be a positive integer.");
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE)
    throw new WorkInputError("INVALID", "Limit must be 1–100.");
  const workItemId = values.workItemId === undefined ? null :
    parseWorkId(values.workItemId, "work item ID");
  const code = values.code === undefined ? null : codeField(values.code);
  return { page, limit, workItemId, code };
}
function metadataOf(value: Prisma.JsonValue | null): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}
export function hydrateTriageEvent(
  raw: {
    id: string;
    organizationId: string;
    resourceId: string | null;
    actorUserId: string | null;
    occurredAt: Date;
    metadata: Prisma.JsonValue | null;
  },
): TriageEvent | null {
  const meta = metadataOf(raw.metadata);
  if (!meta || !raw.resourceId) return null;
  if (typeof meta.code !== "string" || !INTEGRITY_CODES.some(x => x === meta.code))
    return null;
  if (typeof meta.decision !== "string" || !TRIAGE_DECISIONS.some(x => x === meta.decision))
    return null;
  if (typeof meta.resourceId !== "string" || typeof meta.rationale !== "string" ||
      typeof meta.revision !== "number" || !Number.isInteger(meta.revision))
    return null;
  return {
    id: raw.id,
    organizationId: raw.organizationId,
    workItemId: raw.resourceId,
    actorUserId: raw.actorUserId,
    occurredAt: raw.occurredAt,
    decision: meta.decision as TriageDecision,
    code: meta.code as IntegrityCode,
    resourceId: meta.resourceId,
    revision: meta.revision,
    rationale: meta.rationale,
    reference: typeof meta.reference === "string" ? meta.reference : null,
    previousEventId: typeof meta.previousEventId === "string" ? meta.previousEventId : null,
  };
}
export function projectTriageHistory(
  events: readonly TriageEvent[],
  currentRevision: number,
): TriageProjection[] {
  const map = new Map<string, TriageEvent[]>();
  for (const event of events) {
    const key = JSON.stringify([event.workItemId, event.code, event.resourceId]);
    const group = map.get(key) ?? [];
    group.push(event);
    map.set(key, group);
  }
  const result: TriageProjection[] = [];
  for (const group of map.values()) {
    const ordered = [...group].sort((a, b) =>
      b.occurredAt.getTime() - a.occurredAt.getTime() || b.id.localeCompare(a.id));
    const latest = ordered[0]!;
    result.push({
      workItemId: latest.workItemId,
      code: latest.code,
      resourceId: latest.resourceId,
      latestDecision: latest.decision,
      latestRationale: latest.rationale,
      latestActorUserId: latest.actorUserId,
      latestEventId: latest.id,
      lastReviewedAt: latest.occurredAt,
      revisionAtReview: latest.revision,
      staleRevision: latest.revision !== currentRevision,
      totalDecisions: ordered.length,
      history: ordered,
    });
  }
  return result.sort((a, b) =>
    b.lastReviewedAt.getTime() - a.lastReviewedAt.getTime() ||
    b.latestEventId.localeCompare(a.latestEventId));
}
export function canTransitionTriage(previous: TriageDecision | null, next: TriageDecision): boolean {
  if (previous === null) return next !== "REOPEN";
  if (previous === "INVESTIGATE") return next !== "REOPEN";
  if (previous === "REOPEN") return next !== "REOPEN";
  if (previous === "ACKNOWLEDGE" || previous === "DISMISS")
    return next === "REOPEN";
  return false;
}
export function assertTriageTransition(previous: TriageDecision | null, next: TriageDecision): void {
  if (!canTransitionTriage(previous, next))
    throw new WorkInputError("CONFLICT", "Invalid review transition. Refresh the latest decision.");
}
export function triageDisposition(decision: TriageDecision): string {
  if (decision === "INVESTIGATE") return "Investigation requested";
  if (decision === "ACKNOWLEDGE") return "Anomaly acknowledged (not remediation verified)";
  if (decision === "DISMISS") return "Diagnostic dismissed with rationale (not compliance certified)";
  return "Review reopened";
}
function requireManager(scope: TriageScope): void {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Only owners and admins can record integrity triage decisions.");
}
function assertScope(scope: TriageScope) {
  if (!scope.organizationId || !scope.userId)
    throw new WorkInputError("FORBIDDEN", "A signed-in organization member is required.");
}
async function currentReviewTx(
  tx: Prisma.TransactionClient,
  scope: TriageScope,
  command: TriageCommand,
) {
  const events = await tx.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      action: TRIAGE_AUDIT_ACTION,
      resourceType: TRIAGE_RESOURCE_TYPE,
      resourceId: command.workItemId,
    },
    select: {
      id: true, organizationId: true, resourceId: true, actorUserId: true,
      occurredAt: true, metadata: true,
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: MAX_HISTORY,
  });
  return events.map(hydrateTriageEvent).filter((e): e is TriageEvent =>
    e !== null && e.code === command.code && e.resourceId === command.resourceId);
}
export async function saveIntegrityTriage(scope: TriageScope, raw: unknown) {
  assertScope(scope);
  requireManager(scope);
  const command = parseTriageCommand(raw);
  return db.$transaction(async tx => {
    const item = await tx.remediationWorkItem.findFirst({
      where: { id: command.workItemId, organizationId: scope.organizationId },
      select: { id: true, revision: true },
    });
    if (!item) throw new WorkInputError("MISSING", "Work item not found in this organization.");
    if (item.revision !== command.revision)
      throw new WorkInputError("CONFLICT", "Work item revision has changed. Refresh the diagnostic.");
    const history = await currentReviewTx(tx, scope, command);
    const previous = history[0] ?? null;
    if ((previous?.id ?? null) !== command.expectedPreviousEventId)
      throw new WorkInputError("CONFLICT", "Review changed since it was loaded.");
    assertTriageTransition(previous?.decision ?? null, command.decision);
    const created = await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER",
        actorUserId: scope.userId,
        action: TRIAGE_AUDIT_ACTION,
        resourceType: TRIAGE_RESOURCE_TYPE,
        resourceId: command.workItemId,
        metadata: {
          schemaVersion: 1,
          code: command.code,
          resourceId: command.resourceId,
          revision: command.revision,
          decision: command.decision,
          rationale: command.rationale,
          reference: command.reference,
          previousEventId: previous?.id ?? null,
        },
      },
      select: {
        id: true, organizationId: true, resourceId: true, actorUserId: true,
        occurredAt: true, metadata: true,
      },
    });
    return hydrateTriageEvent(created)!;
  }, { isolationLevel: "Serializable" });
}
export async function listIntegrityTriage(scope: TriageScope, values: Record<string, unknown>) {
  assertScope(scope);
  const query = parseTriageQuery(values);
  const where: Prisma.AuditEventWhereInput = {
    organizationId: scope.organizationId,
    action: TRIAGE_AUDIT_ACTION,
    resourceType: TRIAGE_RESOURCE_TYPE,
  };
  if (query.workItemId) {
    const exists = await db.remediationWorkItem.findFirst({
      where: { id: query.workItemId, organizationId: scope.organizationId },
      select: { id: true, revision: true },
    });
    if (!exists) throw new WorkInputError("MISSING", "Work item not found.");
    where.resourceId = query.workItemId;
  }
  const [total, records] = await db.$transaction([
    db.auditEvent.count({ where }),
    db.auditEvent.findMany({
      where,
      orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
      select: {
        id: true, organizationId: true, resourceId: true,
        actorUserId: true, occurredAt: true, metadata: true,
      },
    }),
  ]);
  const events = records.map(hydrateTriageEvent).filter((event): event is TriageEvent =>
    event !== null && (!query.code || event.code === query.code));
  const ids = [...new Set(events.map(event => event.workItemId))];
  const workItems = ids.length ? await db.remediationWorkItem.findMany({
    where: { organizationId: scope.organizationId, id: { in: ids } },
    select: { id: true, revision: true, title: true, status: true },
  }) : [];
  const revisions = new Map(workItems.map(item => [item.id, item.revision]));
  return {
    query,
    total,
    page: query.page,
    pages: Math.max(1, Math.ceil(total / query.limit)),
    events,
    projections: ids.flatMap(id => projectTriageHistory(
      events.filter(event => event.workItemId === id),
      revisions.get(id) ?? -1,
    )),
    workItems,
    coverage: "Pagination applies to raw audit events; filters and projections represent this page, not an exhaustive history.",
    disclaimer: "Triage is a recorded human judgment about diagnostics. It never verifies security or closes a finding.",
  };
}
