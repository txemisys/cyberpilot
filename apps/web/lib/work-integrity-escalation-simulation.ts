import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { parseEscalationPolicy, type EscalationPolicy } from "./work-integrity-escalations";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Read-only escalation policy simulator. A proposal never creates an
 * escalation, sends a notification, or modifies a review.
 */
export type SimulationQuery = {
  captureId?: string;
  policy: EscalationPolicy;
  horizonHours: number;
  limit: number;
  offset: number;
  includeClosed: boolean;
};
export type SimulationTask = {
  id: string;
  captureId: string;
  title: string;
  severity: string;
  disposition: string;
  ownerUserId: string | null;
  createdAt: Date;
  completedAt: Date | null;
  revision: number;
};
export type SimulationEscalation = {
  id: string;
  taskId: string;
  level: number;
  state: string;
  openedAt: Date;
  dueAt: Date;
  resolvedAt: Date | null;
  acknowledgedAt: Date | null;
};
export type SimulationProposal = {
  taskId: string;
  captureId: string;
  taskRevision: number;
  severity: string;
  disposition: string;
  assigned: boolean;
  currentLevel: number;
  proposedLevel: number | null;
  status: "ELIGIBLE" | "NOT_DUE" | "CLOSED" | "MAX_LEVEL" |
    "ACTIVE_ESCALATION" | "MISSING_OWNER";
  dueAt: string | null;
  hoursUntilDue: number | null;
  overdueHours: number;
  reason: string;
  existingEscalations: number;
  activeEscalations: number;
  fingerprint: string;
};
export type SimulationReport = {
  schema: "cyberpilot.integrity.escalation.simulation.v1";
  captureId: string | null;
  organizationId: string;
  simulatedAt: string;
  horizonAt: string;
  offset: number;
  limit: number;
  totalTasks: number;
  hasMore: boolean;
  complete: boolean;
  policy: EscalationPolicy;
  statusCounts: Record<SimulationProposal["status"], number>;
  eligible: number;
  proposals: SimulationProposal[];
  digest: string;
  warnings: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected escalation simulation query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, name: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + name + ".");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseSimulationQuery(value: unknown): SimulationQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "policy", "horizonHours",
    "limit", "offset", "includeClosed",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown simulation field.");
  if (raw.includeClosed !== undefined && typeof raw.includeClosed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeClosed.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    policy: parseEscalationPolicy(raw.policy),
    horizonHours: integer(raw.horizonHours ?? 0, "horizonHours", 0, 720),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    includeClosed: raw.includeClosed === true,
  };
}
export function severityThreshold(
  severity: string, policy: EscalationPolicy,
): number {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
    case "ERROR":
    case "HIGH":
      return policy.errorHours;
    case "WARNING":
    case "MEDIUM":
      return policy.warningHours;
    default:
      return policy.infoHours;
  }
}
function latestEscalation(escalations: SimulationEscalation[]) {
  return [...escalations].sort((a, b) =>
    b.level - a.level ||
    b.openedAt.getTime() - a.openedAt.getTime() ||
    a.id.localeCompare(b.id))[0] ?? null;
}
function activeEscalation(escalations: SimulationEscalation[]) {
  return escalations.some(item =>
    item.state === "OPEN" || item.state === "ACKNOWLEDGED");
}
function elapsedHours(from: Date, to: Date) {
  return (to.getTime() - from.getTime()) / 3600000;
}
export function simulateEscalationTask(
  task: SimulationTask,
  escalations: SimulationEscalation[],
  policy: EscalationPolicy,
  at: Date,
): SimulationProposal {
  const latest = latestEscalation(escalations);
  const currentLevel = escalations.reduce(
    (max, row) => Math.max(max, row.level), 0);
  const active = escalations.filter(row =>
    row.state === "OPEN" || row.state === "ACKNOWLEDGED").length;
  const closed = ["RESOLVED", "WAIVED"].includes(task.disposition) ||
    task.completedAt !== null;
  const threshold = currentLevel === 0 ?
    severityThreshold(task.severity, policy) : policy.repeatHours;
  const anchor = currentLevel === 0 ?
    task.createdAt : (latest?.openedAt ?? task.createdAt);
  const dueAt = new Date(anchor.getTime() + threshold * 3600000);
  const hoursUntilDue = elapsedHours(at, dueAt);
  let status: SimulationProposal["status"];
  let reason: string;
  if (closed) {
    status = "CLOSED";
    reason = "Review is already closed; no escalation proposed.";
  } else if (!task.ownerUserId) {
    status = "MISSING_OWNER";
    reason = "Unassigned review requires manual ownership triage.";
  } else if (activeEscalation(escalations)) {
    status = "ACTIVE_ESCALATION";
    reason = "An existing active escalation requires human handling.";
  } else if (currentLevel >= policy.maxLevel) {
    status = "MAX_LEVEL";
    reason = "Policy maximum escalation level has been reached.";
  } else if (hoursUntilDue > 0) {
    status = "NOT_DUE";
    reason = "Escalation threshold has not been reached.";
  } else {
    status = "ELIGIBLE";
    reason = "Simulated policy threshold reached; no action was executed.";
  }
  const proposedLevel = status === "ELIGIBLE" ? currentLevel + 1 : null;
  const canonical = {
    taskId: task.id, captureId: task.captureId,
    taskRevision: task.revision, severity: task.severity,
    disposition: task.disposition,
    assigned: task.ownerUserId !== null,
    currentLevel, proposedLevel, status,
    dueAt: closed ? null : dueAt.toISOString(),
    hoursUntilDue: closed ? null :
      Math.round(hoursUntilDue * 100) / 100,
    overdueHours: closed ? 0 :
      Math.round(Math.max(0, -hoursUntilDue) * 100) / 100,
    reason, existingEscalations: escalations.length,
    activeEscalations: active,
  };
  return { ...canonical, fingerprint: sha(canonical) };
}
export function buildSimulationReport(
  organizationId: string,
  query: SimulationQuery,
  tasks: SimulationTask[],
  escalations: SimulationEscalation[],
  totalTasks: number,
  now: Date,
  truncated: boolean,
): SimulationReport {
  const at = new Date(now.getTime() + query.horizonHours * 3600000);
  const byTask = new Map<string, SimulationEscalation[]>();
  for (const escalation of escalations) {
    const list = byTask.get(escalation.taskId) ?? [];
    list.push(escalation);
    byTask.set(escalation.taskId, list);
  }
  const proposals = tasks.map(task => simulateEscalationTask(
    task, byTask.get(task.id) ?? [], query.policy, at,
  ));
  const statusCounts: SimulationReport["statusCounts"] = {
    ELIGIBLE: 0, NOT_DUE: 0, CLOSED: 0, MAX_LEVEL: 0,
    ACTIVE_ESCALATION: 0, MISSING_OWNER: 0,
  };
  for (const proposal of proposals) statusCounts[proposal.status]++;
  const canonical = {
    schema: "cyberpilot.integrity.escalation.simulation.v1" as const,
    captureId: query.captureId ?? null, organizationId,
    simulatedAt: now.toISOString(), horizonAt: at.toISOString(),
    offset: query.offset, limit: query.limit, totalTasks,
    hasMore: query.offset + tasks.length < totalTasks,
    complete: !truncated, policy: query.policy,
    statusCounts, eligible: statusCounts.ELIGIBLE, proposals,
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "This is a read-only policy simulation, not a scheduler.",
      "No notifications, escalations or review mutations were executed.",
      "Future predictions assume current review state remains unchanged.",
      "Active escalations block proposals; missing owners require manual triage.",
      "Truncated histories and partial pages cannot certify complete coverage.",
      "Simulated escalation is not evidence of a verified security finding.",
    ],
  };
}
export async function readIntegrityEscalationSimulation(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Simulation requires administrator access.");
  const query = parseSimulationQuery(value);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { organizationId: scope.organizationId, id: query.captureId },
      select: { id: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(query.captureId ? { captureId: query.captureId } : {}),
    ...(query.includeClosed ? {} : { completedAt: null }),
  };
  const [totalTasks, tasks] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, title: true, severity: true,
        disposition: true, ownerUserId: true, createdAt: true,
        completedAt: true, revision: true,
      },
    }),
  ]);
  const ids = tasks.map(task => task.id);
  const cap = 5000;
  const escalations = ids.length ?
    await db.integrityEscalation.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: ids },
      },
      take: cap, orderBy: [{ openedAt: "asc" }, { id: "asc" }],
      select: {
        id: true, taskId: true, level: true, state: true,
        openedAt: true, dueAt: true, resolvedAt: true,
        acknowledgedAt: true,
      },
    }) : [];
  return buildSimulationReport(
    scope.organizationId, query, tasks, escalations,
    totalTasks, now, escalations.length >= cap,
  );
}
