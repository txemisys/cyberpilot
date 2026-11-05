import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

export type PlanningHorizon = 24 | 48 | 72 | 168 | 336;
export type PlanningQuery = {
  captureId?: string;
  horizonHours: PlanningHorizon;
  warningHours: number;
  errorHours: number;
  infoHours: number;
  offset: number;
  limit: number;
  includeClosed: boolean;
};
export type PlanningTask = {
  id: string;
  captureId: string;
  title: string;
  severity: string;
  disposition: string;
  ownerUserId: string | null;
  revision: number;
  required: boolean;
  createdAt: Date;
  updatedAt: Date;
  completedAt: Date | null;
};
export type PlanningEscalation = {
  id: string;
  taskId: string;
  level: number;
  state: string;
  openedAt: Date;
  dueAt: Date;
};
export type PlanningNotification = {
  taskId: string;
  recipientUserId: string;
  readAt: Date | null;
  dismissedAt: Date | null;
  createdAt: Date;
};
export type PlanningCheck = {
  id: string;
  taskId: string;
  outcome: string;
  checkedAt: Date;
  providerObservedAt: Date | null;
};
export type PlanningWorkLink = {
  taskId: string;
  unlinkedAt: Date | null;
};
export type PlanningAssessment = {
  taskId: string;
  decision: string;
  createdAt: Date;
};
export type PlanningSignal =
  | "OVERDUE"
  | "DUE_DURING_HORIZON"
  | "UNASSIGNED"
  | "ACTIVE_ESCALATION"
  | "UNREAD_IN_APP"
  | "NO_ACTIVE_WORK"
  | "NO_PROVIDER_OBSERVATION"
  | "PROVIDER_NOT_PASSING"
  | "PROVIDER_OBSERVATION_STALE"
  | "REVIEW_COMPLETED"
  | "HUMAN_PROVIDER_DISAGREEMENT";
export type PlanningAction =
  | "ASSIGN_OWNER"
  | "REVIEW_OVERDUE"
  | "REVIEW_DEADLINE"
  | "INSPECT_ESCALATION"
  | "FOLLOW_UP_INBOX"
  | "LINK_REMEDIATION_WORK"
  | "VERIFY_PROVIDER"
  | "INSPECT_PROVIDER_FAILURE"
  | "REVALIDATE_PROVIDER"
  | "RECONCILE_DISPOSITION"
  | "NO_AUTOMATIC_ACTION";
export type PlanningRow = {
  taskId: string;
  captureId: string;
  title: string;
  severity: string;
  disposition: string;
  ownerAssigned: boolean;
  revision: number;
  required: boolean;
  dueAt: string;
  hoursToDue: number;
  ageHours: number;
  signals: PlanningSignal[];
  actions: PlanningAction[];
  priority: number;
  urgency: "CRITICAL" | "HIGH" | "NORMAL" | "LOW";
  activeEscalation: { id: string; level: number; state: string } | null;
  inbox: { total: number; unread: number; recipients: number };
  work: { linked: number; active: number };
  provider: { checks: number; latestOutcome: string | null; checkedAt: string | null; observedAt: string | null };
  assessments: number;
  fingerprint: string;
};
export type PlanningSummary = {
  scanned: number;
  active: number;
  closed: number;
  overdue: number;
  dueInHorizon: number;
  unassigned: number;
  escalated: number;
  missingWork: number;
  missingProvider: number;
  failingProvider: number;
  staleProvider: number;
  unreadNotifications: number;
  urgent: number;
  priorityTotal: number;
  bySeverity: Record<string, number>;
  byAction: Partial<Record<PlanningAction, number>>;
  bySignal: Partial<Record<PlanningSignal, number>>;
};
export type PlanningReport = {
  schema: "cyberpilot.integrity.operational.planning.v1";
  organizationId: string;
  captureId: string | null;
  generatedAt: string;
  horizonUntil: string;
  policy: { errorHours: number; warningHours: number; infoHours: number; observationMaxAgeHours: number };
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
  rows: PlanningRow[];
  summary: PlanningSummary;
  digest: string;
  complete: boolean;
  warnings: string[];
};

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected planning query object.");
  return value as Record<string, unknown>;
}
function int(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid planning " + label + ".");
  return value;
}
const horizons: PlanningHorizon[] = [24, 48, 72, 168, 336];
export function parsePlanningQuery(value: unknown): PlanningQuery {
  const raw = object(value);
  const keys = ["captureId", "horizonHours", "warningHours",
    "errorHours", "infoHours", "offset", "limit", "includeClosed"];
  if (Object.keys(raw).some(key => !keys.includes(key)))
    throw new WorkInputError("INVALID", "Unknown planning query field.");
  if (raw.includeClosed !== undefined && typeof raw.includeClosed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeClosed flag.");
  const horizonHours = int(raw.horizonHours ?? 72, "horizon", 24, 336);
  if (!horizons.includes(horizonHours as PlanningHorizon))
    throw new WorkInputError("INVALID", "Unsupported planning horizon.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    horizonHours: horizonHours as PlanningHorizon,
    warningHours: int(raw.warningHours ?? 48, "warning threshold", 1, 8760),
    errorHours: int(raw.errorHours ?? 12, "error threshold", 1, 8760),
    infoHours: int(raw.infoHours ?? 120, "info threshold", 1, 8760),
    offset: int(raw.offset ?? 0, "offset", 0, 1000000),
    limit: int(raw.limit ?? 40, "limit", 1, 100),
    includeClosed: raw.includeClosed === true,
  };
}
export function planningHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function dueForPlanning(task: PlanningTask, query: PlanningQuery) {
  const hours = task.severity === "ERROR" ? query.errorHours :
    task.severity === "WARNING" ? query.warningHours : query.infoHours;
  return new Date(task.createdAt.getTime() + hours * 3600000);
}
export function planningUrgency(priority: number): PlanningRow["urgency"] {
  if (priority >= 700) return "CRITICAL";
  if (priority >= 400) return "HIGH";
  if (priority >= 200) return "NORMAL";
  return "LOW";
}
export type PlanningSources = {
  escalations: PlanningEscalation[];
  notifications: PlanningNotification[];
  links: PlanningWorkLink[];
  checks: PlanningCheck[];
  assessments: PlanningAssessment[];
};
function add<T extends string>(values: T[], value: T) {
  if (!values.includes(value)) values.push(value);
}
export function planTask(
  task: PlanningTask, source: PlanningSources,
  query: PlanningQuery, now: Date,
): PlanningRow {
  const due = dueForPlanning(task, query);
  const closed = task.disposition === "RESOLVED" || task.disposition === "WAIVED";
  const ageHours = Math.max(0, (now.getTime() - task.createdAt.getTime()) / 3600000);
  const hoursToDue = (due.getTime() - now.getTime()) / 3600000;
  const signals: PlanningSignal[] = [];
  const actions: PlanningAction[] = [];
  const escalations = source.escalations.filter(x => x.taskId === task.id)
    .sort((a, b) => b.openedAt.getTime() - a.openedAt.getTime() ||
      b.id.localeCompare(a.id));
  const activeEscalation = escalations.find(x =>
    x.state === "OPEN" || x.state === "ACKNOWLEDGED") ?? null;
  const notes = source.notifications.filter(x => x.taskId === task.id);
  const unread = notes.filter(x => !x.readAt && !x.dismissedAt).length;
  const links = source.links.filter(x => x.taskId === task.id);
  const activeLinks = links.filter(x => !x.unlinkedAt).length;
  const checks = source.checks.filter(x => x.taskId === task.id)
    .sort((a, b) => b.checkedAt.getTime() - a.checkedAt.getTime() ||
      b.id.localeCompare(a.id));
  const latest = checks[0] ?? null;
  const stale = latest !== null && now.getTime() - latest.checkedAt.getTime() > 168 * 3600000;
  const assessments = source.assessments.filter(x => x.taskId === task.id);
  if (!closed) {
    if (!task.ownerUserId) {
      add(signals, "UNASSIGNED");
      add(actions, "ASSIGN_OWNER");
    }
    if (hoursToDue <= 0) {
      add(signals, "OVERDUE");
      add(actions, "REVIEW_OVERDUE");
    } else if (hoursToDue <= query.horizonHours) {
      add(signals, "DUE_DURING_HORIZON");
      add(actions, "REVIEW_DEADLINE");
    }
    if (activeEscalation) {
      add(signals, "ACTIVE_ESCALATION");
      add(actions, "INSPECT_ESCALATION");
    }
    if (unread) {
      add(signals, "UNREAD_IN_APP");
      add(actions, "FOLLOW_UP_INBOX");
    }
    if (!activeLinks) {
      add(signals, "NO_ACTIVE_WORK");
      add(actions, "LINK_REMEDIATION_WORK");
    }
  } else {
    add(signals, "REVIEW_COMPLETED");
  }
  if (!latest) {
    add(signals, "NO_PROVIDER_OBSERVATION");
    add(actions, "VERIFY_PROVIDER");
  } else {
    if (latest.outcome !== "PASS") {
      add(signals, "PROVIDER_NOT_PASSING");
      add(actions, "INSPECT_PROVIDER_FAILURE");
    }
    if (stale) {
      add(signals, "PROVIDER_OBSERVATION_STALE");
      add(actions, "REVALIDATE_PROVIDER");
    }
    if (closed && latest.outcome !== "PASS") {
      add(signals, "HUMAN_PROVIDER_DISAGREEMENT");
      add(actions, "RECONCILE_DISPOSITION");
    }
  }
  if (!actions.length) actions.push("NO_AUTOMATIC_ACTION");
  let priority = task.severity === "ERROR" ? 250 :
    task.severity === "WARNING" ? 140 : 60;
  if (closed) priority = 0;
  if (!closed && hoursToDue <= 0) priority += 350;
  if (!closed && hoursToDue > 0 && hoursToDue <= 24) priority += 140;
  if (!closed && !task.ownerUserId) priority += 100;
  if (activeEscalation) priority += 90 + Math.min(activeEscalation.level, 5) * 25;
  if (latest?.outcome === "FAIL") priority += 220;
  if (latest?.outcome === "ERROR") priority += 180;
  if (!latest) priority += 85;
  if (stale) priority += 70;
  if (closed && latest?.outcome !== "PASS") priority += 150;
  if (!closed && !activeLinks) priority += 60;
  priority = Math.min(priority, 2000);
  const canonical = {
    taskId: task.id, captureId: task.captureId, title: task.title,
    severity: task.severity, disposition: task.disposition,
    ownerAssigned: task.ownerUserId !== null, revision: task.revision,
    required: task.required, dueAt: due.toISOString(),
    hoursToDue: Math.round(hoursToDue * 100) / 100,
    ageHours: Math.round(ageHours * 100) / 100,
    signals, actions, priority, urgency: planningUrgency(priority),
    activeEscalation: activeEscalation ? {
      id: activeEscalation.id, level: activeEscalation.level,
      state: activeEscalation.state,
    } : null,
    inbox: { total: notes.length, unread,
      recipients: new Set(notes.map(x => x.recipientUserId)).size },
    work: { linked: links.length, active: activeLinks },
    provider: {
      checks: checks.length, latestOutcome: latest?.outcome ?? null,
      checkedAt: latest?.checkedAt.toISOString() ?? null,
      observedAt: latest?.providerObservedAt?.toISOString() ?? null,
    },
    assessments: assessments.length,
  };
  return { ...canonical, fingerprint: planningHash(canonical) };
}
export function summarizePlanning(rows: PlanningRow[]): PlanningSummary {
  const result: PlanningSummary = {
    scanned: rows.length, active: 0, closed: 0, overdue: 0,
    dueInHorizon: 0, unassigned: 0, escalated: 0, missingWork: 0,
    missingProvider: 0, failingProvider: 0, staleProvider: 0,
    unreadNotifications: 0, urgent: 0, priorityTotal: 0,
    bySeverity: {}, byAction: {}, bySignal: {},
  };
  for (const row of rows) {
    const closed = ["RESOLVED", "WAIVED"].includes(row.disposition);
    if (closed) result.closed++;
    else result.active++;
    result.priorityTotal += row.priority;
    if (row.urgency === "CRITICAL") result.urgent++;
    result.unreadNotifications += row.inbox.unread;
    result.bySeverity[row.severity] = (result.bySeverity[row.severity] ?? 0) + 1;
    for (const action of row.actions)
      result.byAction[action] = (result.byAction[action] ?? 0) + 1;
    for (const signal of row.signals)
      result.bySignal[signal] = (result.bySignal[signal] ?? 0) + 1;
    if (row.signals.includes("OVERDUE")) result.overdue++;
    if (row.signals.includes("DUE_DURING_HORIZON")) result.dueInHorizon++;
    if (row.signals.includes("UNASSIGNED")) result.unassigned++;
    if (row.signals.includes("ACTIVE_ESCALATION")) result.escalated++;
    if (row.signals.includes("NO_ACTIVE_WORK")) result.missingWork++;
    if (row.signals.includes("NO_PROVIDER_OBSERVATION")) result.missingProvider++;
    if (row.signals.includes("PROVIDER_NOT_PASSING")) result.failingProvider++;
    if (row.signals.includes("PROVIDER_OBSERVATION_STALE")) result.staleProvider++;
  }
  return result;
}
export function buildPlanningReport(
  organizationId: string, query: PlanningQuery, tasks: PlanningTask[],
  sources: PlanningSources, total: number, now: Date,
): PlanningReport {
  const rows = tasks.map(task => planTask(task, sources, query, now))
    .sort((a, b) => b.priority - a.priority ||
      a.dueAt.localeCompare(b.dueAt) || a.taskId.localeCompare(b.taskId));
  const canonical = {
    schema: "cyberpilot.integrity.operational.planning.v1" as const,
    organizationId, captureId: query.captureId ?? null,
    generatedAt: now.toISOString(),
    horizonUntil: new Date(now.getTime() + query.horizonHours * 3600000).toISOString(),
    policy: {
      errorHours: query.errorHours, warningHours: query.warningHours,
      infoHours: query.infoHours, observationMaxAgeHours: 168,
    },
    offset: query.offset, limit: query.limit, total,
    hasMore: query.offset + tasks.length < total,
    rows, summary: summarizePlanning(rows),
  };
  return {
    ...canonical, digest: planningHash(canonical),
    complete: query.offset === 0 && tasks.length === total,
    warnings: [
      "Priorities are advisory and do not change reviews, remediation or CyberScore.",
      "The priority sort and all summary counts cover the selected database page only.",
      "An in-app unread record does not prove notification delivery or attention.",
      "The latest provider observation is historical, not a live security guarantee.",
      "No automated escalation, assignment or provider check is performed.",
    ],
  };
}
export async function readIntegrityOperationalPlanning(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<PlanningReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Operational planning requires an administrator.");
  const query = parsePlanningQuery(value);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { id: query.captureId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(query.captureId ? { captureId: query.captureId } : {}),
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
        id: true, captureId: true, title: true, severity: true,
        disposition: true, ownerUserId: true, revision: true,
        required: true, createdAt: true, updatedAt: true, completedAt: true,
      },
    }),
  ]);
  const ids = tasks.map(row => row.id);
  if (ids.length === 0)
    return buildPlanningReport(scope.organizationId, query, [], {
      escalations: [], notifications: [], links: [], checks: [], assessments: [],
    }, total, now);
  const scoped = { organizationId: scope.organizationId, taskId: { in: ids } };
  const [escalations, notifications, links, checks, assessments] = await Promise.all([
    db.integrityEscalation.findMany({
      where: scoped, take: 5000,
      orderBy: [{ openedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, level: true, state: true,
        openedAt: true, dueAt: true,
      },
    }),
    db.integrityNotification.findMany({
      where: scoped, take: 5000,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        taskId: true, recipientUserId: true,
        readAt: true, dismissedAt: true, createdAt: true,
      },
    }),
    db.integrityReviewWorkLink.findMany({
      where: scoped, take: 5000,
      select: { taskId: true, unlinkedAt: true },
    }),
    db.integrityProviderCheck.findMany({
      where: scoped, take: 5000,
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, outcome: true, checkedAt: true,
        providerObservedAt: true,
      },
    }),
    db.integrityEvidenceAssessment.findMany({
      where: scoped, take: 5000,
      select: { taskId: true, decision: true, createdAt: true },
    }),
  ]);
  const report = buildPlanningReport(scope.organizationId, query, tasks, {
    escalations, notifications, links, checks, assessments,
  }, total, now);
  if ([escalations, notifications, links, checks, assessments].some(x => x.length === 5000)) {
    report.complete = false;
    report.warnings.push("One or more related data collections reached the 5000-row limit; counts may be partial.");
  }
  return report;
}
