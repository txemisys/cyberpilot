import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionCapacityPlan,
  IntegrityExecutionCapacityAssignment,
  IntegrityExecutionCapacityUnassigned,
} from "./work-integrity-remediation-execution-capacity";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";

export type IntegrityExecutionCapacityForecastPolicy = {
  workingDaysPerWeek: number;
  pointsPerDay: number;
  maximumForecastDays: number;
  includeUnassigned: boolean;
  includeExisting: boolean;
  includeProposed: boolean;
};
export type IntegrityExecutionCapacityForecastTask = {
  candidateId: string;
  actorUserId: string | null;
  effortPoints: number;
  priorityScore: number;
  source: "EXISTING" | "PROPOSED" | "UNASSIGNED";
  status: "SCHEDULED" | "CAPACITY_UNAVAILABLE" | "OUTSIDE_HORIZON";
  startDay: number | null;
  finishDay: number | null;
  startDate: string | null;
  finishDate: string | null;
  blockers: string[];
};
export type IntegrityExecutionCapacityForecastDay = {
  day: number;
  date: string;
  workingDay: boolean;
  assignmentsStarted: number;
  assignmentsCompleted: number;
  pointsScheduled: number;
  pointsCompleted: number;
  activeAssignments: number;
  cumulativeCompleted: number;
  cumulativePoints: number;
};
export type IntegrityExecutionCapacityForecastActor = {
  actorUserId: string;
  scheduled: number;
  completedWithinHorizon: number;
  scheduledPoints: number;
  completedPoints: number;
  lastCompletionDate: string | null;
  utilizationPercent: number;
};
export type IntegrityExecutionCapacityForecast = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityExecutionCapacityForecastPolicy;
  tasks: IntegrityExecutionCapacityForecastTask[];
  days: IntegrityExecutionCapacityForecastDay[];
  actors: IntegrityExecutionCapacityForecastActor[];
  totals: {
    candidates: number;
    scheduled: number;
    outsideHorizon: number;
    unavailable: number;
    completedWithinHorizon: number;
    scheduledPoints: number;
    completedPoints: number;
    remainingPoints: number;
    calendarDays: number;
    workingDays: number;
    lastScheduledDate: string | null;
  };
  limitation: string;
};
export type IntegrityExecutionCapacityForecastQuery = {
  actorUserIds?: string[];
  statuses?: IntegrityExecutionCapacityForecastTask["status"][];
  candidateIds?: string[];
  onlyOverdueHorizon?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionCapacityForecastPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityExecutionCapacityForecastTask[];
};
const defaults: IntegrityExecutionCapacityForecastPolicy = {
  workingDaysPerWeek: 5,
  pointsPerDay: 3,
  maximumForecastDays: 90,
  includeUnassigned: true,
  includeExisting: true,
  includeProposed: true,
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function timestamp(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid forecast timestamp.");
}
export function parseIntegrityExecutionCapacityForecastPolicy(
  value: unknown,
): IntegrityExecutionCapacityForecastPolicy {
  if (value === undefined) return { ...defaults };
  const raw = object(value, "capacity forecast policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown forecast policy field.");
  const policy = { ...defaults };
  for (const key of [
    "workingDaysPerWeek", "pointsPerDay", "maximumForecastDays",
  ] as const) {
    if (raw[key] !== undefined)
      policy[key] = integer(raw[key], key, 1,
        key === "workingDaysPerWeek" ? 7 : key === "pointsPerDay" ? 10000 : 365);
  }
  for (const key of [
    "includeUnassigned", "includeExisting", "includeProposed",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid forecast policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  return policy;
}
function calendarDay(evaluatedAt: string, offset: number) {
  const start = Date.parse(evaluatedAt.slice(0, 10) + "T00:00:00.000Z");
  return new Date(start + offset * 86400000).toISOString().slice(0, 10);
}
function isWorkingDay(date: string, policy: IntegrityExecutionCapacityForecastPolicy) {
  const day = new Date(date + "T00:00:00.000Z").getUTCDay();
  return ((day + 6) % 7) < policy.workingDaysPerWeek;
}
export function forecastIntegrityExecutionCapacity(
  plan: IntegrityExecutionCapacityPlan,
  queue: IntegrityExecutionRemediationQueue,
  evaluatedAt: string,
  policy: IntegrityExecutionCapacityForecastPolicy = defaults,
): IntegrityExecutionCapacityForecast {
  timestamp(evaluatedAt);
  if (plan.captureId !== queue.captureId)
    throw new WorkInputError("INVALID", "Forecast capture mismatch.");
  const queueItems = new Map(queue.items.map(x => [x.candidateId, x]));
  const selected = plan.assignments.filter(x =>
    x.source === "EXISTING" ? policy.includeExisting : policy.includeProposed);
  const assignmentsByActor = new Map<string, IntegrityExecutionCapacityAssignment[]>();
  for (const item of selected) {
    const group = assignmentsByActor.get(item.actorUserId) ?? [];
    group.push(item);
    assignmentsByActor.set(item.actorUserId, group);
  }
  const days = Array.from({ length: policy.maximumForecastDays }, (_, index) => {
    const date = calendarDay(evaluatedAt, index);
    return {
      day: index, date, workingDay: isWorkingDay(date, policy),
      assignmentsStarted: 0, assignmentsCompleted: 0,
      pointsScheduled: 0, pointsCompleted: 0,
      activeAssignments: 0, cumulativeCompleted: 0,
      cumulativePoints: 0,
    };
  });
  const tasks: IntegrityExecutionCapacityForecastTask[] = [];
  for (const [actorUserId, assignments] of [...assignmentsByActor].sort(
    (a, b) => a[0].localeCompare(b[0]))) {
    assignments.sort((a, b) => b.score - a.score ||
      a.candidateId.localeCompare(b.candidateId));
    let dayIndex = 0;
    let remainingToday = policy.pointsPerDay;
    for (const assignment of assignments) {
      let effortRemaining = assignment.effortPoints;
      let startDay: number | null = null;
      let finishDay: number | null = null;
      while (effortRemaining > 0 && dayIndex < days.length) {
        const day = days[dayIndex]!;
        if (!day.workingDay) {
          dayIndex++;
          remainingToday = policy.pointsPerDay;
          continue;
        }
        if (startDay === null) {
          startDay = dayIndex;
          day.assignmentsStarted++;
        }
        const consumed = Math.min(remainingToday, effortRemaining);
        day.pointsScheduled += consumed;
        day.activeAssignments++;
        effortRemaining -= consumed;
        remainingToday -= consumed;
        if (effortRemaining === 0) {
          finishDay = dayIndex;
          day.assignmentsCompleted++;
          day.pointsCompleted += assignment.effortPoints;
        }
        if (remainingToday === 0) {
          dayIndex++;
          remainingToday = policy.pointsPerDay;
        }
      }
      tasks.push({
        candidateId: assignment.candidateId, actorUserId,
        effortPoints: assignment.effortPoints,
        priorityScore: assignment.score, source: assignment.source,
        status: finishDay === null ? "OUTSIDE_HORIZON" : "SCHEDULED",
        startDay, finishDay,
        startDate: startDay === null ? null : days[startDay]!.date,
        finishDate: finishDay === null ? null : days[finishDay]!.date,
        blockers: queueItems.get(assignment.candidateId)?.blockers ?? [],
      });
    }
  }
  if (policy.includeUnassigned) {
    for (const item of plan.unassigned) {
      tasks.push({
        candidateId: item.candidateId, actorUserId: null,
        effortPoints: item.effortPoints, priorityScore: item.score,
        source: "UNASSIGNED", status: "CAPACITY_UNAVAILABLE",
        startDay: null, finishDay: null,
        startDate: null, finishDate: null,
        blockers: queueItems.get(item.candidateId)?.blockers ?? [],
      });
    }
  }
  let completed = 0;
  let completedPoints = 0;
  for (const day of days) {
    completed += day.assignmentsCompleted;
    completedPoints += day.pointsCompleted;
    day.cumulativeCompleted = completed;
    day.cumulativePoints = completedPoints;
  }
  const actors = [...assignmentsByActor].map(([actorUserId, assignments]) => {
    const actorTasks = tasks.filter(x => x.actorUserId === actorUserId);
    const completedTasks = actorTasks.filter(x => x.finishDay !== null);
    const scheduledPoints = actorTasks.reduce((sum, x) =>
      sum + x.effortPoints, 0);
    const completedEffort = completedTasks.reduce((sum, x) =>
      sum + x.effortPoints, 0);
    const workingDays = days.filter(x => x.workingDay).length;
    return {
      actorUserId, scheduled: assignments.length,
      completedWithinHorizon: completedTasks.length,
      scheduledPoints, completedPoints: completedEffort,
      lastCompletionDate: completedTasks.map(x => x.finishDate)
        .filter((x): x is string => x !== null).sort().at(-1) ?? null,
      utilizationPercent: workingDays ?
        Math.round(100 * actorTasks.reduce((sum, task) =>
          sum + (task.finishDay === null ?
            Math.min(task.effortPoints, workingDays * policy.pointsPerDay) :
            task.effortPoints), 0) /
          (workingDays * policy.pointsPerDay)) : 0,
    };
  });
  const scheduled = tasks.filter(x => x.status === "SCHEDULED");
  const totalEffort = tasks.reduce((sum, x) => sum + x.effortPoints, 0);
  const donePoints = scheduled.reduce((sum, x) => sum + x.effortPoints, 0);
  return {
    schemaVersion: 1, captureId: plan.captureId, evaluatedAt, policy,
    tasks, days, actors,
    limitation: "Forecast assumes constant declared effort, fixed working days, sequential work per actor, and no holidays or interruptions. No execution is scheduled.",
    totals: {
      candidates: tasks.length,
      scheduled: selected.length,
      outsideHorizon: tasks.filter(x =>
        x.status === "OUTSIDE_HORIZON").length,
      unavailable: tasks.filter(x =>
        x.status === "CAPACITY_UNAVAILABLE").length,
      completedWithinHorizon: scheduled.length,
      scheduledPoints: selected.reduce((sum, x) =>
        sum + x.effortPoints, 0),
      completedPoints: donePoints,
      remainingPoints: totalEffort - donePoints,
      calendarDays: days.length,
      workingDays: days.filter(x => x.workingDay).length,
      lastScheduledDate: scheduled.map(x => x.finishDate)
        .filter((x): x is string => x !== null).sort().at(-1) ?? null,
    },
  };
}
export function parseIntegrityExecutionCapacityForecastQuery(
  value: unknown,
): IntegrityExecutionCapacityForecastQuery {
  const raw = object(value, "forecast query");
  if (Object.keys(raw).some(x => ![
    "actorUserIds", "candidateIds", "statuses",
    "onlyOverdueHorizon", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown forecast query field.");
  const list = (value: unknown) => {
    if (!Array.isArray(value) || value.length > 1000 ||
        value.some(x => typeof x !== "string" || !x ||
          x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
      throw new WorkInputError("INVALID", "Invalid forecast filter.");
    return [...new Set(value as string[])];
  };
  const statuses = raw.statuses === undefined ? undefined :
    list(raw.statuses);
  if (statuses?.some(x => ![
    "SCHEDULED", "CAPACITY_UNAVAILABLE", "OUTSIDE_HORIZON",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown forecast status.");
  if (raw.onlyOverdueHorizon !== undefined &&
      typeof raw.onlyOverdueHorizon !== "boolean")
    throw new WorkInputError("INVALID", "Invalid forecast filter flag.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  integer(offset, "forecast offset", 0, 1000000);
  integer(limit, "forecast limit", 1, 1000);
  return {
    ...(raw.actorUserIds === undefined ? {} :
      { actorUserIds: list(raw.actorUserIds) }),
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: list(raw.candidateIds) }),
    ...(statuses === undefined ? {} :
      { statuses: statuses as IntegrityExecutionCapacityForecastTask["status"][] }),
    onlyOverdueHorizon: raw.onlyOverdueHorizon === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionCapacityForecast(
  forecast: IntegrityExecutionCapacityForecast,
  query: IntegrityExecutionCapacityForecastQuery,
): IntegrityExecutionCapacityForecastPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = forecast.tasks.filter(x =>
    (!query.actorUserIds ||
      (x.actorUserId !== null &&
        query.actorUserIds.includes(x.actorUserId))) &&
    (!query.candidateIds || query.candidateIds.includes(x.candidateId)) &&
    (!query.statuses || query.statuses.includes(x.status)) &&
    (!query.onlyOverdueHorizon || x.status !== "SCHEDULED"));
  return {
    captureId: forecast.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    tasks: selected.slice(offset, offset + limit),
  };
}
