import type { ActionPlan, PlannedAction } from "./evidence-action-plan";

/** Read-only deadlines requiring attention; never makes a risk-verification claim. */
export type ActionDeadline = {
  actionId: string;
  priority: PlannedAction["priority"];
  status: PlannedAction["status"];
  owner: string | null;
  dueDate: string;
  daysRemaining: number;
};
export type ActionDeadlineSummary = {
  organizationId: string;
  asOf: string;
  windowDays: number;
  overdue: ActionDeadline[];
  upcoming: ActionDeadline[];
  unassignedUpcoming: number;
};

/** Offline, tenant-scoped scheduling view. Does not notify users or modify assignments. */
export function summarizeActionDeadlines(
  plan: ActionPlan,
  organizationId: string,
  asOf: string,
  windowDays = 14,
): ActionDeadlineSummary | null {
  if (plan.organizationId !== organizationId || !organizationId ||
      !Number.isInteger(windowDays) || windowDays < 0 || windowDays > 90 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(asOf)) return null;
  const reference = Date.parse(asOf + "T00:00:00Z");
  if (!Number.isFinite(reference) || new Date(reference).toISOString().slice(0, 10) !== asOf) return null;
  const overdue: ActionDeadline[] = [];
  const upcoming: ActionDeadline[] = [];
  for (const item of plan.actions) {
    if (item.status === "DONE" || item.dueDate === null) continue;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(item.dueDate)) return null;
    const timestamp = Date.parse(item.dueDate + "T00:00:00Z");
    if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().slice(0, 10) !== item.dueDate) return null;
    const daysRemaining = Math.round((timestamp - reference) / 86400000);
    const entry: ActionDeadline = {
      actionId: item.id, priority: item.priority, status: item.status,
      owner: item.owner, dueDate: item.dueDate, daysRemaining,
    };
    if (daysRemaining < 0) overdue.push(entry);
    else if (daysRemaining <= windowDays) upcoming.push(entry);
  }
  const priority = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const order = (a: ActionDeadline, b: ActionDeadline) =>
    a.daysRemaining - b.daysRemaining ||
    priority[a.priority] - priority[b.priority] ||
    a.actionId.localeCompare(b.actionId);
  overdue.sort(order);
  upcoming.sort(order);
  return {
    organizationId, asOf, windowDays, overdue, upcoming,
    unassignedUpcoming: upcoming.filter(item => item.owner === null).length,
  };
}
