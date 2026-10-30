import type { ActionDeadlineSummary } from "./evidence-action-deadlines";

/** Workload distribution for pending remediation deadlines. No messages are sent. */
export type ActionOwnerWorkload = {
  owner: string | null;
  overdue: number;
  upcoming: number;
  highPriority: number;
  earliestDueDate: string | null;
};
export type ActionOwnerWorkloadSummary = {
  organizationId: string;
  asOf: string;
  assigned: ActionOwnerWorkload[];
  unassigned: ActionOwnerWorkload;
  totalOverdue: number;
  totalUpcoming: number;
};

/** Deterministic offline roll-up, scoped to the same organization as the input deadlines. */
export function summarizeActionOwnerWorkload(
  deadlines: ActionDeadlineSummary,
  organizationId: string,
): ActionOwnerWorkloadSummary | null {
  if (!organizationId || deadlines.organizationId !== organizationId) return null;
  const items = [...deadlines.overdue, ...deadlines.upcoming];
  const owners = new Map<string, ActionOwnerWorkload>();
  const unassigned: ActionOwnerWorkload = {
    owner: null, overdue: 0, upcoming: 0, highPriority: 0, earliestDueDate: null,
  };
  for (const item of items) {
    const owner = item.owner?.trim() || null;
    const row = owner === null ? unassigned :
      (owners.get(owner) ?? {owner, overdue:0, upcoming:0, highPriority:0, earliestDueDate:null});
    if (item.daysRemaining < 0) row.overdue++;
    else row.upcoming++;
    if (item.priority === "HIGH") row.highPriority++;
    if (row.earliestDueDate === null || item.dueDate < row.earliestDueDate)
      row.earliestDueDate = item.dueDate;
    if (owner !== null) owners.set(owner, row);
  }
  const assigned = [...owners.values()].sort((a,b) =>
    b.overdue-a.overdue || b.highPriority-a.highPriority || a.owner!.localeCompare(b.owner!));
  return {
    organizationId, asOf: deadlines.asOf, assigned, unassigned,
    totalOverdue: deadlines.overdue.length, totalUpcoming: deadlines.upcoming.length,
  };
}
