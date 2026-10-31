import type { ActionOwnerWorkloadSummary } from "./evidence-action-owner-workload";

/** Compare workload handoffs without crossing tenant boundaries or changing evidence. */
export type ActionWorkloadComparison = {
  organizationId: string;
  previousAsOf: string;
  currentAsOf: string;
  overdueChange: number;
  upcomingChange: number;
  highPriorityChange: number;
  newlyAssignedOwners: string[];
  removedOwners: string[];
  unassignedChange: number;
};
export function compareActionOwnerWorkloads(
  previous: ActionOwnerWorkloadSummary,
  current: ActionOwnerWorkloadSummary,
  organizationId: string,
): ActionWorkloadComparison | null {
  if (!organizationId || previous.organizationId !== organizationId ||
      current.organizationId !== organizationId ||
      !/^\d{4}-\d{2}-\d{2}$/.test(previous.asOf) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(current.asOf) ||
      current.asOf < previous.asOf) return null;
  const previousOwners = new Set(previous.assigned.map(x=>x.owner).filter((x):x is string=>x!==null));
  const currentOwners = new Set(current.assigned.map(x=>x.owner).filter((x):x is string=>x!==null));
  const high=(s:ActionOwnerWorkloadSummary) =>
    [...s.assigned,s.unassigned].reduce((sum,row)=>sum+row.highPriority,0);
  const assigned=(s:ActionOwnerWorkloadSummary)=>s.unassigned.overdue+s.unassigned.upcoming;
  return {
    organizationId,previousAsOf:previous.asOf,currentAsOf:current.asOf,
    overdueChange:current.totalOverdue-previous.totalOverdue,
    upcomingChange:current.totalUpcoming-previous.totalUpcoming,
    highPriorityChange:high(current)-high(previous),
    newlyAssignedOwners:[...currentOwners].filter(x=>!previousOwners.has(x)).sort(),
    removedOwners:[...previousOwners].filter(x=>!currentOwners.has(x)).sort(),
    unassignedChange:assigned(current)-assigned(previous),
  };
}
