import type { ActionWorkloadComparison } from "./evidence-action-owner-workload-compare";

export type OwnerWorkloadChangeReport = {
 organizationId: string;
 period: {from:string;to:string};
 headline: string;
 changes: {metric:string;delta:number;direction:"INCREASE"|"DECREASE"|"UNCHANGED"}[];
 ownerChanges: {added:string[];removed:string[]};
};
/** Structured briefing for management; no score or verified-risk inference. */
export function buildOwnerWorkloadChangeReport(
 comparison:ActionWorkloadComparison,organizationId:string,
):OwnerWorkloadChangeReport|null {
 if(!organizationId||comparison.organizationId!==organizationId||
   comparison.currentAsOf<comparison.previousAsOf)return null;
 const metrics=[
  ["Overdue actions",comparison.overdueChange],
  ["Upcoming actions",comparison.upcomingChange],
  ["High-priority actions",comparison.highPriorityChange],
  ["Unassigned actions",comparison.unassignedChange],
 ] as const;
 if(metrics.some(([,delta])=>!Number.isSafeInteger(delta)))return null;
 const changes=metrics.map(([metric,delta])=>({
  metric,delta,direction:delta>0?"INCREASE" as const:delta<0?"DECREASE" as const:"UNCHANGED" as const,
 }));
 const overdue=comparison.overdueChange;
 const headline=overdue>0?`Overdue actions increased by ${overdue}`:
  overdue<0?`Overdue actions decreased by ${-overdue}`:"Overdue action count was unchanged";
 return {organizationId,period:{from:comparison.previousAsOf,to:comparison.currentAsOf},headline,changes,
  ownerChanges:{added:[...comparison.newlyAssignedOwners],removed:[...comparison.removedOwners]}};
}
