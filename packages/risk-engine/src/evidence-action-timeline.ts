import type { ActionPlan, PlannedAction } from "./evidence-action-plan";
import type { ActionProgressEvent } from "./evidence-action-progress";
import { applyActionProgress } from "./evidence-action-progress";
/** Offline, organization-scoped event timeline; never writes to external systems. */
export type ActionTimelineItem = { actionId:string; at:string; status:PlannedAction["status"]; note:string|null };
export type ActionTimeline = { organizationId:string; items:ActionTimelineItem[]; accepted:number; rejected:number; byAction:Record<string,number> };
export function buildActionTimeline(plan:ActionPlan,events:readonly ActionProgressEvent[],asOf:string):ActionTimeline {
 const result=applyActionProgress(plan,events,asOf);
 const rejected=new Set(result.rejected.map(item=>item.index));
 const byAction:Record<string,number>=Object.create(null) as Record<string,number>;
 const items:ActionTimelineItem[]=[];
 for(let i=0;i<events.length;i++){
  if(rejected.has(i))continue;
  const event=events[i]!;
  items.push({actionId:event.actionId,at:event.at,status:event.status,note:event.note?.trim()||null});
  byAction[event.actionId]=(byAction[event.actionId]??0)+1;
 }
 items.sort((a,b)=>a.at.localeCompare(b.at)||a.actionId.localeCompare(b.actionId));
 return {organizationId:plan.organizationId,items,accepted:result.applied,rejected:result.rejected.length,byAction};
}
