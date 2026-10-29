import type { ActionWorkspaceSnapshot } from "./evidence-action-workspace-snapshot";
import { compareActionWorkspaceSnapshots } from "./evidence-action-workspace-delta";
/** Offline deterministic analysis of an ordered series of same-tenant snapshots. */
export type ActionWorkspaceTrend = {
 organizationId:string; points:number; from:string; to:string;
 changes:{from:string;to:string;completed:number;open:number;overdue:number;alerts:number;acceptedEvents:number}[];
 totals:{completed:number;open:number;overdue:number;alerts:number;acceptedEvents:number};
};
export function summarizeActionWorkspaceTrend(snapshots:readonly ActionWorkspaceSnapshot[],organizationId:string):ActionWorkspaceTrend|null {
 if(!organizationId||snapshots.length===0||snapshots.length>366)return null;
 // Validate every snapshot even if there is only one.
 for(const s of snapshots)if(!compareActionWorkspaceSnapshots(s,s,organizationId))return null;
 const changes:ActionWorkspaceTrend["changes"]=[];
 for(let i=1;i<snapshots.length;i++){
  const delta=compareActionWorkspaceSnapshots(snapshots[i-1]!,snapshots[i]!,organizationId);
  if(!delta||snapshots[i-1]!.asOf===snapshots[i]!.asOf)return null;
  changes.push({from:delta.from,to:delta.to,completed:delta.completed,open:delta.open,overdue:delta.overdue,alerts:delta.alerts,acceptedEvents:delta.acceptedEvents});
 }
 const first=snapshots[0]!,last=snapshots[snapshots.length-1]!;
 return {organizationId,points:snapshots.length,from:first.asOf,to:last.asOf,changes,totals:{
 completed:last.totals.completed-first.totals.completed,
 open:last.totals.open-first.totals.open,
 overdue:last.totals.overdue-first.totals.overdue,
 alerts:last.alerts.total-first.alerts.total,
 acceptedEvents:last.events.accepted-first.events.accepted,
 }};
}
