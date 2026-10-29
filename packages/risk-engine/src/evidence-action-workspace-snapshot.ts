import type { ActionPlan } from "./evidence-action-plan";
import type { ActionProgressEvent } from "./evidence-action-progress";
import type { ActionFilter } from "./evidence-action-filter";
import { buildActionWorkspace } from "./evidence-action-workspace";

/** Deterministic, read-only snapshot for offline reporting; never persists or contacts providers. */
export type ActionWorkspaceSnapshot = {
 schemaVersion:1; organizationId:string; asOf:string;
 totals:{actions:number;open:number;completed:number;blocked:number;overdue:number;completionPercent:number};
 events:{accepted:number;rejected:number};
 alerts:{total:number;high:number;medium:number;low:number};
 selection:{total:number;ids:string[]};
};
export function buildActionWorkspaceSnapshot(
 plan:ActionPlan, events:readonly ActionProgressEvent[], organizationId:string,
 asOf:string, filter:ActionFilter={}
):ActionWorkspaceSnapshot|null {
 const workspace=buildActionWorkspace(plan,events,organizationId,asOf,filter);
 if(!workspace)return null;
 const {dashboard,alerts,filtered,timeline}=workspace;
 if(timeline.accepted!==workspace.progress.applied ||
    timeline.rejected!==workspace.progress.rejected.length ||
    dashboard.total!==workspace.plan.actions.length ||
    alerts.total!==alerts.items.length) return null;
 return {
  schemaVersion:1, organizationId, asOf,
  totals:{actions:dashboard.total,open:dashboard.open,completed:dashboard.completed,
   blocked:dashboard.blocked,overdue:dashboard.overdue,completionPercent:dashboard.completionPercent},
  events:{accepted:timeline.accepted,rejected:timeline.rejected},
  alerts:{total:alerts.total,high:alerts.high,medium:alerts.medium,low:alerts.low},
  selection:{total:filtered.total,ids:filtered.items.map(a=>a.id)}
 };
}
export function serializeActionWorkspaceSnapshot(snapshot:ActionWorkspaceSnapshot,organizationId:string):string|null {
 if(!organizationId || snapshot.organizationId!==organizationId ||
 snapshot.schemaVersion!==1 || snapshot.totals.actions<0 ||
 snapshot.totals.open+snapshot.totals.completed!==snapshot.totals.actions ||
 snapshot.events.accepted<0 || snapshot.events.rejected<0 ||
 snapshot.alerts.high+snapshot.alerts.medium+snapshot.alerts.low!==snapshot.alerts.total ||
 snapshot.selection.ids.length>snapshot.selection.total ||
 new Set(snapshot.selection.ids).size!==snapshot.selection.ids.length) return null;
 return JSON.stringify(snapshot);
}
