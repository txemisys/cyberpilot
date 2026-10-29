import type { ActionPlan } from "./evidence-action-plan";
import type { ActionTimeline } from "./evidence-action-timeline";
/** Read-only action management dashboard for an already validated single-tenant plan. */
export type ActionStatusDashboard = {
 organizationId:string; total:number; open:number; completed:number; blocked:number; overdue:number;
 completionPercent:number; byPriority:{HIGH:number;MEDIUM:number;LOW:number};
 events:{accepted:number;rejected:number}; attention:string[];
};
export function summarizeActionStatus(plan:ActionPlan,timeline:ActionTimeline,organizationId:string):ActionStatusDashboard|null {
 if(!organizationId||organizationId!==plan.organizationId||organizationId!==timeline.organizationId) return null;
 const total=plan.actions.length;
 if(plan.summary.total!==total||timeline.accepted!==timeline.items.length||timeline.rejected<0) return null;
 const count=(status:"TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE")=>plan.actions.filter(item=>item.status===status).length;
 const todo=count("TODO"),progress=count("IN_PROGRESS"),blocked=count("BLOCKED"),done=count("DONE");
 if(todo!==plan.summary.todo||progress!==plan.summary.inProgress||blocked!==plan.summary.blocked||done!==plan.summary.done) return null;
 const high=plan.actions.filter(x=>x.priority==="HIGH").length,medium=plan.actions.filter(x=>x.priority==="MEDIUM").length,low=plan.actions.filter(x=>x.priority==="LOW").length;
 if(high!==plan.summary.high||medium!==plan.summary.medium||low!==plan.summary.low) return null;
 const attention:string[]=[];
 if(blocked) attention.push("BLOCKED_ACTIONS");
 if(plan.summary.overdue) attention.push("OVERDUE_ACTIONS");
 if(timeline.rejected) attention.push("REJECTED_EVENTS");
 return {
  organizationId,total,open:total-done,completed:done,blocked,overdue:plan.summary.overdue,
  completionPercent:total===0?0:Math.round(100*done/total),
  byPriority:{HIGH:high,MEDIUM:medium,LOW:low},
  events:{accepted:timeline.accepted,rejected:timeline.rejected},attention,
 };
}
