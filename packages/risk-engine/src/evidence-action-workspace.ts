import type { ActionPlan } from "./evidence-action-plan";
import type { ActionProgressEvent } from "./evidence-action-progress";
import { applyActionProgress } from "./evidence-action-progress";
import { buildActionTimeline } from "./evidence-action-timeline";
import { summarizeActionStatus } from "./evidence-action-status";
import { suggestActionAlerts } from "./evidence-action-alerts";
import { summarizeActionAlerts } from "./evidence-action-alert-digest";
import { filterActionPlan } from "./evidence-action-filter";
import type { ActionFilter } from "./evidence-action-filter";
/** An offline, tenant-scoped view that composes the action workflow. Never persists or sends alerts. */
export function buildActionWorkspace(plan:ActionPlan,events:readonly ActionProgressEvent[],organizationId:string,asOf:string,options:ActionFilter = {}) {
 if(!organizationId||organizationId!==plan.organizationId)return null;
 const progressed=applyActionProgress(plan,events,asOf);
 const timeline=buildActionTimeline(plan,events,asOf);
 const dashboard=summarizeActionStatus(progressed.plan,timeline,organizationId);
 const alerts=suggestActionAlerts(progressed.plan,organizationId,asOf);
 const filtered=filterActionPlan(progressed.plan,organizationId,options,asOf);
 if(!dashboard||!alerts||!filtered)return null;
 const digest=summarizeActionAlerts(organizationId,alerts);
 if(!digest)return null;
 return {organizationId,plan:progressed.plan,progress:{applied:progressed.applied,rejected:progressed.rejected},timeline,dashboard,alerts:digest,filtered};
}
