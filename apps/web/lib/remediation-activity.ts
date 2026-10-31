export type RemediationActivityEvent = {
  id:string;
  action:string;
  resourceId:string|null;
  occurredAt:Date;
  actorType:string;
  metadata:unknown;
};
export type RemediationActivityRow = {
  id:string;
  remediationId:string;
  title:string;
  description:string;
  occurredAt:Date;
  actorLabel:string;
  href:string;
};
export type RemediationActivityDigest = {
  total:number;
  approvals:number;
  guidedSteps:number;
  executions:number;
  verifications:number;
  other:number;
  mostRecentAt:Date|null;
};

const EVENTS:Readonly<Record<string,{title:string;description:string;group:keyof Omit<RemediationActivityDigest,"total"|"mostRecentAt">}>>={
  "remediation.approved":{title:"Action approved",description:"A user approved a remediation plan.",group:"approvals"},
  "remediation.guided_step_attested":{title:"Guided step acknowledged",description:"A guided instruction was marked as performed. Security is not yet verified.",group:"guidedSteps"},
  "remediation.execute_started":{title:"Execution started",description:"The approved remediation was started.",group:"executions"},
  "remediation.execution_started":{title:"Execution started",description:"The approved remediation was started.",group:"executions"},
  "remediation.executed":{title:"Execution recorded",description:"An execution result was recorded. Evidence-based verification is still required.",group:"executions"},
  "remediation.verified":{title:"Security verified",description:"The remediation was verified by the recorded workflow.",group:"verifications"},
};
export function summarizeRemediationActivity(rows:readonly RemediationActivityRow[]):RemediationActivityDigest {
 const digest:RemediationActivityDigest={total:rows.length,approvals:0,guidedSteps:0,executions:0,verifications:0,other:0,mostRecentAt:null};
 for(const row of rows) {
  if(!digest.mostRecentAt||row.occurredAt>digest.mostRecentAt)digest.mostRecentAt=row.occurredAt;
  if(row.title==="Action approved")digest.approvals++;
  else if(row.title==="Guided step acknowledged")digest.guidedSteps++;
  else if(row.title.includes("Execution"))digest.executions++;
  else if(row.title==="Security verified")digest.verifications++;
  else digest.other++;
 }
 return digest;
}
/** Only expose known user-facing descriptions; never render arbitrary audit metadata. */
export function buildRemediationActivityTimeline(
 events:readonly RemediationActivityEvent[],
 knownRemediationIds:ReadonlySet<string>,
):RemediationActivityRow[] {
 return events
  .filter(x=>x.resourceId!==null&&knownRemediationIds.has(x.resourceId)&&x.occurredAt instanceof Date&&Number.isFinite(x.occurredAt.getTime()))
  .map(event=>{
   const descriptor=EVENTS[event.action];
   return {
    id:event.id,remediationId:event.resourceId!,occurredAt:event.occurredAt,
    title:descriptor?.title??"Action activity recorded",
    description:descriptor?.description??"An action event was recorded. Review the action for details.",
    actorLabel:event.actorType==="USER"?"Organization user":"CyberPilot process",
    href:`#activity-${event.id}`,
   };
  }).sort((a,b)=>b.occurredAt.getTime()-a.occurredAt.getTime()||a.id.localeCompare(b.id));
}
export type RemediationMilestone = {label:string;occurredAt:Date|null;verified:boolean};
export function buildRemediationMilestones(action:{
  createdAt:Date;approvedAt:Date|null;startedAt:Date|null;
  completedAt:Date|null;verifiedAt:Date|null;status:string;
}):RemediationMilestone[] {
 return [
  {label:"Action proposed",occurredAt:action.createdAt,verified:false},
  {label:"Plan approved",occurredAt:action.approvedAt,verified:false},
  {label:"Execution started",occurredAt:action.startedAt,verified:false},
  {label:"Work recorded",occurredAt:action.completedAt,verified:false},
  {label:"Security verified",occurredAt:action.status==="VERIFIED"?action.verifiedAt:null,verified:action.status==="VERIFIED"&&action.verifiedAt!==null},
 ];
}
