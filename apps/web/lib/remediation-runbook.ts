export type ActionRunbook = {
 id:string;title:string;summary:string;status:string;mode:string;
 severity:string;findingTitle:string;findingStatus:string;
 instructions:string[];verification:string[];acknowledgedSteps:ReadonlySet<number>;
 createdAt:Date;approvedAt:Date|null;startedAt:Date|null;completedAt:Date|null;verifiedAt:Date|null;
};
export type RunbookReadiness = {
 completed:number;total:number;remaining:number;percentage:number|null;
 nextStep:number|null;needsEvidence:boolean;verified:boolean;
 stage:"proposed"|"approved"|"working"|"awaiting-evidence"|"verified"|"failed"|"other";
 notice:string;
};
export function normalizeRunbookSteps(raw:unknown):string[]{
 return Array.isArray(raw)?raw.filter((x):x is string=>typeof x==="string"&&x.trim().length>0):[];
}
/** Acknowledgement is an operational signal, not proof that a control is effective. */
export function assessRunbookReadiness(action:ActionRunbook):RunbookReadiness{
 const total=action.instructions.length;
 const completed=action.instructions.filter((_,i)=>action.acknowledgedSteps.has(i)).length;
 const remaining=total-completed;
 const nextStep=action.instructions.findIndex((_,i)=>!action.acknowledgedSteps.has(i));
 const verified=action.status==="VERIFIED"&&action.verifiedAt!==null;
 const needsEvidence=!verified&&(action.status==="SUCCEEDED"||
    (action.mode==="GUIDED"&&action.status==="APPROVED"&&total>0&&remaining===0));
 const stage=verified?"verified":action.status==="FAILED"?"failed":
  needsEvidence?"awaiting-evidence":action.status==="EXECUTING"?"working":
  action.status==="APPROVED"?"approved":action.status==="PROPOSED"?"proposed":"other";
 const notices={
  proposed:"A manager must approve the proposed plan before guided work begins.",
  approved:"Work may be recorded, but completing instructions alone does not verify security.",
  working:"Execution is in progress. Review results before requesting verification.",
  "awaiting-evidence":"Request fresh evidence to verify whether the security finding was resolved.",
  verified:"The workflow records evidence-based verification. Review its audit history.",
  failed:"The last remediation attempt failed. Review failure information before retrying.",
  other:"Check the workflow status and the linked security finding before taking further action.",
 };
 return {completed,total,remaining,percentage:total?Math.round(completed/total*100):null,
  nextStep:nextStep<0?null:nextStep,needsEvidence,verified,stage,notice:notices[stage]};
}
export function runbookPlainText(action:ActionRunbook):string {
 const result=assessRunbookReadiness(action);
 const lines=[
  "CYBERPILOT — REMEDIATION RUNBOOK",
  "Operational plan; not a certificate of security compliance",
  "",
  "Action: "+action.title,
  "ID: "+action.id,
  "Severity: "+action.severity,
  "Finding: "+action.findingTitle+" ("+action.findingStatus+")",
  "Workflow: "+action.status+" / "+action.mode,
  "Summary: "+action.summary,
  "",
  "GUIDED INSTRUCTIONS",
  ...action.instructions.map((step,i)=>`${i+1}. [${action.acknowledgedSteps.has(i)?"x":" "}] ${step}`),
  "",
  "VERIFICATION CHECKLIST",
  ...action.verification.map((step,i)=>`${i+1}. [ ] ${step}`),
  "",
  "NEXT ACTION",
  result.notice,
  "",
  "RECORDED MILESTONES (UTC)",
  ...([
   ["Created",action.createdAt],["Approved",action.approvedAt],
   ["Started",action.startedAt],["Completed",action.completedAt],["Verified",action.verifiedAt],
  ] as const).map(([label,value])=>label+": "+(value?.toISOString()??"Not recorded")),
  "",
  "IMPORTANT: Acknowledged work does not establish that the finding was resolved.",
 ];
 return lines.join("\n")+"\n";
}
