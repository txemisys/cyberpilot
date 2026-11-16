import { createHash } from "node:crypto";

/** Explicit, non-remediating workflow for a persisted cross-source risk. */
export type ActionState="OPEN"|"IN_PROGRESS"|"BLOCKED"|
  "DONE_REPORTED"|"EXCEPTION"|"REOPENED";
export type ActionPriority="LOW"|"NORMAL"|"HIGH"|"URGENT";
export type ActionCommandName="CREATE"|"ASSIGN"|"PRIORITIZE"|
  "START"|"BLOCK"|"REPORT_DONE"|"ACCEPT_EXCEPTION"|
  "REOPEN"|"EDIT_DUE"|"COMMENT"|"EXPIRE_EXCEPTION";
export type ActionSnapshot={
  organizationId:string;actionId:string;riskKey:string;
  title:string;description:string;
  severity:string;sourceFingerprint:string;evidenceRefs:string[];
  status:ActionState;priority:ActionPriority;
  ownerUserId:string|null;dueAt:string|null;rationale:string|null;
  exceptionReason:string|null;exceptionExpiresAt:string|null;
  revision:number;createdById:string;updatedById:string;
  updatedAt:string;
  independentRemediationVerified:false;
  customerLegalAcceptanceProven:false;
  sourceEvidenceReevaluated:false;
};
export type ActionCommand={
  actionId:string;organizationId:string;actorUserId:string;
  expectedRevision:number;kind:ActionCommandName;
  nextOwnerUserId?:string|null;
  nextPriority?:ActionPriority;
  nextDueAt?:string|null;
  reason?:string;
  exceptionExpiresAt?:string|null;
  at:string;
};
export type ActionDomainEvent={
  organizationId:string;actionId:string;revision:number;
  kind:ActionCommandName;
  previousStatus:ActionState;nextStatus:ActionState;
  actorUserId:string;occurredAt:string;
  snapshotDigest:string;
  automaticallyExecutedRemediation:false;
};
export type ActionTransition={
  accepted:boolean;
  code:string;
  previous:ActionSnapshot;
  next:ActionSnapshot|null;
  event:ActionDomainEvent|null;
  requiresIndependentVerification:boolean;
  legalConsentAutomaticallyCreated:false;
};
export type ActionAuditResult={
  valid:boolean;errors:string[];
  latestStatus:ActionState|null;
  latestRevision:number;
  eventsChecked:number;
  sourceBindingUnchanged:boolean;
  externallyVerifiedRemediation:false;
  businessRiskAcceptedByAuthority:false;
};
export type ActionBoardSummary={
  total:number;open:number;inProgress:number;
  blocked:number;doneReported:number;exceptions:number;reopened:number;
  overdue:number;unassigned:number;
  urgent:number;high:number;normal:number;low:number;
  expiringExceptions:number;expiredExceptions:number;
  withoutEvidence:number;revisionConflicts:number;
  reportedButNotVerified:number;
  acceptedRiskLegallyConfirmed:0;
  riskActuallyRemediated:0;
};
const states:ActionState[]=[
  "OPEN","IN_PROGRESS","BLOCKED","DONE_REPORTED","EXCEPTION","REOPENED",
];
const priorities:ActionPriority[]=["LOW","NORMAL","HIGH","URGENT"];
const isISO=(x:string):boolean=>typeof x==="string"&&
  Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const id=(x:string):boolean=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const digest=(x:string):boolean=>typeof x==="string"&&
  /^[a-f0-9]{64}$/.test(x);
const safe=(x:string,max:number)=>typeof x==="string"&&
  x.length<=max&&!/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(x);
function canonical(x:unknown):string{
  if(x===null)return "null";
  if(typeof x==="string"||typeof x==="boolean")return JSON.stringify(x);
  if(typeof x==="number"){
    if(!Number.isFinite(x))throw Error("Nonfinite audit input");
    return JSON.stringify(x);
  }
  if(Array.isArray(x))return"["+x.map(canonical).join(",")+"]";
  if(typeof x==="object")return"{"+Object.entries(x).sort(
    ([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
  throw Error("Unsupported audit input");
}
const hash=(x:unknown)=>createHash("sha256")
  .update(canonical(x)).digest("hex");
function reject(previous:ActionSnapshot,code:string):ActionTransition{
  return{accepted:false,code,previous,next:null,event:null,
    requiresIndependentVerification:true,
    legalConsentAutomaticallyCreated:false};
}
function transitionPermitted(status:ActionState,kind:ActionCommandName){
  if(["ASSIGN","PRIORITIZE","EDIT_DUE","COMMENT"].includes(kind))
    return true;
  switch(kind){
    case"START":return ["OPEN","REOPENED","BLOCKED"].includes(status);
    case"BLOCK":return ["OPEN","IN_PROGRESS","REOPENED"].includes(status);
    case"REPORT_DONE":return ["IN_PROGRESS","BLOCKED"].includes(status);
    case"ACCEPT_EXCEPTION":return [
      "OPEN","IN_PROGRESS","BLOCKED","REOPENED"].includes(status);
    case"REOPEN":return ["DONE_REPORTED","EXCEPTION","BLOCKED"].includes(status);
    case"EXPIRE_EXCEPTION":return status==="EXCEPTION";
    default:return false;
  }
}
function nextStatus(status:ActionState,kind:ActionCommandName):ActionState{
  if(kind==="START")return"IN_PROGRESS";
  if(kind==="BLOCK")return"BLOCKED";
  if(kind==="REPORT_DONE")return"DONE_REPORTED";
  if(kind==="ACCEPT_EXCEPTION")return"EXCEPTION";
  if(kind==="REOPEN"||kind==="EXPIRE_EXCEPTION")return"REOPENED";
  return status;
}
export function validateActionSnapshot(snapshot:ActionSnapshot):
  {valid:boolean;issues:string[]}{
  const issues:string[]=[];
  if(!id(snapshot.organizationId)||!id(snapshot.actionId)||
    !digest(snapshot.riskKey)||!digest(snapshot.sourceFingerprint))
    issues.push("IDENTITY_OR_PROVENANCE_INVALID");
  if(!safe(snapshot.title,250)||snapshot.title.trim().length===0||
    !safe(snapshot.description,4000))
    issues.push("RISK_TEXT_INVALID");
  if(!states.includes(snapshot.status)||!priorities.includes(snapshot.priority))
    issues.push("STATUS_OR_PRIORITY_INVALID");
  if(!Array.isArray(snapshot.evidenceRefs)||
    snapshot.evidenceRefs.length>100||
    snapshot.evidenceRefs.some(x=>!id(x))||
    new Set(snapshot.evidenceRefs).size!==snapshot.evidenceRefs.length)
    issues.push("EVIDENCE_REFS_INVALID");
  if(snapshot.ownerUserId!==null&&!id(snapshot.ownerUserId))
    issues.push("OWNER_INVALID");
  if(snapshot.dueAt!==null&&!isISO(snapshot.dueAt))
    issues.push("DUE_INVALID");
  if(snapshot.rationale!==null&&!safe(snapshot.rationale,2000))
    issues.push("RATIONALE_INVALID");
  if(snapshot.exceptionReason!==null&&
    (!safe(snapshot.exceptionReason,2000)||
      snapshot.exceptionReason.trim().length<15))
    issues.push("EXCEPTION_REASON_INSUFFICIENT");
  if(snapshot.exceptionExpiresAt!==null&&!isISO(snapshot.exceptionExpiresAt))
    issues.push("EXCEPTION_EXPIRY_INVALID");
  if(snapshot.status==="EXCEPTION"&&
    (!snapshot.exceptionReason||!snapshot.exceptionExpiresAt))
    issues.push("UNBOUNDED_EXCEPTION_NOT_ALLOWED");
  if(!Number.isSafeInteger(snapshot.revision)||snapshot.revision<1)
    issues.push("REVISION_INVALID");
  if(!id(snapshot.createdById)||!id(snapshot.updatedById)||
    !isISO(snapshot.updatedAt))
    issues.push("ACTOR_OR_TIME_INVALID");
  if(snapshot.independentRemediationVerified!==false||
    snapshot.customerLegalAcceptanceProven!==false||
    snapshot.sourceEvidenceReevaluated!==false)
    issues.push("FALSE_SECURITY_ASSERTION");
  return{valid:issues.length===0,issues};
}
export function applyIntegratedActionCommand(
  previous:ActionSnapshot,command:ActionCommand):ActionTransition{
  const baseline=validateActionSnapshot(previous);
  if(!baseline.valid)return reject(previous,"SOURCE_SNAPSHOT_INVALID");
  if(command.kind==="CREATE")return reject(previous,"CREATE_REQUIRES_ORIGINAL_RISK");
  if(command.organizationId!==previous.organizationId||
    command.actionId!==previous.actionId||
    !id(command.actorUserId))
    return reject(previous,"CROSS_TENANT_OR_ACTOR_INVALID");
  if(!isISO(command.at)||command.at<previous.updatedAt)
    return reject(previous,"INVALID_OR_NONMONOTONIC_CLOCK");
  if(!Number.isSafeInteger(command.expectedRevision)||
    command.expectedRevision!==previous.revision)
    return reject(previous,"CAS_REVISION_CONFLICT");
  if(!transitionPermitted(previous.status,command.kind))
    return reject(previous,"ILLEGAL_WORKFLOW_TRANSITION");
  const reason=command.reason?.trim()??"";
  if(!safe(reason,2000))
    return reject(previous,"COMMAND_REASON_INVALID");
  if(["BLOCK","REPORT_DONE","ACCEPT_EXCEPTION"].includes(command.kind)&&
    reason.length<15)
    return reject(previous,"REASON_MINIMUM_NOT_MET");
  if(command.kind==="ASSIGN"&&
    command.nextOwnerUserId!==null&&
    (!command.nextOwnerUserId||!id(command.nextOwnerUserId)))
    return reject(previous,"OWNER_NOT_VALID");
  if(command.kind==="PRIORITIZE"&&
    (!command.nextPriority||!priorities.includes(command.nextPriority)))
    return reject(previous,"PRIORITY_NOT_VALID");
  if(command.kind==="EDIT_DUE"&&
    command.nextDueAt!==null&&
    (!command.nextDueAt||!isISO(command.nextDueAt)))
    return reject(previous,"DUE_DATE_NOT_VALID");
  if(command.kind==="ACCEPT_EXCEPTION"&&
    (!command.exceptionExpiresAt||
      !isISO(command.exceptionExpiresAt)||
      command.exceptionExpiresAt<=command.at||
      Date.parse(command.exceptionExpiresAt)-Date.parse(command.at)>
        90*86400000))
    return reject(previous,"EXCEPTION_DURATION_INVALID");
  if(command.kind==="EXPIRE_EXCEPTION"&&
    (!previous.exceptionExpiresAt||
      previous.exceptionExpiresAt>command.at))
    return reject(previous,"EXCEPTION_NOT_EXPIRED");
  const next:ActionSnapshot={
    ...previous,revision:previous.revision+1,
    updatedById:command.actorUserId,updatedAt:command.at,
    status:nextStatus(previous.status,command.kind),
    independentRemediationVerified:false,
    customerLegalAcceptanceProven:false,
    sourceEvidenceReevaluated:false,
  };
  if(command.kind==="ASSIGN")
    next.ownerUserId=command.nextOwnerUserId??null;
  if(command.kind==="PRIORITIZE")
    next.priority=command.nextPriority!;
  if(command.kind==="EDIT_DUE")
    next.dueAt=command.nextDueAt??null;
  if(reason&&command.kind!=="ACCEPT_EXCEPTION")
    next.rationale=reason;
  if(command.kind==="ACCEPT_EXCEPTION"){
    next.exceptionReason=reason;
    next.exceptionExpiresAt=command.exceptionExpiresAt!;
  }
  if(command.kind==="REOPEN"||command.kind==="EXPIRE_EXCEPTION"){
    next.exceptionReason=null;next.exceptionExpiresAt=null;
  }
  if(command.kind==="REPORT_DONE"&&next.ownerUserId===null)
    return reject(previous,"OWNER_REQUIRED_TO_REPORT_COMPLETION");
  const valid=validateActionSnapshot(next);
  if(!valid.valid)return reject(previous,valid.issues[0]??"NEXT_INVALID");
  return{
    accepted:true,code:"TRANSITION_ACCEPTED",previous,next,
    event:{
      organizationId:next.organizationId,
      actionId:next.actionId,revision:next.revision,
      kind:command.kind,previousStatus:previous.status,
      nextStatus:next.status,actorUserId:command.actorUserId,
      occurredAt:command.at,snapshotDigest:hash(next),
      automaticallyExecutedRemediation:false,
    },
    requiresIndependentVerification:true,
    legalConsentAutomaticallyCreated:false,
  };
}
export function auditIntegratedActionHistory(
  snapshot:ActionSnapshot,events:ActionDomainEvent[],
):ActionAuditResult {
  const issues:string[]=[];
  if(!validateActionSnapshot(snapshot).valid)
    issues.push("SNAPSHOT_INVALID");
  const ordered=[...events].sort((a,b)=>a.revision-b.revision);
  if(ordered.length!==snapshot.revision)issues.push("EVENT_HISTORY_INCOMPLETE");
  for(let i=0;i<ordered.length;i++){
    const event=ordered[i]!;
    if(event.revision!==i+1)issues.push("EVENT_SEQUENCE_BROKEN");
    if(event.organizationId!==snapshot.organizationId||
      event.actionId!==snapshot.actionId)
      issues.push("EVENT_CROSS_SCOPE");
    if(i>0&&event.previousStatus!==ordered[i-1]!.nextStatus)
      issues.push("EVENT_TRANSITION_BREAK");
    if(!digest(event.snapshotDigest)||
      !id(event.actorUserId)||!isISO(event.occurredAt))
      issues.push("EVENT_PROVENANCE_INVALID");
    if(event.automaticallyExecutedRemediation!==false)
      issues.push("FALSE_REMEDIATION_EVENT");
  }
  const latest=ordered.at(-1);
  if(latest&&latest.nextStatus!==snapshot.status)
    issues.push("LATEST_STATE_MISMATCH");
  if(latest&&latest.revision!==snapshot.revision)
    issues.push("LATEST_CAS_MISMATCH");
  if(latest&&latest.snapshotDigest!==hash(snapshot))
    issues.push("LATEST_DIGEST_MISMATCH");
  return{
    valid:issues.length===0,errors:[...new Set(issues)],
    latestStatus:latest?.nextStatus??null,
    latestRevision:latest?.revision??0,
    eventsChecked:ordered.length,
    sourceBindingUnchanged:true,
    externallyVerifiedRemediation:false,
    businessRiskAcceptedByAuthority:false,
  };
}
export function summarizeIntegratedActionBoard(
  actions:ActionSnapshot[],asOf:string
):ActionBoardSummary {
  if(!isISO(asOf))throw Error("Invalid board timestamp");
  const total=actions.length;
  const count=(state:ActionState)=>
    actions.filter(x=>x.status===state).length;
  const priority=(p:ActionPriority)=>
    actions.filter(x=>x.priority===p).length;
  const due=(x:ActionSnapshot)=>
    x.dueAt!==null&&x.dueAt<asOf&&
    !["DONE_REPORTED","EXCEPTION"].includes(x.status);
  const activeExceptions=actions.filter(x=>x.status==="EXCEPTION");
  return {
    total,open:count("OPEN"),inProgress:count("IN_PROGRESS"),
    blocked:count("BLOCKED"),doneReported:count("DONE_REPORTED"),
    exceptions:count("EXCEPTION"),reopened:count("REOPENED"),
    overdue:actions.filter(due).length,
    unassigned:actions.filter(x=>!x.ownerUserId).length,
    urgent:priority("URGENT"),high:priority("HIGH"),
    normal:priority("NORMAL"),low:priority("LOW"),
    expiringExceptions:activeExceptions.filter(x=>
      x.exceptionExpiresAt!==null&&x.exceptionExpiresAt>asOf&&
      Date.parse(x.exceptionExpiresAt)-Date.parse(asOf)<7*86400000).length,
    expiredExceptions:activeExceptions.filter(x=>
      x.exceptionExpiresAt!==null&&x.exceptionExpiresAt<=asOf).length,
    withoutEvidence:actions.filter(x=>x.evidenceRefs.length===0).length,
    revisionConflicts:0,
    reportedButNotVerified:count("DONE_REPORTED"),
    acceptedRiskLegallyConfirmed:0,
    riskActuallyRemediated:0,
  };
}
export function sortIntegratedActions(
  actions:ActionSnapshot[],order:"PRIORITY"|"DUE"|"UPDATED"="PRIORITY"
):ActionSnapshot[]{
  const ranks:Record<ActionPriority,number>={
    URGENT:0,HIGH:1,NORMAL:2,LOW:3,
  };
  return [...actions].sort((a,b)=>{
    if(order==="UPDATED")
      return b.updatedAt.localeCompare(a.updatedAt)||
        a.actionId.localeCompare(b.actionId);
    if(order==="DUE")
      return (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||
        a.actionId.localeCompare(b.actionId);
    return ranks[a.priority]-ranks[b.priority]||
      (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||
      a.actionId.localeCompare(b.actionId);
  });
}
export function compareIntegratedActionBoards(
  before:ActionSnapshot[],after:ActionSnapshot[],asOf:string){
  const past=summarizeIntegratedActionBoard(before,asOf);
  const next=summarizeIntegratedActionBoard(after,asOf);
  const b=new Map(before.map(x=>[x.actionId,x]));
  const a=new Map(after.map(x=>[x.actionId,x]));
  const changed=after.filter(x=>
    b.has(x.actionId)&&
    b.get(x.actionId)!.revision!==x.revision);
  return{
    newlyTracked:after.filter(x=>!b.has(x.actionId)).map(x=>x.actionId),
    removed:before.filter(x=>!a.has(x.actionId)).map(x=>x.actionId),
    revised:changed.map(x=>x.actionId),
    blockedDelta:next.blocked-past.blocked,
    overdueDelta:next.overdue-past.overdue,
    doneReportedDelta:next.doneReported-past.doneReported,
    remediationIndependentlyVerified:false as const,
    humanRiskAcceptanceEstablished:false as const,
  };
}
export function serializeActionBoard(
  actions:ActionSnapshot[],asOf:string,organizationId:string
){
  if(actions.some(x=>x.organizationId!==organizationId||
    !validateActionSnapshot(x).valid))
    throw Error("Tenant or action validation failed");
  const sorted=sortIntegratedActions(actions);
  const summary=summarizeIntegratedActionBoard(sorted,asOf);
  const base={
    schema:"cyberpilot.integrated.action.board.v1" as const,
    organizationId,asOf,summary,
    rows:sorted.map(x=>({
      actionId:x.actionId,riskKey:x.riskKey,
      title:x.title,severity:x.severity,status:x.status,
      ownerUserId:x.ownerUserId,priority:x.priority,
      dueAt:x.dueAt,revision:x.revision,
      evidenceCount:x.evidenceRefs.length,
      independentlyVerifiedRemediation:false as const,
    })),
    customerRiskAcceptanceVerified:false as const,
    liveRemediationExecuted:false as const,
    historicalScoreUpdated:false as const,
  };
  return {...base,digest:hash(base)};
}
