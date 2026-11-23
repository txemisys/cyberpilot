import { createHash } from "node:crypto";
import { getIncidentPlaybook } from "./incident-playbook-catalog";
import { type IncidentSnapshot, type IncidentEvent,
  incidentDigest } from "./incident-case-domain";
import { evaluateIncidentTriage, DEFAULT_INCIDENT_TRIAGE_POLICY }
  from "./incident-triage-assurance";
export type IncidentTimelineProblem = {
  code:string;revision:number|null;
  severity:"ERROR"|"WARNING";message:string;
  manualResolutionRequired:true;
};
export type IncidentEventTimeline = {
  schema:"cyberpilot.incident.timeline.audit.v1";
  organizationId:string;incidentId:string;
  caseRevision:number;eventCount:number;
  complete:boolean;latestEventDigestMatches:boolean;
  monotonic:boolean;noCrossTenantEvents:boolean;
  oldestEventAt:string|null;newestEventAt:string|null;
  previousStatuses:string[];
  reviewerChanges:Array<{revision:number;actor:string;
    action:string;when:string}>;
  missingRevisionNumbers:number[];
  problems:IncidentTimelineProblem[];
  chronologyDigest:string;technicalExecutionProven:false;
};
export function auditIncidentTimeline(s:IncidentSnapshot,
  events:readonly IncidentEvent[],truncated=false):IncidentEventTimeline{
  if(events.length>2000)throw Error("INCIDENT_TIMELINE_LIMIT");
  const sorted=[...events].sort((a,b)=>a.revision-b.revision);
  const problems:IncidentTimelineProblem[]=[];
  const flag=(code:string,revision:number|null,message:string)=>
    problems.push({code,revision,severity:"ERROR",message,
      manualResolutionRequired:true});
  const missing:number[]=[];
  for(let i=0;i<sorted.length;i++){
    const e=sorted[i]!;
    if(e.organizationId!==s.organizationId||e.incidentId!==s.id)
      flag("FOREIGN_EVENT",e.revision,"Event is not part of this tenant case");
    if(e.revision!==i+1){
      missing.push(i+1);
      flag("MISSING_REVISION",i+1,"Expected immutable event revision is missing");
    }
    const prior=sorted[i-1];
    if(prior&&e.previousState!==prior.nextState)
      flag("STATE_CHAIN_GAP",e.revision,"State transition does not match predecessor");
    if(prior&&e.occurredAt<prior.occurredAt)
      flag("NONMONOTONIC_TIME",e.revision,"Chronology moves backward");
    if(e.providerWrite!==false||e.independentlyClosed!==false)
      flag("UNSUPPORTED_PROVIDER_CLAIM",e.revision,
        "Offline workflow cannot prove provider execution");
  }
  const last=sorted.at(-1);
  const latestEventDigestMatches=last?.snapshotDigest===incidentDigest(s);
  if(!latestEventDigestMatches)
    flag("CURRENT_DIGEST_NOT_BOUND",last?.revision??null,
      "Latest event checksum does not bind current case");
  if(last?.nextState!==s.status)
    flag("CURRENT_STATE_NOT_BOUND",last?.revision??null,
      "Latest event state differs from case");
  if(truncated||sorted.length!==s.revision)
    flag("HISTORY_INCOMPLETE",null,"Not all persisted revisions were retrieved");
  if(sorted[0]?.kind!=="CREATE")
    flag("INITIAL_CREATE_MISSING",1,"First recorded revision must create the case");
  const chronologyDigest=createHash("sha256").update(JSON.stringify(sorted.map(e=>
    [e.revision,e.snapshotDigest,e.occurredAt,e.nextState]))).digest("hex");
  return {schema:"cyberpilot.incident.timeline.audit.v1",
    organizationId:s.organizationId,incidentId:s.id,
    caseRevision:s.revision,eventCount:events.length,
    complete:problems.length===0,
    latestEventDigestMatches,monotonic:!problems.some(p=>
      p.code==="NONMONOTONIC_TIME"||p.code==="STATE_CHAIN_GAP"),
    noCrossTenantEvents:!problems.some(p=>p.code==="FOREIGN_EVENT"),
    oldestEventAt:sorted[0]?.occurredAt??null,
    newestEventAt:last?.occurredAt??null,
    previousStatuses:[...new Set(sorted.map(e=>e.nextState))],
    reviewerChanges:sorted.filter(e=>["RECORD_APPROVAL","STEP_VERIFY",
      "CLOSE","REOPEN"].includes(e.kind)).map(e=>({
        revision:e.revision,actor:e.actorUserId,
        action:e.kind,when:e.occurredAt})),
    missingRevisionNumbers:missing,problems,
    chronologyDigest,technicalExecutionProven:false};
}
export type IncidentApprovalDiagnostic = {
  schema:"cyberpilot.incident.approval-review.v1";
  organizationId:string;incidentId:string;
  evaluatedAt:string;expectedApprovalSteps:number;
  observedApprovals:number;
  validCurrentApprovals:number;expiredApprovals:number;
  wrongScopeApprovals:number;selfApprovalRisks:number;
  approvalsByActor:Array<{actorId:string;steps:number;lastApprovedAt:string}>;
  reviewItems:Array<{stepId:string;needsApproval:boolean;
    approved:boolean;lastApprovedAt:string|null;
    expiresAt:string|null;approver:string|null;
    sourceScopeValid:boolean;separationValid:boolean;
    humanReviewRequired:boolean;reason:string}>;
  remediationActionsExecuted:0;legalAuthorizationInferred:false;
};
export function reviewIncidentApprovals(s:IncidentSnapshot,at:string):
IncidentApprovalDiagnostic{
  if(!Number.isFinite(Date.parse(at))||new Date(at).toISOString()!==at)
    throw Error("INCIDENT_APPROVAL_TIME_INVALID");
  const book=getIncidentPlaybook(s.type);
  const triage=evaluateIncidentTriage(s,at,DEFAULT_INCIDENT_TRIAGE_POLICY);
  const reviewItems=book.steps.map(spec=>{
    const state=s.steps.find(x=>x.stepId===spec.id)!;
    const approvals=s.approvals.filter(x=>x.stepId===spec.id)
      .sort((a,b)=>b.approvedAt.localeCompare(a.approvedAt));
    const last=approvals[0]??null;
    const approved=!spec.requiresApproval||Boolean(last&&last.approvedAt<=at&&
      last.expiresAt>at);
    const scopeValid=!last||/^[a-f0-9]{64}$/.test(last.scopeDigest);
    const separationValid=!last||last.approvedById!==s.updatedById&&
      last.approvedById!==state.verifiedById;
    const needsApproval=spec.requiresApproval;
    return {stepId:spec.id,needsApproval,approved,
      lastApprovedAt:last?.approvedAt??null,
      expiresAt:last?.expiresAt??null,approver:last?.approvedById??null,
      sourceScopeValid:scopeValid,separationValid,
      humanReviewRequired:needsApproval&&(!approved||!scopeValid||
        !separationValid||state.status==="REPORTED_DONE"),
      reason:!needsApproval?"No approval required for read-only guidance":
        !last?"Approval missing":!approved?"Approval expired or not yet valid":
        !scopeValid?"Approval scope digest malformed":
        !separationValid?"Reviewer may be approving own action":
        "Approval registered; execution still not proven"};
  });
  const actors=new Map<string,{steps:number;lastApprovedAt:string}>();
  for(const approval of s.approvals){
    const value=actors.get(approval.approvedById)??{steps:0,lastApprovedAt:""};
    value.steps++;
    if(value.lastApprovedAt<approval.approvedAt)
      value.lastApprovedAt=approval.approvedAt;
    actors.set(approval.approvedById,value);
  }
  return {schema:"cyberpilot.incident.approval-review.v1",
    organizationId:s.organizationId,incidentId:s.id,evaluatedAt:at,
    expectedApprovalSteps:book.steps.filter(x=>x.requiresApproval).length,
    observedApprovals:s.approvals.length,
    validCurrentApprovals:reviewItems.filter(x=>x.needsApproval&&x.approved).length,
    expiredApprovals:reviewItems.filter(x=>x.needsApproval&&!x.approved&&
      x.lastApprovedAt!==null).length,
    wrongScopeApprovals:reviewItems.filter(x=>!x.sourceScopeValid).length,
    selfApprovalRisks:reviewItems.filter(x=>!x.separationValid).length,
    approvalsByActor:[...actors.entries()].map(([actorId,x])=>({actorId,...x}))
      .sort((a,b)=>b.steps-a.steps),
    reviewItems,remediationActionsExecuted:0,legalAuthorizationInferred:false};
}
export type IncidentFollowUp = {
  code:string;incidentId:string;stepId:string|null;
  severity:"CRITICAL"|"HIGH"|"MEDIUM"|"LOW";
  ownerId:string|null;createdAt:string;dueAt:string;
  rationale:string;requiredEvidence:string[];
  readyForExecution:false;isExternalProviderOperation:false;
};
export function planIncidentFollowUps(s:IncidentSnapshot,at:string):
IncidentFollowUp[]{
  const triage=evaluateIncidentTriage(s,at);
  if(s.status==="CLOSED")return [];
  const book=getIncidentPlaybook(s.type);
  const due=(minutes:number)=>new Date(Date.parse(at)+minutes*60000).toISOString();
  const items:IncidentFollowUp[]=[];
  const push=(code:string,stepId:string|null,
    severity:IncidentFollowUp["severity"],minutes:number,
    rationale:string,requiredEvidence:string[])=>{
    items.push({code,incidentId:s.id,stepId,severity,ownerId:s.ownerUserId,
      createdAt:at,dueAt:due(minutes),rationale,requiredEvidence,
      readyForExecution:false,isExternalProviderOperation:false});
  };
  if(!s.ownerUserId)push("ASSIGN_OWNER",null,"HIGH",30,
    "An incident needs accountable ownership",["active membership"]);
  if(triage.overdueByMinutes>0)
    push("REVIEW_SLA_OVERDUE",null,triage.urgency==="IMMEDIATE"?
      "CRITICAL":"HIGH",15,"Incident review is past configured deadline",
      ["reviewer acknowledgement"]);
  for(const step of triage.stageReviews){
    const spec=book.steps.find(x=>x.id===step.stepId)!;
    if(step.status==="VERIFIED")continue;
    const severity=spec.risk==="DESTRUCTIVE"||spec.risk==="FINANCIAL"?
      "CRITICAL":spec.risk==="EXTERNAL_CHANGE"?"HIGH":"MEDIUM";
    if(step.barriers.includes("EVIDENCE_CONFLICT"))
      push("RECONCILE_CONFLICT",step.stepId,severity,30,
        "Contradictory provider or human observations",
        ["independent source reconciliation"]);
    if(step.barriers.includes("APPROVAL_EXPIRED"))
      push("RENEW_EXPIRED_APPROVAL",step.stepId,severity,30,
        "Approval expired before independent verification",
        ["scope-bound approval","current identity"]);
    if(step.status==="REPORTED_DONE")
      push("VERIFY_REPORTED_STEP",step.stepId,severity,60,
        "Human declared completion without complete independent proof",
        spec.requiredEvidence);
    if(step.status==="BLOCKED")
      push("UNBLOCK_WITH_EVIDENCE",step.stepId,severity,60,
        "Step is blocked by documented unknowns",
        spec.requiredEvidence);
    if(step.status==="IN_PROGRESS"&&step.missingSources.length)
      push("COLLECT_MISSING_SOURCE",step.stepId,severity,120,
        "Required proof classes were not independently observed",
        step.missingSources);
  }
  return items.sort((a,b)=>{
    const weight={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};
    return weight[b.severity]-weight[a.severity]||
      a.dueAt.localeCompare(b.dueAt)||
      a.code.localeCompare(b.code);
  }).slice(0,100);
}
