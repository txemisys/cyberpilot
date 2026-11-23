import { createHash } from "node:crypto";
import { getIncidentPlaybook, type IncidentType, type IncidentSeverity,
  type RiskClass, type IncidentState } from "./incident-playbook-catalog";
import { type IncidentSnapshot, type IncidentEvent,
  type IncidentEvidence, incidentDigest, validateIncidentSnapshot }
  from "./incident-case-domain";

export type TriageUrgency = "IMMEDIATE" | "HIGH" | "NORMAL" | "MONITOR";
export type IncidentTriagePolicy = {
  triageTargetMinutes: Record<IncidentSeverity, number>;
  followUpMinutes: Record<IncidentSeverity, number>;
  maximumOpenHours: Record<IncidentSeverity, number>;
  evidenceStaleHours: number; earliestEscalationMinutes: number;
  requireSeparateApprover: boolean; maxPageItems: number;
};
export const DEFAULT_INCIDENT_TRIAGE_POLICY: IncidentTriagePolicy = {
  triageTargetMinutes: {LOW:1440,MEDIUM:480,HIGH:120,CRITICAL:30},
  followUpMinutes: {LOW:2880,MEDIUM:1440,HIGH:240,CRITICAL:60},
  maximumOpenHours: {LOW:720,MEDIUM:336,HIGH:72,CRITICAL:24},
  evidenceStaleHours:72, earliestEscalationMinutes:5,
  requireSeparateApprover:true,maxPageItems:100,
};
export type TriageBarrier = "UNKNOWN_SOURCE" | "EVIDENCE_CONFLICT" |
  "EVIDENCE_STALE" | "APPROVAL_REQUIRED" | "APPROVAL_EXPIRED" |
  "APPROVAL_SELF_ISSUED" | "NO_OWNER" | "STEP_BLOCKED" |
  "REPORTED_NOT_VERIFIED" | "HISTORY_INCOMPLETE" | "PLAYBOOK_DRIFT" |
  "TENANT_SCOPE_INVALID" | "UNSUPPORTED_SECURITY_CLAIM";
export type TriageStepReview = {
  stepId:string;title:string;
  risk:RiskClass;status:string;owner:string|null;
  expectedSources:string[];presentSources:string[];
  missingSources:string[];unknownSources:string[];
  declaredSources:string[];conflictingSources:string[];
  staleEvidenceIds:string[];approved:boolean;
  approvalExpiresAt:string|null;approvalBy:string|null;
  separateApprover:boolean;
  needsManualReview:boolean;barriers:TriageBarrier[];
  technicalRemediationVerified:false;
};
export type IncidentTriageItem = {
  id:string;organizationId:string;type:IncidentType;
  status:IncidentState;severity:IncidentSeverity;
  title:string;revision:number;
  createdAt:string;updatedAt:string;
  ownerUserId:string|null;
  ageMinutes:number;minutesToTriage:number;
  minutesToNextReview:number;overdueByMinutes:number;
  urgency:TriageUrgency;urgencyWeight:number;
  triageDueAt:string;reviewDueAt:string;
  highImpactPending:number;stepsBlocked:number;
  stepsReportedNotVerified:number;missingProofCategories:number;
  evidenceConflicts:number;staleEvidenceCount:number;
  approvalExpiryCount:number;unassigned:boolean;
  blockers:TriageBarrier[];nextSteps:string[];
  stageReviews:TriageStepReview[];
  currentSnapshotDigest:string;
  cyberScoreV1Untouched:true;containmentProven:false;
};
export type TriageBoard = {
  schema:"cyberpilot.incident.triage.board.v1";
  organizationId:string;generatedAt:string;
  total:number;truncated:boolean;
  policyDigest:string;pageDigest:string;
  items:IncidentTriageItem[];
  immediate:number;overdue:number;unassigned:number;
  evidenceGaps:number;approvalProblems:number;staleEvidence:number;
  collisions:number;closedWorkflowOnly:number;
  assignedOwners:Array<{ownerId:string;count:number;immediate:number}>;
  nextReviewQueue:string[];
  completeHistoryAudited:false;
  providerWrites:0;independentContainmentProven:false;
};
const isDate=(s:unknown):s is string=>typeof s==="string"&&
  Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const hash=(v:unknown)=>createHash("sha256").update(JSON.stringify(v)).digest("hex");
const minutes=(ms:number)=>Math.floor(ms/60000);
const severityOrder:Record<IncidentSeverity,number>={
  CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};
const safeNumber=(x:unknown,min:number,max:number)=>
  Number.isSafeInteger(x)&&Number(x)>=min&&Number(x)<=max;
export function validateIncidentTriagePolicy(p:IncidentTriagePolicy){
  const errors:string[]=[];
  for(const severity of ["LOW","MEDIUM","HIGH","CRITICAL"] as const){
    if(!safeNumber(p.triageTargetMinutes?.[severity],1,10080)||
      !safeNumber(p.followUpMinutes?.[severity],1,20160)||
      !safeNumber(p.maximumOpenHours?.[severity],1,8760))
      errors.push("INCIDENT_TRIAGE_OBJECTIVES_INVALID");
  }
  if(!safeNumber(p.evidenceStaleHours,1,8760)||
    !safeNumber(p.earliestEscalationMinutes,1,240)||
    !safeNumber(p.maxPageItems,1,500)||
    typeof p.requireSeparateApprover!=="boolean")
    errors.push("INCIDENT_TRIAGE_POLICY_INVALID");
  return [...new Set(errors)];
}
function evidenceConflict(evidence:IncidentEvidence[]){
  const bySource=new Map<string,Set<string>>();
  for(const x of evidence){
    const key=x.stepId+"::"+x.source+"::"+x.sourceReference;
    const statuses=bySource.get(key)??new Set<string>();
    statuses.add(x.verdict);bySource.set(key,statuses);
  }
  return [...bySource.entries()].filter(([,verdicts])=>verdicts.size>1)
    .map(([key])=>key);
}
function examineStep(s:IncidentSnapshot,stepId:string,
  at:string,policy:IncidentTriagePolicy):TriageStepReview{
  const spec=getIncidentPlaybook(s.type).steps.find(x=>x.id===stepId);
  const progress=s.steps.find(x=>x.stepId===stepId);
  if(!spec||!progress)throw Error("INCIDENT_TRIAGE_STEP_UNKNOWN");
  const linked=s.evidence.filter(e=>progress.evidenceIds.includes(e.id));
  const cutoff=Date.parse(at)-policy.evidenceStaleHours*3600000;
  const independent=linked.filter(e=>e.verdict==="OBSERVED"&&e.independent&&
    e.observedAt!==null&&Date.parse(e.observedAt)<=Date.parse(at)&&
    Date.parse(e.observedAt)>=cutoff);
  const declared=linked.filter(x=>x.verdict==="DECLARED"||!x.independent);
  const unknown=linked.filter(x=>x.verdict==="UNKNOWN"||x.verdict==="ERROR");
  const missingSources=spec.requiredEvidence.filter(source=>
    source!=="approval"&&!independent.some(x=>x.source===source));
  const approval=s.approvals.filter(x=>x.stepId===stepId)
    .sort((a,b)=>b.approvedAt.localeCompare(a.approvedAt))[0]??null;
  const approved=!spec.requiresApproval||Boolean(approval&&
    approval.approvedAt<=at&&approval.expiresAt>at);
  const separateApprover=!approval||approval.approvedById!==progress.verifiedById&&
    approval.approvedById!==s.updatedById;
  const conflicts=evidenceConflict(linked);
  const staleEvidenceIds=linked.filter(x=>x.observedAt===null||
    Date.parse(x.observedAt)<cutoff||Date.parse(x.observedAt)>Date.parse(at))
    .map(x=>x.id);
  const barriers:TriageBarrier[]=[];
  if(missingSources.length)barriers.push("UNKNOWN_SOURCE");
  if(conflicts.length)barriers.push("EVIDENCE_CONFLICT");
  if(staleEvidenceIds.length)barriers.push("EVIDENCE_STALE");
  if(spec.requiresApproval&&!approval)barriers.push("APPROVAL_REQUIRED");
  if(spec.requiresApproval&&approval&&!approved)barriers.push("APPROVAL_EXPIRED");
  if(spec.requiresApproval&&approval&&!separateApprover&&policy.requireSeparateApprover)
    barriers.push("APPROVAL_SELF_ISSUED");
  if(progress.status==="BLOCKED")barriers.push("STEP_BLOCKED");
  if(progress.status==="REPORTED_DONE")barriers.push("REPORTED_NOT_VERIFIED");
  return {stepId,title:spec.title,risk:spec.risk,status:progress.status,
    owner:progress.assignedTo,expectedSources:spec.requiredEvidence,
    presentSources:[...new Set(independent.map(x=>x.source))].sort(),
    missingSources,unknownSources:[...new Set(unknown.map(x=>x.source))],
    declaredSources:[...new Set(declared.map(x=>x.source))],
    conflictingSources:conflicts,staleEvidenceIds,
    approved,approvalExpiresAt:approval?.expiresAt??null,
    approvalBy:approval?.approvedById??null,separateApprover,
    needsManualReview:barriers.length>0||progress.status!=="VERIFIED",
    barriers,technicalRemediationVerified:false};
}
export function evaluateIncidentTriage(s:IncidentSnapshot,at:string,
  policy:IncidentTriagePolicy=DEFAULT_INCIDENT_TRIAGE_POLICY):IncidentTriageItem{
  if(!isDate(at)||validateIncidentTriagePolicy(policy).length)
    throw Error("INCIDENT_TRIAGE_INPUT_INVALID");
  const errors=validateIncidentSnapshot(s);
  if(errors.length)throw Error("INCIDENT_TRIAGE_SNAPSHOT_INVALID:"+errors.join(","));
  const time=Date.parse(at),created=Date.parse(s.createdAt),
    updated=Date.parse(s.updatedAt);
  if(time<created)throw Error("INCIDENT_TRIAGE_FUTURE_CASE");
  const severity=s.severity as IncidentSeverity;
  const triageAt=created+policy.triageTargetMinutes[severity]*60000;
  const reviewAt=updated+policy.followUpMinutes[severity]*60000;
  const due=created+policy.maximumOpenHours[severity]*3600000;
  const stageReviews=s.steps.map(p=>examineStep(s,p.stepId,at,policy));
  const evidenceConflicts=stageReviews.reduce((n,x)=>
    n+x.conflictingSources.length,0);
  const staleEvidenceCount=stageReviews.reduce((n,x)=>
    n+x.staleEvidenceIds.length,0);
  const approvalExpiryCount=stageReviews.filter(x=>
    x.barriers.includes("APPROVAL_EXPIRED")).length;
  const highImpactPending=stageReviews.filter(x=>x.risk!=="READ_ONLY"&&
    x.status!=="VERIFIED").length;
  const stepsBlocked=stageReviews.filter(x=>x.status==="BLOCKED").length;
  const stepsReportedNotVerified=stageReviews.filter(x=>
    x.status==="REPORTED_DONE").length;
  const missingProofCategories=stageReviews.reduce((n,x)=>
    n+x.missingSources.length,0);
  const active=s.status!=="CLOSED";
  const overdueByMinutes=active?Math.max(0,minutes(time-Math.min(
    s.status==="OPEN"?triageAt:reviewAt,due))):0;
  const warning=stageReviews.some(x=>x.barriers.includes("APPROVAL_EXPIRED")||
    x.barriers.includes("EVIDENCE_CONFLICT"));
  const urgency:TriageUrgency=!active?"MONITOR":
    severity==="CRITICAL"||overdueByMinutes>=policy.earliestEscalationMinutes||
    warning&&severityOrder[severity]>=3?"IMMEDIATE":
    severity==="HIGH"||overdueByMinutes>0||stepsBlocked>0?"HIGH":
    severity==="MEDIUM"||highImpactPending>0?"NORMAL":"MONITOR";
  const weight={IMMEDIATE:4,HIGH:3,NORMAL:2,MONITOR:1}[urgency];
  const blockers=[...new Set(stageReviews.flatMap(x=>x.barriers))];
  if(!s.ownerUserId)blockers.push("NO_OWNER");
  const nextSteps=[
    ...(!s.ownerUserId?["Assign an accountable incident owner"]:[]),
    ...(s.status==="OPEN"?["Begin time-bounded triage"]:[]),
    ...(stepsBlocked?["Review blocked playbook actions"]:[]),
    ...(stepsReportedNotVerified?["Reconcile reported work with independent proof"]:[]),
    ...(missingProofCategories?["Collect missing source-specific evidence"]:[]),
    ...(approvalExpiryCount?["Renew approval after scope revalidation"]:[]),
    ...(evidenceConflicts?["Reconcile contradictory observations"]:[]),
    ...(s.status==="REVIEW"?["Perform separate closure review"]:[]),
    ...(s.status==="CLOSED"?["Retain audit; closure is not provider containment"]:[]),
  ];
  return {id:s.id,organizationId:s.organizationId,type:s.type,
    status:s.status,severity,title:s.title,revision:s.revision,
    createdAt:s.createdAt,updatedAt:s.updatedAt,ownerUserId:s.ownerUserId,
    ageMinutes:Math.max(0,minutes(time-created)),
    minutesToTriage:Math.max(0,minutes(triageAt-time)),
    minutesToNextReview:Math.max(0,minutes(reviewAt-time)),
    overdueByMinutes,urgency,urgencyWeight:weight,
    triageDueAt:new Date(triageAt).toISOString(),
    reviewDueAt:new Date(reviewAt).toISOString(),
    highImpactPending,stepsBlocked,stepsReportedNotVerified,
    missingProofCategories,evidenceConflicts,staleEvidenceCount,
    approvalExpiryCount,unassigned:s.ownerUserId===null,
    blockers,nextSteps:nextSteps.length?nextSteps:[
      "Review case status and evidence at the next scheduled checkpoint"],
    stageReviews,currentSnapshotDigest:incidentDigest(s),
    cyberScoreV1Untouched:true,containmentProven:false};
}
export function buildIncidentTriageBoard(organizationId:string,
  snapshots:IncidentSnapshot[],at:string,
  policy:IncidentTriagePolicy=DEFAULT_INCIDENT_TRIAGE_POLICY,
  truncated=false):TriageBoard{
  if(!organizationId||snapshots.length>policy.maxPageItems||
    snapshots.some(x=>x.organizationId!==organizationId))
    throw Error("INCIDENT_BOARD_SCOPE_OR_BOUND_INVALID");
  const items=snapshots.map(x=>evaluateIncidentTriage(x,at,policy))
    .sort((a,b)=>b.urgencyWeight-a.urgencyWeight||
      b.overdueByMinutes-a.overdueByMinutes||
      severityOrder[b.severity]-severityOrder[a.severity]||
      a.createdAt.localeCompare(b.createdAt)||a.id.localeCompare(b.id));
  const owners=new Map<string,{count:number;immediate:number}>();
  for(const item of items){
    if(!item.ownerUserId)continue;
    const n=owners.get(item.ownerUserId)??{count:0,immediate:0};
    n.count++;if(item.urgency==="IMMEDIATE")n.immediate++;
    owners.set(item.ownerUserId,n);
  }
  const collisions=new Set<string>();
  const references=new Map<string,string>();
  for(const item of items){
    const key=item.type+"::"+item.title.toLowerCase().trim();
    if(references.has(key))collisions.add(key);
    references.set(key,item.id);
  }
  return {schema:"cyberpilot.incident.triage.board.v1",
    organizationId,generatedAt:at,total:items.length,truncated,
    policyDigest:hash(policy),pageDigest:hash(items.map(x=>
      [x.id,x.revision,x.currentSnapshotDigest])),
    items,immediate:items.filter(x=>x.urgency==="IMMEDIATE").length,
    overdue:items.filter(x=>x.overdueByMinutes>0).length,
    unassigned:items.filter(x=>x.unassigned&&x.status!=="CLOSED").length,
    evidenceGaps:items.filter(x=>x.missingProofCategories>0).length,
    approvalProblems:items.filter(x=>x.approvalExpiryCount>0).length,
    staleEvidence:items.filter(x=>x.staleEvidenceCount>0).length,
    collisions:collisions.size,
    closedWorkflowOnly:items.filter(x=>x.status==="CLOSED").length,
    assignedOwners:[...owners.entries()].map(([ownerId,n])=>({ownerId,...n}))
      .sort((a,b)=>b.immediate-a.immediate||b.count-a.count),
    nextReviewQueue:items.filter(x=>x.status!=="CLOSED")
      .sort((a,b)=>a.reviewDueAt.localeCompare(b.reviewDueAt))
      .slice(0,30).map(x=>x.id),
    completeHistoryAudited:false,providerWrites:0,
    independentContainmentProven:false};
}
