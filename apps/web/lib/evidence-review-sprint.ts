import type{EvidenceDecisionReport,EvidenceDecisionPriority,
  EvidenceDecisionCode}from "./evidence-decision-engine";
import {verifyEvidenceDecisionReport}from "./evidence-decision-engine";
export type EvidenceReviewSprint={
  organizationId:string;startAt:string;endAt:string;
  capacity:number;selection:string[];
  planned:Array<{decisionKey:string;priority:EvidenceDecisionPriority;
    code:EvidenceDecisionCode;ownerNeeded:boolean;
    sourceEvidenceCount:number;estimatedUnits:number;
    label:string}>;
  deferred:Array<{decisionKey:string;reason:string}>;
  blocked:boolean;
  unidentifiedCustomerProof:true;
  actualRemediationVerified:false;
};
export function planEvidenceReviewSprint(input:{
  report:EvidenceDecisionReport;startAt:string;
  capacity:number;includeMonitor?:boolean;
  sourceLimit?:number;domainLimit?:number;
}):EvidenceReviewSprint{
  if(!verifyEvidenceDecisionReport(input.report).valid)
    throw Error("INVALID_EVIDENCE_SPRINT_REPORT");
  const{report}=input;
  const iso=(s:string)=>Number.isFinite(Date.parse(s))&&
    new Date(s).toISOString()===s;
  if(!iso(input.startAt)||!Number.isSafeInteger(input.capacity)||
    input.capacity<1||input.capacity>500||
    input.sourceLimit!==undefined&&
      (!Number.isSafeInteger(input.sourceLimit)||input.sourceLimit<1||
        input.sourceLimit>500)||
    input.domainLimit!==undefined&&
      (!Number.isSafeInteger(input.domainLimit)||input.domainLimit<1||
        input.domainLimit>500))
    throw Error("INVALID_REVIEW_CAPACITY");
  const endAt=new Date(Date.parse(input.startAt)+14*86400000).toISOString();
  const selected:EvidenceReviewSprint["planned"]=[];
  const deferred:EvidenceReviewSprint["deferred"]=[];
  const sourceCounts=new Map<string,number>();
  const domainCounts=new Map<string,number>();
  let used=0;
  for(const entry of report.decisions){
    if(entry.status==="MONITOR"&&!input.includeMonitor){
      deferred.push({decisionKey:entry.key,reason:"MONITORING_ONLY"});
      continue;
    }
    const primary=entry.source[0]??"UNKNOWN";
    const counted=sourceCounts.get(primary)??0;
    const domainCount=domainCounts.get(entry.domain)??0;
    const units=(entry.priority==="P0"?3:
      entry.priority==="P1"?2:1)+
      (entry.supportingEvidenceIds.length===0?1:0);
    if(counted>=(input.sourceLimit??500)){
      deferred.push({decisionKey:entry.key,reason:"SOURCE_CAPACITY"});
      continue;
    }
    if(domainCount>=(input.domainLimit??500)){
      deferred.push({decisionKey:entry.key,reason:"DOMAIN_CAPACITY"});
      continue;
    }
    if(used+units>input.capacity){
      deferred.push({decisionKey:entry.key,reason:"CAPACITY_EXCEEDED"});
      continue;
    }
    used+=units;sourceCounts.set(primary,counted+1);
    domainCounts.set(entry.domain,domainCount+1);
    selected.push({
      decisionKey:entry.key,priority:entry.priority,
      code:entry.code,ownerNeeded:true,
      sourceEvidenceCount:entry.supportingEvidenceIds.length,
      estimatedUnits:units,
      label:entry.domain+" / "+entry.controlId,
    });
  }
  return{
    organizationId:report.organizationId,startAt:input.startAt,endAt,
    capacity:input.capacity,selection:selected.map(x=>x.decisionKey),
    planned:selected,deferred,
    blocked:report.outcome==="BLOCKED"||report.totals.blocked>0,
    unidentifiedCustomerProof:true,
    actualRemediationVerified:false,
  };
}
export function summarizeEvidenceReviewBacklog(report:EvidenceDecisionReport){
  if(!verifyEvidenceDecisionReport(report).valid)
    throw Error("INVALID_EVIDENCE_BACKLOG");
  const sources=report.sources.map(x=>({
    source:x.source,
    totalReviewItems:x.assignedDecisions,
    technicalOrScopeProofNeeded:report.decisions.filter(d=>
      d.source.includes(x.source)&&
      (d.code==="REQUEST_TECHNICAL_PROOF"||
        d.code==="REQUEST_SCOPE_PROOF")).length,
    urgent:report.decisions.filter(d=>
      d.source.includes(x.source)&&d.priority==="P0").length,
    withoutEvidence:report.decisions.filter(d=>
      d.source.includes(x.source)&&
      d.supportingEvidenceIds.length===0).length,
    notAnAuthenticatedTenant:true as const,
  }));
  const codeBreakdown=report.decisions.reduce(
    (map,decision)=>{
      map[decision.code]=(map[decision.code]??0)+1;
      return map;
    },{} as Partial<Record<EvidenceDecisionCode,number>>);
  return{
    organizationId:report.organizationId,
    reportDigest:report.reportDigest,
    sourceSummary:sources,codeBreakdown,
    priorityBreakdown:{
      P0:report.totals.priority0,P1:report.totals.priority1,
      P2:report.totals.priority2,P3:report.totals.priority3,
    },
    backlogWithoutEvidence:report.totals.decisionsWithoutEvidence,
    decisions:report.decisions.length,
    customerSecurityVerified:false as const,
  };
}
export function compareEvidenceReviewSprints(
  earlier:EvidenceReviewSprint,later:EvidenceReviewSprint){
  if(earlier.organizationId!==later.organizationId||
    earlier.startAt>=later.startAt)
    throw Error("CROSS_TENANT_OR_NONCHRONOLOGICAL_SPRINT");
  const first=new Set(earlier.selection);
  const second=new Set(later.selection);
  return{
    organizationId:earlier.organizationId,
    added:later.selection.filter(x=>!first.has(x)),
    omitted:earlier.selection.filter(x=>!second.has(x)),
    capacityDelta:later.capacity-earlier.capacity,
    deferredDelta:later.deferred.length-earlier.deferred.length,
    omissionDoesNotProveRemediation:true as const,
  };
}
